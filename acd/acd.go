package acd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/marcopeereboom/acdb/acd/token"
	"github.com/marcopeereboom/acdb/debug"
)

// unexported contants
const (
	metadataURL = "https://drive.amazonaws.com/drive/v1/nodes"
	contentURL  = "https://content-na.drive.amazonaws.com/cdproxy/nodes"
)

// exported contants
const (
	AssetFile   = "FILE"
	AssetFolder = "FOLDER"

	StatusAvailable = "AVAILABLE"
	StatusTrash     = "TRASH"
	StatusPurged    = "PURGED"

	DebugTrace = 1 << 0 // function calls
	DebugHTTP  = 1 << 1 // HTTP return errors
	DebugURL   = 1 << 2 // URL
	DebugBody  = 1 << 3 // raw body
	DebugJSON  = 1 << 4 // pretty JSON
	DebugToken = 1 << 5 // login with amazon token
	DebugLoud  = 1 << 6 // frequent function calls
)

// ResponseError is returned by cloud drive REST api.
type ResponseError struct {
	Code    string `json:"code"`
	LogRef  string `json:"logref"`
	Message string `json:"message"`
	Info    struct {
		NodeId string `json:"nodeId"`
	} `json:"info"`
}

// Assets is a collection of assets.  This structure is returned by several
// commands.
type Assets struct {
	Count     int     `json:"count"`
	NextToken string  `json:"nextToken"`
	Data      []Asset `json:"data"`
}

// Asset is either a file or a folder.  Since most fields overlap use Kind to
// determine which is which.
type Asset struct {
	// Overlapped
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Kind         string    `json:"kind"` // ACDAsset*
	Version      int       `json:"version"`
	ModifiedDate time.Time `json:"modifiedDate"`
	CreatedDate  time.Time `json:"createdDate"`
	Labels       []string  `json:"labels"`
	Description  string    `json:"description"`
	CreatedBy    string    `json:"createdBy"`
	Parents      []string  `json:"parents"`
	Status       string    `json:"status"` // ACDStatus*

	// File
	TempLink          string `json:"tempLink"`
	ContentProperties struct {
		Version     int       `json:"version"`
		MD5         string    `json:"md5"`
		Size        int       `json:"size"`
		ContentType string    `json:"contentType"`
		Extension   string    `json:"extension"`
		ContentDate time.Time `json:"contentDate"`
	} `json:"contentProperties"`

	// Folder
	Restricted bool `json:"restricted"`
	IsRoot     bool `json:"isRoot"`
	IsShared   bool `json:"isShared"`
}

type NodeJSON struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Labels []string `json:"labels,omitempty"`
	//Properties
	Parents []string `json:"parents,omitempty"`
}

// Client context
type Client struct {
	ts   *token.Source
	root string // cache root id

	debug.Debugger
}

func NewClient(path string, d debug.Debugger) (*Client, error) {
	c := Client{
		Debugger: d,
	}

	// just in case
	if d == nil {
		c.Debugger = debug.NewDebugNil()
	}

	c.Log(DebugTrace, "[TRC] NewClient %v", path)

	var err error
	c.ts, err = token.New(path, DebugToken, c.Debugger)
	if err != nil {
		return nil, err
	}

	// cache root id
	a, err := c.GetMetadataJSON("")
	if err != nil {
		return nil, err
	}

	// sanity
	if a.Name != "" || a.Kind != AssetFolder || a.IsRoot == false {
		return nil, fmt.Errorf("inconsistent root")
	}
	if a.Status != StatusAvailable {
		return nil, fmt.Errorf("root not available")
	}
	c.root = a.ID

	return &c, nil
}

func (c *Client) GetRoot() string {
	return c.root
}

func (c *Client) GetMetadataJSON(id string) (*Asset, error) {
	c.Log(DebugTrace, "[TRC] GetMetadataJSON %v", id)

	t, err := c.ts.Token()
	if err != nil {
		return nil, err
	}

	var url string
	if id == "" {
		// "" is special and means return root id
		url = metadataURL + "?filters=isRoot:true"
	} else {
		url = metadataURL + "/" + id
	}

	c.Log(DebugURL, "[URL] %v", url)

	// create http request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)

	// execute request
	clt := &http.Client{}
	res, err := clt.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	c.Log(DebugHTTP, "[HTP] %v", res.Status)

	// obtain body
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	c.Log(DebugBody, "[BDY] %v", string(body))

	switch res.StatusCode {
	case http.StatusOK:
		// success
	default:
		return nil, NewCombinedError(res.StatusCode, res.Status, body)
	}

	// convert to JSON
	var assets Assets
	err = json.Unmarshal(body, &assets)
	if err != nil {
		return nil, err
	}
	c.Log(DebugJSON, "[JSN] %v", spew.Sdump(assets))

	// sanity
	if assets.Count != 1 || len(assets.Data) != 1 {
		return nil, fmt.Errorf("sanity")
	}

	return &assets.Data[0], nil
}

func (c *Client) GetChildrenJSON(id, filter string) (*Assets, error) {
	c.Log(DebugTrace, "[TRC] GetChildrenJSON %v", id)

	t, err := c.ts.Token()
	if err != nil {
		return nil, err
	}

	var url string
	if id == "" {
		// "" uses cached root
		url = metadataURL + "/" + c.root + "/children" + filter
	} else {
		url = metadataURL + "/" + id + "/children" + filter
	}

	c.Log(DebugURL, "[URL] %v", url)

	// create http request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)

	// execute request
	clt := &http.Client{}
	res, err := clt.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	c.Log(DebugHTTP, "[HTP] %v", res.Status)

	// obtain body
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	c.Log(DebugBody, "[BDY] %v", string(body))

	switch res.StatusCode {
	case http.StatusOK:
		// success
	default:
		return nil, NewCombinedError(res.StatusCode, res.Status, body)
	}

	// convert to JSON
	var assets Assets
	err = json.Unmarshal(body, &assets)
	if err != nil {
		return nil, err
	}
	c.Log(DebugJSON, "[JSN] %v", spew.Sdump(assets))

	return &assets, nil
}

func (c *Client) MkdirJSON(parent, name string) (*Asset, error) {
	c.Log(DebugTrace, "[TRC] MkdirJSON %v %v", parent, name)

	t, err := c.ts.Token()
	if err != nil {
		return nil, err
	}

	j := NodeJSON{
		Name:    name,
		Kind:    `FOLDER`,
		Parents: []string{parent},
	}
	jj, err := json.Marshal(j)
	if err != nil {
		return nil, err
	}
	body := bytes.NewReader(jj)

	c.Log(DebugURL, "[URL] %v", metadataURL)

	// create http request
	req, err := http.NewRequest("POST", metadataURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)

	// execute request
	clt := &http.Client{}
	res, err := clt.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	c.Log(DebugHTTP, "[HTP] %v", res.Status)

	// obtain body
	rbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	c.Log(DebugBody, "[BDY] %v", string(rbody))

	switch res.StatusCode {
	case http.StatusCreated:
		// success
	default:
		return nil, NewCombinedError(res.StatusCode, res.Status, rbody)
	}

	var asset Asset
	err = json.Unmarshal(rbody, &asset)
	if err != nil {
		return nil, err
	}

	return &asset, nil
}

func (c *Client) DownloadJSON(id string) ([]byte, error) {
	c.Log(DebugTrace, "[TRC] DownloadJSON %v", id)

	t, err := c.ts.Token()
	if err != nil {
		return nil, err
	}

	url := contentURL + "/" + id + "/content"
	c.Log(DebugURL, "[URL] %v", url)

	// create http request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)

	// execute request
	clt := &http.Client{}
	res, err := clt.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	c.Log(DebugHTTP, "[HTP] %v", res.Status)

	// obtain body
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	c.Log(DebugBody, "[BDY] %v", string(body))

	switch res.StatusCode {
	case http.StatusOK:
		// success
	default:
		return nil, NewCombinedError(res.StatusCode, res.Status, body)
	}

	return body, nil
}

func (c *Client) UploadJSON(parent, filename string, payload []byte) (*Asset,
	error) {

	c.Log(DebugTrace, "[TRC] UploadJSON %v %v", filename, len(payload))

	t, err := c.ts.Token()
	if err != nil {
		return nil, err
	}

	url := contentURL
	c.Log(DebugURL, "[URL] %v", url)

	// create body
	j := NodeJSON{
		Name:    filename,
		Kind:    AssetFile,
		Parents: []string{parent},
	}
	jj, err := json.Marshal(j)
	if err != nil {
		return nil, err
	}

	// metadata
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	mh := textproto.MIMEHeader{}
	mh.Add("Content-Disposition", `form-data; name="metadata"`)
	mh.Add("Content-Type", "application/json")
	part, err := writer.CreatePart(mh)
	if err != nil {
		return nil, err
	}
	part.Write(jj)

	// content
	mh = textproto.MIMEHeader{}
	mh.Add("Content-Disposition", `form-data; name="content"; filename="`+
		filename+`"`)
	mh.Add("Content-Type", http.DetectContentType(payload))
	part, err = writer.CreatePart(mh)
	if err != nil {
		return nil, err
	}
	part.Write(payload)

	// flush
	writer.Close()

	// create http request
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	req.Header.Add("Content-Type", "multipart/form-data; boundary="+
		writer.Boundary())

	// dump body
	if c.GetMask()&DebugBody == DebugBody {
		x, _ := httputil.DumpRequestOut(req, true)
		c.Log(DebugBody, "BDY: %s", x)
	}

	// execute request
	clt := &http.Client{}
	res, err := clt.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	c.Log(DebugHTTP, "[HTP] %v", res.Status)

	// obtain body
	rbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	c.Log(DebugBody, "[BDY] %v", string(rbody))

	switch res.StatusCode {
	case http.StatusCreated:
		// success
	default:
		return nil, NewCombinedError(res.StatusCode, res.Status, rbody)
	}

	var asset Asset
	err = json.Unmarshal(rbody, &asset)
	if err != nil {
		return nil, err
	}

	return &asset, nil
}
