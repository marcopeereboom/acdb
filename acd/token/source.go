// Package token represents an oauth2.TokenSource which has the ability to
// refresh the access token through the oauth server.
package token

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"

	"github.com/marcopeereboom/acdb/debug"

	"golang.org/x/oauth2"
)

const refreshURL = "https://go-acd.appspot.com/refresh"

// Source provides a Source with support for refreshing from the acd server.
type Source struct {
	path  string
	token *oauth2.Token

	// debug
	mask int
	debug.Debugger
}

// New returns a new Source implementing oauth2.TokenSource. The path must
// exist on the filesystem and must be of permissions 0600.
func New(path string, mask int, d debug.Debugger) (*Source, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, ErrFileNotFound
	}

	ts := &Source{
		path:     path,
		token:    new(oauth2.Token),
		mask:     mask,
		Debugger: d,
	}
	ts.readToken()

	return ts, nil
}

// Token returns an oauth2.Token. If the cached token (in (*Source).path) has
// expired, it will fetch the token from the server and cache it before
// returning it.
func (ts *Source) Token() (*oauth2.Token, error) {
	if !ts.token.Valid() {
		ts.Log(ts.mask, "[TKN] token is not valid, it has probably expired")
		if err := ts.refreshToken(); err != nil {
			return nil, err
		}

		if err := ts.saveToken(); err != nil {
			return nil, err
		}
	}

	return ts.token, nil
}

func (ts *Source) readToken() error {
	ts.Log(ts.mask, "[TKN] reading the token from %s", ts.path)
	f, err := os.Open(ts.path)
	if err != nil {
		ts.Log(ts.mask, "[TKN] %s: %s", ErrOpenFile, ts.path)
		return ErrOpenFile
	}
	if err := json.NewDecoder(f).Decode(ts.token); err != nil {
		ts.Log(ts.mask, "[TKN] %s: %s", ErrJSONDecoding, err)
		return ErrJSONDecoding
	}

	ts.Log(ts.mask, "[TKN] token loaded successfully")
	return nil
}

func (ts *Source) saveToken() error {
	ts.Log(ts.mask, "[TKN] saving the token to %s", ts.path)
	f, err := os.Create(ts.path)
	if err != nil {
		ts.Log(ts.mask, "[TKN] %s: %s", ErrCreateFile, ts.path)
		return ErrCreateFile
	}
	if err := json.NewEncoder(f).Encode(ts.token); err != nil {
		ts.Log(ts.mask, "[TKN] %s: %s", ErrJSONEncoding, err)
		return ErrJSONEncoding
	}

	ts.Log(ts.mask, "[TKN] token saved successfully")
	return nil
}

func (ts *Source) refreshToken() error {
	ts.Log(ts.mask, "[TKN] refreshing the token from %q", refreshURL)

	data, err := json.Marshal(ts.token)
	if err != nil {
		ts.Log(ts.mask, "[TKN] %s: %s", ErrJSONEncoding, err)
		return ErrJSONEncoding
	}
	req, err := http.NewRequest("POST", refreshURL, bytes.NewBuffer(data))
	if err != nil {
		ts.Log(ts.mask, "[TKN] %s: %s", ErrCreatingHTTPRequest, err)
		return ErrCreatingHTTPRequest
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		ts.Log(ts.mask, "[TKN] %s: %s", ErrDoingHTTPRequest, err)
		return ErrDoingHTTPRequest
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(ts.token); err != nil {
		ts.Log(ts.mask, "[TKN] %s: %s", ErrJSONDecodingResponseBody, err)
		return ErrJSONDecodingResponseBody
	}
	ts.Log(ts.mask, "[TKN] token was refreshed successfully")

	return nil
}
