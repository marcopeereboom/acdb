package main

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/marcopeereboom/acdb/acd"
	"github.com/marcopeereboom/acdb/debug"
	"github.com/marcopeereboom/acdb/metadata"
	"github.com/marcopeereboom/acdb/shared"
	"github.com/marcopeereboom/goutil"
)

const (
	dataName     = "data"
	metadataName = "metadata"
	secretsName  = "secrets"

	debugApp = 1 << 32

	modeCreate = iota
	modeExtract
	modeList
)

// acdb amazon cloud drive backup context.
type acdb struct {
	debug.Debugger

	me *metadata.MetadataEncoder
	md *metadata.MetadataDecoder

	c    *acd.Client
	keys shared.Keys

	dataID     string
	metadataID string

	// flags
	verbose  bool
	compress bool
	perms    bool
	target   string
	mode     int
	root     string

	// permission for directories
	permList *list.List
}

func (a *acdb) makeDirectories() error {
	a.Log(acd.DebugTrace, "[TRC] makeDirectories")

	asset, err := a.c.MkdirJSON(a.c.GetRoot(), dataName)
	if err != nil {
		if e, ok := acd.IsCombinedError(err); ok {
			if e.StatusCode != http.StatusConflict {
				return err
			}
		} else {
			return err
		}
	} else {
		a.dataID = asset.ID
	}

	asset, err = a.c.MkdirJSON(a.c.GetRoot(), metadataName)
	if err != nil {
		if e, ok := acd.IsCombinedError(err); ok {
			if e.StatusCode != http.StatusConflict {
				return err
			}
		} else {
			return err
		}
	} else {
		a.metadataID = asset.ID
	}

	return nil
}

func (a *acdb) walk(path string, info os.FileInfo, errIn error) error {
	a.Log(acd.DebugLoud, "[TRC] walk")

	if errIn != nil {
		fmt.Printf("skipping %v error: %v\n", path, errIn)
		return nil
	}

	var (
		payload []byte
		digest  *[sha256.Size]byte
		err     error
	)

	switch {
	case info.Mode()&os.ModeDir == os.ModeDir:
		// dir
		err = a.me.Dir(path, info)
		if err != nil {
			break
		}

	case info.Mode()&os.ModeSymlink == os.ModeSymlink:
		// symlink
		err = a.me.Symlink(path, info)
		if err != nil {
			break
		}

	case info.Mode().IsRegular() && info.Size() == 0:
		// zero sized file
		err = a.me.File(path, info, "", nil)
		if err != nil {
			break
		}

	case info.Mode().IsRegular():
		// regular file

		// external pointer AND digest
		digest, err = goutil.FileHMACSHA256(path, a.keys.Dedup[:])
		if err != nil {
			break
		}

		payload, err = shared.FileNaClEncrypt(path, a.compress,
			&a.keys.Data)
		if err != nil {
			break
		}

		mime, _, err := goutil.FileCompressible(path)
		if err != nil {
			break
		}

		err = a.me.File(path, info, mime, digest)
		if err != nil {
			break
		}

	default:
		fmt.Printf("skipping %v: unsuported file type\n", path)

		return nil
	}

	if err != nil {
		fmt.Printf("skipping %v: %v\n", path, err)
		return nil
	}

	var d, ds string
	if digest != nil {
		d = hex.EncodeToString(digest[:])
	}

	if digest != nil {
		asset, err := a.c.UploadJSON(a.dataID, d, payload)
		if err != nil {
			if e, ok := acd.IsCombinedError(err); ok {
				if e.StatusCode != http.StatusConflict {
					fmt.Printf("skipping %v: %v\n",
						path, err)
					return nil
				}
				ds += " deduped "
			} else {
				fmt.Printf("should not happen %T: %v\n",
					err, err)
				return nil
			}
		} else {
			ds += " new "
		}

		_ = asset
	}

	if a.verbose {
		if digest != nil {
			ds += "=> " + d
		}
		fmt.Printf("%v %15v %v%v\n",
			info.Mode(),
			info.Size(),
			path,
			ds)
	}

	return nil
}

func (a *acdb) archive(args []string) error {
	a.Log(acd.DebugTrace, "[TRC] archive")

	var (
		f   *os.File
		err error
	)
	if a.target == "-" {
		f, err = ioutil.TempFile("", "acdb")
	} else {
		f, err = os.Create(a.target)
	}
	if err != nil {
		return err
	}
	defer f.Close()

	// setup metadata encoder
	a.me, err = metadata.NewEncoder(f, a.compress)
	if err != nil {
		return err
	}
	defer a.me.Flush()

	// go online
	err = a.online()
	if err != nil {
		return err
	}

	for _, v := range args {
		err := filepath.Walk(v, a.walk)
		if err != nil {
			return err
		}
	}

	// determine what to do with metadata
	if a.target == "-" {
		a.me.Flush()

		// upload to cloud drive
		_, err = f.Seek(0, os.SEEK_SET)
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			return err
		}

		// read metadata
		md := make([]byte, fi.Size())
		_, err = f.Read(md)
		if err != nil {
			return err
		}

		// encrypt metadata
		nonce, err := shared.NaClNonce()
		if err != nil {
			return err
		}
		mde := secretbox.Seal(nonce[:], md, nonce, &a.keys.MD)

		// upload metadata
		name := time.Now().Format("20060102.150405")
		_, err = a.c.UploadJSON(a.metadataID, name, mde)
		if err != nil {
			return err
		}

		fmt.Printf("backup complete: %v\n", name)
	}

	return nil
}

func (a *acdb) downloadPayload(fullpath string, id [sha256.Size]byte) error {

	ids := hex.EncodeToString(id[:])

	a.Log(acd.DebugTrace, "[TRC] downloadPayload %v", ids)

	asset, err := a.c.GetMetadataFS("/data/" + ids)
	if err != nil {
		return fmt.Errorf("remote object not found")
	}
	a.Log(acd.DebugTrace, "[TRC] found asset: %v -> %v\n",
		asset.ID,
		asset.Name)
	body, err := a.c.DownloadJSON(asset.ID)
	if err != nil {
		return err
	}

	// decrypt
	_, payload, err := shared.NaClDecrypt(body, &a.keys.Data)
	if err != nil {
		return err
	}

	// save file
	out, err := ioutil.TempFile(a.root, "acdb")
	defer func() { _ = out.Close() }()
	_, err = out.Write(payload)
	if err != nil {
		return err
	}

	// rename file
	err = os.Rename(out.Name(), path.Join(a.root, fullpath))
	if err != nil {
		return err
	}

	return nil
}

func (a *acdb) extract(e *metadata.File) (bool, error) {
	a.Log(acd.DebugTrace, "[TRC] extract")

	// ensure we have a valid path
	err := os.MkdirAll(path.Join(a.root, path.Dir(e.Name)), 0755)
	if err != nil {
		return true, err
	}

	evalpath := path.Join(a.root, e.Name)
	switch {
	case a.mode == modeExtract && e.Size == 0:
		f, err := os.Create(evalpath)
		if err != nil {
			return true, err
		}
		f.Close()

	default:
		err = a.downloadPayload(e.Name, e.Digest)
		if err != nil {
			return false, err
		}
	}

	if a.perms {
		// set UID/GID/perms
		err = os.Chmod(evalpath, e.Mode)
		if err != nil {
			return true, err
		}

		err = os.Chtimes(evalpath, e.Modified,
			e.Modified)
		if err != nil {
			return true, err
		}

		err = os.Chown(evalpath, e.Owner, e.Group)
		if err != nil {
			return true, err
		}
	}

	return false, nil
}

func (a *acdb) online() error {
	a.Log(acd.DebugTrace, "[TRC] online")

	keysFilename, err := shared.DefaultKeysFilename()
	if err != nil {
		return err
	}
	rootDir := path.Dir(keysFilename)
	err = os.MkdirAll(rootDir, 0700)
	if err != nil {
		return err
	}

	filename := path.Join(rootDir, shared.TokenFilename)
	a.c, err = acd.NewClient(filename, a.Debugger)
	if err != nil {
		return fmt.Errorf("%v: %v", filename, err)
	}

	err = shared.LoadKeys(keysFilename, &a.keys)
	if err != nil {
		return err
	}

	// get root folders
	children, err := a.c.GetChildrenJSON("",
		"?filters=kind:"+acd.AssetFolder)
	if err != nil {
		return err
	}

	// save off data and metadata ids
	count := 0
	for _, v := range children.Data {
		switch v.Name {
		case dataName:
			a.dataID = v.ID
		case metadataName:
			a.metadataID = v.ID
		default:
			continue
		}
		count++
		if count == 2 {
			break
		}
	}
	if count != 2 {
		err = a.makeDirectories()
		if err != nil {
			return fmt.Errorf("could not create required "+
				"directories: %v", err)
		}
	}
	a.Log(debugApp, "[APP] root: %v data: %v metadata: %v",
		a.c.GetRoot(),
		a.dataID,
		a.metadataID)

	err = a.downloadSecrets()
	if err != nil {
		return err
	}

	return nil
}

func (a *acdb) list() error {
	a.Log(acd.DebugTrace, "[TRC] list %v", a.mode)

	if a.mode == modeExtract {
		err := a.online()
		if err != nil {
			return err
		}
	}

	// determine where md resides
	f, err := os.Open(a.target)
	if err != nil {
		// not localy so try cloud drive
		md, err := a.downloadMD(a.target)
		if err != nil {
			return err
		}

		// decrypt
		var nonce [shared.NonceSize]byte
		copy(nonce[:], md[:shared.NonceSize])
		mdd, ok := secretbox.Open(nil, md[shared.NonceSize:], &nonce,
			&a.keys.MD)
		if !ok {
			return fmt.Errorf("could not decrypt metadata")
		}

		// create local md file
		f, err = ioutil.TempFile("", "acdb")
		if err != nil {
			return err
		}
		_, err = f.Write(mdd)
		if err != nil {
			return err
		}
		_, err = f.Seek(0, os.SEEK_SET)
		if err != nil {
			return err
		}
	}

	a.md, err = metadata.NewDecoder(f)
	if err != nil {
		return err
	}

	var (
		fullpath string
		mode     os.FileMode
		size     int64
	)
	for {
		t, err := a.md.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		switch e := t.(type) {
		case metadata.Dir:
			fullpath = e.Name
			mode = e.Mode
			size = 0

			if a.mode == modeExtract {
				err := os.MkdirAll(path.Join(a.root, fullpath),
					0755)
				if err != nil {
					return err
				}

				if a.perms {
					// set perms after extracting
					a.permList.PushFront(e)
				}
			}

		case metadata.Symlink:
			fullpath = e.Name
			mode = os.ModeSymlink | 0755
			size = 0

			if a.mode == modeExtract {
				err := os.Symlink(path.Join(a.root, e.Link),
					path.Join(a.root, fullpath))
				if err != nil {
					return err
				}
			}

		case metadata.File:
			fullpath = e.Name
			mode = e.Mode
			size = e.Size

			if a.mode == modeExtract {
				fatal, err := a.extract(&e)
				if fatal && err != nil {
					return err
				}
				if err != nil {
					fmt.Printf("could not extract %v: %v\n",
						fullpath, err)
					continue
				}
			}

		default:
			return fmt.Errorf("unsuported type: %T", t)
		}

		fmt.Printf("%v %15v %v\n",
			mode,
			size,
			fullpath)
	}

	// set directory permissions
	for e := a.permList.Front(); e != nil; e = e.Next() {
		ee, ok := e.Value.(metadata.Dir)
		if !ok {
			continue
		}

		evalpath := path.Join(a.root, ee.Name)
		// set UID/GID/perms
		err = os.Chmod(evalpath, ee.Mode)
		if err != nil {
			return err
		}

		err = os.Chtimes(evalpath, ee.Modified,
			ee.Modified)
		if err != nil {
			return err
		}

		err = os.Chown(evalpath, ee.Owner, ee.Group)
		if err != nil {
			return err
		}

	}

	return nil
}

// uploadSecrets encrypts and uploads the secrets to acd for safe keeping.
func (a *acdb) uploadSecrets() error {
	a.Log(acd.DebugTrace, "[TRC] uploadSecrets")

	fmt.Printf("Cloud Drive does not have a copy of the secrets.  Please enter " +
		"the password to encrypt the secrets.  Loss of this password is " +
		"unrecoverable!\n")

	p, err := shared.PromptPassword(true)
	if err != nil {
		return err
	}
	defer func() {
		goutil.Zero(p)
	}()

	blob, err := a.keys.Encrypt(p, 32768, 16, 2)
	if err != nil {
		return err
	}

	asset, err := a.c.UploadJSON(a.metadataID, secretsName, blob)
	if err != nil {
		if e, ok := acd.IsCombinedError(err); ok {
			if e.StatusCode != http.StatusConflict {
				return fmt.Errorf("secrets appeared unexpectedly")
			}
		}
	}

	a.Log(acd.DebugTrace, "[TRC] uploadSecrets object: %v", asset.ID)

	return nil
}

func (a *acdb) verifySecrets(p, blob []byte) error {
	a.Log(acd.DebugTrace, "[TRC] verifySecrets")

	// decrypt remote secrets
	kk, err := shared.KeysDecrypt(p, 32768, 16, 2, blob)
	if err != nil {
		return err
	}

	// compare to disk one
	if bytes.Equal(a.keys.MD[:], kk.MD[:]) &&
		bytes.Equal(a.keys.Data[:], kk.Data[:]) &&
		bytes.Equal(a.keys.Dedup[:], kk.Dedup[:]) {

		return nil
	}

	return fmt.Errorf("remote secrets not identical to local secrets")
}

func (a *acdb) downloadMD(name string) ([]byte, error) {
	a.Log(acd.DebugTrace, "[TRC] downloadMD %v", name)

	asset, err := a.c.GetMetadataFS(metadataName + "/" + name)
	if err != nil {
		return nil, fmt.Errorf("remote metadata %v: not found", name)
	}
	a.Log(acd.DebugTrace, "[TRC] found asset: %v -> %v\n",
		asset.ID,
		asset.Name)
	blob, err := a.c.DownloadJSON(asset.ID)
	if err != nil {
		return nil, err
	}

	return blob, nil
}

func (a *acdb) downloadSecrets() error {
	a.Log(acd.DebugTrace, "[TRC] downloadSecrets")

	asset, err := a.c.GetMetadataFS(metadataName + "/" + secretsName)
	if err != nil {
		if err == acd.ErrNotFound {
			return a.uploadSecrets()
		}
		return fmt.Errorf("remote object not found")
	}
	a.Log(acd.DebugTrace, "[TRC] found asset: %v -> %v\n",
		asset.ID,
		asset.Name)
	blob, err := a.c.DownloadJSON(asset.ID)
	if err != nil {
		return err
	}

	var p []byte
	defer func() {
		goutil.Zero(p)
	}()

	for {
		p, err = shared.ReadPassword()
		if err == nil {
			break
		}

		if !os.IsNotExist(err) {
			return err
		}

		fmt.Printf("There is no local password file.  Please enter " +
			"password to verify the integrity of the remote " +
			"secrets.\n")
		p, err = shared.PromptPassword(false)
		if err != nil {
			return err
		}
		err = a.verifySecrets(p, blob)
		if err != nil {
			fmt.Printf("invalid password: %v\n",
				err)
			continue
		}
		return shared.WritePassword(p)
	}

	return a.verifySecrets(p, blob)
}

func _main() error {
	// tar like
	create := flag.Bool("c", false, "create archive") // default *is* true
	extract := flag.Bool("x", false, "extract archive")
	lst := flag.Bool("t", false, "list archive contents")
	verbose := flag.Bool("v", false, "verbose")
	compress := flag.Bool("z", false, "enable compression (default false)")
	perms := flag.Bool("p", false, "restore ACL")
	target := flag.String("f", "-", "archive target is Cloud Drive)")
	root := flag.String("C", "", "extract path")

	// not tar like
	debugLevel := flag.Int("d", 0, "debug level: 0 off, 1 trace, 2 loud")
	debugTarget := flag.String("l", "-", "debug target file name, - is stdout")
	flag.Parse()

	args := flag.Args()

	var err error
	a := acdb{
		permList: list.New(),
		target:   *target,
		verbose:  *verbose,
		compress: *compress,
		perms:    *perms,
		root:     *root,
	}
	defer func() {
		goutil.Zero(a.keys.MD[:])
		goutil.Zero(a.keys.Data[:])
		goutil.Zero(a.keys.Dedup[:])
	}()

	// debug target
	if *debugTarget == "-" {
		a.Debugger, err = debug.NewDebugStdout()
		if err != nil {
			return err
		}
	} else {
		a.Debugger, err = debug.NewDebugFile(*debugTarget)
		if err != nil {
			return err
		}
	}

	switch *debugLevel {
	case 0:
		a.Debugger = debug.NewDebugNil()
	case 1:
		a.Debugger.Mask(acd.DebugTrace | acd.DebugHTTP | acd.DebugURL |
			debugApp)
	case 2:
		a.Debugger.Mask(acd.DebugTrace | acd.DebugHTTP | acd.DebugURL |
			acd.DebugBody | acd.DebugJSON | acd.DebugToken |
			acd.DebugLoud | debugApp)
	default:
		return fmt.Errorf("invalid debug level %v", *debugLevel)
	}

	//a.Debugger.Mask(acd.DebugTrace | acd.DebugHTTP | acd.DebugURL |
	//acd.DebugJSON | debugApp)

	a.Log(debugApp, "[APP] start of day")
	defer a.Log(debugApp, "[APP] end of times")

	// default to create
	if *create == false && *extract == false && *lst == false {
		*create = true
	}

	// determine operation
	switch {
	case *create && !(*extract || *lst):
		a.mode = modeCreate

		if len(args) == 0 {
			fmt.Printf("acdbackup <-c> [-vzf target] filenames...\n")
			flag.PrintDefaults()
			return nil
		}

		return a.archive(args)

	case *extract && !(*create || *lst):
		a.mode = modeExtract

		if a.target == "-" {
			return fmt.Errorf("must provide archive metadata file")
		}
		return a.list()

	case *lst && !(*create || *extract):
		a.mode = modeList

		if a.target == "-" {
			return fmt.Errorf("must provide archive metadata file")
		}
		return a.list()

	default:
		return fmt.Errorf("must specify only -c, -x or -t")
	}

}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
