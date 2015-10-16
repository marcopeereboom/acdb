package shared

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path"

	"github.com/davecgh/go-xdr/xdr2"
	"github.com/klauspost/pgzip"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/marcopeereboom/goutil"
)

const (
	RootDirectory    = ".acdbackup"
	TokenFilename    = "acd-token.json"
	KeysFilename     = "keys.json"
	PasswordFilename = "password"
)

type Keys struct {
	MD    [KeySize]byte // uploaded metadata key
	Data  [KeySize]byte // uploaded data key
	Dedup [KeySize]byte // hmac key for dedup collisions
}

// internal metadata
const (
	Version = 1

	KeySize   = 32
	NonceSize = 24
)

var (
	CompNone = [4]byte{'n', 'o', 'n', 'e'}
	CompGZIP = [4]byte{'g', 'z', 'i', 'p'}
)

type Header struct {
	Version     int               // header version
	Compression [4]byte           // payload compression
	Size        uint64            // payload size
	Digest      [sha256.Size]byte // payload digest
	MimeType    string            // MIME type
}

// Encrypt returns an encrypted Keys blob.  The format of the blob is
// [salt][nonce][encrypted keys]
func (k *Keys) Encrypt(password []byte, N, r, p int) ([]byte, error) {
	// encode Keys
	var keysXDR bytes.Buffer
	_, err := xdr.Marshal(&keysXDR, k)
	if err != nil {
		return nil, err
	}

	// generate a derived key
	var salt [KeySize]byte
	_, err = io.ReadFull(rand.Reader, salt[:])
	if err != nil {
		return nil, err
	}
	dk, err := scrypt.Key(password, salt[:], N, r, p, KeySize)
	if err != nil {
		return nil, err
	}
	var key [KeySize]byte
	copy(key[:], dk)
	goutil.Zero(dk)
	go func() {
		goutil.Zero(key[:])
	}()

	// encrypt KeySafe
	nonce, err := NaClNonce()
	if err != nil {
		return nil, err
	}
	ksEncrypted := secretbox.Seal(nil, keysXDR.Bytes(), nonce, &key)

	var blob bytes.Buffer
	w := bufio.NewWriter(&blob)

	// salt
	_, err = w.Write(salt[:])
	if err != nil {
		return nil, err
	}

	// nonce
	_, err = w.Write(nonce[:])
	if err != nil {
		return nil, err
	}

	// encrypted blob
	_, err = w.Write(ksEncrypted[:])
	if err != nil {
		return nil, err
	}
	w.Flush()

	return blob.Bytes(), nil
}

// KeysDecrypt decrypts keys from a blob.  This function relies on secretbox's
// property that it'll fail decryption due to authenticators.  As such it does
// not carry a digest to validate the contents.
func KeysDecrypt(password []byte, N, r, p int,
	blob []byte) (*Keys, error) {

	var (
		salt  [KeySize]byte
		nonce [NonceSize]byte
	)

	copy(salt[:], blob[0:KeySize])
	copy(nonce[:], blob[KeySize:KeySize+NonceSize])

	// key
	dk, err := scrypt.Key(password, salt[:], N, r, p, KeySize)
	if err != nil {
		return nil, err
	}
	var key [KeySize]byte
	copy(key[:], dk)
	goutil.Zero(dk)
	go func() {
		goutil.Zero(key[:])
	}()

	ksXDR, ok := secretbox.Open(nil, blob[KeySize+NonceSize:], &nonce, &key)
	if !ok {
		return nil, fmt.Errorf("could not decrypt")
	}

	k := Keys{}
	_, err = xdr.Unmarshal(bytes.NewReader(ksXDR), &k)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal")
	}

	return &k, nil
}

func PromptPassword(save bool) ([]byte, error) {
	var (
		p1, p2 []byte
		err    error
	)
	defer func() {
		goutil.Zero(p2)
	}()

	for {
		fmt.Printf("Password: ")
		p1, err = terminal.ReadPassword(0)
		if err != nil {
			return nil, err
		}
		fmt.Printf("\nAgain   : ")
		p2, err = terminal.ReadPassword(0)
		if err != nil {
			return nil, err
		}
		fmt.Printf("\n")

		if bytes.Equal(p1, p2) && len(p1) != 0 {
			break
		}
		fmt.Printf("Passwords do not match or are empty.\n")
	}

	if save {
		err = WritePassword(p1)
		if err != nil {
			return nil, err
		}
	}

	return p1, nil
}

func DefaultPasswordFilename() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	return path.Join(usr.HomeDir, RootDirectory, PasswordFilename), nil
}

func ReadPassword() ([]byte, error) {
	filename, err := DefaultPasswordFilename()
	if err != nil {
		return nil, err
	}

	password, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return password, nil
}

func WritePassword(password []byte) error {
	filename, err := DefaultPasswordFilename()
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, password, 0600)
}

func DefaultKeysFilename() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	return path.Join(usr.HomeDir, RootDirectory, KeysFilename), nil
}

func CreateNewKeys(filename string) error {
	k := Keys{}

	_, err := io.ReadFull(rand.Reader, k.MD[:])
	if err != nil {
		return err
	}

	_, err = io.ReadFull(rand.Reader, k.Data[:])
	if err != nil {
		return err
	}

	_, err = io.ReadFull(rand.Reader, k.Dedup[:])
	if err != nil {
		return err
	}

	dir := path.Dir(filename)

	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0600)
	defer func() { _ = f.Close() }()

	e := json.NewEncoder(f)
	err = e.Encode(k)
	if err != nil {
		return err
	}

	goutil.Zero(k.MD[:])
	goutil.Zero(k.Data[:])
	goutil.Zero(k.Dedup[:])

	return nil
}

func LoadKeys(filename string, keys *Keys) error {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		err = CreateNewKeys(filename)
		if err != nil {
			return err
		}
	}

	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	d := json.NewDecoder(f)
	err = d.Decode(keys)
	if err != nil {
		return err
	}

	return nil
}

func NaClNonce() (*[NonceSize]byte, error) {
	n := [NonceSize]byte{}
	_, err := io.ReadFull(rand.Reader, n[:])
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func FileNaClEncrypt(filename string, compress bool,
	key *[KeySize]byte) ([]byte, error) {

	fd, err := goutil.FileSHA256(filename)
	if err != nil {
		return nil, err
	}

	// test compressible
	var comp bool
	payloadHeader := Header{
		Version:     Version,
		Digest:      *fd,
		Compression: CompNone,
	}
	payloadHeader.MimeType, comp, err = goutil.FileCompressible(filename)
	if err != nil {
		return nil, err
	}
	if compress {
		if comp {
			payloadHeader.Compression = CompGZIP
		}
	} else {
		comp = false
	}

	// set up reader
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	payloadHeader.Size = uint64(fi.Size())

	// encode payload [nonce][blob]
	var payload bytes.Buffer
	pw := bufio.NewWriter(&payload)

	// nonce
	nonce, err := NaClNonce()
	if err != nil {
		return nil, err
	}
	_, err = pw.Write(nonce[:])
	if err != nil {
		return nil, err
	}

	// create payload
	var b bytes.Buffer

	// can't encode directly into b because of appended 0x0a
	_, err = xdr.Marshal(&b, payloadHeader)
	if err != nil {
		return nil, err
	}

	var w io.Writer
	if comp {
		// per https://github.com/klauspost/pgzip use pgzip on > 1MB
		if fi.Size() > 1024*1024 {
			w = pgzip.NewWriter(&b)
		} else {
			w = gzip.NewWriter(&b)
		}
	} else {
		w = bufio.NewWriter(&b)
	}

	// file content
	_, err = io.Copy(w, f)
	if err != nil {
		return nil, err
	}
	_, ok := w.(io.WriteCloser)
	if ok {
		w.(io.WriteCloser).Close()
	} else {
		w.(*bufio.Writer).Flush()
	}

	// encrypt
	encryptedPayload := secretbox.Seal(nil, b.Bytes(), nonce, key)

	// append encryptedPayload to payload
	pw.Write(encryptedPayload)
	pw.Flush()

	return payload.Bytes(), nil
}

func FileNaClDecrypt(filename string, key *[KeySize]byte) (*Header, []byte,
	error) {

	body, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	return NaClDecrypt(body, key)
}

func NaClDecrypt(body []byte, key *[KeySize]byte) (*Header, []byte, error) {

	// obtain nonce
	var nonce [NonceSize]byte
	copy(nonce[:], body[:NonceSize])

	// decrypt payload
	payload, ok := secretbox.Open(nil, body[NonceSize:], &nonce, key)
	if !ok {
		return nil, nil, fmt.Errorf("could not decrypt body")
	}

	// deal with actual payload
	r := bytes.NewReader(payload)

	// decode header
	d := xdr.NewDecoder(r)
	var mh Header
	_, err := d.Decode(&mh)
	if err != nil {
		return nil, nil, err
	}

	// deal with compression
	var rd io.Reader
	switch mh.Compression {
	case CompNone:
		// reuse reader
		rd = r
	case CompGZIP:
		// always use parallel decompression
		rd, err = pgzip.NewReader(r)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("invalid compression: %v",
			mh.Compression)
	}

	var cleartext bytes.Buffer
	f := bufio.NewWriter(&cleartext)

	// read left over from the xdr reader
	_, err = io.Copy(f, rd)
	if err != nil {
		return nil, nil, err
	}

	f.Flush()

	return &mh, cleartext.Bytes(), nil
}
