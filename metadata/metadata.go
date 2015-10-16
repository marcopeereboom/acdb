package metadata

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/davecgh/go-xdr/xdr2"
	"github.com/klauspost/pgzip"
)

const (
	Version = 1
)

var (
	ErrVersion     = errors.New("invalid version")
	ErrCompression = errors.New("invalid compression")
	ErrType        = errors.New("invalid type")
	ErrTypeDir     = errors.New("invalid dir type")
	ErrTypeSymlink = errors.New("invalid symlink type")
	ErrTypeFile    = errors.New("invalid file type")

	CompNone = [4]byte{'n', 'o', 'n', 'e'}
	CompGZIP = [4]byte{'g', 'z', 'i', 'p'}

	TypeDir     = [4]byte{'d', 'i', 'r'}
	TypeSymlink = [4]byte{'s', 'y', 'm', 'l'}
	TypeFile    = [4]byte{'f', 'i', 'l', 'e'}
)

type flusher interface {
	Flush() error
}

type MetadataDecoder struct {
	d *xdr.Decoder
}

func NewDecoder(r io.Reader) (*MetadataDecoder, error) {
	m := MetadataDecoder{}

	// read header
	var h Header
	d := xdr.NewDecoder(r)
	_, err := d.Decode(&h)
	if err != nil {
		return nil, err
	}

	if h.Version != Version {
		return nil, ErrVersion
	}

	switch {
	case bytes.Compare(h.Compression[:], CompNone[:]) == 0:
		m.d = d
	case bytes.Compare(h.Compression[:], CompGZIP[:]) == 0:
		br, err := pgzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		m.d = xdr.NewDecoder(br)
	default:
		return nil, ErrCompression
	}

	return &m, nil
}

func (m *MetadataDecoder) Next() (interface{}, error) {
	var t [4]byte
	_, err := m.d.Decode(&t)
	if err != nil {
		if IsEOF(err) {
			return nil, io.EOF
		}
		return nil, ErrType
	}

	switch {
	case bytes.Compare(t[:], TypeDir[:]) == 0:
		var dir Dir
		_, err = m.d.Decode(&dir)
		if err != nil {
			return nil, ErrTypeDir
		}
		return dir, nil

	case bytes.Compare(t[:], TypeSymlink[:]) == 0:
		var symlink Symlink
		_, err = m.d.Decode(&symlink)
		if err != nil {
			return nil, ErrTypeSymlink
		}
		return symlink, nil

	case bytes.Compare(t[:], TypeFile[:]) == 0:
		var file File
		_, err = m.d.Decode(&file)
		if err != nil {
			return nil, ErrTypeFile
		}
		return file, nil
	}

	return nil, ErrType
}

type MetadataEncoder struct {
	e  *xdr.Encoder
	bw io.Writer // for flushing
}

func NewEncoder(w io.Writer, compress bool) (*MetadataEncoder, error) {
	m := MetadataEncoder{}

	h := Header{
		Version: Version,
	}
	if compress {
		h.Compression = CompGZIP
	} else {
		h.Compression = CompNone
	}

	// write header
	e := xdr.NewEncoder(w)
	_, err := e.Encode(h)
	if err != nil {
		return nil, err
	}

	if compress {
		m.bw = gzip.NewWriter(w)
	} else {
		m.bw = bufio.NewWriter(w)
	}
	m.e = xdr.NewEncoder(m.bw)

	return &m, nil
}

func (m *MetadataEncoder) Dir(path string, fi os.FileInfo) error {
	_, err := m.e.Encode(TypeDir)
	if err != nil {
		return err
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		stat = &syscall.Stat_t{
			Uid: 0xffffffff,
			Gid: 0xffffffff,
		}
	}
	_, err = m.e.Encode(Dir{
		Name:     path,
		Mode:     fi.Mode(),
		Owner:    int(stat.Uid),
		Group:    int(stat.Gid),
		Modified: fi.ModTime(),
	})
	if err != nil {
		return err
	}

	return nil
}

func (m *MetadataEncoder) Symlink(path string, fi os.FileInfo) error {
	_, err := m.e.Encode(TypeSymlink)
	if err != nil {
		return err
	}

	var link string
	if filepath.IsAbs(path) {
		link, err = filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
	} else {
		link, err = filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		link, err = filepath.Rel(path, link)
		if err != nil {
			return err
		}
	}

	_, err = m.e.Encode(Symlink{
		Name: path,
		Link: link,
	})
	if err != nil {
		return err
	}

	return nil
}

func (m *MetadataEncoder) File(path string, fi os.FileInfo, mime string,
	digest *[sha256.Size]byte) error {

	_, err := m.e.Encode(TypeFile)
	if err != nil {
		return err
	}

	if digest == nil {
		digest = &[sha256.Size]byte{}
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		stat = &syscall.Stat_t{
			Uid: 0xffffffff,
			Gid: 0xffffffff,
		}
	}
	_, err = m.e.Encode(File{
		Name:     path,
		Mode:     fi.Mode(),
		Owner:    int(stat.Uid),
		Group:    int(stat.Gid),
		Size:     fi.Size(),
		Modified: fi.ModTime(),

		MimeType: mime,
		Digest:   *digest,
	})
	if err != nil {
		return err
	}

	return nil
}

func (m *MetadataEncoder) Flush() {
	if w, ok := m.bw.(flusher); ok {
		w.Flush()
	}
}

type Header struct {
	Version     int     // metadata version
	Compression [4]byte // metadata compression
}

type File struct {
	Name     string      // filename
	Mode     os.FileMode // file mode
	Owner    int         // owner id
	Group    int         // group id
	Size     int64       // file size
	Modified time.Time   // modification time

	MimeType string            // MIME type
	Digest   [sha256.Size]byte // payload digest AND external pointer
}

type Symlink struct {
	Name string // filename
	Link string // symbolic link path
}

type Dir struct {
	Name     string      // directory name
	Mode     os.FileMode // mode
	Owner    int         // owner id
	Group    int         // group id
	Modified time.Time   // modification time
}

func IsEOF(err error) bool {
	switch e := err.(type) {
	case *xdr.UnmarshalError:
		return e.ErrorCode == xdr.ErrIO && (e.Err == io.EOF || e.Err == io.ErrUnexpectedEOF)
	case *xdr.MarshalError:
		return e.ErrorCode == xdr.ErrIO && e.Err == io.EOF
	}
	return false
}
