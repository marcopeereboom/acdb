package debug

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Debug context
type Debugger interface {
	Log(level int, format string, args ...interface{})
	GetMask() int
	Mask(mask int)
}

type debugNil struct{}

type debugFile struct {
	sync.Mutex
	path string
	mask int
}

type debugStdout struct {
	f debugFile
}

var (
	_ Debugger = (*debugNil)(nil)    // ensure interface is satisfied
	_ Debugger = (*debugFile)(nil)   // ensure interface is satisfied
	_ Debugger = (*debugStdout)(nil) // ensure interface is satisfied
)

// debugNil
func NewDebugNil() *debugNil {
	return &debugNil{}
}

func (d *debugNil) Log(level int, format string, args ...interface{}) {}
func (d *debugNil) Mask(mask int)                                     {}
func (d *debugNil) GetMask() int {
	return 0
}

// debugStdout
func NewDebugStdout() (*debugFile, error) {
	return NewDebugFile("")
}
func (d *debugStdout) Log(level int, format string, args ...interface{}) {
	d.f.Log(level, format, args...)
}

func (d *debugStdout) Mask(mask int) {
	d.f.Mask(mask)
}

func (d *debugStdout) GetMask() int {
	return d.f.GetMask()
}

// debugFile
func NewDebugFile(path string) (*debugFile, error) {
	d := debugFile{
		path: path,
	}
	return &d, nil
}

func (d *debugFile) Log(level int, format string, args ...interface{}) {
	d.Lock()
	defer d.Unlock()

	if d.mask&level != level {
		return
	}

	var (
		f   *os.File
		err error
	)
	if d.path != "" {
		f, err = os.OpenFile(d.path, os.O_CREATE|os.O_RDWR|os.O_APPEND,
			0600)
		defer func() { _ = f.Close() }()
	} else {
		f = os.Stdout
	}

	if err != nil {
		// XXX
		return
	}

	ts := time.Now().Format("2006/01/02 15:04:05 ")
	// stupid spew needs a trim
	output := strings.TrimRight(fmt.Sprintf(ts+format, args...), " \n\t")

	fmt.Fprintln(f, output)
}

func (d *debugFile) Mask(mask int) {
	d.Lock()
	defer d.Unlock()

	d.mask = mask
}

func (d *debugFile) GetMask() int {
	d.Lock()
	defer d.Unlock()

	return d.mask
}
