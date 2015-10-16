package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime"

	"github.com/marcopeereboom/acdb/debug"
	"github.com/marcopeereboom/acdb/shared"
	"github.com/marcopeereboom/goutil"
)

const (
	dbgTrace = 1 << 31
	dbgLoud  = 1 << 32
)

type sfe struct {
	debug.Debugger

	compress bool
	keys     shared.Keys
	home     string
}

func (s *sfe) decrypt(filename string) error {
	md, payload, err := shared.FileNaClDecrypt(filename, &s.keys.Data)
	if err != nil {
		return err
	}

	// save file
	out, err := ioutil.TempFile(".", "sfe")
	defer func() { _ = out.Close() }()
	_, err = out.Write(payload)
	if err != nil {
		return err
	}

	fmt.Printf("%v %v\n", out.Name(), md.MimeType)

	return nil
}

func (s *sfe) encrypt(filename string) error {
	payload, err := shared.FileNaClEncrypt(filename, s.compress,
		&s.keys.Data)
	if err != nil {
		return err
	}

	outFilename := filename + ".sfe"
	for {
		_, err = os.Stat(outFilename)
		if err != nil {
			break
		}
		outFilename = "1" + outFilename
	}

	out, err := os.OpenFile(outFilename, os.O_CREATE|os.O_RDWR, 0600)
	defer func() { _ = out.Close() }()
	_, err = out.Write(payload)
	if err != nil {
		return err
	}

	return nil
}

func _main() error {
	debugLevel := flag.Int("d", 0, "debug level: 0 off, 1 trace, 2 loud")
	debugTarget := flag.String("l", "-", "debug target file name, - is stdout")
	compress := flag.Bool("c", false, "try to compress (default = false)")
	extract := flag.Bool("e", false, "extract files")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Printf("sfe [-d][-l target] <filename> ...\n")
		flag.PrintDefaults()
		return nil
	}

	var (
		err error
	)

	s := sfe{
		compress: *compress,
	}
	defer func() {
		goutil.Zero(s.keys.MD[:])
		goutil.Zero(s.keys.Data[:])
		goutil.Zero(s.keys.Dedup[:])
	}()

	// debug target
	if *debugTarget == "-" {
		s.Debugger, err = debug.NewDebugStdout()
		if err != nil {
			return err
		}
	} else {
		s.Debugger, err = debug.NewDebugFile(*debugTarget)
		if err != nil {
			return err
		}
	}

	switch *debugLevel {
	case 0:
		s.Debugger = debug.NewDebugNil()
	case 1:
		s.Debugger.Mask(dbgTrace)
	case 2:
		s.Debugger.Mask(dbgTrace | dbgLoud)
	default:
		return fmt.Errorf("invalid debug level %v", *debugLevel)
	}

	keysFilename, err := shared.DefaultKeysFilename()
	if err != nil {
		return err
	}
	rootDir := path.Dir(keysFilename)
	err = os.MkdirAll(rootDir, 0700)
	if err != nil {
		return err
	}

	err = shared.LoadKeys(keysFilename, &s.keys)
	if err != nil {
		return err
	}

	for _, v := range args {
		if *extract {
			s.Log(dbgTrace, "decrypting: %v\n", v)
			err = s.decrypt(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not decrypt: %v\n",
					err)
				continue
			}
		} else {
			s.Log(dbgTrace, "encrypting: %v\n", v)
			err = s.encrypt(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not encrypt: %v\n",
					err)
				continue
			}
		}
	}

	return nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
