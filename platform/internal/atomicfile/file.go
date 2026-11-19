// Package atomicfile publishes complete files within one directory.
package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
)

// Write creates a file or atomically replaces the previous copy when replace is true.
func Write(path string, data []byte, replace bool) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".alexandria-stage-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if replace {
		err = os.Rename(tmp.Name(), path)
	} else {
		err = publishNew(tmp.Name(), path)
	}
	if err != nil || runtime.GOOS == "windows" {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
