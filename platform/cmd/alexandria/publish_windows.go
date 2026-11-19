package main

import (
	"os"
	"syscall"
)

// MoveFileW publishes within the same directory and fails if the destination exists.
func publishNew(staged, dest string) error {
	source, err := syscall.UTF16PtrFromString(staged)
	if err != nil {
		return err
	}
	target, err := syscall.UTF16PtrFromString(dest)
	if err != nil {
		return err
	}
	if err := syscall.MoveFile(source, target); err != nil {
		return &os.LinkError{Op: "publish", Old: staged, New: dest, Err: err}
	}
	return nil
}
