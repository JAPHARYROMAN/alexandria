//go:build !windows

package main

import "os"

// A hard link creates the final name atomically and fails if it already exists.
func publishNew(staged, dest string) error {
	return os.Link(staged, dest)
}
