package repository

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"alexandria/internal/atomicfile"
	"alexandria/internal/founding"
)

func latest(dir string, key ed25519.PublicKey) (*Release, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var number uint64
	var name string
	for _, entry := range entries {
		n := entry.Name()
		if !strings.HasPrefix(n, "release-") || !strings.HasSuffix(n, ".json") {
			continue
		}
		seq, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(n, "release-"), ".json"), 10, 64)
		if err != nil || seq == 0 || n != releaseName(seq) {
			return nil, fmt.Errorf("invalid release filename %q", n)
		}
		if seq > number {
			number, name = seq, n
		}
	}
	if name == "" {
		return nil, nil
	}
	wire, err := founding.ReadBounded(filepath.Join(dir, name), MaxReleaseBytes)
	if err != nil {
		return nil, err
	}
	release, err := decode(wire, key)
	if err != nil {
		return nil, err
	}
	if release.Catalogue.Revision != number {
		return nil, errors.New("release number differs from filename")
	}
	return release, nil
}

func releaseName(n uint64) string { return fmt.Sprintf("release-%020d.json", n) }

// Publish retries on a concurrent winning writer, carrying forward all withdrawals.
func Publish(dir string, records []founding.Replica, withdraw []string, key ed25519.PrivateKey) (*Release, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing key")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 8; attempt++ {
		old, err := latest(dir, key.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}
		next, err := advance(old, records, withdraw, key)
		if err != nil {
			return nil, err
		}
		if next == old {
			return old, nil
		}
		err = atomicfile.Write(filepath.Join(dir, releaseName(next.Catalogue.Revision)), next.Wire, false)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return next, nil
	}
	return nil, errors.New("concurrent catalogue changes; retry publication")
}
