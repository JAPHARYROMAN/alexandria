// Package repository distributes only the public projection of the catalogue.
package repository

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"

	"alexandria/internal/founding"
)

const protocol = "alexandria.catalogue.v1"
const MaxReleaseBytes = 4 << 20

var identifier = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Catalogue struct {
	Protocol  string             `json:"protocol"`
	Revision  uint64             `json:"revision"`
	Parent    string             `json:"parent,omitempty"`
	Records   []founding.Replica `json:"records"`
	Withdrawn []string           `json:"withdrawn"`
}

type envelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type Release struct {
	Catalogue Catalogue
	Digest    string
	Wire      []byte
}

func decode(raw []byte, key ed25519.PublicKey) (*Release, error) {
	if len(raw) > MaxReleaseBytes || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid catalogue size or key")
	}
	var e envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, e.Payload, e.Signature) {
		return nil, errors.New("catalogue signature does not verify")
	}
	var c Catalogue
	if err := json.Unmarshal(e.Payload, &c); err != nil {
		return nil, err
	}
	if c.Protocol != protocol || c.Revision == 0 || (c.Revision == 1 && c.Parent != "") || (c.Revision > 1 && !digestPattern.MatchString(c.Parent)) {
		return nil, errors.New("invalid catalogue header")
	}
	seen := map[string]bool{}
	for _, r := range c.Records {
		if seen[r.ID] {
			return nil, errors.New("duplicate record")
		}
		if err := r.ValidatePublic(); err != nil {
			return nil, fmt.Errorf("record %q: %w", r.ID, err)
		}
		seen[r.ID] = true
	}
	for _, id := range c.Withdrawn {
		if !identifier.MatchString(id) || seen[id] {
			return nil, errors.New("invalid or conflicting withdrawal")
		}
		seen[id] = true
	}
	return &Release{Catalogue: c, Digest: founding.Digest(e.Payload), Wire: bytes.Clone(raw)}, nil
}

func advance(old *Release, records []founding.Replica, withdraw []string, key ed25519.PrivateKey) (*Release, error) {
	c := Catalogue{Protocol: protocol, Revision: 1, Records: []founding.Replica{}, Withdrawn: []string{}}
	available := map[string]bool{}
	revoked := map[string]bool{}
	for _, r := range records {
		available[r.ID] = true
	}
	if old != nil {
		if old.Catalogue.Revision == math.MaxUint64 {
			return nil, errors.New("catalogue revision exhausted")
		}
		c.Revision = old.Catalogue.Revision + 1
		c.Parent = old.Digest
		for _, id := range old.Catalogue.Withdrawn {
			revoked[id] = true
		}
		for _, r := range old.Catalogue.Records {
			if !available[r.ID] {
				revoked[r.ID] = true
			}
		}
	}
	for _, id := range withdraw {
		if !available[id] && !revoked[id] {
			return nil, fmt.Errorf("unknown public record %q", id)
		}
		revoked[id] = true
	}
	for id := range revoked {
		c.Withdrawn = append(c.Withdrawn, id)
	}
	sort.Strings(c.Withdrawn)
	for _, r := range records {
		if !revoked[r.ID] {
			c.Records = append(c.Records, r)
		}
	}
	sort.Slice(c.Records, func(i, j int) bool { return c.Records[i].ID < c.Records[j].ID })
	if old != nil && slices.Equal(old.Catalogue.Records, c.Records) && slices.Equal(old.Catalogue.Withdrawn, c.Withdrawn) {
		return old, nil
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	wire, err := json.Marshal(envelope{Payload: body, Signature: ed25519.Sign(key, body)})
	if err != nil {
		return nil, err
	}
	return decode(wire, key.Public().(ed25519.PublicKey))
}

func currentAfter(old, next *Release) error {
	if old == nil {
		return nil
	}
	a, b := old.Catalogue, next.Catalogue
	if b.Revision < a.Revision || (b.Revision == a.Revision && next.Digest != old.Digest) {
		return errors.New("stale or conflicting catalogue")
	}
	if b.Revision == a.Revision {
		return nil
	}
	if b.Revision == a.Revision+1 && b.Parent != old.Digest {
		return errors.New("catalogue parent differs")
	}
	revoked := map[string]bool{}
	for _, id := range b.Withdrawn {
		revoked[id] = true
	}
	for _, id := range a.Withdrawn {
		if !revoked[id] {
			return errors.New("withdrawal disappeared")
		}
	}
	for _, r := range b.Records {
		revoked[r.ID] = true
	}
	for _, r := range a.Records {
		if !revoked[r.ID] {
			return errors.New("record removed without withdrawal")
		}
	}
	return nil
}

func recordVersion(r founding.Replica) string {
	// All fields are strings, so this type always marshals successfully.
	data, _ := json.Marshal(r)
	return founding.Digest(data)
}

func Lines(body string) []string {
	if body == "" {
		return nil
	}
	return strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
}
