// Package founding validates the internal collection and the terms of its approval.
package founding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxFile = 1 << 20

type Collection struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type Record struct {
	ID          string `json:"id"`
	Collection  string `json:"collection"`
	Title       string `json:"title"`
	Language    string `json:"language"`
	Credit      string `json:"credit"`
	Mode        string `json:"mode"`
	Rights      string `json:"rights"`
	Evidence    string `json:"evidence"`
	Origin      string `json:"origin,omitempty"`
	Description string `json:"description"`
	Body        string `json:"body,omitempty"`
}

type Manifest struct {
	Schema          int          `json:"schema"`
	SoftwareLicense string       `json:"software_license"`
	FirstSource     string       `json:"first_source"`
	Collections     []Collection `json:"collections"`
	Records         []Record     `json:"records"`
}

type Foundation struct {
	Manifest Manifest
	Charter  string
}

func ReadBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return b, nil
}

func Load(dir string) (*Foundation, error) {
	raw, err := ReadBounded(filepath.Join(dir, "manifest.json"), maxFile)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := decodeManifest(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	raw, err = ReadBounded(filepath.Join(dir, "charter.md"), maxFile)
	if err != nil {
		return nil, err
	}
	charter := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !validText(charter, true) {
		return nil, errors.New("charter must contain readable UTF-8 text")
	}
	return &Foundation{Manifest: m, Charter: charter}, nil
}

// JSON permits repeated keys in some parsers. An approval must have one interpretation.
func decodeManifest(raw []byte, m *Manifest) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	keys := json.NewDecoder(bytes.NewReader(raw))
	if err := inspectValue(keys, 0); err != nil {
		return err
	}
	if _, err := keys.Token(); err != io.EOF {
		return errors.New("unexpected trailing input")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(m)
}

func inspectValue(d *json.Decoder, depth int) error {
	if depth > 12 {
		return errors.New("excessive nesting")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, compound := t.(json.Delim)
	if !compound {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || !jsonKey.MatchString(name) || seen[name] {
				return fmt.Errorf("invalid or repeated field %q", key)
			}
			seen[name] = true
		}
		if err := inspectValue(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

var (
	jsonKey     = regexp.MustCompile(`^[a-z_]+$`)
	identifier  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	languageTag = regexp.MustCompile(`^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$`)
)

func validText(s string, multiline bool) bool {
	return strings.TrimSpace(s) != "" && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t'))
	}) == -1
}

func httpsURL(s string) bool {
	u, err := url.ParseRequestURI(s)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil
}

func (m Manifest) validate() error {
	if m.Schema != 1 {
		return fmt.Errorf("unsupported schema %d", m.Schema)
	}
	switch m.SoftwareLicense {
	case "Apache-2.0", "MIT", "AGPL-3.0-only":
	default:
		return fmt.Errorf("unrecognized software licence %q", m.SoftwareLicense)
	}
	collections := map[string]int{}
	for _, c := range m.Collections {
		if !identifier.MatchString(c.ID) || !validText(c.Title, false) {
			return errors.New("invalid collection identifier or title")
		}
		if _, exists := collections[c.ID]; exists {
			return fmt.Errorf("duplicate collection %q", c.ID)
		}
		collections[c.ID] = 0
	}
	for _, id := range []string{"reading-the-sky", "general-reading-room"} {
		if _, exists := collections[id]; !exists {
			return fmt.Errorf("missing founding collection %q", id)
		}
	}
	seen := map[string]bool{}
	modes := map[string]bool{}
	firstEligible := false
	for _, r := range m.Records {
		if seen[r.ID] {
			return fmt.Errorf("duplicate record %q", r.ID)
		}
		if _, exists := collections[r.Collection]; !exists {
			return fmt.Errorf("record %q has unknown collection %q", r.ID, r.Collection)
		}
		if err := r.validate(); err != nil {
			return fmt.Errorf("record %q: %w", r.ID, err)
		}
		seen[r.ID], modes[r.Mode] = true, true
		collections[r.Collection]++
		if r.ID == m.FirstSource && r.Mode == "open-data" {
			firstEligible = true
		}
	}
	if !firstEligible {
		return errors.New("first_source must identify a reusable source with permission evidence")
	}
	for _, c := range m.Collections {
		if collections[c.ID] == 0 {
			return fmt.Errorf("collection %q is empty", c.ID)
		}
	}
	for _, mode := range []string{"internal-original", "open-data", "external-link"} {
		if !modes[mode] {
			return fmt.Errorf("founding collection lacks %s material", mode)
		}
	}
	return nil
}

func (r Record) validate() error {
	if !identifier.MatchString(r.ID) || !languageTag.MatchString(r.Language) {
		return errors.New("invalid identifier or language tag")
	}
	for _, s := range []string{r.Title, r.Credit, r.Description, r.Evidence} {
		if !validText(s, false) {
			return errors.New("title, credit, description and rights evidence must be readable text")
		}
	}
	if r.Origin != "" && !httpsURL(r.Origin) {
		return errors.New("origin must be an HTTPS URL without credentials")
	}
	switch r.Mode {
	case "open-data":
		if r.Rights != "CC0-1.0" || !httpsURL(r.Evidence) || r.Origin == "" || !validText(r.Body, true) {
			return errors.New("open data requires a CC0 grant, evidence URL, origin and body")
		}
	case "external-link":
		if r.Rights != "link-only" || r.Origin == "" || r.Body != "" {
			return errors.New("external links require link-only terms, an origin and an empty body")
		}
	case "internal-original":
		if r.Rights != "internal-review" || !validText(r.Body, true) {
			return errors.New("internal originals require internal-review terms and a body")
		}
	default:
		return fmt.Errorf("unknown access mode %q", r.Mode)
	}
	return nil
}

// ReplicationPlan is an allowlist projection. Internal records and private review notes stay local.
type Replica struct {
	ID          string `json:"id"`
	Collection  string `json:"collection"`
	Title       string `json:"title"`
	Language    string `json:"language"`
	Credit      string `json:"credit"`
	Description string `json:"description"`
	Origin      string `json:"origin"`
	Rights      string `json:"rights"`
	RightsURL   string `json:"rights_url,omitempty"`
	Body        string `json:"body,omitempty"`
}

func (m Manifest) ReplicationPlan() []Replica {
	out := []Replica{}
	for _, r := range m.Records {
		if r.Mode != "external-link" && r.Mode != "open-data" {
			continue
		}
		item := Replica{ID: r.ID, Collection: r.Collection, Title: r.Title, Language: r.Language, Credit: r.Credit, Description: r.Description, Origin: r.Origin, Rights: r.Rights}
		if r.Mode == "open-data" {
			item.RightsURL, item.Body = r.Evidence, r.Body
		}
		out = append(out, item)
	}
	return out
}
