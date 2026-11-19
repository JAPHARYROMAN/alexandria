package founding

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) *Foundation {
	t.Helper()
	f, err := Load(filepath.Join("..", "..", "founding"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestInvalidProposals(t *testing.T) {
	cases := map[string]func(*Manifest){
		"missing scope":           func(m *Manifest) { m.Collections = m.Collections[:1] },
		"duplicate id":            func(m *Manifest) { m.Records = append(m.Records, m.Records[0]) },
		"unknown collection":      func(m *Manifest) { m.Records[0].Collection = "missing" },
		"unsupported schema":      func(m *Manifest) { m.Schema++ },
		"invalid licence":         func(m *Manifest) { m.SoftwareLicense = "TBD" },
		"link as first source":    func(m *Manifest) { m.FirstSource = "moon-phases" },
		"empty credit":            func(m *Manifest) { m.Records[0].Credit = " " },
		"link with copied text":   func(m *Manifest) { m.Records[1].Body = "reproduced without permission" },
		"unknown mode":            func(m *Manifest) { m.Records[1].Mode = "public" },
		"missing evidence":        func(m *Manifest) { m.Records[0].Evidence = "not checked" },
		"invalid private rights":  func(m *Manifest) { m.Records[2].Rights = "CC0-1.0" },
		"origin with credentials": func(m *Manifest) { m.Records[0].Origin = "https://name:pass@example.org/file" },
		"empty collection":        func(m *Manifest) { m.Records = m.Records[:3] },
		"missing original":        func(m *Manifest) { m.Records = append(m.Records[:2], m.Records[4]) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			m := fixture(t).Manifest
			edit(&m)
			if m.validate() == nil {
				t.Fatal("invalid proposal accepted")
			}
		})
	}
}

func TestManifestDecoding(t *testing.T) {
	for _, bad := range []string{`{"schema":1,"schema":2}`, `{"SCHEMA":1}`, `{"unknown":true}`, `{}{}`, `{"records":[{"id":"a","id":"b"}]}`, "{\"id\":\"\xff\"}"} {
		var m Manifest
		if decodeManifest([]byte(bad), &m) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestProjection(t *testing.T) {
	m := fixture(t).Manifest
	items := m.ReplicationPlan()
	if len(items) != 3 {
		t.Fatalf("unexpected projected records: %d", len(items))
	}
	for _, r := range items {
		if r.Rights == "link-only" && (r.Body != "" || r.RightsURL != "") {
			t.Fatalf("link leaked content: %q", r.ID)
		}
		if r.Rights == "CC0-1.0" && (r.Body == "" || r.RightsURL == "") {
			t.Fatalf("missing public data or rights for %q", r.ID)
		}
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"internal-review", "sky-log", "question-card", "editor", "evidence"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("internal data leaked: %s", s)
		}
	}
}

func TestApprovalBindsTermsAndSources(t *testing.T) {
	f := fixture(t)
	packet, err := f.Packet()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sig := ed25519.Sign(key, packet)
	if err := Verify(packet, sig, public); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Foundation){
		"scope":   func(f *Foundation) { f.Charter += "Changed authority." },
		"license": func(f *Foundation) { f.Manifest.SoftwareLicense = "MIT" },
		"source":  func(f *Foundation) { f.Manifest.Records[0].Body += " Edited." },
		"credit":  func(f *Foundation) { f.Manifest.Records[0].Credit = "Another editor" },
	} {
		t.Run(name, func(t *testing.T) {
			g := fixture(t)
			edit(g)
			other, err := g.Packet()
			if err != nil {
				t.Fatal(err)
			}
			if Verify(other, sig, public) == nil {
				t.Fatal("approved a changed packet")
			}
		})
	}
	if Verify(packet, sig[:63], public) == nil || Verify(packet, sig, []byte("invalid")) == nil || Verify(packet, sig, append(public, public...)) == nil {
		t.Fatal("accepted malformed approval")
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der2, err := x509.MarshalPKIXPublicKey(pub2)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(packet, sig, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der2})) == nil {
		t.Fatal("accepted wrong owner key")
	}
}

func TestStablePacketAndLimits(t *testing.T) {
	f := fixture(t)
	dir := t.TempDir()
	data, err := json.Marshal(f.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "charter.md")
	if err = os.WriteFile(path, []byte(strings.ReplaceAll(f.Charter, "\n", "\r\n")), 0600); err != nil {
		t.Fatal(err)
	}
	g, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := f.Packet()
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.Packet()
	if err != nil || !bytes.Equal(want, got) {
		t.Fatal("packet changed across formatting or operating systems", err)
	}
	if _, err := ReadBounded(path, 5); err == nil {
		t.Fatal("accepted oversized input")
	}
	if err := os.WriteFile(path, []byte("   "), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("accepted blank charter")
	}
}
