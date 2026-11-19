package repository

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"alexandria/internal/founding"
)

func seed(t *testing.T) ([]founding.Replica, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	f, err := founding.Load(filepath.Join("..", "..", "founding"))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return f.Manifest.ReplicationPlan(), pub, priv
}

func get(t *testing.T, url string, want int) (string, http.Header) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s: status %d, expected %d: %s", url, resp.StatusCode, want, b)
	}
	return string(b), resp.Header
}

func startNode(t *testing.T, dir, upstream string, key ed25519.PublicKey) *httptest.Server {
	t.Helper()
	n, err := OpenNode(dir, upstream, key)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(n)
}

func TestWithdrawalWhileNodeOffline(t *testing.T) {
	rec, pub, priv := seed(t)
	store := t.TempDir()
	first, err := Publish(store, rec, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(Origin(store, pub))
	defer origin.Close()
	upstream := origin.URL + "/v1/head"
	aDir, bDir := t.TempDir(), t.TempDir()
	a := startNode(t, aDir, upstream, pub)
	b := startNode(t, bDir, upstream, pub)
	defer b.Close()
	_, h := get(t, a.URL+"/v1/records/moon-identity", 200)
	citation := h.Get("Content-Location") + "/lines/1"
	original, _ := get(t, a.URL+citation, 200)
	other, _ := get(t, b.URL+citation, 200)
	if original != other || !strings.Contains(original, "Moon") {
		t.Fatal("citation differs across nodes")
	}
	for _, id := range []string{"sky-log", "question-card"} {
		get(t, b.URL+"/v1/records/"+id, 404)
	}
	_, lh := get(t, b.URL+"/v1/records/moon-phases", 200)
	get(t, b.URL+lh.Get("Content-Location")+"/lines/1", 404)
	a.Close()
	get(t, b.URL+citation, 200)
	second, err := Publish(store, rec, []string{"moon-identity"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if second.Catalogue.Revision != 2 || second.Catalogue.Parent != first.Digest {
		t.Fatal("invalid sequence")
	}
	get(t, b.URL+citation, 410)
	a = startNode(t, aDir, upstream, pub)
	defer a.Close()
	get(t, a.URL+citation, 410)
	again, err := Publish(store, rec, nil, priv)
	if err != nil || again.Digest != second.Digest {
		t.Fatal("reimport changed the withdrawn source", err)
	}
	for _, dir := range []string{aDir, bDir} {
		wire, err := os.ReadFile(filepath.Join(dir, "checkpoint.json"))
		if err != nil {
			t.Fatal(err)
		}
		stored, err := decode(wire, pub)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range stored.Catalogue.Records {
			if r.ID == "moon-identity" || strings.Contains(r.Body, original) {
				t.Fatal("withdrawn body remains in live checkpoint")
			}
		}
	}
	get(t, origin.URL+"/"+releaseName(1), 404)
	origin.Close()
	get(t, a.URL+"/v1/records/moon-phases", 503)
}

func TestRejectsStaleForgedAndConflictingHeads(t *testing.T) {
	records, pub, key := seed(t)
	a, err := advance(nil, records, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := advance(a, records, []string{"moon-identity"}, key)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := advance(a, records, []string{"moon-phases"}, key)
	if err != nil {
		t.Fatal(err)
	}
	_, _, other := seed(t)
	forged, err := advance(nil, records, nil, other)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	wire := b.Wire
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); defer mu.Unlock(); _, _ = w.Write(wire) }))
	defer origin.Close()
	dir := t.TempDir()
	srv := startNode(t, dir, origin.URL, pub)
	get(t, srv.URL+"/v1/records/moon-identity", 410)
	srv.Close()
	srv = startNode(t, dir, origin.URL, pub)
	defer srv.Close()
	for _, bad := range [][]byte{a.Wire, alternate.Wire, forged.Wire, []byte("corrupt")} {
		mu.Lock()
		wire = bad
		mu.Unlock()
		get(t, srv.URL+"/v1/records/moon-identity", 503)
	}
	mu.Lock()
	wire = b.Wire
	mu.Unlock()
	get(t, srv.URL+"/v1/records/moon-identity", 410)
	disk, err := os.ReadFile(filepath.Join(dir, "checkpoint.json"))
	if err != nil || !bytes.Equal(disk, b.Wire) {
		t.Fatal("checkpoint changed on rejected input", err)
	}
	if err = os.WriteFile(filepath.Join(dir, "checkpoint.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenNode(dir, origin.URL, pub); err == nil {
		t.Fatal("opened corrupt local data")
	}
}

func TestConcurrentWithdrawalsAndPermissionValidation(t *testing.T) {
	records, pub, key := seed(t)
	dir := t.TempDir()
	if _, err := Publish(dir, records, nil, key); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, id := range []string{"moon-identity", "moon-phases"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if _, err := Publish(dir, records, []string{id}, key); err != nil {
				t.Error(err)
			}
		}(id)
	}
	wg.Wait()
	head, err := latest(dir, pub)
	if err != nil || head == nil {
		t.Fatal(err)
	}
	if head.Catalogue.Revision != 3 || len(head.Catalogue.Withdrawn) != 2 {
		t.Fatal("lost a concurrent withdrawal")
	}
	if _, err := Publish(dir, records, []string{"unrecognized"}, key); err == nil {
		t.Fatal("unknown withdrawal accepted")
	}
	for i := range records {
		if records[i].Rights == "link-only" {
			records[i].Body = "private copy"
			break
		}
	}
	if _, err := Publish(t.TempDir(), records, nil, key); err == nil {
		t.Fatal("published a link-only body")
	}
	if _, err := OpenNode(t.TempDir(), "http://example.org/v1/head", pub); err == nil {
		t.Fatal("remote plaintext accepted")
	}
}
