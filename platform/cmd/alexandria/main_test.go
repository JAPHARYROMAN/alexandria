package main

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
	"sync"
	"testing"
)

func TestFoundingCommands(t *testing.T) {
	dir := filepath.Join("..", "..", "founding")
	exec := func(args ...string) (string, error) {
		var out, diag bytes.Buffer
		err := run(append(args, "-dir", dir), &out, &diag)
		return out.String(), err
	}
	check, err := exec("check")
	if err != nil || !strings.Contains(check, "5 records") {
		t.Fatalf("%s %v", check, err)
	}
	shelf, err := exec("shelf", "-collection", "reading-the-sky")
	var records []struct{ ID string }
	if err != nil || json.Unmarshal([]byte(shelf), &records) != nil || len(records) != 3 {
		t.Fatalf("%s %v", shelf, err)
	}
	if _, err := exec("shelf", "-collection", "missing"); err == nil {
		t.Fatal("unknown collection accepted")
	}
	out, err := exec("replication-plan")
	if err != nil || strings.Contains(out, "question-card") || !strings.Contains(out, "moon-identity") {
		t.Fatalf("%s %v", out, err)
	}
	tmp := t.TempDir()
	packetPath := filepath.Join(tmp, "review.txt")
	if _, err := exec("review", "-out", packetPath); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDer, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPath, sigPath := filepath.Join(tmp, "owner.pem"), filepath.Join(tmp, "review.sig")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}), 0600); err != nil {
		t.Fatal(err)
	}
	packet, err := os.ReadFile(packetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, ed25519.Sign(priv, packet), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := exec("verify", "-owner-key", keyPath, "-signature", sigPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, ed25519.Sign(priv, []byte("other packet")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := exec("verify", "-owner-key", keyPath, "-signature", sigPath); err == nil {
		t.Fatal("invalid approval accepted")
	}
	if _, err := exec("verify"); err == nil {
		t.Fatal("accepted no key and signature")
	}
}

func TestConcurrentReviewPreservesWinner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "packet")
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- writeNew(path, []byte("complete packet")) }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !os.IsExist(err) {
			t.Fatal(err)
		}
	}
	contents, err := os.ReadFile(path)
	if err != nil || success != 1 || string(contents) != "complete packet" {
		t.Fatalf("success %d, bytes %q, error %v", success, contents, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary output leaked", err)
	}
}
