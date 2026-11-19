package repository

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"alexandria/internal/atomicfile"
	"alexandria/internal/founding"
)

func readOnly(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return false
	}
	return true
}

// Origin serves the latest signed projection. Historical files have no HTTP route.
func Origin(dir string, key ed25519.PublicKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !readOnly(w, r) {
			return
		}
		if r.URL.Path != "/v1/head" {
			http.NotFound(w, r)
			return
		}
		head, err := latest(dir, key)
		if err != nil || head == nil {
			http.Error(w, "catalogue unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(head.Wire)
	})
}

type Node struct {
	mu         sync.Mutex
	endpoint   string
	key        ed25519.PublicKey
	checkpoint string
	head       *Release
	client     *http.Client
}

// OpenNode verifies local state at startup. Readers consult the live origin before serving.
func OpenNode(dir, endpoint string, key ed25519.PublicKey) (*Node, error) {
	u, err := url.ParseRequestURI(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid origin URL")
	}
	ip := net.ParseIP(u.Hostname())
	local := strings.EqualFold(u.Hostname(), "localhost") || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, errors.New("remote origins require HTTPS")
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid trusted key")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	n := &Node{endpoint: endpoint, key: slices.Clone(key), checkpoint: filepath.Join(dir, "checkpoint.json"), client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	raw, err := founding.ReadBounded(n.checkpoint, MaxReleaseBytes)
	if errors.Is(err, os.ErrNotExist) {
		return n, nil
	}
	if err != nil {
		return nil, err
	}
	n.head, err = decode(raw, n.key)
	if err != nil {
		return nil, fmt.Errorf("invalid local checkpoint: %w", err)
	}
	return n, nil
}

func (n *Node) refresh(ctx context.Context) (*Release, error) {
	// Serialize fetch, monotonicity check and checkpoint publication for this node.
	n.mu.Lock()
	defer n.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, "GET", n.endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cache-Control", "no-cache, no-store")
	res, err := n.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("origin status %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, MaxReleaseBytes+1))
	if err != nil {
		return nil, err
	}
	next, err := decode(raw, n.key)
	if err != nil {
		return nil, err
	}
	if err := currentAfter(n.head, next); err != nil {
		return nil, err
	}
	if n.head != nil && n.head.Digest == next.Digest {
		return n.head, nil
	}
	if err := atomicfile.Write(n.checkpoint, next.Wire, true); err != nil {
		return nil, err
	}
	n.head = next
	return next, nil
}

func (n *Node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !readOnly(w, r) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "v1" || parts[1] != "records" || !identifier.MatchString(parts[2]) {
		http.NotFound(w, r)
		return
	}
	switch len(parts) {
	case 3:
	case 5, 7:
		if parts[3] != "versions" || !digestPattern.MatchString(parts[4]) || (len(parts) == 7 && parts[5] != "lines") {
			http.NotFound(w, r)
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	head, err := n.refresh(r.Context())
	if err != nil {
		slog.Warn("catalogue unavailable", "error", err)
		http.Error(w, "catalogue unavailable", 503)
		return
	}
	id := parts[2]
	if slices.Contains(head.Catalogue.Withdrawn, id) {
		http.Error(w, "record withdrawn", 410)
		return
	}
	for _, rec := range head.Catalogue.Records {
		if rec.ID != id {
			continue
		}
		version := recordVersion(rec)
		if len(parts) >= 5 && version != parts[4] {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Location", "/v1/records/"+id+"/versions/"+version)
		if len(parts) == 7 {
			lines := Lines(rec.Body)
			line, err := strconv.Atoi(parts[6])
			if err != nil || line < 1 || line > len(lines) || strconv.Itoa(line) != parts[6] {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Location", r.URL.Path)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, lines[line-1])
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Version string           `json:"version"`
			Record  founding.Replica `json:"record"`
		}{version, rec})
		return
	}
	http.NotFound(w, r)
}
