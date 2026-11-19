// Command alexandria-repo publishes, distributes and serves signed catalogue releases.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"alexandria/internal/founding"
	"alexandria/internal/repository"
)

const usage = "alexandria-repo publish -store DIR -signing-key PEM [-founding DIR] [-withdraw ID,...]\nalexandria-repo origin -store DIR -public-key PEM [-listen ADDR]\nalexandria-repo node -store DIR -public-key PEM -upstream URL [-listen ADDR]"

func keyFile(path, kind string) ([]byte, error) {
	raw, err := founding.ReadBounded(path, 8192)
	if err != nil {
		return nil, err
	}
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != kind || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("expected one %s PEM block", kind)
	}
	return b.Bytes, nil
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" {
		fmt.Println(usage)
		return nil
	}
	mode := args[0]
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	store := fs.String("store", "", "private storage directory")
	var private, public, found, withdraw, listen, upstream string
	switch mode {
	case "publish":
		fs.StringVar(&private, "signing-key", "", "PKCS#8 Ed25519 private key")
		fs.StringVar(&found, "founding", "founding", "editorial input directory")
		fs.StringVar(&withdraw, "withdraw", "", "comma-separated public record IDs")
	case "origin", "node":
		fs.StringVar(&public, "public-key", "", "trusted Ed25519 public key")
		fs.StringVar(&listen, "listen", "127.0.0.1:8080", "listener address")
		if mode == "node" {
			fs.StringVar(&upstream, "upstream", "", "official latest-catalogue endpoint")
		}
	default:
		return errors.New(usage)
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *store == "" || fs.NArg() != 0 {
		return errors.New(usage)
	}
	if mode == "publish" {
		raw, err := keyFile(private, "PRIVATE KEY")
		if err != nil {
			return err
		}
		parsed, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return err
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return errors.New("expected Ed25519 signing key")
		}
		f, err := founding.Load(found)
		if err != nil {
			return err
		}
		var ids []string
		if withdraw != "" {
			ids = strings.Split(withdraw, ",")
		}
		release, err := repository.Publish(*store, f.Manifest.ReplicationPlan(), ids, key)
		if err != nil {
			return err
		}
		fmt.Printf("Catalogue %d %s\n", release.Catalogue.Revision, release.Digest)
		return nil
	}
	raw, err := keyFile(public, "PUBLIC KEY")
	if err != nil {
		return err
	}
	parsed, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return errors.New("expected Ed25519 public key")
	}
	var handler http.Handler
	if mode == "node" {
		handler, err = repository.OpenNode(*store, upstream, key)
		if err != nil {
			return err
		}
	} else {
		handler = repository.Origin(*store, key)
	}
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	return server.ListenAndServe()
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
