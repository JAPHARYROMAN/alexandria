// Command alexandria inspects the founding collection and verifies its owner's approval.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"alexandria/internal/founding"
)

const usage = `Alexandria founding tools

  alexandria check             Validate terms and seed records
  alexandria shelf             Inspect internal records; optionally pass -collection ID
  alexandria replication-plan  Show the proposed public replica contents
  alexandria review -out PATH  Write a new owner review packet
  alexandria verify -owner-key PATH -signature PATH
                               Verify the owner's signature over the current packet

Each command accepts -dir PATH (default: founding).
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "alexandria:", err)
		os.Exit(1)
	}
}

func run(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	cmd := args[0]
	opts := flag.NewFlagSet(cmd, flag.ContinueOnError)
	opts.SetOutput(diagnostics)
	dir := opts.String("dir", "founding", "directory containing charter.md and manifest.json")
	var collection, path, ownerKey, signature string
	switch cmd {
	case "check", "replication-plan":
	case "shelf":
		opts.StringVar(&collection, "collection", "", "collection ID")
	case "review":
		opts.StringVar(&path, "out", "", "new packet file")
	case "verify":
		opts.StringVar(&ownerKey, "owner-key", "", "independently trusted owner public key (PEM)")
		opts.StringVar(&signature, "signature", "", "detached Ed25519 signature (binary)")
	default:
		return fmt.Errorf("unknown command %q; see alexandria help", cmd)
	}
	if err := opts.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if opts.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	f, err := founding.Load(*dir)
	if err != nil {
		return err
	}
	m := f.Manifest
	switch cmd {
	case "check":
		_, err = fmt.Fprintf(out, "Valid draft: %d collections, %d records. Proposed licence: %s. First source: %s. Owner approval is a separate verification.\n", len(m.Collections), len(m.Records), m.SoftwareLicense, m.FirstSource)
		return err
	case "shelf":
		records := m.Records
		if collection != "" {
			records = nil
			for _, r := range m.Records {
				if r.Collection == collection {
					records = append(records, r)
				}
			}
			if len(records) == 0 {
				return fmt.Errorf("unknown collection %q", collection)
			}
		}
		return printJSON(out, records)
	case "replication-plan":
		return printJSON(out, m.ReplicationPlan())
	}
	packet, err := f.Packet()
	if err != nil {
		return err
	}
	if cmd == "review" {
		if path == "" {
			return errors.New("review requires -out PATH")
		}
		if err := writeNew(path, packet); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Review packet written. SHA-256 %s\n", founding.Digest(packet))
		return err
	}
	if ownerKey == "" || signature == "" {
		return errors.New("verify requires -owner-key and -signature")
	}
	key, err := founding.ReadBounded(ownerKey, 4096)
	if err != nil {
		return err
	}
	sig, err := founding.ReadBounded(signature, 64)
	if err != nil {
		return err
	}
	if err := founding.Verify(packet, sig, key); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Phase 1 approval verified against the supplied owner key. Packet SHA-256 %s\n", founding.Digest(packet))
	return err
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Publish the complete file once. Concurrent reviews cannot overwrite one another.
func writeNew(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".alexandria-review-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return publishNew(tmp.Name(), path)
}
