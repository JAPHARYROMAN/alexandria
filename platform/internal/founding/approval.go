package founding

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// Packet binds both the human-readable charter and the validated records to the same decision.
// Keep this framing stable. Change the protocol version if its meaning or encoding changes.
func (f Foundation) Packet() ([]byte, error) {
	manifest, err := json.MarshalIndent(f.Manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("ALEXANDRIA | PHASE 1 FOUNDING APPROVAL | v1\n")
	b.WriteString("Approval covers the scope, software licence, release authority and first source below.\n\n")
	b.Write(manifest)
	b.WriteString("\n\n")
	b.WriteString(f.Charter)
	return b.Bytes(), nil
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Verify uses a public key pinned by the operator outside the review packet.
func Verify(packet, signature, ownerPEM []byte) error {
	trimmed := bytes.TrimSpace(ownerPEM)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PUBLIC KEY-----")) {
		return errors.New("expected a PEM public key")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("expected one PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("owner public key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return errors.New("owner key must be Ed25519")
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, packet, signature) {
		return errors.New("owner approval does not verify for the current founding packet")
	}
	return nil
}
