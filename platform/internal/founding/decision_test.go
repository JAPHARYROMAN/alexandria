package founding

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordedDecisionCoversFoundingPacket(t *testing.T) {
	dir := filepath.Join("..", "..", "founding")
	f, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := f.Packet()
	if err != nil {
		t.Fatal(err)
	}
	decision, err := os.ReadFile(filepath.Join(dir, "decision.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(decision, []byte("`"+Digest(packet)+"`")) {
		t.Fatal("current charter or seed manifest differs from the recorded founding decision")
	}
}
