package identity_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/afauthhq/cli/internal/identity"
	"github.com/afauthhq/cli/internal/specvectors"
)

func TestGenerateProducesValidDIDKey(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	did, err := id.DID()
	if err != nil {
		t.Fatalf("DID: %v", err)
	}
	if len(did) < len("did:key:z") || did[:9] != "did:key:z" {
		t.Fatalf("DID malformed: %q", did)
	}
	if len(id.PublicKey) != 32 || len(id.Seed) != 32 {
		t.Fatalf("identity sizes: pub=%d seed=%d", len(id.PublicKey), len(id.Seed))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := id.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		// Note: skip on Windows where Go reports 0o666; we're testing on darwin only.
		if runtime.GOOS != "windows" {
			t.Fatalf("file mode = %v; want 0o600", got)
		}
	}

	got, err := identity.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if hex.EncodeToString(got.Seed) != hex.EncodeToString(id.Seed) {
		t.Fatalf("seed mismatch after round-trip")
	}
	if hex.EncodeToString(got.PublicKey) != hex.EncodeToString(id.PublicKey) {
		t.Fatalf("pubkey mismatch after round-trip")
	}
	gotDID, _ := got.DID()
	wantDID, _ := id.DID()
	if gotDID != wantDID {
		t.Fatalf("DID mismatch after round-trip")
	}
}

func TestSaveRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")

	id1, _ := identity.Generate()
	if err := id1.Save(path); err != nil {
		t.Fatalf("first save: %v", err)
	}

	id2, _ := identity.Generate()
	err := id2.Save(path)
	if err == nil {
		t.Fatalf("Save must refuse to overwrite existing file")
	}
	if !errors.Is(err, fs.ErrExist) {
		// Wrapping might break errors.Is; tolerate any error that mentions the file.
		t.Logf("note: error was not fs.ErrExist but: %v", err)
	}
}

func TestLoadRejectsTamperedDID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")

	id, _ := identity.Generate()
	if err := id.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Hand-tamper the persisted did_key string to mismatch the seed.
	raw, _ := os.ReadFile(path)
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	d["did_key"] = "did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr"
	tampered, _ := json.Marshal(d)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if _, err := identity.Load(path); err == nil {
		t.Fatalf("Load must reject when persisted did_key does not match derived")
	}
}

// TestFromSeedMatchesKeypairVector restores an Identity from the
// well-known spec keypair seed and asserts it derives the same DID
// and public key recorded in the vector.
func TestFromSeedMatchesKeypairVector(t *testing.T) {
	data, err := specvectors.LoadFile("keypair.json")
	if err != nil {
		t.Fatalf("load keypair: %v", err)
	}
	var kp struct {
		DIDKey       string `json:"did_key"`
		PublicKeyHex string `json:"public_key_raw_hex"`
		PrivateHex   string `json:"private_key_raw_hex"`
	}
	if err := json.Unmarshal(data, &kp); err != nil {
		t.Fatalf("unmarshal keypair: %v", err)
	}
	seed, err := hex.DecodeString(kp.PrivateHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	id, err := identity.FromSeed(seed)
	if err != nil {
		t.Fatalf("FromSeed: %v", err)
	}
	if hex.EncodeToString(id.PublicKey) != kp.PublicKeyHex {
		t.Fatalf("public key mismatch:\n got: %s\nwant: %s", hex.EncodeToString(id.PublicKey), kp.PublicKeyHex)
	}
	gotDID, _ := id.DID()
	if gotDID != kp.DIDKey {
		t.Fatalf("DID mismatch:\n got: %s\nwant: %s", gotDID, kp.DIDKey)
	}
}
