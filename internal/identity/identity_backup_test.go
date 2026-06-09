package identity

// Internal tests for the backup-lifecycle helpers. They live in package
// identity (not identity_test) so they can reach the unexported
// overwriteInPlace and assert the seed bytes are actually zeroed before
// the file is unlinked.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupsCatchesLegacyAndTimestamped(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.json")

	// Files that should be reported as backups, in the lexical order
	// Backups returns them ('.'<'1'<'b', so timestamped sort ahead of the
	// legacy plain ".bak").
	wantBackups := []string{
		key + ".1700000000.bak", // timestamped backup Replace creates
		key + ".1700000001.bak",
		key + ".bak", // legacy plain backup (the orphan case)
	}
	// ...and decoys that must NOT be: the active key and rotation temps.
	decoys := []string{key, key + ".new", key + ".tmp"}
	for _, p := range append(append([]string{}, wantBackups...), decoys...) {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed file %s: %v", p, err)
		}
	}

	got, err := Backups(key)
	if err != nil {
		t.Fatalf("Backups: %v", err)
	}
	if len(got) != len(wantBackups) {
		t.Fatalf("Backups returned %v; want %v", got, wantBackups)
	}
	for i, w := range wantBackups {
		if got[i] != w {
			t.Fatalf("Backups[%d] = %q; want %q (full: %v)", i, got[i], w, got)
		}
	}
}

func TestOverwriteInPlaceZerosBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json.bak")
	secret := []byte("private_key_seed_hex deadbeef")
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := overwriteInPlace(path); err != nil {
		t.Fatalf("overwriteInPlace: %v", err)
	}

	// File still exists, same length, all zeros — the unlink is a
	// separate step (ShredFile) so the overwrite is observable here.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after overwrite: %v", err)
	}
	if len(got) != len(secret) {
		t.Fatalf("length changed: got %d want %d", len(got), len(secret))
	}
	if !bytes.Equal(got, make([]byte, len(secret))) {
		t.Fatalf("bytes not zeroed: %q", got)
	}
}

func TestShredFileOverwritesThenRemoves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json.bak")
	if err := os.WriteFile(path, []byte("seed"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := ShredFile(path); err != nil {
		t.Fatalf("ShredFile: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still present after shred (err=%v)", err)
	}

	// Shredding a file that isn't there is an error the caller can report.
	if err := ShredFile(path); err == nil {
		t.Fatalf("ShredFile on a missing file should error")
	}
}
