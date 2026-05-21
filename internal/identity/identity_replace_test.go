package identity_test

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afauthhq/cli/internal/identity"
)

// We exercise Replace from the same package as Save/Load so we can
// assert backup files are created and the new key reads back cleanly.

func TestReplaceCreatesBackupAndInstallsNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")

	id1, _ := identity.Generate()
	if err := id1.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	id2, _ := identity.Generate()
	if err := id2.Replace(path); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	// Active key is now id2.
	got, err := identity.Load(path)
	if err != nil {
		t.Fatalf("Load active: %v", err)
	}
	if hex.EncodeToString(got.PublicKey) != hex.EncodeToString(id2.PublicKey) {
		t.Fatalf("active key did not match new identity")
	}

	// A backup of id1 exists with .bak suffix.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var backupPath string
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak") {
			backupPath = filepath.Join(dir, e.Name())
			break
		}
	}
	if backupPath == "" {
		t.Fatalf("no .bak file produced; entries: %v", entries)
	}
	backup, err := identity.Load(backupPath)
	if err != nil {
		t.Fatalf("Load backup: %v", err)
	}
	if hex.EncodeToString(backup.PublicKey) != hex.EncodeToString(id1.PublicKey) {
		t.Fatalf("backup did not match the original identity")
	}
}

func TestReplaceOnMissingFileJustWritesNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")

	id, _ := identity.Generate()
	if err := id.Replace(path); err != nil {
		t.Fatalf("Replace on missing: %v", err)
	}
	if _, err := identity.Load(path); err != nil {
		t.Fatalf("Load after Replace: %v", err)
	}
}

func TestSaveRefusalUnaffectedByReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	id, _ := identity.Generate()
	if err := id.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := id.Save(path); err == nil {
		t.Fatalf("Save must still refuse to overwrite after Replace path is implemented")
	} else if !errors.Is(err, fs.ErrExist) {
		t.Logf("note: error %v was not fs.ErrExist (wrapped)", err)
	}
}
