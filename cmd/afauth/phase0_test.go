package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afauthhq/cli/internal/accounts"
)

// Phase 0 — key-rotation safety: consumption guards refuse to use a
// binding that belongs to a different key, key-mutating commands keep a
// .bak instead of destroying the old key, and status surfaces stranded
// per-service ledger entries.

func TestTrustTokenRefusesOrphanedBinding(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	// A binding for a different key — e.g. left behind by a rotation.
	// The guard must fire before any network call, so no stub is needed.
	seedTrustState(t, trustBinding{
		BaseURL:                 "https://trust.example",
		AgentDID:                "did:key:zPreviousKey",
		BindingID:               "bind-1",
		BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix(),
	})
	_, _, err := runCLI(t, "trust", "token", "did:web:svc.example", "--timeout", "5")
	if err == nil {
		t.Fatal("trust token must refuse an orphaned binding")
	}
	if !strings.Contains(err.Error(), "afauth trust link") {
		t.Fatalf("error should guide the user to re-link, got: %v", err)
	}
}

func TestSignupRefusesOrphanedBinding(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	seedTrustState(t, trustBinding{
		BaseURL:                 "https://trust.example",
		AgentDID:                "did:key:zPreviousKey",
		BindingID:               "bind-1",
		BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix(),
	})
	srv := newMockService(t)
	serveAttestedDiscoveryDoc(srv, attestedDiscoveryDoc())

	_, _, err := runCLI(t, "signup", srv.URL())
	if err == nil {
		t.Fatal("attested-only signup must refuse an orphaned binding")
	}
	if !strings.Contains(err.Error(), "afauth trust link") {
		t.Fatalf("error should guide the user to re-link, got: %v", err)
	}
	// The guard fires before minting, so no signed request is sent.
	if c := srv.lastCall("GET", "/afauth/v1/accounts/me"); c != nil {
		t.Fatal("must not send a signed request with an orphaned binding")
	}
}

func TestInitForceBacksUpOldKey(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	first := whoamiDID(t)
	if _, _, err := runCLI(t, "init", "--force"); err != nil {
		t.Fatalf("init --force: %v", err)
	}
	if second := whoamiDID(t); second == first {
		t.Fatal("init --force should generate a new key")
	}
	baks, _ := filepath.Glob(filepath.Join(home, "key.json.*.bak"))
	if len(baks) == 0 {
		t.Fatal("init --force must archive the old key as a .bak (no silent data loss)")
	}
}

func TestImportForceBacksUpOldKey(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	// An independent key to import over the active one.
	other := filepath.Join(home, "other.json")
	if _, _, err := runCLI(t, "init", "--key", other); err != nil {
		t.Fatalf("init --key other: %v", err)
	}
	if _, _, err := runCLI(t, "keys", "import", "--force", other); err != nil {
		t.Fatalf("keys import --force: %v", err)
	}
	baks, _ := filepath.Glob(filepath.Join(home, "key.json.*.bak"))
	if len(baks) == 0 {
		t.Fatal("keys import --force must archive the overwritten key as a .bak")
	}
}

func TestStatusFlagsStrandedLedgerEntries(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	did := whoamiDID(t)
	lp, err := accounts.DefaultPath()
	if err != nil {
		t.Fatalf("ledger path: %v", err)
	}
	// One entry on the active key, one stranded under a previous key.
	l := &accounts.Ledger{Accounts: map[string]*accounts.Entry{}}
	l.Upsert("https://a.example", func(e *accounts.Entry) { e.AgentDID = did; e.State = "UNCLAIMED" })
	l.Upsert("https://b.example", func(e *accounts.Entry) { e.AgentDID = "did:key:zOldKey"; e.State = "CLAIMED" })
	if err := l.Save(lp); err != nil {
		t.Fatalf("save ledger: %v", err)
	}

	out, _, err := runCLI(t, "status", "--json")
	if err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var info statusInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("parse json: %v\n%s", err, out)
	}
	if info.Accounts == nil || info.Accounts.Stranded != 1 {
		t.Fatalf("want 1 stranded account, got %+v", info.Accounts)
	}
	human, _, _ := runCLI(t, "status")
	if !strings.Contains(human, "stranded") {
		t.Fatalf("human status should flag stranded entries, got:\n%s", human)
	}
}
