package accounts_test

import (
	"path/filepath"
	"testing"

	"github.com/afauthhq/cli/internal/accounts"
)

func TestLoadMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	l, err := accounts.Load(filepath.Join(dir, "accounts.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(l.Accounts) != 0 {
		t.Fatalf("empty ledger expected; got %d entries", len(l.Accounts))
	}
}

func TestUpsertSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")

	l, _ := accounts.Load(path)
	l.Upsert("https://api.example.com/", func(e *accounts.Entry) {
		e.AgentDID = "did:key:z6Mk1"
		e.State = "UNCLAIMED"
	})
	if err := l.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	l2, err := accounts.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(l2.Accounts) != 1 {
		t.Fatalf("expected 1 entry; got %d", len(l2.Accounts))
	}
	e := l2.Get("https://api.example.com")
	if e == nil {
		t.Fatalf("trailing-slash collapse failed")
	}
	if e.AgentDID != "did:key:z6Mk1" {
		t.Fatalf("DID lost in round-trip: %q", e.AgentDID)
	}
	if e.State != "UNCLAIMED" {
		t.Fatalf("State lost in round-trip: %q", e.State)
	}
}

func TestUpsertPreservesCreatedAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	l, _ := accounts.Load(path)
	l.Upsert("https://x", func(e *accounts.Entry) { e.State = "UNCLAIMED" })
	createdAt := l.Get("https://x").CreatedAt

	l.Upsert("https://x", func(e *accounts.Entry) { e.State = "CLAIMED" })
	if !l.Get("https://x").CreatedAt.Equal(createdAt) {
		t.Fatalf("CreatedAt should be preserved on second Upsert")
	}
	if l.Get("https://x").State != "CLAIMED" {
		t.Fatalf("Upsert should have updated State")
	}
}

func TestSortedIsStable(t *testing.T) {
	dir := t.TempDir()
	l, _ := accounts.Load(filepath.Join(dir, "accounts.json"))
	l.Upsert("https://c.example", func(e *accounts.Entry) {})
	l.Upsert("https://a.example", func(e *accounts.Entry) {})
	l.Upsert("https://b.example", func(e *accounts.Entry) {})
	sorted := l.Sorted()
	want := []string{"https://a.example", "https://b.example", "https://c.example"}
	for i, e := range sorted {
		if e.ServiceURL != want[i] {
			t.Fatalf("[%d]: got %q want %q", i, e.ServiceURL, want[i])
		}
	}
}
