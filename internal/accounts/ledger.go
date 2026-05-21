// Package accounts maintains a local cache of AFAuth accounts the
// agent has interacted with — one entry per (service-url, agent-did)
// pair. The service is authoritative; the ledger is a client-side
// convenience for the CLI's `accounts list/show` and signup flows.
//
// On disk: ~/.afauth/accounts.json (or $AFAUTH_HOME/accounts.json),
// mode 0600.
package accounts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Entry is one ledger row.
type Entry struct {
	// ServiceURL is the AFAuth-enabled service's origin (e.g.
	// "https://api.example.com"). Used as the ledger key.
	ServiceURL string `json:"service_url"`
	// AgentDID is the agent's did:key at the time of this entry.
	AgentDID string `json:"agent_did"`
	// State is the last observed account state (UNCLAIMED, INVITED, CLAIMED, …).
	State string `json:"state,omitempty"`
	// CreatedAt is the timestamp this entry was first written.
	CreatedAt time.Time `json:"created_at"`
	// LastSeenAt is the timestamp the entry was last refreshed.
	LastSeenAt time.Time `json:"last_seen_at"`
	// Owner is populated once the account is CLAIMED.
	Owner *Owner `json:"owner,omitempty"`
}

// Owner mirrors the §6.5 owner sub-object.
type Owner struct {
	Identity  json.RawMessage `json:"identity,omitempty"`
	UserID    string          `json:"user_id,omitempty"`
	ClaimedAt time.Time       `json:"claimed_at,omitempty"`
}

// Ledger is the persisted form of the accounts file.
type Ledger struct {
	Version  int               `json:"version"`
	Accounts map[string]*Entry `json:"accounts"`
}

const ledgerVersion = 1

// DefaultPath returns ~/.afauth/accounts.json (or $AFAUTH_HOME/accounts.json
// when set).
func DefaultPath() (string, error) {
	if h := os.Getenv("AFAUTH_HOME"); h != "" {
		return filepath.Join(h, "accounts.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("accounts: locate home: %w", err)
	}
	return filepath.Join(home, ".afauth", "accounts.json"), nil
}

// Load reads the ledger at path. Returns a fresh empty ledger if the
// file does not exist; surfaces other I/O errors.
func Load(path string) (*Ledger, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Ledger{Version: ledgerVersion, Accounts: map[string]*Entry{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("accounts: read %s: %w", path, err)
	}
	var l Ledger
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("accounts: parse %s: %w", path, err)
	}
	if l.Version != ledgerVersion {
		return nil, fmt.Errorf("accounts: unsupported ledger version %d (this build understands %d)", l.Version, ledgerVersion)
	}
	if l.Accounts == nil {
		l.Accounts = map[string]*Entry{}
	}
	return &l, nil
}

// Save atomically rewrites path with the current ledger contents.
// Creates the parent directory at 0700 if missing.
func (l *Ledger) Save(path string) error {
	if l.Accounts == nil {
		l.Accounts = map[string]*Entry{}
	}
	l.Version = ledgerVersion

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("accounts: create dir: %w", err)
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return fmt.Errorf("accounts: marshal: %w", err)
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("accounts: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("accounts: rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

// Upsert inserts or updates the entry keyed by canonical service URL.
// CreatedAt is preserved across updates; LastSeenAt is bumped to now.
func (l *Ledger) Upsert(serviceURL string, mutate func(*Entry)) {
	if l.Accounts == nil {
		l.Accounts = map[string]*Entry{}
	}
	key := CanonicalServiceURL(serviceURL)
	now := time.Now().UTC()
	e := l.Accounts[key]
	if e == nil {
		e = &Entry{
			ServiceURL: key,
			CreatedAt:  now,
		}
		l.Accounts[key] = e
	}
	e.LastSeenAt = now
	mutate(e)
}

// Get returns the entry for the canonicalised service URL, or nil if
// not present.
func (l *Ledger) Get(serviceURL string) *Entry {
	if l.Accounts == nil {
		return nil
	}
	return l.Accounts[CanonicalServiceURL(serviceURL)]
}

// Sorted returns entries in canonical-URL order — useful for stable
// `accounts list` output.
func (l *Ledger) Sorted() []*Entry {
	out := make([]*Entry, 0, len(l.Accounts))
	for _, e := range l.Accounts {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ServiceURL < out[j].ServiceURL
	})
	return out
}

// CanonicalServiceURL strips any trailing slash so different spellings
// of the same service URL collapse to a single ledger entry.
func CanonicalServiceURL(s string) string {
	return strings.TrimRight(s, "/")
}
