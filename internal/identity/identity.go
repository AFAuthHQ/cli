// Package identity manages the agent's Ed25519 keypair and the did:key
// representation of its public key.
//
// The on-disk layout in v0.1 is a single key per agent at
// ~/.afauth/key.json (or whatever path the caller passes). Multi-key
// support is deferred to v0.2.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/afauthhq/cli/internal/proto"
)

// replaceClock is overridden in tests to make backup paths deterministic.
var replaceClock = func() int64 { return time.Now().Unix() }

// Identity holds an agent's keypair and the derived did:key identifier.
type Identity struct {
	// PublicKey is the raw 32-byte Ed25519 public key.
	PublicKey []byte
	// Seed is the raw 32-byte Ed25519 seed (private key material).
	// ed25519.NewKeyFromSeed expands this into the 64-byte signing key
	// at signing time; we do not persist the expanded form.
	Seed []byte
}

// Generate creates a fresh Ed25519 keypair from crypto/rand.
func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate ed25519: %w", err)
	}
	return &Identity{
		PublicKey: pub,
		Seed:      priv.Seed(),
	}, nil
}

// FromSeed restores an Identity from a 32-byte Ed25519 seed.
func FromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity: ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Identity{
		PublicKey: priv.Public().(ed25519.PublicKey),
		Seed:      append([]byte(nil), seed...),
	}, nil
}

// DID returns the did:key identifier for this agent.
func (i *Identity) DID() (string, error) {
	return proto.EncodeDidKey(i.PublicKey)
}

// onDiskFormat is the JSON shape persisted at ~/.afauth/key.json.
// Hex is friendly enough for humans to inspect and copy out of band.
type onDiskFormat struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	DIDKey     string `json:"did_key"`
	PublicKey  string `json:"public_key_hex"`
	PrivateKey string `json:"private_key_seed_hex"`
}

const onDiskVersion = 1

// Save writes the keypair to path with file mode 0600 and creates the
// parent directory at 0700 if missing. Returns an error if a file
// already exists at the given path (clobbering a key is a footgun;
// callers can delete the file explicitly if rotation is intended).
func (i *Identity) Save(path string) error {
	if len(i.PublicKey) != proto.Ed25519PubKeyLen || len(i.Seed) != ed25519.SeedSize {
		return errors.New("identity: cannot save incomplete identity")
	}
	did, err := i.DID()
	if err != nil {
		return err
	}
	out := onDiskFormat{
		Version:    onDiskVersion,
		Algorithm:  "ed25519",
		DIDKey:     did,
		PublicKey:  hex.EncodeToString(i.PublicKey),
		PrivateKey: hex.EncodeToString(i.Seed),
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: marshal: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("identity: create dir: %w", err)
	}
	// O_EXCL refuses to overwrite an existing file.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("identity: open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("identity: write %s: %w", path, err)
	}
	return nil
}

// Replace atomically swaps the keypair at path with this identity,
// preserving the prior key as a sibling backup file with a unix-second
// suffix (path + ".<ts>.bak"). Suitable for `afauth keys rotate`.
//
// Layout on success:
//
//	path                   = new identity
//	path.<old-unix>.bak    = previous identity
//
// Returns the path of the backup it created, or "" when path did not
// exist (in which case this behaves like Save with no backup). Callers
// surface the backup path so the user knows what to shred with
// `afauth keys forget-backup` once the rotation is confirmed.
func (i *Identity) Replace(path string) (string, error) {
	if len(i.PublicKey) != proto.Ed25519PubKeyLen || len(i.Seed) != ed25519.SeedSize {
		return "", errors.New("identity: cannot replace with incomplete identity")
	}
	did, err := i.DID()
	if err != nil {
		return "", err
	}
	out := onDiskFormat{
		Version:    onDiskVersion,
		Algorithm:  "ed25519",
		DIDKey:     did,
		PublicKey:  hex.EncodeToString(i.PublicKey),
		PrivateKey: hex.EncodeToString(i.Seed),
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", fmt.Errorf("identity: marshal: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("identity: create dir: %w", err)
	}

	newPath := path + ".new"
	if err := os.WriteFile(newPath, data, 0o600); err != nil {
		return "", fmt.Errorf("identity: write %s: %w", newPath, err)
	}

	// Archive existing key (if any) under a unix-second suffix so the
	// caller can recover from a rotation that the service later disputes.
	var backup string
	if _, statErr := os.Stat(path); statErr == nil {
		backup = fmt.Sprintf("%s.%d.bak", path, replaceClock())
		if err := os.Rename(path, backup); err != nil {
			return "", fmt.Errorf("identity: archive old key to %s: %w", backup, err)
		}
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("identity: stat %s: %w", path, statErr)
	}

	if err := os.Rename(newPath, path); err != nil {
		return "", fmt.Errorf("identity: install new key at %s: %w", path, err)
	}
	return backup, nil
}

// Load reads a keypair from disk. Verifies the persisted public key
// matches the derived one (catches on-disk tampering or truncation).
func Load(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}
	var d onDiskFormat
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("identity: parse %s: %w", path, err)
	}
	if d.Version != onDiskVersion {
		return nil, fmt.Errorf("identity: unsupported on-disk version %d (this build understands %d)", d.Version, onDiskVersion)
	}
	if d.Algorithm != "ed25519" {
		return nil, fmt.Errorf("identity: unsupported algorithm %q (v0.1: ed25519 only)", d.Algorithm)
	}
	seed, err := hex.DecodeString(d.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("identity: private_key_seed_hex: %w", err)
	}
	pub, err := hex.DecodeString(d.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("identity: public_key_hex: %w", err)
	}
	id, err := FromSeed(seed)
	// FromSeed copied the seed into id; drop our transient decode buffer
	// so the only live copy is the one the caller can Destroy later.
	wipe(seed)
	if err != nil {
		return nil, err
	}
	if !bytesEqual(id.PublicKey, pub) {
		return nil, fmt.Errorf("identity: persisted public key does not match derived public key (file %s)", path)
	}
	derivedDID, _ := id.DID()
	if derivedDID != d.DIDKey {
		return nil, fmt.Errorf("identity: persisted did_key %q does not match derived %q", d.DIDKey, derivedDID)
	}
	return id, nil
}

// DefaultPath returns the canonical key location, ~/.afauth/key.json.
// Honours $AFAUTH_HOME when set, for sandbox-style tests.
func DefaultPath() (string, error) {
	if h := os.Getenv("AFAUTH_HOME"); h != "" {
		return filepath.Join(h, "key.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("identity: locate home dir: %w", err)
	}
	return filepath.Join(home, ".afauth", "key.json"), nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// wipe zeros b in place. runtime.KeepAlive keeps b reachable past the
// loop so the compiler cannot treat the writes as a dead store and elide
// them.
//
// Best-effort only: the Go GC may already have copied the backing array
// during a heap move (leaving an un-zeroed ghost we never reach), and
// ed25519.NewKeyFromSeed expands the seed into an internal 64-byte key
// that is not visible here. Zeroizing shrinks the window in which the
// seed sits in recoverable memory (swap, core dumps); it is not a
// guarantee that no copy survives.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// Destroy zeros the private seed held by this Identity. Call it once the
// identity is no longer needed (e.g. via defer at the end of a command).
// After Destroy the Identity can no longer sign. Best-effort — see wipe.
func (i *Identity) Destroy() {
	wipe(i.Seed)
}

// Backups returns the archived key backups that sit alongside keyPath,
// i.e. files matching "<keyPath>*.bak". This catches both the timestamped
// backups Replace creates ("<keyPath>.<unix>.bak") and any legacy plain
// "<keyPath>.bak". The active key itself is never matched (it has no .bak
// suffix). Results are sorted by filename.
func Backups(keyPath string) ([]string, error) {
	matches, err := filepath.Glob(keyPath + "*.bak")
	if err != nil {
		return nil, fmt.Errorf("identity: list backups: %w", err)
	}
	sort.Strings(matches)
	return matches, nil
}

// overwriteInPlace overwrites a file's existing bytes with zeros and
// fsyncs, without unlinking it.
//
// Best-effort: on SSDs and copy-on-write filesystems (APFS, btrfs, ZFS)
// the write may land on freshly-allocated blocks rather than the original
// ones, so the old bytes can survive. This raises the bar against casual
// undelete/forensics but is not a guarantee — full-disk encryption is the
// real backstop.
func overwriteInPlace(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if n := info.Size(); n > 0 {
		zeros := make([]byte, n)
		if _, err := f.WriteAt(zeros, 0); err != nil {
			return err
		}
	}
	return f.Sync()
}

// ShredFile overwrites a key backup's bytes with zeros and then unlinks
// it. See overwriteInPlace for the best-effort caveat.
func ShredFile(path string) error {
	if err := overwriteInPlace(path); err != nil {
		return fmt.Errorf("identity: shred %s: %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("identity: remove %s: %w", path, err)
	}
	return nil
}
