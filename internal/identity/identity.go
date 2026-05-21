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

	"github.com/afauthhq/cli/internal/proto"
)

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
