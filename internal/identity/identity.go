// Package identity manages the agent's Ed25519 keypair and the did:key
// representation of its public key.
package identity

import "errors"

// Identity holds an agent's keypair and the derived did:key identifier.
//
// TODO: implement Ed25519 keypair generation, did:key encoding (multibase
// multicodec, prefix 0xed01), keypair serialisation to/from disk, and
// optional KMS-backed signers.
type Identity struct {
	// PublicKey is the raw 32-byte Ed25519 public key.
	PublicKey []byte

	// PrivateKey is the raw 64-byte Ed25519 private key (including the
	// public-key suffix per RFC 8032).
	PrivateKey []byte
}

// Generate creates a fresh Ed25519 keypair.
func Generate() (*Identity, error) {
	return nil, ErrNotImplemented
}

// Load reads a keypair from disk at the given path.
func Load(path string) (*Identity, error) {
	return nil, ErrNotImplemented
}

// Save persists the keypair to disk at the given path with mode 0600.
func (i *Identity) Save(path string) error {
	return ErrNotImplemented
}

// DID returns the did:key identifier for this agent.
func (i *Identity) DID() string {
	return ""
}

// ErrNotImplemented is returned by stubbed functions.
var ErrNotImplemented = errors.New("not yet implemented")
