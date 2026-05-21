// Package signing implements HTTP Message Signatures (RFC 9421) over Ed25519
// for AFAuth-signed requests.
package signing

import (
	"errors"
	"net/http"
)

// Sign mutates req in place, adding the Signature-Input, Signature, and
// Content-Digest (for body-carrying requests) headers required by
// AFAuth per §5.2 of the protocol spec.
//
// Canonical signed components for v0.1 are "@method", "@target-uri",
// and "content-digest" (when body is present). Signature parameters
// are created, expires, nonce, keyid (the agent's did:key), and alg
// ("ed25519"). The signer's identity is carried in keyid; there is no
// separate afauth-account header.
//
// TODO: implement RFC 9421 canonicalisation and Ed25519 signing.
func Sign(req *http.Request, accountDID string, privateKey []byte) error {
	return ErrNotImplemented
}

// Verify validates the signature on an incoming request against the public
// key encoded in the account DID. On success it returns the verified
// account DID.
func Verify(req *http.Request) (accountDID string, err error) {
	return "", ErrNotImplemented
}

// ErrNotImplemented is returned by stubbed functions.
var ErrNotImplemented = errors.New("not yet implemented")
