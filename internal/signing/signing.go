// Package signing implements HTTP Message Signatures (RFC 9421) over Ed25519
// for AFAuth-signed requests.
package signing

import (
	"errors"
	"net/http"
)

// Sign mutates req in place, adding the Signature-Input, Signature, and
// related headers required by AFAuth (see §6.3 of the protocol spec).
//
// TODO: implement RFC 9421 canonicalisation, Ed25519 signing, and the
// AFAuth-specific signed components: @method, @target-uri, @authority,
// content-digest, afauth-account, created, nonce.
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
