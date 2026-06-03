package discovery

import (
	"fmt"
	"strings"
)

// IsDIDWeb reports whether serviceDID uses the did:web method.
func IsDIDWeb(serviceDID string) bool {
	return strings.HasPrefix(serviceDID, "did:web:")
}

// didWebHost decodes the host authority from a did:web identifier. Per
// [W3C-DID-WEB] the method-specific id is the colon-separated host
// (with the port percent-encoded as %3A) optionally followed by path
// segments. We return just the host:port authority, lowercased.
func didWebHost(serviceDID string) string {
	rest := strings.TrimPrefix(serviceDID, "did:web:")
	// did:web uses ':' as the path separator; the first segment is the
	// host (with %3A-encoded port). Strip any path segments.
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	// Decode the percent-encoded port separator.
	rest = strings.ReplaceAll(rest, "%3A", ":")
	rest = strings.ReplaceAll(rest, "%3a", ":")
	return strings.ToLower(strings.TrimSuffix(rest, "."))
}

// VerifyServiceDIDOrigin enforces the §4.3 / §12.8 binding between a
// service's did:web identity and the host that served its discovery
// document. For a did:web service DID the encoded host MUST equal the
// discovery host; otherwise a hostile host could advertise ANOTHER
// service's DID and harvest an attestation that is audience-bound to it
// and replayable against the real service (confused-deputy, audit #4).
//
// Non-did:web DIDs (e.g. did:key) carry no DNS anchor — the spec notes a
// party controlling the connection can claim any did:key — so this
// function returns nil for them; callers SHOULD warn before minting to a
// non-did:web audience. originHost is the host (optionally host:port) of
// the URL the discovery document was fetched from.
func VerifyServiceDIDOrigin(serviceDID, originHost string) error {
	if !IsDIDWeb(serviceDID) {
		return nil
	}
	want := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(originHost), "."))
	got := didWebHost(serviceDID)
	if got != want {
		return fmt.Errorf(
			"service_did %q is anchored to host %q but its discovery document was served by %q; refusing to mint an attestation that could be replayed against %q",
			serviceDID, got, want, got,
		)
	}
	return nil
}
