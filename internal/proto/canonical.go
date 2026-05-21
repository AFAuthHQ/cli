package proto

import (
	"fmt"
	"strings"
)

// CoveredComponent is one of the AFAuth-permitted RFC 9421 covered
// components. v0.1 fixes the set; future versions may expand it.
type CoveredComponent string

const (
	ComponentMethod        CoveredComponent = "@method"
	ComponentTargetURI     CoveredComponent = "@target-uri"
	ComponentContentDigest CoveredComponent = "content-digest"
)

// SignatureParams carries the §5.2 signature parameters.
type SignatureParams struct {
	Created int64  // unix seconds, signing timestamp
	Expires int64  // unix seconds, hard expiration
	Nonce   string // unique per request
	KeyID   string // the account's DID — the sole identity surface
	Alg     string // "ed25519" in v0.1
}

// CanonicalRequest is the minimum shape of an AFAuth-signed request
// needed to construct the canonical input. The agent and verifier
// build this from their respective request types.
type CanonicalRequest struct {
	Method        string
	TargetURI     string
	ContentDigest string // empty when the request has no body
}

// BuildCanonicalInput constructs the byte-exact RFC 9421 canonical
// signature input string per §5.2. No trailing newline. The output
// of this function is what gets signed with Ed25519 and what the
// verifier reconstructs.
//
// Drift from the spec's canonicalisation rule fails the cross-language
// conformance suite; treat changes to this function as protocol changes.
func BuildCanonicalInput(req CanonicalRequest, params SignatureParams, covered []CoveredComponent) (string, error) {
	var b strings.Builder
	for i, c := range covered {
		if i > 0 {
			b.WriteByte('\n')
		}
		switch c {
		case ComponentMethod:
			b.WriteString(`"@method": `)
			b.WriteString(req.Method)
		case ComponentTargetURI:
			b.WriteString(`"@target-uri": `)
			b.WriteString(req.TargetURI)
		case ComponentContentDigest:
			if req.ContentDigest == "" {
				return "", fmt.Errorf("covered components include content-digest but request has none")
			}
			b.WriteString(`"content-digest": `)
			b.WriteString(req.ContentDigest)
		default:
			return "", fmt.Errorf("unsupported covered component in v0.1: %q", c)
		}
	}
	b.WriteByte('\n')
	b.WriteString(`"@signature-params": (`)
	for i, c := range covered {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('"')
		b.WriteString(string(c))
		b.WriteByte('"')
	}
	b.WriteByte(')')
	fmt.Fprintf(&b, ";created=%d;expires=%d;nonce=%q;keyid=%q;alg=%q",
		params.Created, params.Expires, params.Nonce, params.KeyID, params.Alg)
	return b.String(), nil
}
