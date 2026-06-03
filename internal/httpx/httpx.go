// Package httpx provides hardened http.Client construction shared by the
// CLI's outbound calls.
//
// The CLI attaches credential headers to its requests — the RFC 9421
// `Signature`/`Signature-Input` and, for attested calls, the
// `AFAuth-Attestation` JWT. Go's default redirect policy follows up to 10
// redirects and strips only `Authorization`, `WWW-Authenticate`,
// `Cookie`, and `Cookie2` when the host changes — it does NOT strip these
// custom headers. A service (or a network attacker) that 30x-redirects an
// AFAuth request to another origin would therefore receive the live
// attestation JWT and signature (audit #3). NoCrossOriginRedirect closes
// that by refusing any redirect that crosses origins.
package httpx

import (
	"fmt"
	"net/http"
	"time"
)

// NoCrossOriginRedirect is an http.Client CheckRedirect policy that
// refuses any redirect to a different origin (scheme + host). Same-origin
// redirects remain allowed (Go still caps them at 10). Returning an error
// aborts the request rather than silently following — AFAuth protocol
// endpoints are not expected to redirect, and a redirect would in any
// case break the signature's `@target-uri` binding.
func NoCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	orig := via[0].URL
	if req.URL.Scheme != orig.Scheme || req.URL.Host != orig.Host {
		return fmt.Errorf(
			"refusing cross-origin redirect to %s://%s (from %s://%s): would leak signature/attestation headers",
			req.URL.Scheme, req.URL.Host, orig.Scheme, orig.Host,
		)
	}
	return nil
}

// Client returns an *http.Client with the given timeout and the
// NoCrossOriginRedirect policy. A zero timeout means no client-level
// timeout (callers relying on a context deadline).
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: NoCrossOriginRedirect}
}
