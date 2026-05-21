// Package signing implements HTTP Message Signatures (RFC 9421) over
// Ed25519 for AFAuth-signed requests, per §5.2 of the protocol spec.
//
// Canonical signed components for v0.1 are "@method", "@target-uri",
// and "content-digest" (when body is present). Signature parameters
// are created, expires, nonce, keyid (the agent's did:key), and alg
// ("ed25519"). The signer's identity is carried in keyid; there is no
// separate afauth-account header.
//
// This is the high-level driver — the byte-exact canonical input
// construction lives in internal/proto so the same code path is used
// here and by the offline conformance harness.
package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/afauthhq/cli/internal/proto"
)

// MaxSignatureLifetimeSeconds is the §5.2 hard cap on expires - created.
const MaxSignatureLifetimeSeconds = 300

// DefaultSignatureLifetimeSeconds is the lifetime applied when SignOptions
// does not specify one. Sixty seconds matches the agent SDK default and
// gives services well within the 300-second cap.
const DefaultSignatureLifetimeSeconds = 60

// SignOptions are the optional knobs for Sign. All fields are filled in
// with spec-conformant defaults when zero.
type SignOptions struct {
	// Created in unix seconds. Defaults to time.Now().Unix() if zero.
	Created int64
	// ExpiresIn is the lifetime of the signature in seconds.
	// Defaults to DefaultSignatureLifetimeSeconds; capped at
	// MaxSignatureLifetimeSeconds per §5.2.
	ExpiresIn int64
	// Nonce overrides the random 16-byte hex nonce. Test-only.
	Nonce string
}

// Sign mutates req in place, attaching the Signature-Input, Signature,
// and (when the body is non-empty) Content-Digest and Content-Type
// headers required by §5.2.
//
// accountDID is the agent's did:key value. privateKey is the 32-byte
// Ed25519 seed; ed25519.NewKeyFromSeed derives the 64-byte expanded
// key per RFC 8032.
//
// On entry, req.Body MAY be nil. If it is non-nil, Sign reads it fully
// to compute the content-digest, then replaces it with a fresh reader
// so the request body is still available for transmission.
func Sign(req *http.Request, accountDID string, privateKey []byte, opts *SignOptions) error {
	if req == nil {
		return errors.New("signing: nil request")
	}
	if len(privateKey) != ed25519.SeedSize {
		return fmt.Errorf("signing: ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(privateKey))
	}
	if accountDID == "" {
		return errors.New("signing: empty accountDID")
	}

	if opts == nil {
		opts = &SignOptions{}
	}
	created := opts.Created
	if created == 0 {
		created = nowUnix()
	}
	lifetime := opts.ExpiresIn
	if lifetime == 0 {
		lifetime = DefaultSignatureLifetimeSeconds
	}
	if lifetime > MaxSignatureLifetimeSeconds {
		return fmt.Errorf("signing: lifetime %ds exceeds §5.2 cap of %ds", lifetime, MaxSignatureLifetimeSeconds)
	}
	expires := created + lifetime

	nonce := opts.Nonce
	if nonce == "" {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("signing: read random nonce: %w", err)
		}
		nonce = hex.EncodeToString(buf)
	}

	bodyBytes, err := drainAndRestoreBody(req)
	if err != nil {
		return fmt.Errorf("signing: read body: %w", err)
	}
	hasBody := len(bodyBytes) > 0
	covered := []proto.CoveredComponent{proto.ComponentMethod, proto.ComponentTargetURI}
	canonReq := proto.CanonicalRequest{
		Method:    req.Method,
		TargetURI: req.URL.String(),
	}
	if hasBody {
		covered = append(covered, proto.ComponentContentDigest)
		canonReq.ContentDigest = proto.SHA256ContentDigest(bodyBytes)
	}

	params := proto.SignatureParams{
		Created: created,
		Expires: expires,
		Nonce:   nonce,
		KeyID:   accountDID,
		Alg:     "ed25519",
	}

	canonical, err := proto.BuildCanonicalInput(canonReq, params, covered)
	if err != nil {
		return fmt.Errorf("signing: canonical input: %w", err)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(privateKey), []byte(canonical))

	req.Header.Set("Signature-Input", buildSignatureInputHeader(covered, params))
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	if hasBody {
		req.Header.Set("Content-Digest", canonReq.ContentDigest)
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	return nil
}

// Verify reconstructs the canonical input from req and verifies the
// signature against the public key encoded in the keyid did:key. On
// success it returns the verified account DID. It does NOT enforce
// freshness, replay, or revocation — those are policy decisions for
// callers built on top of this primitive.
func Verify(req *http.Request) (string, error) {
	if req == nil {
		return "", errors.New("verify: nil request")
	}
	sigInputHdr := req.Header.Get("Signature-Input")
	if sigInputHdr == "" {
		return "", errors.New("verify: missing Signature-Input header")
	}
	sigHdr := req.Header.Get("Signature")
	if sigHdr == "" {
		return "", errors.New("verify: missing Signature header")
	}

	covered, params, err := parseSignatureInput(sigInputHdr)
	if err != nil {
		return "", fmt.Errorf("verify: %w", err)
	}
	sigBytes, err := parseSignatureHeader(sigHdr)
	if err != nil {
		return "", fmt.Errorf("verify: %w", err)
	}

	bodyBytes, err := drainAndRestoreBody(req)
	if err != nil {
		return "", fmt.Errorf("verify: read body: %w", err)
	}
	canonReq := proto.CanonicalRequest{
		Method:    req.Method,
		TargetURI: req.URL.String(),
	}
	for _, c := range covered {
		if c == proto.ComponentContentDigest {
			if len(bodyBytes) == 0 {
				return "", errors.New("verify: content-digest covered but body is empty")
			}
			canonReq.ContentDigest = proto.SHA256ContentDigest(bodyBytes)
			break
		}
	}

	canonical, err := proto.BuildCanonicalInput(canonReq, params, covered)
	if err != nil {
		return "", fmt.Errorf("verify: %w", err)
	}
	pubkey, err := proto.DecodeDidKey(params.KeyID)
	if err != nil {
		return "", fmt.Errorf("verify: keyid: %w", err)
	}
	if !ed25519.Verify(pubkey, []byte(canonical), sigBytes) {
		return "", errors.New("verify: signature verification failed")
	}
	return params.KeyID, nil
}

func buildSignatureInputHeader(covered []proto.CoveredComponent, p proto.SignatureParams) string {
	var b strings.Builder
	b.WriteString("sig1=(")
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
		p.Created, p.Expires, p.Nonce, p.KeyID, p.Alg)
	return b.String()
}

// parseSignatureInput parses the Signature-Input header into the covered
// components and parameters. Only the AFAuth-required v0.1 components
// and params are recognised; anything extra fails the parse.
//
// The header is expected to look like:
//
//	sig1=("@method" "@target-uri" "content-digest");created=...;expires=...;nonce="..";keyid="..";alg=".."
func parseSignatureInput(hdr string) ([]proto.CoveredComponent, proto.SignatureParams, error) {
	const prefix = "sig1="
	if !strings.HasPrefix(hdr, prefix) {
		return nil, proto.SignatureParams{}, fmt.Errorf("Signature-Input must start with %q", prefix)
	}
	rest := hdr[len(prefix):]
	openParen := strings.IndexByte(rest, '(')
	closeParen := strings.IndexByte(rest, ')')
	if openParen != 0 || closeParen < 0 {
		return nil, proto.SignatureParams{}, errors.New("Signature-Input missing component list")
	}
	componentList := rest[openParen+1 : closeParen]
	paramSection := rest[closeParen+1:]
	if !strings.HasPrefix(paramSection, ";") {
		return nil, proto.SignatureParams{}, errors.New("Signature-Input missing parameter section")
	}
	paramSection = paramSection[1:]

	var covered []proto.CoveredComponent
	for _, raw := range strings.Fields(componentList) {
		if !strings.HasPrefix(raw, `"`) || !strings.HasSuffix(raw, `"`) {
			return nil, proto.SignatureParams{}, fmt.Errorf("covered component %q not quoted", raw)
		}
		name := raw[1 : len(raw)-1]
		switch proto.CoveredComponent(name) {
		case proto.ComponentMethod, proto.ComponentTargetURI, proto.ComponentContentDigest:
			covered = append(covered, proto.CoveredComponent(name))
		default:
			return nil, proto.SignatureParams{}, fmt.Errorf("unsupported covered component in v0.1: %q", name)
		}
	}

	params := proto.SignatureParams{}
	for _, kv := range splitParams(paramSection) {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			return nil, proto.SignatureParams{}, fmt.Errorf("malformed param %q", kv)
		}
		k := kv[:eq]
		v := kv[eq+1:]
		switch k {
		case "created":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, proto.SignatureParams{}, fmt.Errorf("created: %w", err)
			}
			params.Created = n
		case "expires":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, proto.SignatureParams{}, fmt.Errorf("expires: %w", err)
			}
			params.Expires = n
		case "nonce":
			unq, err := unquote(v)
			if err != nil {
				return nil, proto.SignatureParams{}, fmt.Errorf("nonce: %w", err)
			}
			params.Nonce = unq
		case "keyid":
			unq, err := unquote(v)
			if err != nil {
				return nil, proto.SignatureParams{}, fmt.Errorf("keyid: %w", err)
			}
			params.KeyID = unq
		case "alg":
			unq, err := unquote(v)
			if err != nil {
				return nil, proto.SignatureParams{}, fmt.Errorf("alg: %w", err)
			}
			params.Alg = unq
		default:
			return nil, proto.SignatureParams{}, fmt.Errorf("unexpected parameter: %q", k)
		}
	}
	if params.Created == 0 || params.Expires == 0 || params.Nonce == "" || params.KeyID == "" || params.Alg == "" {
		return nil, proto.SignatureParams{}, errors.New("Signature-Input missing one of created/expires/nonce/keyid/alg")
	}
	return covered, params, nil
}

// splitParams splits a parameter section like
// "created=1;expires=2;nonce=\"abc\";keyid=\"did:key:..\";alg=\"ed25519\""
// on top-level ';' boundaries (i.e., outside of quoted strings).
func splitParams(s string) []string {
	var out []string
	inQuotes := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuotes = !inQuotes
		case ';':
			if !inQuotes {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

var quotedRe = regexp.MustCompile(`^"(.*)"$`)

func unquote(s string) (string, error) {
	m := quotedRe.FindStringSubmatch(s)
	if m == nil {
		return "", fmt.Errorf("value %q is not quoted", s)
	}
	return m[1], nil
}

func parseSignatureHeader(hdr string) ([]byte, error) {
	const prefix = "sig1=:"
	const suffix = ":"
	if !strings.HasPrefix(hdr, prefix) || !strings.HasSuffix(hdr, suffix) {
		return nil, fmt.Errorf("Signature header must be sig1=:<base64>: , got %q", hdr)
	}
	encoded := hdr[len(prefix) : len(hdr)-len(suffix)]
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("Signature base64: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("Signature must be %d bytes, got %d", ed25519.SignatureSize, len(raw))
	}
	return raw, nil
}

// drainAndRestoreBody reads the entire body (if any) and rewinds the
// request so the body is still readable downstream.
func drainAndRestoreBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	buf, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(buf))
	if req.GetBody == nil {
		body := append([]byte(nil), buf...)
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	return buf, nil
}

// nowUnix is var so tests can monkey-patch. Production callers shouldn't.
var nowUnix = defaultNow

func defaultNow() int64 {
	return timeNowUnix()
}
