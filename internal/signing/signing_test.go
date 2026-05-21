package signing_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/afauthhq/cli/internal/proto"
	"github.com/afauthhq/cli/internal/signing"
	"github.com/afauthhq/cli/internal/specvectors"
)

func mustReq(t *testing.T, method, rawURL string, body io.Reader) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	req := &http.Request{
		Method: method,
		URL:    u,
		Header: http.Header{},
	}
	if body != nil {
		req.Body = io.NopCloser(body)
	}
	return req
}

func freshSeed(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return priv.Seed()
}

func TestSignVerifyRoundTripGET(t *testing.T) {
	seed := freshSeed(t)
	id, err := proto.EncodeDidKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("encode did: %v", err)
	}
	req := mustReq(t, http.MethodGet, "https://api.example.com/afauth/v1/accounts/me", nil)
	if err := signing.Sign(req, id, seed, nil); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := req.Header.Get("Signature-Input"); got == "" {
		t.Fatalf("missing Signature-Input header")
	}
	if got := req.Header.Get("Signature"); got == "" {
		t.Fatalf("missing Signature header")
	}
	if got := req.Header.Get("Content-Digest"); got != "" {
		t.Fatalf("GET should not have Content-Digest; got %q", got)
	}
	gotDID, err := signing.Verify(req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotDID != id {
		t.Fatalf("Verify returned %q; want %q", gotDID, id)
	}
}

func TestSignVerifyRoundTripPOSTWithBody(t *testing.T) {
	seed := freshSeed(t)
	id, _ := proto.EncodeDidKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	body := []byte(`{"recipient":{"type":"email","value":"alice@example.com"}}`)
	req := mustReq(t, http.MethodPost,
		"https://api.example.com/afauth/v1/accounts/me/owner-invitation",
		bytes.NewReader(body))
	if err := signing.Sign(req, id, seed, nil); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if req.Header.Get("Content-Digest") == "" {
		t.Fatalf("POST with body must have Content-Digest")
	}
	if req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("POST with body should default Content-Type to application/json")
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body after sign: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body was not restored after sign: got %q, want %q", got, body)
	}
	req.Body = io.NopCloser(bytes.NewReader(got))
	gotDID, err := signing.Verify(req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotDID != id {
		t.Fatalf("Verify did = %q; want %q", gotDID, id)
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	seed := freshSeed(t)
	id, _ := proto.EncodeDidKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	body := []byte(`{"hello":"world"}`)
	req := mustReq(t, http.MethodPost, "https://api.example.com/x", bytes.NewReader(body))
	if err := signing.Sign(req, id, seed, nil); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Replace the body with something else; the original content-digest
	// header is now wrong for the body and verification must fail.
	req.Body = io.NopCloser(strings.NewReader(`{"hello":"evil"}`))
	if _, err := signing.Verify(req); err == nil {
		t.Fatalf("Verify should fail on tampered body")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	seed := freshSeed(t)
	id, _ := proto.EncodeDidKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	req := mustReq(t, http.MethodGet, "https://api.example.com/x", nil)
	if err := signing.Sign(req, id, seed, nil); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Flip a single base64 character inside the Signature header.
	sig := req.Header.Get("Signature")
	const prefix = "sig1=:"
	const suffix = ":"
	encoded := sig[len(prefix) : len(sig)-len(suffix)]
	flipped := []byte(encoded)
	if flipped[0] == 'A' {
		flipped[0] = 'B'
	} else {
		flipped[0] = 'A'
	}
	req.Header.Set("Signature", prefix+string(flipped)+suffix)
	if _, err := signing.Verify(req); err == nil {
		t.Fatalf("Verify should fail on tampered signature")
	}
}

func TestSignRejectsOverlyLongLifetime(t *testing.T) {
	seed := freshSeed(t)
	id, _ := proto.EncodeDidKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	req := mustReq(t, http.MethodGet, "https://api.example.com/x", nil)
	err := signing.Sign(req, id, seed, &signing.SignOptions{ExpiresIn: 301})
	if err == nil {
		t.Fatalf("Sign should reject lifetime > 300s per §5.2")
	}
	if !strings.Contains(err.Error(), "cap of 300") {
		t.Fatalf("error should mention cap: %v", err)
	}
}

// TestVerifySpecVectors round-trips every committed signature vector
// through the high-level Verify path: rebuild a *http.Request from the
// vector's fields and confirm signing.Verify returns the keyid.
func TestVerifySpecVectors(t *testing.T) {
	files, names, err := specvectors.LoadAll("signatures")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, name := range names {
		v := struct {
			Request struct {
				Method    string  `json:"method"`
				TargetURI string  `json:"target_uri"`
				Body      *string `json:"body"`
			} `json:"request"`
			ContentDigest     *string  `json:"content_digest"`
			CoveredComponents []string `json:"covered_components"`
			SignatureParams   struct {
				Created int64  `json:"created"`
				Expires int64  `json:"expires"`
				Nonce   string `json:"nonce"`
				KeyID   string `json:"keyid"`
				Alg     string `json:"alg"`
			} `json:"signature_params"`
			CanonicalSignatureInput string `json:"canonical_signature_input"`
			SignatureHex            string `json:"signature_hex"`
			PublicKeyDID            string `json:"public_key_did"`
		}{}
		if err := json.Unmarshal(files[name], &v); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		t.Run(name, func(t *testing.T) {
			u, err := url.Parse(v.Request.TargetURI)
			if err != nil {
				t.Fatalf("parse target_uri: %v", err)
			}
			req := &http.Request{
				Method: v.Request.Method,
				URL:    u,
				Header: http.Header{},
			}
			if v.Request.Body != nil {
				req.Body = io.NopCloser(strings.NewReader(*v.Request.Body))
			}
			if v.ContentDigest != nil {
				req.Header.Set("Content-Digest", *v.ContentDigest)
			}
			req.Header.Set("Signature-Input", buildSigInputFromVector(v.CoveredComponents, v.SignatureParams))
			sigRaw, err := hex.DecodeString(v.SignatureHex)
			if err != nil {
				t.Fatalf("decode signature_hex: %v", err)
			}
			req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sigRaw)+":")
			gotDID, err := signing.Verify(req)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if gotDID != v.PublicKeyDID {
				t.Fatalf("Verify returned %q; want %q", gotDID, v.PublicKeyDID)
			}
		})
	}
}

// buildSigInputFromVector mirrors the wire format produced by Sign,
// for use when reconstructing a *http.Request from a JSON vector.
func buildSigInputFromVector(covered []string, params struct {
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
	Nonce   string `json:"nonce"`
	KeyID   string `json:"keyid"`
	Alg     string `json:"alg"`
}) string {
	var b strings.Builder
	b.WriteString("sig1=(")
	for i, c := range covered {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('"')
		b.WriteString(c)
		b.WriteByte('"')
	}
	b.WriteByte(')')
	b.WriteString(";created=")
	b.WriteString(fmtI64(params.Created))
	b.WriteString(";expires=")
	b.WriteString(fmtI64(params.Expires))
	b.WriteString(";nonce=\"")
	b.WriteString(params.Nonce)
	b.WriteString("\";keyid=\"")
	b.WriteString(params.KeyID)
	b.WriteString("\";alg=\"")
	b.WriteString(params.Alg)
	b.WriteString("\"")
	return b.String()
}

func fmtI64(n int64) string { return strings.TrimSpace(itoa(n)) }
func itoa(n int64) string {
	// Avoid importing strconv just for this — tests already import strings.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
