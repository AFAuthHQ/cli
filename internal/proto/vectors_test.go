// Cross-language conformance gate: every committed signature vector
// MUST produce byte-exact canonical input in Go AND verify under
// crypto/ed25519 against the committed signature. Drift here means the
// Go implementation has fallen out of step with @afauth/core and the
// Node harness.
//
// Vectors live under <repo>/testdata/spec-vectors, vendored from
// AFAuthHQ/spec at the SHA recorded in VERSION. Refresh with
// `make sync-vectors`.

package proto_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/afauthhq/cli/internal/proto"
	"github.com/afauthhq/cli/internal/specvectors"
)

// signatureVector mirrors the JSON shape used by every file in
// vectors/signatures/. The body is `*string` so we can distinguish
// "no body" (nil) from "empty body" (pointer to empty string).
type signatureVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Section     string `json:"section"`
	Request     struct {
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
}

func loadSignatureVectors(t *testing.T) []signatureVector {
	t.Helper()
	files, names, err := specvectors.LoadAll("signatures")
	if err != nil {
		t.Fatalf("load signature vectors: %v", err)
	}
	out := make([]signatureVector, 0, len(files))
	for _, name := range names {
		var v signatureVector
		if err := json.Unmarshal(files[name], &v); err != nil {
			t.Fatalf("parse %s.json: %v", name, err)
		}
		out = append(out, v)
	}
	return out
}

// TestCanonicalInputByteExact is the load-bearing cross-language gate.
// If any vector's canonical input differs from what Go produces, this
// test fails and the binary must not ship.
func TestCanonicalInputByteExact(t *testing.T) {
	for _, v := range loadSignatureVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			covered := make([]proto.CoveredComponent, 0, len(v.CoveredComponents))
			for _, c := range v.CoveredComponents {
				covered = append(covered, proto.CoveredComponent(c))
			}
			req := proto.CanonicalRequest{
				Method:    v.Request.Method,
				TargetURI: v.Request.TargetURI,
			}
			if v.ContentDigest != nil {
				req.ContentDigest = *v.ContentDigest
			}
			params := proto.SignatureParams{
				Created: v.SignatureParams.Created,
				Expires: v.SignatureParams.Expires,
				Nonce:   v.SignatureParams.Nonce,
				KeyID:   v.SignatureParams.KeyID,
				Alg:     v.SignatureParams.Alg,
			}
			got, err := proto.BuildCanonicalInput(req, params, covered)
			if err != nil {
				t.Fatalf("BuildCanonicalInput: %v", err)
			}
			if got != v.CanonicalSignatureInput {
				t.Fatalf("canonical input mismatch\n got: %q\nwant: %q", got, v.CanonicalSignatureInput)
			}
		})
	}
}

// TestSignatureVerifies asserts every committed signature verifies
// against the canonical input + public key from the vector. This is
// the crypto round-trip across language boundaries.
func TestSignatureVerifies(t *testing.T) {
	for _, v := range loadSignatureVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			pub, err := proto.DecodeDidKey(v.PublicKeyDID)
			if err != nil {
				t.Fatalf("DecodeDidKey(%q): %v", v.PublicKeyDID, err)
			}
			sig, err := hex.DecodeString(v.SignatureHex)
			if err != nil {
				t.Fatalf("decode signature_hex: %v", err)
			}
			if !ed25519.Verify(pub, []byte(v.CanonicalSignatureInput), sig) {
				t.Fatalf("signature did not verify against canonical input")
			}
		})
	}
}

// TestContentDigestMatchesBody asserts that for every body-carrying
// vector, our SHA256ContentDigest of the body reproduces the
// content_digest committed in the vector.
func TestContentDigestMatchesBody(t *testing.T) {
	for _, v := range loadSignatureVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			if v.Request.Body == nil {
				if v.ContentDigest != nil {
					t.Fatalf("vector has nil body but non-nil content_digest")
				}
				return
			}
			got := proto.SHA256ContentDigest([]byte(*v.Request.Body))
			if v.ContentDigest == nil {
				t.Fatalf("vector has body but nil content_digest")
			}
			if got != *v.ContentDigest {
				t.Fatalf("content_digest mismatch\n got: %q\nwant: %q", got, *v.ContentDigest)
			}
			h := sha256.Sum256([]byte(*v.Request.Body))
			expect := "sha-256=:" + base64.StdEncoding.EncodeToString(h[:]) + ":"
			if got != expect {
				t.Fatalf("digest formatting drift\n got: %q\nwant: %q", got, expect)
			}
		})
	}
}

// TestDidKeyRoundTripFromKeypair uses the well-known keypair.json
// vector to confirm our codec produces the canonical did:key from a
// known public key and decodes it back to the same bytes.
func TestDidKeyRoundTripFromKeypair(t *testing.T) {
	data, err := specvectors.LoadFile("keypair.json")
	if err != nil {
		t.Fatalf("load keypair.json: %v", err)
	}
	var kp struct {
		DIDKey       string `json:"did_key"`
		PublicKeyHex string `json:"public_key_raw_hex"`
	}
	if err := json.Unmarshal(data, &kp); err != nil {
		t.Fatalf("parse keypair.json: %v", err)
	}
	pub, err := hex.DecodeString(kp.PublicKeyHex)
	if err != nil {
		t.Fatalf("decode public_key_raw_hex: %v", err)
	}
	got, err := proto.EncodeDidKey(pub)
	if err != nil {
		t.Fatalf("EncodeDidKey: %v", err)
	}
	if got != kp.DIDKey {
		t.Fatalf("EncodeDidKey mismatch\n got: %q\nwant: %q", got, kp.DIDKey)
	}
	roundTrip, err := proto.DecodeDidKey(kp.DIDKey)
	if err != nil {
		t.Fatalf("DecodeDidKey: %v", err)
	}
	if hex.EncodeToString(roundTrip) != kp.PublicKeyHex {
		t.Fatalf("DecodeDidKey mismatch\n got: %s\nwant: %s",
			hex.EncodeToString(roundTrip), kp.PublicKeyHex)
	}
}
