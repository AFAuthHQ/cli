package probe_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afauthhq/cli/internal/probe"
	"github.com/afauthhq/cli/internal/signing"
)

// stub is a minimal in-process AFAuth service for probe tests. The
// behaviour knobs control how it diverges from spec compliance so we
// can confirm the probe catches the bug.
type stub struct {
	t                  *testing.T
	mu                 sync.Mutex
	nonces             map[string]bool
	signupSucceeded    bool
	rejectExpired      bool // if false, the stub erroneously accepts expired
	rejectReplay       bool // if false, the stub erroneously accepts replays
	rejectGarbageSig   bool
	rejectUnsupported  bool
	declareTypes       []string
	billingAttestOnly  bool
}

func newConformantStub(t *testing.T) (*httptest.Server, *stub) {
	s := &stub{
		t:                  t,
		nonces:             map[string]bool{},
		rejectExpired:      true,
		rejectReplay:       true,
		rejectGarbageSig:   true,
		rejectUnsupported:  true,
		declareTypes:       []string{"email", "oidc"},
	}
	return httptest.NewServer(http.HandlerFunc(s.handle)), s
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"code": code, "message": msg}})
	_, _ = w.Write(body)
}

func writeOK(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	out, _ := json.Marshal(body)
	_, _ = w.Write(out)
}

func writeStatus(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	out, _ := json.Marshal(body)
	_, _ = w.Write(out)
}

func (s *stub) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/.well-known/afauth" && r.Method == http.MethodGet:
		doc := map[string]any{
			"afauth_version": "0.1",
			"service_did":    "did:web:stub.test",
			"endpoints": map[string]any{
				"accounts":         "/afauth/v1/accounts",
				"owner_invitation": "/afauth/v1/accounts/me/owner-invitation",
				"claim_page":       "https://claim.stub.test",
				"claim_completion": "/afauth/v1/claim",
				"key_rotation":     "/afauth/v1/accounts/me/keys/rotate",
			},
			"signature_algorithms": []string{"ed25519"},
			"recipient_types":      s.declareTypes,
		}
		if s.billingAttestOnly {
			doc["billing"] = map[string]any{"unclaimed_mode": "attested_only"}
		}
		writeOK(w, doc)

	case r.URL.Path == "/afauth/v1/accounts/me" && r.Method == http.MethodGet:
		s.handleAccountsMe(w, r)

	case r.URL.Path == "/afauth/v1/accounts/me/owner-invitation" && r.Method == http.MethodPost:
		s.handleOwnerInvitation(w, r)

	default:
		http.NotFound(w, r)
	}
}

// handleAccountsMe implements the signed GET /accounts/me path with
// the relevant §5 checks the probe exercises.
func (s *stub) handleAccountsMe(w http.ResponseWriter, r *http.Request) {
	// Verify the signature first. This catches malformed-signature probes.
	did, err := signing.Verify(r)
	if err != nil {
		if s.rejectGarbageSig {
			writeErr(w, 401, "invalid_signature", err.Error())
			return
		}
		// Buggy mode: accept anyway.
	}

	// Parse signature-input for expiry + nonce.
	created, expires, nonce := parseSigParams(r.Header.Get("Signature-Input"))
	if expires > 0 && expires < time.Now().Unix() {
		if s.rejectExpired {
			writeErr(w, 401, "expired_signature", "signature expired")
			return
		}
	}
	_ = created

	s.mu.Lock()
	keyNonce := did + ":" + nonce
	if s.nonces[keyNonce] {
		if s.rejectReplay {
			s.mu.Unlock()
			writeErr(w, 401, "replayed_nonce", "nonce already used")
			return
		}
	}
	s.nonces[keyNonce] = true
	s.signupSucceeded = true
	s.mu.Unlock()

	writeOK(w, map[string]any{
		"account_did":          did,
		"state":                "UNCLAIMED",
		"created_at":           time.Now().UTC().Format(time.RFC3339),
		"unclaimed_expires_at": time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"owner":                nil,
	})
}

func (s *stub) handleOwnerInvitation(w http.ResponseWriter, r *http.Request) {
	if _, err := signing.Verify(r); err != nil {
		writeErr(w, 401, "invalid_signature", err.Error())
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Recipient struct {
			Type  string `json:"type"`
			Value any    `json:"value"`
		} `json:"recipient"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, 400, "malformed_request", err.Error())
		return
	}
	if !contains(s.declareTypes, req.Recipient.Type) {
		if s.rejectUnsupported {
			writeErr(w, 400, "unsupported_recipient_type", "type not declared")
			return
		}
	}
	writeStatus(w, 202, map[string]any{
		"invitation_id": "inv_TEST123",
		"expires_at":    time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339),
		"state":         "INVITED",
	})
}

func parseSigParams(hdr string) (created, expires int64, nonce string) {
	// Cheap regex-free parser sufficient for tests.
	for _, p := range strings.Split(hdr, ";") {
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(p[:eq])
		v := strings.TrimSpace(p[eq+1:])
		switch k {
		case "created":
			fmt.Sscanf(v, "%d", &created)
		case "expires":
			fmt.Sscanf(v, "%d", &expires)
		case "nonce":
			nonce = strings.Trim(v, `"`)
		}
	}
	return
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestProbeAllPassOnConformantStub(t *testing.T) {
	srv, _ := newConformantStub(t)
	defer srv.Close()

	res, err := probe.Run(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	pass, failCount, _ := res.Counts()
	if failCount != 0 {
		for _, p := range res.Probes {
			t.Logf("%-32s %s  %s", p.Name, p.Status, p.Detail)
		}
		t.Fatalf("expected zero failures; got %d (pass=%d)", failCount, pass)
	}
	// Sanity: at least 6 of 7 probes execute (the seventh might skip when
	// the stub declares all four recipient types).
	if pass < 6 {
		t.Fatalf("expected ≥6 passes; got %d", pass)
	}
}

func TestProbeCatchesMissingReplayProtection(t *testing.T) {
	srv, s := newConformantStub(t)
	defer srv.Close()
	s.rejectReplay = false // service erroneously accepts replays

	res, err := probe.Run(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Failed() {
		t.Fatalf("probe must fail when replay protection is missing")
	}
	found := false
	for _, p := range res.Probes {
		if p.Name == "replayed_nonce" && p.Status == "fail" {
			found = true
		}
	}
	if !found {
		for _, p := range res.Probes {
			t.Logf("%-30s %s  %s", p.Name, p.Status, p.Detail)
		}
		t.Fatalf("expected replayed_nonce probe to fail")
	}
}

func TestProbeCatchesExpiredAccepted(t *testing.T) {
	srv, s := newConformantStub(t)
	defer srv.Close()
	s.rejectExpired = false

	res, err := probe.Run(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Failed() {
		t.Fatalf("expected failure when expired signatures are accepted")
	}
	found := false
	for _, p := range res.Probes {
		if p.Name == "expired_signature" && p.Status == "fail" {
			found = true
		}
	}
	if !found {
		for _, p := range res.Probes {
			t.Logf("%-30s %s  %s", p.Name, p.Status, p.Detail)
		}
		t.Fatalf("expected expired_signature probe to fail")
	}
}

func TestProbeSkipsAttestedOnly(t *testing.T) {
	srv, s := newConformantStub(t)
	defer srv.Close()
	s.billingAttestOnly = true

	res, err := probe.Run(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// implicit_signup should skip, not fail.
	var p probe.Probe
	for _, candidate := range res.Probes {
		if candidate.Name == "implicit_signup" {
			p = candidate
			break
		}
	}
	if p.Status != probe.StatusSkip {
		t.Fatalf("attested_only: implicit_signup should skip; got %s (%s)", p.Status, p.Detail)
	}
}
