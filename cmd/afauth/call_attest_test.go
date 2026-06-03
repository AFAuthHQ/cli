package main

// §10.7 critical path from the agent side: a signed business request is
// challenged with `401 attestation_required`, the CLI mints a fresh
// attestation from the cached trust binding and retries once, and the
// retry — carrying the attestation — passes. A revoked binding surfaces
// as a terminal error instead of an unbounded retry.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/afauthhq/cli/internal/client"
	"github.com/afauthhq/cli/internal/identity"
)

// attestedServiceDoc is a minimal §9.2 attested_only discovery document.
func attestedServiceDoc() map[string]any {
	doc := discoveryDoc()
	doc["service_did"] = "did:web:svc.example"
	doc["features"] = []string{"attestation", "attested_session"}
	doc["billing"] = map[string]any{
		"unclaimed_mode":     "attested_only",
		"accepted_attestors": []string{"afauth-trust"},
	}
	return doc
}

func loadTestIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	p, err := identity.DefaultPath()
	if err != nil {
		t.Fatalf("identity path: %v", err)
	}
	id, err := identity.Load(p)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	return id
}

func TestCall_AttestationRefreshOnChallenge(t *testing.T) {
	withTempHome(t)
	id := loadTestIdentity(t)
	did, err := id.DID()
	if err != nil {
		t.Fatal(err)
	}

	// Fake trust attestor that mints a token for the cached binding.
	binding := trustBindingResp{BindingID: "b", BindingTokenExpiresAt: time.Now().Add(time.Hour).Unix()}
	stub := newStubTrust(t, 0, binding,
		trustTokenResp{JWT: "att-jwt", ExpiresAt: time.Now().Add(15 * time.Minute).Unix(), Verification: "oauth"},
	)
	if err := saveTrustState(&trustState{
		BaseURL: stub.server.URL, AgentDID: did, BindingID: "b",
		BindingTokenExpiresUnix: binding.BindingTokenExpiresAt,
	}); err != nil {
		t.Fatalf("save trust state: %v", err)
	}

	// Fake attested_only service: the business endpoint 401s until an
	// attestation header is present (simulating a lapsed §10.7 window).
	svc := newMockService(t)
	svc.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, attestedServiceDoc())
	})
	var apiCalls atomic.Int32
	svc.mux.HandleFunc("/api/thing", func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		if r.Header.Get("AFAuth-Attestation") == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": map[string]string{"code": "attestation_required", "message": "attested session lapsed"},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
	})

	c := client.New(id)
	target := svc.URL() + "/api/thing"
	build := func() (*http.Request, error) { return http.NewRequest(http.MethodGet, target, nil) }

	resp, err := attestedCall(context.Background(), c, build, target, did, "", io.Discard)
	if err != nil {
		t.Fatalf("attestedCall: %v", err)
	}
	if resp.HTTPResponse.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200; body=%s", resp.HTTPResponse.StatusCode, resp.Body)
	}
	if got := apiCalls.Load(); got != 2 {
		t.Fatalf("service /api/thing called %d times, want 2 (challenge + re-minted retry)", got)
	}
}

func TestCall_AttestationRefresh_TerminalOnRevokedBinding(t *testing.T) {
	withTempHome(t)
	id := loadTestIdentity(t)
	did, err := id.DID()
	if err != nil {
		t.Fatal(err)
	}

	// Trust attestor that refuses to mint: the binding was revoked.
	trustSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/token" {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": map[string]string{"code": "binding_revoked", "message": "revoked by the human"},
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(trustSrv.Close)
	if err := saveTrustState(&trustState{
		BaseURL: trustSrv.URL, AgentDID: did, BindingID: "b",
		BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatalf("save trust state: %v", err)
	}

	svc := newMockService(t)
	svc.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, attestedServiceDoc())
	})
	var apiCalls atomic.Int32
	svc.mux.HandleFunc("/api/thing", func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": map[string]string{"code": "attestation_required", "message": "lapsed"},
		})
	})

	c := client.New(id)
	target := svc.URL() + "/api/thing"
	build := func() (*http.Request, error) { return http.NewRequest(http.MethodGet, target, nil) }

	_, err = attestedCall(context.Background(), c, build, target, did, "", io.Discard)
	if err == nil {
		t.Fatal("expected a terminal error when the binding is revoked, got nil")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("error should explain the revoked binding, got: %v", err)
	}
	if got := apiCalls.Load(); got != 1 {
		t.Fatalf("service called %d times, want 1 (no retry after a failed mint)", got)
	}
}
