package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStatusNotInitialized(t *testing.T) {
	withTempHome(t)
	stdout, _, err := runCLI(t, "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(stdout, "no identity") || !strings.Contains(stdout, "afauth init") {
		t.Fatalf("want not-initialized hint, got: %q", stdout)
	}

	jsonOut, _, err := runCLI(t, "status", "--json")
	if err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var info statusInfo
	if err := json.Unmarshal([]byte(jsonOut), &info); err != nil {
		t.Fatalf("parse json: %v\n%s", err, jsonOut)
	}
	if info.Initialized {
		t.Fatalf("want initialized=false, got true: %s", jsonOut)
	}
}

func TestStatusJSONUnlinked(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	out, _, err := runCLI(t, "status", "--json")
	if err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var info statusInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("parse json: %v\n%s", err, out)
	}
	if !info.Initialized {
		t.Fatalf("want initialized=true")
	}
	if !strings.HasPrefix(info.DID, "did:key:z") {
		t.Fatalf("want did:key, got %q", info.DID)
	}
	if info.KeyPath == "" {
		t.Fatalf("want key_path set")
	}
	if info.Algorithm != "ed25519" {
		t.Fatalf("want algorithm ed25519, got %q", info.Algorithm)
	}
	if info.Link == nil || info.Link.Linked || info.Link.State != "unlinked" {
		t.Fatalf("want unlinked link summary, got %+v", info.Link)
	}
}

func TestStatusHumanUnlinked(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	stdout, _, err := runCLI(t, "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	// Includes the algorithm, the resolved key path, and an actionable
	// not-linked hint that points the operator at `afauth trust link`.
	for _, want := range []string{"ed25519", home, "not linked", "afauth trust link"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("status output missing %q:\n%s", want, stdout)
		}
	}
}

func TestStatusLinkedLive(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	did := whoamiDID(t)
	seedTrustState(t, trustState{
		BaseURL:                 "https://trust.afauth.org",
		AgentDID:                did,
		BindingID:               "bind-1",
		BindingToken:            "tok",
		BindingTokenExpiresUnix: time.Now().Add(90 * 24 * time.Hour).Unix(),
		Verification:            "email",
	})

	stdout, _, err := runCLI(t, "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{"trust.afauth.org", "live", "(email)"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("status output missing %q:\n%s", want, stdout)
		}
	}

	out, _, err := runCLI(t, "status", "--json")
	if err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var info statusInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if info.Link == nil || info.Link.State != "live" || !info.Link.MatchesActiveKey {
		t.Fatalf("want live + matches_active_key, got %+v", info.Link)
	}
}

func TestStatusLinkExpired(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	did := whoamiDID(t)
	seedTrustState(t, trustState{
		BaseURL:                 "https://trust.afauth.org",
		AgentDID:                did,
		BindingID:               "bind-1",
		BindingToken:            "tok",
		BindingTokenExpiresUnix: time.Now().Add(-time.Hour).Unix(),
	})
	stdout, _, err := runCLI(t, "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(stdout, "expired") {
		t.Fatalf("want 'expired', got:\n%s", stdout)
	}
}

func TestStatusLinkOrphaned(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Binding belongs to a different key — e.g. after a key rotation
	// that left trust.json behind. status must catch this rather than
	// reporting the agent as linked.
	seedTrustState(t, trustState{
		BaseURL:                 "https://trust.afauth.org",
		AgentDID:                "did:key:zDifferentKey",
		BindingID:               "bind-1",
		BindingToken:            "tok",
		BindingTokenExpiresUnix: time.Now().Add(90 * 24 * time.Hour).Unix(),
	})
	stdout, _, err := runCLI(t, "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(stdout, "different key") {
		t.Fatalf("want orphaned hint, got:\n%s", stdout)
	}

	out, _, err := runCLI(t, "status", "--json")
	if err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var info statusInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if info.Link == nil || info.Link.State != "orphaned" || info.Link.MatchesActiveKey {
		t.Fatalf("want orphaned + !matches_active_key, got %+v", info.Link)
	}
}

// TestTrustTokenCachesVerification proves the §10 mint side-effect: a
// successful `trust token` writes the verification method back into
// trust.json so `afauth status` can show it offline.
func TestTrustTokenCachesVerification(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	did := whoamiDID(t)
	stub := newStubTrust(t, 0, trustBindingResp{}, trustTokenResp{
		JWT:          "header.payload.sig",
		ExpiresAt:    time.Now().Add(15 * time.Minute).Unix(),
		Verification: "email",
	})
	seedTrustState(t, trustState{
		BaseURL:                 stub.server.URL,
		AgentDID:                did,
		BindingID:               "bind-1",
		BindingToken:            "bind-tok",
		BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix(),
	})

	if _, _, err := runCLI(t, "trust", "token", "did:web:example.com"); err != nil {
		t.Fatalf("trust token: %v", err)
	}

	st, err := loadTrustState()
	if err != nil {
		t.Fatalf("loadTrustState: %v", err)
	}
	if st.Verification != "email" {
		t.Fatalf("want cached verification 'email', got %q", st.Verification)
	}
	if st.VerificationSeenUnix == 0 {
		t.Fatalf("want verification_seen_at set")
	}

	stdout, _, err := runCLI(t, "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(stdout, "(email)") {
		t.Fatalf("want '(email)' in status, got:\n%s", stdout)
	}
}
