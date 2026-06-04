package main

// End-to-end coverage for service-aware attestor selection across one or
// more trust bindings (#1 reconcile against accepted_attestors, #2 honest
// breadcrumb, #3 --attestor override, #4 multiple bindings, #5 learn+persist
// the attestor iss). The flows are driven through the real cobra commands
// against httptest stand-ins for the attestor(s) and the service.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// initAgent runs `afauth init` and returns the new agent's did:key.
func initAgent(t *testing.T) string {
	t.Helper()
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	return whoamiDID(t)
}

// makeJWT builds a syntactically valid JWT whose payload carries iss, so
// issFromJWT can decode it. The signature is a placeholder — these tests
// exercise the agent's local bookkeeping, not signature verification.
func makeJWT(t *testing.T, iss string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(map[string]any{
		"iss": iss,
		"aud": "did:web:svc.example",
		"sub": "did:key:zAgent",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return header + "." + payload + ".sig"
}

// countingTrust is a trust-attestor stand-in that mints a fixed token and
// counts /v1/token hits, so a test can assert whether a mint actually
// happened (e.g. that a pre-mint reconcile short-circuited it).
type countingTrust struct {
	server *httptest.Server
	mints  atomic.Int32
	jwt    string
	verif  string
}

func newCountingTrust(t *testing.T, jwt, verif string) *countingTrust {
	t.Helper()
	ct := &countingTrust{jwt: jwt, verif: verif}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		ct.mints.Add(1)
		writeJSON(w, 200, trustTokenResp{
			JWT:          ct.jwt,
			ExpiresAt:    time.Now().Add(15 * time.Minute).Unix(),
			Verification: ct.verif,
		})
	})
	ct.server = httptest.NewServer(mux)
	t.Cleanup(ct.server.Close)
	return ct
}

// attestedDocWithAttestors is attestedDiscoveryDoc with a caller-chosen
// accepted_attestors list.
func attestedDocWithAttestors(attestors ...string) map[string]any {
	doc := discoveryDoc()
	doc["billing"] = map[string]any{
		"unclaimed_mode":     "attested_only",
		"accepted_attestors": attestors,
	}
	return doc
}

// ---------------------------------------------------------------------
// #5 — iss is decoded from the minted JWT
// ---------------------------------------------------------------------

func TestIssFromJWT(t *testing.T) {
	if got := issFromJWT(makeJWT(t, "acme-trust")); got != "acme-trust" {
		t.Fatalf("iss = %q, want acme-trust", got)
	}
	// Non-decodable / malformed tokens degrade to "" rather than erroring.
	for _, bad := range []string{"", "not-a-jwt", "only.two", "a.!!!.c"} {
		if got := issFromJWT(bad); got != "" {
			t.Fatalf("issFromJWT(%q) = %q, want empty", bad, got)
		}
	}
}

// ---------------------------------------------------------------------
// selection logic (unit) — selectAttestorBinding branch coverage
// ---------------------------------------------------------------------

func TestSelectAttestorBinding(t *testing.T) {
	const me = "did:key:zMe"
	mk := func(base, iss string) *trustBinding {
		return &trustBinding{BaseURL: base, Iss: iss, AgentDID: me, BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()}
	}

	t.Run("no bindings is not linked", func(t *testing.T) {
		_, err := selectAttestorBinding(newTrustState(), []string{"afauth-trust"}, "", me)
		if err == nil || !strings.Contains(err.Error(), "afauth trust link") {
			t.Fatalf("want not-linked error, got %v", err)
		}
	})

	t.Run("accepted list picks the matching iss", func(t *testing.T) {
		af, acme := mk("https://a", "afauth-trust"), mk("https://b", "acme-trust")
		got, err := selectAttestorBinding(newTrustState(af, acme), []string{"acme-trust"}, "", me)
		if err != nil || got != acme {
			t.Fatalf("want acme binding, got %v err=%v", got, err)
		}
	})

	t.Run("known iss none accepted is a hard error", func(t *testing.T) {
		af := mk("https://a", "afauth-trust")
		_, err := selectAttestorBinding(newTrustState(af), []string{"acme-trust"}, "", me)
		if err == nil || !strings.Contains(err.Error(), "acme-trust") || !strings.Contains(err.Error(), "afauth-trust") {
			t.Fatalf("want not-accepted error naming both sides, got %v", err)
		}
	})

	t.Run("sole unknown-iss binding is returned optimistically", func(t *testing.T) {
		fresh := mk("https://a", "") // iss not learned yet
		got, err := selectAttestorBinding(newTrustState(fresh), []string{"acme-trust"}, "", me)
		if err != nil || got != fresh {
			t.Fatalf("want optimistic return of sole binding, got %v err=%v", got, err)
		}
	})

	t.Run("two accepted matches are ambiguous", func(t *testing.T) {
		a, b := mk("https://a", "afauth-trust"), mk("https://b", "acme-trust")
		_, err := selectAttestorBinding(newTrustState(a, b), []string{"afauth-trust", "acme-trust"}, "", me)
		if err == nil || !strings.Contains(err.Error(), "--attestor") {
			t.Fatalf("want ambiguity error pointing at --attestor, got %v", err)
		}
	})

	t.Run("override wins, matched by iss or base", func(t *testing.T) {
		a, b := mk("https://a", "afauth-trust"), mk("https://b", "acme-trust")
		st := newTrustState(a, b)
		if got, err := selectAttestorBinding(st, []string{"afauth-trust", "acme-trust"}, "acme-trust", me); err != nil || got != b {
			t.Fatalf("override by iss: got %v err=%v", got, err)
		}
		if got, err := selectAttestorBinding(st, nil, "https://a", me); err != nil || got != a {
			t.Fatalf("override by base: got %v err=%v", got, err)
		}
	})

	t.Run("override with no match errors", func(t *testing.T) {
		a := mk("https://a", "afauth-trust")
		_, err := selectAttestorBinding(newTrustState(a), nil, "nope", me)
		if err == nil || !strings.Contains(err.Error(), "no linked attestor matches") {
			t.Fatalf("want no-match error, got %v", err)
		}
	})

	t.Run("orphaned and expired bindings are not candidates", func(t *testing.T) {
		orphan := &trustBinding{BaseURL: "https://o", Iss: "afauth-trust", AgentDID: "did:key:zOther", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()}
		expired := &trustBinding{BaseURL: "https://e", Iss: "afauth-trust", AgentDID: me, BindingTokenExpiresUnix: time.Now().Add(-time.Hour).Unix()}
		_, err := selectAttestorBinding(newTrustState(orphan, expired), []string{"afauth-trust"}, "", me)
		if err == nil {
			t.Fatal("want an error when no usable binding exists")
		}
	})
}

// ---------------------------------------------------------------------
// #1 — reconcile the bound attestor against billing.accepted_attestors
// ---------------------------------------------------------------------

// Known-iss mismatch: the failure is caught BEFORE any mint or signed
// request, with a re-link hint — not as an opaque server rejection.
func TestSignup_RejectsUnacceptedAttestor_PreMint(t *testing.T) {
	withTempHome(t)
	did := initAgent(t)

	attestor := newCountingTrust(t, makeJWT(t, "afauth-trust"), "email")
	seedTrustState(t, trustBinding{
		BaseURL:                 attestor.server.URL,
		Iss:                     "afauth-trust", // already known
		AgentDID:                did,
		BindingID:               "bind-1",
		BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix(),
	})

	svc := newMockService(t)
	serveAttestedDiscoveryDoc(svc, attestedDocWithAttestors("acme-trust"))

	_, _, err := runCLI(t, "signup", svc.URL())
	if err == nil {
		t.Fatal("expected signup to fail: the bound attestor is not accepted")
	}
	for _, want := range []string{"acme-trust", "afauth-trust", "afauth trust link"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must name accepted+linked attestors and a fix; missing %q in: %v", want, err)
		}
	}
	if n := attestor.mints.Load(); n != 0 {
		t.Fatalf("must not mint from an unaccepted attestor; minted %d times", n)
	}
	if c := svc.lastCall("GET", "/afauth/v1/accounts/me"); c != nil {
		t.Fatal("must not send a signed request when the attestor is unaccepted")
	}
}

// Unknown-iss mismatch: the iss is learned from the mint, persisted (#5),
// then reconciled (#1) before sending — so it still fails locally.
func TestSignup_LearnsIssThenRejects_PostMint(t *testing.T) {
	withTempHome(t)
	did := initAgent(t)

	attestor := newCountingTrust(t, makeJWT(t, "afauth-trust"), "email")
	seedTrustState(t, trustBinding{
		BaseURL: attestor.server.URL,
		// Iss intentionally empty — not yet learned.
		AgentDID:                did,
		BindingID:               "bind-1",
		BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix(),
	})

	svc := newMockService(t)
	serveAttestedDiscoveryDoc(svc, attestedDocWithAttestors("acme-trust"))

	_, _, err := runCLI(t, "signup", svc.URL())
	if err == nil || !strings.Contains(err.Error(), "acme-trust") {
		t.Fatalf("expected a not-accepted error after learning the iss, got %v", err)
	}
	if n := attestor.mints.Load(); n != 1 {
		t.Fatalf("expected exactly one mint (to learn the iss), got %d", n)
	}
	if c := svc.lastCall("GET", "/afauth/v1/accounts/me"); c != nil {
		t.Fatal("must not send the unaccepted attestation to the service")
	}
	// #5: the learned iss is now persisted, so the next attempt short-circuits.
	st, err := loadTrustState()
	if err != nil || len(st.Bindings) != 1 || st.Bindings[0].Iss != "afauth-trust" {
		t.Fatalf("learned iss not persisted: %+v (err=%v)", st, err)
	}
}

// ---------------------------------------------------------------------
// #5 — happy path: iss learned + persisted, attestation sent
// ---------------------------------------------------------------------

func TestSignup_LearnsAndPersistsIss_HappyPath(t *testing.T) {
	withTempHome(t)
	did := initAgent(t)

	jwt := makeJWT(t, "afauth-trust")
	attestor := newCountingTrust(t, jwt, "email")
	seedTrustState(t, trustBinding{
		BaseURL:                 attestor.server.URL,
		AgentDID:                did,
		BindingID:               "bind-1",
		BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix(),
	})

	svc := newMockService(t)
	serveAttestedDiscoveryDoc(svc, attestedDocWithAttestors("afauth-trust"))
	svc.mux.HandleFunc("/afauth/v1/accounts/me", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"state": "UNCLAIMED"})
	})

	_, stderr, err := runCLI(t, "signup", svc.URL())
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if got := svc.lastCall("GET", "/afauth/v1/accounts/me"); got == nil || got.Header.Get("AFAuth-Attestation") != jwt {
		t.Fatalf("attestation not sent to the accepting service")
	}
	if !strings.Contains(stderr, "attested via afauth-trust") { // #2 honest breadcrumb (now iss-named)
		t.Fatalf("breadcrumb should name the learned iss, got: %q", stderr)
	}
	st, _ := loadTrustState()
	if len(st.Bindings) != 1 || st.Bindings[0].Iss != "afauth-trust" {
		t.Fatalf("iss not persisted after mint: %+v", st)
	}
}

// ---------------------------------------------------------------------
// #4 — multiple bindings; selection picks the accepted one
// ---------------------------------------------------------------------

func TestSignup_PicksAcceptedAttestorAmongMany(t *testing.T) {
	withTempHome(t)
	did := initAgent(t)

	afauth := newCountingTrust(t, makeJWT(t, "afauth-trust"), "email")
	acme := newCountingTrust(t, makeJWT(t, "acme-trust"), "oauth")
	seedTrustState(t,
		trustBinding{BaseURL: afauth.server.URL, Iss: "afauth-trust", AgentDID: did, BindingID: "b-af", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()},
		trustBinding{BaseURL: acme.server.URL, Iss: "acme-trust", AgentDID: did, BindingID: "b-acme", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()},
	)

	svc := newMockService(t)
	serveAttestedDiscoveryDoc(svc, attestedDocWithAttestors("acme-trust")) // only acme
	svc.mux.HandleFunc("/afauth/v1/accounts/me", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"state": "UNCLAIMED"})
	})

	if _, stderr, err := runCLI(t, "signup", svc.URL()); err != nil {
		t.Fatalf("signup: %v\n%s", err, stderr)
	}
	if acme.mints.Load() != 1 {
		t.Fatalf("acme attestor should mint once, got %d", acme.mints.Load())
	}
	if afauth.mints.Load() != 0 {
		t.Fatalf("afauth attestor must not be used, minted %d times", afauth.mints.Load())
	}
}

// Two usable bindings, both accepted: without --attestor this is ambiguous
// and the CLI asks the user to choose, rather than guessing (#3/#4).
func TestSignup_AmbiguousAttestors_RequireOverride(t *testing.T) {
	withTempHome(t)
	did := initAgent(t)

	afauth := newCountingTrust(t, makeJWT(t, "afauth-trust"), "email")
	acme := newCountingTrust(t, makeJWT(t, "acme-trust"), "oauth")
	seedTrustState(t,
		trustBinding{BaseURL: afauth.server.URL, Iss: "afauth-trust", AgentDID: did, BindingID: "b-af", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()},
		trustBinding{BaseURL: acme.server.URL, Iss: "acme-trust", AgentDID: did, BindingID: "b-acme", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()},
	)

	svc := newMockService(t)
	serveAttestedDiscoveryDoc(svc, attestedDocWithAttestors("afauth-trust", "acme-trust"))
	svc.mux.HandleFunc("/afauth/v1/accounts/me", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"state": "UNCLAIMED"})
	})

	// No override → ambiguous.
	_, _, err := runCLI(t, "signup", svc.URL())
	if err == nil || !strings.Contains(err.Error(), "--attestor") {
		t.Fatalf("want ambiguity error pointing at --attestor, got %v", err)
	}

	// #3 override resolves it.
	if _, _, err := runCLI(t, "signup", "--attestor", "acme-trust", svc.URL()); err != nil {
		t.Fatalf("signup --attestor: %v", err)
	}
	if acme.mints.Load() != 1 || afauth.mints.Load() != 0 {
		t.Fatalf("override should mint only from acme; acme=%d afauth=%d", acme.mints.Load(), afauth.mints.Load())
	}
}

// AFAUTH_TRUST_BASE acts as a selector when no --attestor flag is given.
func TestSignup_EnvSelectsAttestor(t *testing.T) {
	withTempHome(t)
	did := initAgent(t)

	afauth := newCountingTrust(t, makeJWT(t, "afauth-trust"), "email")
	acme := newCountingTrust(t, makeJWT(t, "acme-trust"), "oauth")
	seedTrustState(t,
		trustBinding{BaseURL: afauth.server.URL, Iss: "afauth-trust", AgentDID: did, BindingID: "b-af", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()},
		trustBinding{BaseURL: acme.server.URL, Iss: "acme-trust", AgentDID: did, BindingID: "b-acme", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()},
	)
	t.Setenv("AFAUTH_TRUST_BASE", acme.server.URL)

	svc := newMockService(t)
	serveAttestedDiscoveryDoc(svc, attestedDocWithAttestors("afauth-trust", "acme-trust"))
	svc.mux.HandleFunc("/afauth/v1/accounts/me", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"state": "UNCLAIMED"})
	})

	if _, _, err := runCLI(t, "signup", svc.URL()); err != nil {
		t.Fatalf("signup with env selector: %v", err)
	}
	if acme.mints.Load() != 1 || afauth.mints.Load() != 0 {
		t.Fatalf("env selector should mint only from acme; acme=%d afauth=%d", acme.mints.Load(), afauth.mints.Load())
	}
}

// ---------------------------------------------------------------------
// #3 — trust token --attestor among several bindings
// ---------------------------------------------------------------------

func TestTrustToken_AttestorOverrideAmongMany(t *testing.T) {
	withTempHome(t)
	did := initAgent(t)

	afauth := newCountingTrust(t, makeJWT(t, "afauth-trust"), "email")
	acme := newCountingTrust(t, makeJWT(t, "acme-trust"), "oauth")
	seedTrustState(t,
		trustBinding{BaseURL: afauth.server.URL, Iss: "afauth-trust", AgentDID: did, BindingID: "b-af", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()},
		trustBinding{BaseURL: acme.server.URL, Iss: "acme-trust", AgentDID: did, BindingID: "b-acme", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()},
	)

	// No --attestor and no accepted list → ambiguous, no mint.
	if _, _, err := runCLI(t, "trust", "token", "did:web:svc.example", "--timeout", "5"); err == nil || !strings.Contains(err.Error(), "--attestor") {
		t.Fatalf("want ambiguity error, got %v", err)
	}

	// Select acme by iss.
	stdout, _, err := runCLI(t, "trust", "token", "did:web:svc.example", "--attestor", "acme-trust", "--timeout", "5")
	if err != nil {
		t.Fatalf("trust token --attestor: %v", err)
	}
	if strings.TrimSpace(stdout) != makeJWT(t, "acme-trust") {
		// Tokens carry a timestamp; compare iss instead of exact bytes.
		if issFromJWT(strings.TrimSpace(stdout)) != "acme-trust" {
			t.Fatalf("token not minted from acme: %q", stdout)
		}
	}
	if acme.mints.Load() != 1 || afauth.mints.Load() != 0 {
		t.Fatalf("override should mint only from acme; acme=%d afauth=%d", acme.mints.Load(), afauth.mints.Load())
	}
}

// ---------------------------------------------------------------------
// #4 — trust link adds bindings; forget drops one; status lists all
// ---------------------------------------------------------------------

func TestTrustLink_AddsSecondBinding(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	stubA := newStubTrust(t, 0, trustBindingResp{BindingID: "bind-A", BindingTokenExpiresAt: time.Now().Add(90 * 24 * time.Hour).Unix()}, trustTokenResp{})
	stubB := newStubTrust(t, 0, trustBindingResp{BindingID: "bind-B", BindingTokenExpiresAt: time.Now().Add(90 * 24 * time.Hour).Unix()}, trustTokenResp{})

	link := func(base string) {
		t.Helper()
		if _, _, err := runCLI(t, "trust", "link", "--base", base, "--no-loopback", "--no-browser", "--poll", "0", "--timeout", "5"); err != nil {
			t.Fatalf("link %s: %v", base, err)
		}
	}
	link(stubA.server.URL)
	link(stubB.server.URL)

	st, err := loadTrustState()
	if err != nil || len(st.Bindings) != 2 {
		t.Fatalf("want 2 bindings after linking two attestors, got %d (err=%v)", len(st.Bindings), err)
	}

	// Re-linking the same attestor refreshes in place, not duplicates.
	link(stubA.server.URL)
	st, _ = loadTrustState()
	if len(st.Bindings) != 2 {
		t.Fatalf("re-linking should not duplicate; got %d bindings", len(st.Bindings))
	}

	out, _, err := runCLI(t, "trust", "status")
	if err != nil {
		t.Fatalf("trust status: %v", err)
	}
	for _, want := range []string{stubA.server.URL, stubB.server.URL, "bind-A", "bind-B"} {
		if !strings.Contains(out, want) {
			t.Fatalf("trust status should list all bindings; missing %q in:\n%s", want, out)
		}
	}
}

func TestTrustForget_OneAttestor(t *testing.T) {
	withTempHome(t)
	did := initAgent(t)
	seedTrustState(t,
		trustBinding{BaseURL: "https://a.example", Iss: "afauth-trust", AgentDID: did, BindingID: "b-af", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()},
		trustBinding{BaseURL: "https://b.example", Iss: "acme-trust", AgentDID: did, BindingID: "b-acme", BindingTokenExpiresUnix: time.Now().Add(time.Hour).Unix()},
	)

	if _, _, err := runCLI(t, "trust", "forget", "--attestor", "afauth-trust"); err != nil {
		t.Fatalf("trust forget --attestor: %v", err)
	}
	st, err := loadTrustState()
	if err != nil || len(st.Bindings) != 1 || st.Bindings[0].Iss != "acme-trust" {
		t.Fatalf("want only the acme binding left, got %+v (err=%v)", st, err)
	}

	out, _, err := runCLI(t, "trust", "status")
	if err != nil {
		t.Fatalf("trust status: %v", err)
	}
	if strings.Contains(out, "a.example") || !strings.Contains(out, "b.example") {
		t.Fatalf("forgotten attestor should be gone; status:\n%s", out)
	}
}

// ---------------------------------------------------------------------
// migration — a v1 single-binding file loads as one v2 binding
// ---------------------------------------------------------------------

func TestTrustState_MigratesV1(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	exp := time.Now().Add(48 * time.Hour).Unix()
	v1, err := json.Marshal(map[string]any{
		"version":                  1,
		"base_url":                 "https://trust.afauth.org",
		"agent_did":                "did:key:zLegacy",
		"binding_id":               "bind-old",
		"binding_token_expires_at": exp,
		"verification":             "email",
	})
	if err != nil {
		t.Fatalf("marshal v1: %v", err)
	}
	path, err := trustStatePath()
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	if err := os.WriteFile(path, v1, 0o600); err != nil {
		t.Fatalf("seed v1: %v", err)
	}

	st, err := loadTrustState()
	if err != nil {
		t.Fatalf("load v1: %v", err)
	}
	if len(st.Bindings) != 1 {
		t.Fatalf("v1 file should migrate to one binding, got %d", len(st.Bindings))
	}
	b := st.Bindings[0]
	if b.BaseURL != "https://trust.afauth.org" || b.BindingID != "bind-old" || b.Verification != "email" || b.BindingTokenExpiresUnix != exp {
		t.Fatalf("migrated binding lost fields: %+v", b)
	}

	out, _, err := runCLI(t, "trust", "status")
	if err != nil {
		t.Fatalf("trust status after migration: %v", err)
	}
	for _, want := range []string{"trust.afauth.org", "bind-old"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status should show the migrated binding; missing %q in:\n%s", want, out)
		}
	}
}
