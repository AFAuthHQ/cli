package main

// End-to-end tests for the afauth CLI command tree. Each test builds a
// fresh root cobra command via newRootCmd, points the binary at an
// isolated AFAUTH_HOME under t.TempDir(), and drives the command against
// either a per-test httptest.Server or nothing at all. The goal is to
// exercise the RunE bodies that the unit tests don't reach — flag
// wiring, file I/O, output formatting, ledger persistence — so that
// flag renames and cobra-tree changes surface as visible failures.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/afauthhq/cli/internal/identity"
	"github.com/afauthhq/cli/internal/signing"
)

// runCLI drives the cobra root with the given args and returns
// (stdout, stderr, err). It always sets SilenceUsage so cobra doesn't
// dump help text on error paths and pollute stderr; the error is
// returned to the caller verbatim.
func runCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	root.SilenceUsage = true
	root.SilenceErrors = true
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

// withTempHome points $AFAUTH_HOME at a fresh temp directory. The
// process-level env is restored automatically by t.Setenv.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AFAUTH_HOME", dir)
	return dir
}

// mockService is the minimal AFAuth-shaped HTTP server used by the
// signup/discover/call/keys-rotate/accounts paths. Endpoints are
// declared per test so each path's response shape is local to the test
// that needs it.
type mockService struct {
	mu       sync.Mutex
	calls    []*http.Request
	bodies   map[string][]byte
	srv      *httptest.Server
	mux      *http.ServeMux
}

func newMockService(t *testing.T) *mockService {
	t.Helper()
	m := &mockService{bodies: map[string][]byte{}, mux: http.NewServeMux()}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.calls = append(m.calls, cloneRequest(r))
		m.bodies[r.Method+" "+r.URL.Path] = body
		m.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		m.mux.ServeHTTP(w, r)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockService) URL() string { return m.srv.URL }

func (m *mockService) lastCall(method, path string) *http.Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.calls) - 1; i >= 0; i-- {
		if m.calls[i].Method == method && m.calls[i].URL.Path == path {
			return m.calls[i]
		}
	}
	return nil
}

func (m *mockService) lastBody(method, path string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.bodies[method+" "+path]...)
}

func cloneRequest(r *http.Request) *http.Request {
	out := r.Clone(r.Context())
	out.Header = r.Header.Clone()
	return out
}

// discoveryDoc returns a minimally valid v0.1 discovery document
// pointing every endpoint at this mock service's origin.
func discoveryDoc() map[string]any {
	return map[string]any{
		"afauth_version":       "0.1",
		"service_did":          "did:web:test.example",
		"signature_algorithms": []string{"ed25519"},
		"endpoints": map[string]any{
			"accounts":          "/afauth/v1/accounts",
			"owner_invitation":  "/afauth/v1/accounts/me/owner-invitation",
			"claim_page":        "/claim",
			"claim_completion":  "/afauth/v1/claim",
			"key_rotation":      "/afauth/v1/accounts/me/keys/rotate",
		},
		"recipient_types": []string{"email"},
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

// ---------- init / whoami ----------

func TestInitWritesKeyAndDID(t *testing.T) {
	home := withTempHome(t)
	stdout, stderr, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("init: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "wrote ") {
		t.Fatalf("stdout missing 'wrote' line: %q", stdout)
	}
	if !strings.Contains(stdout, "did:key:z") {
		t.Fatalf("stdout missing did:key: %q", stdout)
	}
	keyFile := filepath.Join(home, "key.json")
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("expected key at %s: %v", keyFile, err)
	}
	if _, err := identity.Load(keyFile); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestInitRefusesOverwriteWithoutForce(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("first init: %v", err)
	}
	_, _, err := runCLI(t, "init")
	if err == nil {
		t.Fatal("second init must error without --force")
	}
	if !strings.Contains(err.Error(), "exists") && !strings.Contains(err.Error(), "open") {
		t.Logf("note: init overwrite error message was %q", err.Error())
	}
}

func TestInitForceOverwritesKey(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("first init: %v", err)
	}
	firstDID := whoamiDID(t)

	if _, _, err := runCLI(t, "init", "--force"); err != nil {
		t.Fatalf("init --force: %v", err)
	}
	secondDID := whoamiDID(t)

	if firstDID == secondDID {
		t.Fatalf("--force did not generate a new key (DID unchanged: %s)", firstDID)
	}
	if _, err := os.Stat(filepath.Join(home, "key.json")); err != nil {
		t.Fatalf("key file missing after --force: %v", err)
	}
}

func whoamiDID(t *testing.T) string {
	t.Helper()
	stdout, stderr, err := runCLI(t, "whoami")
	if err != nil {
		t.Fatalf("whoami: %v\nstderr: %s", err, stderr)
	}
	did := strings.TrimSpace(stdout)
	if !strings.HasPrefix(did, "did:key:z") {
		t.Fatalf("whoami output not a did:key: %q", stdout)
	}
	return did
}

func TestWhoamiRequiresKey(t *testing.T) {
	withTempHome(t)
	_, _, err := runCLI(t, "whoami")
	if err == nil {
		t.Fatal("whoami without an existing key must error")
	}
}

// ---------- keys export / import ----------

func TestKeysExportToStdout(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	stdout, _, err := runCLI(t, "keys", "export")
	if err != nil {
		t.Fatalf("keys export: %v", err)
	}
	var d struct {
		Version    int    `json:"version"`
		Algorithm  string `json:"algorithm"`
		DIDKey     string `json:"did_key"`
		PrivateKey string `json:"private_key_seed_hex"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &d); err != nil {
		t.Fatalf("export not JSON: %v\nstdout: %s", err, stdout)
	}
	if d.Version != 1 || d.Algorithm != "ed25519" || d.PrivateKey == "" {
		t.Fatalf("export shape: %+v", d)
	}
}

func TestKeysExportToFile(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	out := filepath.Join(home, "exported.json")
	stdout, _, err := runCLI(t, "keys", "export", "--out", out)
	if err != nil {
		t.Fatalf("keys export --out: %v", err)
	}
	if !strings.Contains(stdout, out) {
		t.Fatalf("stdout missing destination path: %q", stdout)
	}
	if _, err := identity.Load(out); err != nil {
		t.Fatalf("exported file not loadable as identity: %v", err)
	}
}

func TestKeysImportRoundTrip(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	originalDID := whoamiDID(t)

	// Export to a sidecar, blow away the active key, import it back.
	sidecar := filepath.Join(t.TempDir(), "sidecar.json")
	if _, _, err := runCLI(t, "keys", "export", "--out", sidecar); err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := os.Remove(filepath.Join(os.Getenv("AFAUTH_HOME"), "key.json")); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	if _, _, err := runCLI(t, "keys", "import", sidecar); err != nil {
		t.Fatalf("import: %v", err)
	}
	if got := whoamiDID(t); got != originalDID {
		t.Fatalf("DID after import = %s; want %s", got, originalDID)
	}
}

func TestKeysImportRefusesOverwrite(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Generate another key in a separate dir and try to import without --force.
	other := filepath.Join(t.TempDir(), "other.json")
	t.Setenv("AFAUTH_HOME", filepath.Dir(other))
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init other: %v", err)
	}
	// Now the source key.json sits next to `other`; "real" home from
	// earlier still holds the first key. Switch back and attempt import.
	t.Setenv("AFAUTH_HOME", filepath.Dir(other))
	srcKey := filepath.Join(filepath.Dir(other), "key.json")

	// Restore the original home but copy in the src and attempt import.
	homeRestore := t.TempDir()
	t.Setenv("AFAUTH_HOME", homeRestore)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init restore: %v", err)
	}
	_, _, err := runCLI(t, "keys", "import", srcKey)
	if err == nil {
		t.Fatal("import must refuse to overwrite existing key without --force")
	}
}

// ---------- discover ----------

func TestDiscoverHumanReadable(t *testing.T) {
	withTempHome(t)
	srv := newMockService(t)
	srv.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, discoveryDoc())
	})

	stdout, _, err := runCLI(t, "discover", srv.URL())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	for _, want := range []string{
		"afauth 0.1 @ did:web:test.example",
		"endpoints:",
		"accounts          /afauth/v1/accounts",
		"signature_algorithms: [ed25519]",
		"recipient_types:      [email]",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("discover output missing %q\nfull:\n%s", want, stdout)
		}
	}
}

func TestDiscoverJSON(t *testing.T) {
	withTempHome(t)
	srv := newMockService(t)
	srv.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, discoveryDoc())
	})
	stdout, _, err := runCLI(t, "discover", "--json", srv.URL())
	if err != nil {
		t.Fatalf("discover --json: %v", err)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(stdout), &d); err != nil {
		t.Fatalf("discover --json output not JSON: %v\n%s", err, stdout)
	}
	if d["afauth_version"] != "0.1" {
		t.Fatalf("afauth_version = %v", d["afauth_version"])
	}
}

func TestDiscoverServiceError(t *testing.T) {
	withTempHome(t)
	srv := newMockService(t)
	srv.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", 503)
	})
	if _, _, err := runCLI(t, "discover", srv.URL()); err == nil {
		t.Fatal("discover must error when discovery returns 503")
	}
}

// ---------- signup (implicit + explicit) ----------

func TestSignupImplicitWritesLedger(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	srv := newMockService(t)
	srv.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, discoveryDoc())
	})
	srv.mux.HandleFunc("/afauth/v1/accounts/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "wrong method", 405)
			return
		}
		writeJSON(w, 200, map[string]any{"state": "UNCLAIMED", "account_did": "did:key:test"})
	})

	stdout, _, err := runCLI(t, "signup", srv.URL())
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if !strings.Contains(stdout, "signed up to "+srv.URL()) {
		t.Fatalf("signup stdout: %q", stdout)
	}
	if !strings.Contains(stdout, "(UNCLAIMED)") {
		t.Fatalf("state missing from stdout: %q", stdout)
	}
	if c := srv.lastCall("GET", "/afauth/v1/accounts/me"); c == nil {
		t.Fatal("expected a signed GET /accounts/me")
	} else if c.Header.Get("Signature-Input") == "" {
		t.Fatal("signup did not sign /accounts/me")
	}
	ledger := filepath.Join(home, "accounts.json")
	if _, err := os.Stat(ledger); err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
}

func TestSignupExplicitWithTermsVersion(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv := newMockService(t)
	srv.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, discoveryDoc())
	})
	srv.mux.HandleFunc("/afauth/v1/accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		writeJSON(w, 201, map[string]any{"state": "UNCLAIMED", "account_did": "did:key:test"})
	})

	stdout, _, err := runCLI(t, "signup", "--explicit", "--terms-version", "2026-05-01", srv.URL())
	if err != nil {
		t.Fatalf("signup --explicit: %v", err)
	}
	if !strings.Contains(stdout, "(UNCLAIMED)") {
		t.Fatalf("stdout missing state: %q", stdout)
	}
	body := srv.lastBody("POST", "/afauth/v1/accounts")
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body parse: %v (%q)", err, body)
	}
	if got["terms_version"] != "2026-05-01" {
		t.Fatalf("terms_version not forwarded: %+v", got)
	}
}

func TestSignupSurfacesAFAuthError(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv := newMockService(t)
	srv.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, discoveryDoc())
	})
	srv.mux.HandleFunc("/afauth/v1/accounts/me", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 401, map[string]any{
			"error": map[string]any{
				"code":    "invalid_signature",
				"message": "bad sig",
			},
		})
	})
	_, _, err := runCLI(t, "signup", srv.URL())
	if err == nil {
		t.Fatal("signup must surface AFAuth error envelope as Go error")
	}
	if !strings.Contains(err.Error(), "invalid_signature") {
		t.Fatalf("error doesn't name code: %v", err)
	}
}

// ---------- accounts ----------

func TestAccountsListEmpty(t *testing.T) {
	withTempHome(t)
	stdout, _, err := runCLI(t, "accounts", "list")
	if err != nil {
		t.Fatalf("accounts list: %v", err)
	}
	if !strings.Contains(stdout, "(no accounts") {
		t.Fatalf("empty list output: %q", stdout)
	}
}

func TestAccountsListAfterSignup(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv := newMockService(t)
	srv.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, discoveryDoc())
	})
	srv.mux.HandleFunc("/afauth/v1/accounts/me", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"state": "UNCLAIMED"})
	})
	if _, _, err := runCLI(t, "signup", srv.URL()); err != nil {
		t.Fatalf("signup: %v", err)
	}

	stdout, _, err := runCLI(t, "accounts", "list")
	if err != nil {
		t.Fatalf("accounts list: %v", err)
	}
	if !strings.Contains(stdout, "UNCLAIMED") || !strings.Contains(stdout, srv.URL()) {
		t.Fatalf("expected ledger entry in stdout: %q", stdout)
	}

	jsonOut, _, err := runCLI(t, "accounts", "list", "--json")
	if err != nil {
		t.Fatalf("accounts list --json: %v", err)
	}
	var entries []map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &entries); err != nil {
		t.Fatalf("--json parse: %v\n%s", err, jsonOut)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestAccountsShowUnknownService(t *testing.T) {
	withTempHome(t)
	_, _, err := runCLI(t, "accounts", "show", "https://nowhere.example")
	if err == nil {
		t.Fatal("accounts show on unknown service must error")
	}
	if !strings.Contains(err.Error(), "no entry") {
		t.Fatalf("error message: %v", err)
	}
}

func TestAccountsShowRefresh(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv := newMockService(t)
	srv.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, discoveryDoc())
	})
	// First call: UNCLAIMED. Second call: CLAIMED. The signup writes
	// UNCLAIMED to the ledger; --refresh upgrades the state.
	calls := 0
	srv.mux.HandleFunc("/afauth/v1/accounts/me", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		state := "UNCLAIMED"
		if calls > 1 {
			state = "CLAIMED"
		}
		writeJSON(w, 200, map[string]any{
			"state":       state,
			"account_did": "did:key:test",
		})
	})

	if _, _, err := runCLI(t, "signup", srv.URL()); err != nil {
		t.Fatalf("signup: %v", err)
	}
	stdout, _, err := runCLI(t, "accounts", "show", "--refresh", srv.URL())
	if err != nil {
		t.Fatalf("accounts show --refresh: %v", err)
	}
	if !strings.Contains(stdout, `"CLAIMED"`) {
		t.Fatalf("expected refreshed state in stdout: %q", stdout)
	}
}

// ---------- call ----------

func TestCallSignedGET(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv := newMockService(t)
	srv.mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		// Validate the request was signed — otherwise the test would
		// happily report a green that didn't actually exercise signing.
		if r.Header.Get("Signature-Input") == "" {
			http.Error(w, "unsigned", 400)
			return
		}
		if _, err := signing.Verify(r); err != nil {
			http.Error(w, "verify: "+err.Error(), 401)
			return
		}
		writeJSON(w, 200, map[string]any{"pong": true})
	})
	stdout, _, err := runCLI(t, "call", srv.URL()+"/ping")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(stdout, `"pong"`) {
		t.Fatalf("call output missing body: %q", stdout)
	}
	if !strings.Contains(stdout, " 200 ") {
		t.Fatalf("call output missing status line: %q", stdout)
	}
}

func TestCallPostJSONBody(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv := newMockService(t)
	srv.mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Digest") == "" {
			http.Error(w, "missing content-digest", 400)
			return
		}
		if _, err := signing.Verify(r); err != nil {
			http.Error(w, "verify: "+err.Error(), 401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		writeJSON(w, 200, json.RawMessage(body))
	})
	stdout, _, err := runCLI(t, "call",
		"--method", "POST",
		"--data", `{"hello":"world"}`,
		"--header", "X-Trace: abc123",
		srv.URL()+"/echo",
	)
	if err != nil {
		t.Fatalf("call POST: %v", err)
	}
	if !strings.Contains(stdout, "hello") {
		t.Fatalf("response body missing: %q", stdout)
	}
	if got := srv.lastCall("POST", "/echo").Header.Get("X-Trace"); got != "abc123" {
		t.Fatalf("custom header not forwarded: %q", got)
	}
}

func TestCallDataFromFile(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	bodyFile := filepath.Join(home, "body.json")
	if err := os.WriteFile(bodyFile, []byte(`{"from":"file"}`), 0o600); err != nil {
		t.Fatalf("write body: %v", err)
	}
	srv := newMockService(t)
	srv.mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(200)
		_, _ = w.Write(body)
	})
	stdout, _, err := runCLI(t, "call",
		"--method", "POST",
		"--data", "@"+bodyFile,
		srv.URL()+"/echo",
	)
	if err != nil {
		t.Fatalf("call --data @file: %v", err)
	}
	if !strings.Contains(stdout, `"from":"file"`) {
		t.Fatalf("file body not forwarded: %q", stdout)
	}
}

func TestCallMalformedHeader(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, _, err := runCLI(t, "call",
		"--header", "no-colon-here",
		"http://127.0.0.1:1/whatever", // arbitrary; flag check runs first
	)
	if err == nil {
		t.Fatal("expected error on malformed --header")
	}
	if !strings.Contains(err.Error(), "must be 'Name: value'") {
		t.Fatalf("error message: %v", err)
	}
}

// ---------- invite (resolveRecipient path through the CLI tree) ----------

func TestInviteRequiresService(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv := newMockService(t)
	srv.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, discoveryDoc())
	})
	srv.mux.HandleFunc("/afauth/v1/accounts/me/owner-invitation", func(w http.ResponseWriter, r *http.Request) {
		if _, err := signing.Verify(r); err != nil {
			http.Error(w, "verify: "+err.Error(), 401)
			return
		}
		writeJSON(w, 200, map[string]any{
			"invitation_id":     "inv_1",
			"claim_page_url":    "/claim/abc",
			"expires_at":        "2099-01-01T00:00:00Z",
		})
	})

	stdout, _, err := runCLI(t, "invite",
		"--service", srv.URL(),
		"alice@example.com",
	)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if !strings.Contains(stdout, "inv_1") && !strings.Contains(stdout, "claim/abc") {
		t.Fatalf("invite stdout: %q", stdout)
	}
	body := srv.lastBody("POST", "/afauth/v1/accounts/me/owner-invitation")
	if !strings.Contains(string(body), "alice@example.com") {
		t.Fatalf("invite did not include recipient value: %q", body)
	}
}

// ---------- keys rotate ----------

func TestKeysRotateSwapsActiveKey(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	oldDID := whoamiDID(t)

	srv := newMockService(t)
	srv.mux.HandleFunc("/.well-known/afauth", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, discoveryDoc())
	})
	srv.mux.HandleFunc("/afauth/v1/accounts/me/keys/rotate", func(w http.ResponseWriter, r *http.Request) {
		// Request MUST be signed by the OLD key per §8.1; verify.
		if _, err := signing.Verify(r); err != nil {
			http.Error(w, "verify: "+err.Error(), 401)
			return
		}
		writeJSON(w, 200, map[string]any{"state": "UNCLAIMED"})
	})

	if _, _, err := runCLI(t, "keys", "rotate", "--service", srv.URL()); err != nil {
		t.Fatalf("keys rotate: %v", err)
	}
	newDID := whoamiDID(t)
	if newDID == oldDID {
		t.Fatalf("DID unchanged after rotation: %s", newDID)
	}

	// Backup file with .<unix>.bak suffix should be present.
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "key.json.") && strings.HasSuffix(e.Name(), ".bak") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected key.json.<unix>.bak in %s; got: %v", home, dirNames(entries))
	}
}

func TestKeysRotateRequiresServiceFlag(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, _, err := runCLI(t, "keys", "rotate")
	if err == nil {
		t.Fatal("keys rotate must require --service")
	}
}

func dirNames(entries []os.DirEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// ---------- normalizeArgs at the integration level ----------

func TestVersionFlag(t *testing.T) {
	stdout, _, err := runCLI(t, "--version")
	if err != nil {
		t.Fatalf("--version: %v", err)
	}
	if !strings.Contains(stdout, "afauth") || !strings.Contains(stdout, "version") {
		t.Fatalf("--version stdout: %q", stdout)
	}
}

// Single-dash `-version` is normalised to `--version` by normalizeArgs
// before cobra parses; we exercise that wiring at the binary level by
// taking the same code path Execute() walks (the unit test only covers
// the pure transform).
func TestGoStyleVersionFlag(t *testing.T) {
	// We can't drive normalizeArgs through Execute() without going via
	// os.Args, but we can confirm it produces the value cobra would
	// have accepted, and that cobra accepts that value.
	got := normalizeArgs([]string{"-version"})
	if fmt.Sprintf("%v", got) != "[--version]" {
		t.Fatalf("normalize: %v", got)
	}
	if _, _, err := runCLI(t, got...); err != nil {
		t.Fatalf("--version through cobra: %v", err)
	}
}
