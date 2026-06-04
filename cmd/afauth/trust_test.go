package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/afauthhq/cli/internal/signing"
)

// stubTrust is a minimal trust.afauth.org stand-in. It exposes the
// three endpoints `afauth trust` uses and lets each test seed the
// confirmation state to drive the polling loop.
type stubTrust struct {
	server       *httptest.Server
	pollCount    atomic.Int32
	confirmAfter int32 // pendings before confirming; 0 = confirm immediately
	binding      trustBindingResp
	tokenResp    trustTokenResp
}

func newStubTrust(t *testing.T, confirmAfter int32, binding trustBindingResp, tokenResp trustTokenResp) *stubTrust {
	t.Helper()
	s := &stubTrust{
		confirmAfter: confirmAfter,
		binding:      binding,
		tokenResp:    tokenResp,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/link/start", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["agent_did"] == nil || body["agent_pubkey_b64"] == nil {
			http.Error(w, "missing fields", 400)
			return
		}
		writeJSON(w, 200, trustLinkStartResp{
			ReqID:     "req-1",
			LinkURL:   s.server.URL + "/link?req=stub",
			PollURL:   s.server.URL + "/v1/link/poll",
			ExpiresIn: 60,
		})
	})
	mux.HandleFunc("/v1/link/poll", func(w http.ResponseWriter, r *http.Request) {
		n := s.pollCount.Add(1)
		if n <= s.confirmAfter {
			writeJSON(w, 200, map[string]string{"state": "pending"})
			return
		}
		writeJSON(w, 200, struct {
			State string `json:"state"`
			trustBindingResp
		}{State: "confirmed", trustBindingResp: s.binding})
	})
	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		// §3.1 keyless mint: the CLI authenticates by signing the request
		// with its agent key (no bearer token). Verify that §5 signature
		// the way the real attestor does, and confirm the keyid is a
		// did:key (the agent account identifier).
		did, err := signing.Verify(r)
		if err != nil {
			http.Error(w, "mint not signed by agent key: "+err.Error(), 401)
			return
		}
		if !strings.HasPrefix(did, "did:key:") {
			http.Error(w, "mint keyid is not a did:key", 401)
			return
		}
		writeJSON(w, 200, s.tokenResp)
	})
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func TestTrustLink_FullFlow(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	binding := trustBindingResp{
		BindingID:             "bind-1",
		BindingTokenExpiresAt: time.Now().Add(90 * 24 * time.Hour).Unix(),
	}
	stub := newStubTrust(t, 1, binding, trustTokenResp{})

	stdout, _, err := runCLI(t, "trust", "link",
		"--base", stub.server.URL,
		"--label", "test-agent",
		"--no-loopback", // exercise the polling path
		"--no-browser",  // don't actually launch a browser during tests
		"--poll", "0",   // immediate retry — test uses tiny sleeps
		"--timeout", "5",
	)
	if err != nil {
		t.Fatalf("trust link: %v", err)
	}
	if !strings.Contains(stdout, "linked ✓") {
		t.Fatalf("want 'linked ✓' in stdout, got: %s", stdout)
	}
	if !strings.Contains(stdout, "bind-1") {
		t.Fatalf("want binding_id in stdout, got: %s", stdout)
	}
	// Polled at least twice (pending → confirmed).
	if c := stub.pollCount.Load(); c < 2 {
		t.Fatalf("expected ≥2 polls, got %d", c)
	}

	// Binding persisted with chmod 600.
	statePath := filepath.Join(home, "trust.json")
	st, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat trust.json: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("trust.json mode = %o, want 0600", mode)
	}

	// Status command shows the persisted binding.
	out, _, err := runCLI(t, "trust", "status")
	if err != nil {
		t.Fatalf("trust status: %v", err)
	}
	if !strings.Contains(out, "bind-1") {
		t.Fatalf("status missing binding: %s", out)
	}
}

func TestTrustToken_UsesPersistedBinding(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	stub := newStubTrust(t, 0,
		trustBindingResp{BindingID: "b", BindingTokenExpiresAt: time.Now().Add(time.Hour).Unix()},
		trustTokenResp{JWT: "eyJ.HEADER.SIG", ExpiresAt: time.Now().Add(900 * time.Second).Unix(), Verification: "email"},
	)

	if _, _, err := runCLI(t, "trust", "link",
		"--base", stub.server.URL, "--no-loopback", "--no-browser", "--poll", "0", "--timeout", "5",
	); err != nil {
		t.Fatalf("link: %v", err)
	}

	stdout, _, err := runCLI(t, "trust", "token", "did:web:svc.example", "--timeout", "5")
	if err != nil {
		t.Fatalf("trust token: %v", err)
	}
	got := strings.TrimSpace(stdout)
	if got != "eyJ.HEADER.SIG" {
		t.Fatalf("token output = %q, want JWT only", got)
	}
}

func TestTrustStatus_NoBinding(t *testing.T) {
	withTempHome(t)
	out, _, err := runCLI(t, "trust", "status")
	if err != nil {
		t.Fatalf("trust status: %v", err)
	}
	if !strings.Contains(out, "no binding") {
		t.Fatalf("want 'no binding' message, got: %s", out)
	}
}

func TestTrustForget_RemovesLocalState(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Hand-write a state file.
	statePath := filepath.Join(home, "trust.json")
	if err := os.WriteFile(statePath, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if _, _, err := runCLI(t, "trust", "forget"); err != nil {
		t.Fatalf("trust forget: %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("trust.json still exists after forget: err=%v", err)
	}

	// Idempotent — second call is fine.
	if _, _, err := runCLI(t, "trust", "forget"); err != nil {
		t.Fatalf("trust forget (second): %v", err)
	}
}

func TestTrustPoll_SignaturesValid(t *testing.T) {
	// Verify the poll signature is correct Ed25519 over the req_id
	// using the agent's seed.
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	keyJSON, err := os.ReadFile(filepath.Join(home, "key.json"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	var k struct {
		PublicKey  string `json:"public_key_hex"`
		PrivateKey string `json:"private_key_seed_hex"`
	}
	if err := json.Unmarshal(keyJSON, &k); err != nil {
		t.Fatalf("parse key: %v", err)
	}

	var captured struct {
		mu    sync.Mutex
		sig   string
		reqID string
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/link/start", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, trustLinkStartResp{
			ReqID: "req-sig-test", LinkURL: "http://example/link", PollURL: "http://example/poll", ExpiresIn: 30,
		})
	})
	mux.HandleFunc("/v1/link/poll", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		captured.mu.Lock()
		captured.sig = body["sig_b64"]
		captured.reqID = body["req_id"]
		captured.mu.Unlock()
		writeJSON(w, 200, struct {
			State string `json:"state"`
			trustBindingResp
		}{
			State: "confirmed",
			trustBindingResp: trustBindingResp{
				BindingID:             "b",
				BindingTokenExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if _, _, err := runCLI(t, "trust", "link", "--base", srv.URL, "--no-loopback", "--no-browser", "--poll", "0", "--timeout", "5"); err != nil {
		t.Fatalf("link: %v", err)
	}

	captured.mu.Lock()
	defer captured.mu.Unlock()
	if captured.reqID != "req-sig-test" {
		t.Fatalf("unexpected reqID: %q", captured.reqID)
	}
	sig, err := base64.RawURLEncoding.DecodeString(captured.sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	pubBytes := mustHex(t, k.PublicKey)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(captured.reqID), sig) {
		t.Fatalf("agent's poll signature does not verify against its own pubkey")
	}
}

func TestTrustLink_LoopbackCallbackAccelerates(t *testing.T) {
	// On a local machine (non-headless) the loopback callback wakes the
	// poll loop the instant the human confirms, instead of waiting out
	// the poll interval. We prove the wake works by setting a poll
	// interval far longer than the test timeout: the link can ONLY
	// complete in time if the callback fires and pulls the loop forward.
	forceNonHeadless(t) // exercise the loopback path, not the headless auto-skip
	home := withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	var captured struct {
		mu          sync.Mutex
		callbackURL string
	}
	var pollN atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/link/start", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		captured.mu.Lock()
		if cb, ok := body["callback_url"].(string); ok {
			captured.callbackURL = cb
		}
		captured.mu.Unlock()
		writeJSON(w, 200, trustLinkStartResp{
			ReqID: "req-cb", LinkURL: "http://example/link", PollURL: "http://example/poll", ExpiresIn: 30,
		})

		// Simulate the human confirming in a browser on THIS machine: hit
		// the agent's loopback callback from the server side after a pause.
		go func() {
			time.Sleep(50 * time.Millisecond)
			captured.mu.Lock()
			cb := captured.callbackURL
			captured.mu.Unlock()
			if cb != "" {
				if resp, err := http.Get(cb); err == nil {
					resp.Body.Close()
				}
			}
		}()
	})
	mux.HandleFunc("/v1/link/poll", func(w http.ResponseWriter, r *http.Request) {
		// Poll #1 is pending; only the callback-woken poll (#2) confirms.
		if pollN.Add(1) <= 1 {
			writeJSON(w, 200, map[string]string{"state": "pending"})
			return
		}
		writeJSON(w, 200, struct {
			State string `json:"state"`
			trustBindingResp
		}{
			State: "confirmed",
			trustBindingResp: trustBindingResp{
				BindingID:             "b-cb",
				BindingTokenExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	stdout, _, err := runCLI(t, "trust", "link",
		"--base", srv.URL, "--no-browser",
		"--poll", "30", // >> --timeout: only a callback wake can finish in time
		"--timeout", "5",
	)
	if err != nil {
		t.Fatalf("trust link (callback should wake the poll loop): %v", err)
	}
	if !strings.Contains(stdout, "linked ✓") {
		t.Fatalf("want linked, got: %s", stdout)
	}

	captured.mu.Lock()
	cb := captured.callbackURL
	captured.mu.Unlock()
	if !strings.HasPrefix(cb, "http://127.0.0.1:") {
		t.Fatalf("callback URL not loopback: %q", cb)
	}

	// trust.json should exist and be 0600.
	statePath := filepath.Join(home, "trust.json")
	if st, err := os.Stat(statePath); err != nil {
		t.Fatalf("stat trust.json: %v", err)
	} else if st.Mode().Perm() != 0o600 {
		t.Fatalf("trust.json mode = %o", st.Mode().Perm())
	}
}

func TestTrustLink_LoopbackUnreachable_PollRescues(t *testing.T) {
	// Regression for the SSH/split-machine case: the agent is on a remote
	// host (loopback ENABLED), but the human confirms in a browser on a
	// DIFFERENT machine, so the callback is never hit — its post-confirm
	// redirect lands on the human's own loopback, not ours. The
	// background poll loop must still complete the link. Before the fix,
	// the CLI waited on the callback alone and hung until --timeout.
	forceNonHeadless(t) // loopback IS started; nothing ever hits it
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	binding := trustBindingResp{
		BindingID:             "b-rescue",
		BindingTokenExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	// confirmAfter=1: poll #1 pending, poll #2 confirmed. The stub never
	// touches the callback URL, so only polling can finish the link.
	stub := newStubTrust(t, 1, binding, trustTokenResp{})

	stdout, _, err := runCLI(t, "trust", "link",
		"--base", stub.server.URL,
		"--no-browser",
		"--poll", "0", // tight poll so the rescue is quick
		"--timeout", "5",
	)
	if err != nil {
		t.Fatalf("expected the poll loop to rescue an unreachable callback, got: %v", err)
	}
	if !strings.Contains(stdout, "linked ✓") {
		t.Fatalf("want 'linked ✓', got: %s", stdout)
	}
	if c := stub.pollCount.Load(); c < 2 {
		t.Fatalf("expected ≥2 polls (pending→confirmed), got %d", c)
	}
}

func TestTrustLink_HeadlessSkipsLoopback(t *testing.T) {
	// Under SSH (or a display-less Linux box) the loopback callback can
	// never be reached, so the CLI must not start it or advertise a
	// callback_url — the confirm page would otherwise offer a dead
	// "Return to the agent" button. Polling alone drives the link, and
	// the user is told why.
	t.Setenv("SSH_CONNECTION", "10.0.0.1 2222 10.0.0.2 22")
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_TTY", "")
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	var mu sync.Mutex
	var gotCallback string
	var sawStart bool
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/link/start", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		gotCallback, _ = body["callback_url"].(string)
		sawStart = true
		mu.Unlock()
		writeJSON(w, 200, trustLinkStartResp{
			ReqID: "req-headless", LinkURL: "http://example/link",
			PollURL: "http://example/poll", ExpiresIn: 30,
		})
	})
	mux.HandleFunc("/v1/link/poll", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, struct {
			State string `json:"state"`
			trustBindingResp
		}{
			State: "confirmed",
			trustBindingResp: trustBindingResp{
				BindingID:             "b-h",
				BindingTokenExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	stdout, stderr, err := runCLI(t, "trust", "link",
		"--base", srv.URL, "--no-browser", "--poll", "0", "--timeout", "5",
	)
	if err != nil {
		t.Fatalf("trust link: %v", err)
	}
	if !strings.Contains(stdout, "linked ✓") {
		t.Fatalf("want 'linked ✓', got: %s", stdout)
	}

	mu.Lock()
	defer mu.Unlock()
	if !sawStart {
		t.Fatal("server never received /v1/link/start")
	}
	if gotCallback != "" {
		t.Fatalf("headless link must NOT advertise a callback_url, got %q", gotCallback)
	}
	if !strings.Contains(stderr, "using polling") {
		t.Fatalf("expected a headless→polling notice on stderr, got: %s", stderr)
	}
}

func TestTrustLink_NoLoopback_PollsAsFallback(t *testing.T) {
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	binding := trustBindingResp{
		BindingID:             "b",
		BindingTokenExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	stub := newStubTrust(t, 0, binding, trustTokenResp{})

	var capturedCallback string
	var mu sync.Mutex
	// Wrap the existing handler chain by re-mounting the start handler to
	// capture the callback_url field.
	stub.server.Config.Handler.(*http.ServeMux).HandleFunc("/v1/link/start-capture", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		if cb, ok := body["callback_url"].(string); ok {
			capturedCallback = cb
		}
		mu.Unlock()
		w.WriteHeader(200)
	})
	// Note: we can't intercept the actual handler easily; instead verify
	// the no-loopback flag path completes successfully via polling.

	_, _, err := runCLI(t, "trust", "link",
		"--base", stub.server.URL,
		"--no-loopback",
		"--no-browser",
		"--poll", "0", "--timeout", "5",
	)
	if err != nil {
		t.Fatalf("trust link --no-loopback: %v", err)
	}
	if c := stub.pollCount.Load(); c < 1 {
		t.Fatalf("expected ≥1 poll, got %d", c)
	}
	// Silence the unused capturedCallback warning.
	_ = capturedCallback
}

func TestTrustLink_PhasePromptOnAwaitingConfirm(t *testing.T) {
	// First two polls report `awaiting_signin` (browser not loaded yet);
	// subsequent polls flip to `awaiting_confirm` (browser loaded the
	// page); finally `confirmed` lands the binding. The CLI should
	// emit the "click Confirm" line exactly once, at the transition.
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	var pollN atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/link/start", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, trustLinkStartResp{
			ReqID: "req-phase", LinkURL: "http://example/link",
			PollURL: "http://example/poll", ExpiresIn: 60,
		})
	})
	mux.HandleFunc("/v1/link/poll", func(w http.ResponseWriter, r *http.Request) {
		n := pollN.Add(1)
		switch {
		case n <= 2:
			writeJSON(w, 200, map[string]string{
				"state": "pending", "phase": "awaiting_signin",
			})
		case n <= 4:
			writeJSON(w, 200, map[string]string{
				"state": "pending", "phase": "awaiting_confirm",
			})
		default:
			writeJSON(w, 200, struct {
				State string `json:"state"`
				trustBindingResp
			}{
				State: "confirmed",
				trustBindingResp: trustBindingResp{
					BindingID:             "b",
					BindingTokenExpiresAt: time.Now().Add(time.Hour).Unix(),
				},
			})
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	stdout, _, err := runCLI(t, "trust", "link",
		"--base", srv.URL,
		"--no-loopback", "--no-browser",
		"--poll", "0", "--timeout", "5",
	)
	if err != nil {
		t.Fatalf("trust link: %v", err)
	}
	if !strings.Contains(stdout, "Browser opened; waiting for you to click Confirm") {
		t.Fatalf("expected confirm-phase prompt in stdout; got:\n%s", stdout)
	}
	// Should appear exactly once even though phase repeats across polls.
	if got := strings.Count(stdout, "Browser opened; waiting for you to click Confirm"); got != 1 {
		t.Fatalf("expected exactly 1 confirm-phase prompt, got %d:\n%s", got, stdout)
	}
}

func TestHeadlessReason(t *testing.T) {
	// Wipe every var the function inspects so each subtest starts clean.
	for _, k := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "DISPLAY", "WAYLAND_DISPLAY"} {
		t.Setenv(k, "")
	}

	t.Run("local desktop is not headless", func(t *testing.T) {
		// On Linux the default is "no DISPLAY" → headless; only assert
		// the cross-platform contract: zero env vars and no SSH means
		// non-Linux is non-headless.
		if runtime.GOOS == "linux" {
			t.Skip("Linux without DISPLAY is headless by design")
		}
		t.Setenv("SSH_CONNECTION", "")
		if r := headlessReason(); r != "" {
			t.Fatalf("expected non-headless on %s with no SSH vars, got %q", runtime.GOOS, r)
		}
	})

	t.Run("SSH_CONNECTION marks headless", func(t *testing.T) {
		t.Setenv("SSH_CONNECTION", "10.0.0.1 2222 10.0.0.2 22")
		if r := headlessReason(); r == "" {
			t.Fatal("expected headless when SSH_CONNECTION is set")
		}
	})

	t.Run("SSH_CLIENT marks headless", func(t *testing.T) {
		t.Setenv("SSH_CONNECTION", "")
		t.Setenv("SSH_CLIENT", "10.0.0.1 2222 22")
		if r := headlessReason(); r == "" {
			t.Fatal("expected headless when SSH_CLIENT is set")
		}
	})

	t.Run("Linux without DISPLAY is headless", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("DISPLAY check is Linux-only")
		}
		if r := headlessReason(); r == "" {
			t.Fatal("expected headless on Linux with no DISPLAY")
		}
	})

	t.Run("Linux with DISPLAY is not headless", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("DISPLAY check is Linux-only")
		}
		t.Setenv("DISPLAY", ":0")
		if r := headlessReason(); r != "" {
			t.Fatalf("expected non-headless with DISPLAY set, got %q", r)
		}
	})
}

func TestTrustLink_NoBrowserFlagSuppressesOpenAttempt(t *testing.T) {
	// On a dev macOS box the test would otherwise launch a real browser
	// at httptest's link_url. --no-browser must short-circuit that and
	// emit neither the success nor the failure line.
	withTempHome(t)
	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	binding := trustBindingResp{
		BindingID:             "b",
		BindingTokenExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	stub := newStubTrust(t, 0, binding, trustTokenResp{})

	stdout, stderr, err := runCLI(t, "trust", "link",
		"--base", stub.server.URL,
		"--no-loopback", "--no-browser",
		"--poll", "0", "--timeout", "5",
	)
	if err != nil {
		t.Fatalf("trust link: %v", err)
	}
	if strings.Contains(stdout, "opened in your browser") {
		t.Fatalf("--no-browser should suppress the open-success line; stdout: %s", stdout)
	}
	if strings.Contains(stderr, "could not auto-open browser") {
		t.Fatalf("--no-browser should suppress the open-failure line; stderr: %s", stderr)
	}
}

// forceNonHeadless clears the env signals headlessReason() inspects so a
// test exercises the loopback path rather than the SSH/headless auto-skip.
// DISPLAY satisfies the Linux check; on macOS/Windows the empty SSH vars
// are enough (DISPLAY is ignored there).
func forceNonHeadless(t *testing.T) {
	t.Helper()
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_TTY", "")
	t.Setenv("DISPLAY", ":0")
	t.Setenv("WAYLAND_DISPLAY", "")
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 | (c - '0')
			case c >= 'a' && c <= 'f':
				v = v<<4 | (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				v = v<<4 | (c - 'A' + 10)
			default:
				t.Fatalf("bad hex byte %q in %q", c, s)
			}
		}
		b[i] = v
	}
	return b
}

// TestCacheBindingExpiry pins the sliding-window refresh throttle: the
// attestor re-arms the binding expiry on every mint, but the CLI only
// rewrites trust.json once the cached value would advance by >1h, and an
// absent (0) value from an older attestor is a no-op.
func TestCacheBindingExpiry(t *testing.T) {
	t.Setenv("AFAUTH_HOME", t.TempDir()) // best-effort save lands in temp

	b := &trustBinding{BindingTokenExpiresUnix: 1_000_000}
	st := newTrustState(b)

	// Sub-hour advance: throttled, cached value unchanged.
	cacheBindingExpiry(st, b, 1_000_000+1800)
	if b.BindingTokenExpiresUnix != 1_000_000 {
		t.Fatalf("sub-hour advance should be throttled, got %d", b.BindingTokenExpiresUnix)
	}

	// >1h advance: refreshed.
	cacheBindingExpiry(st, b, 1_000_000+7200)
	if b.BindingTokenExpiresUnix != 1_000_000+7200 {
		t.Fatalf("over-hour advance should refresh, got %d", b.BindingTokenExpiresUnix)
	}

	// Absent field (older attestor): no-op, never writes a non-positive expiry.
	cacheBindingExpiry(st, b, 0)
	if b.BindingTokenExpiresUnix != 1_000_000+7200 {
		t.Fatalf("zero expiry should be a no-op, got %d", b.BindingTokenExpiresUnix)
	}
}
