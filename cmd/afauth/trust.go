package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// trust.afauth.org client commands, implementing the AFAP-0006
// `afauth-trust` attestor flow from the agent side.
//
//   afauth trust link    — bind the agent's DID to a human account
//   afauth trust token   — mint a §10 attestation JWT for a service
//   afauth trust status  — show the cached binding
//   afauth trust forget  — delete the local binding (server-side
//                          revocation lives in the human dashboard at
//                          trust.afauth.org/account)
//
// Binding state lives at ~/.afauth/trust.json with chmod 600
// alongside the agent's key. The file is rewritten atomically on
// every change.

const defaultTrustBase = "https://trust.afauth.org"

func newTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Bind the agent to a human account at an afauth-trust attestor (AFAP-0006)",
	}
	cmd.AddCommand(
		newTrustLinkCmd(),
		newTrustTokenCmd(),
		newTrustStatusCmd(),
		newTrustForgetCmd(),
	)
	return cmd
}

// ---------------------------------------------------------------------
// link
// ---------------------------------------------------------------------

func newTrustLinkCmd() *cobra.Command {
	var (
		base       string
		label      string
		keyPath    string
		pollSec    int
		timeoutSec int
		noLoopback bool
		noBrowser  bool
	)
	cmd := &cobra.Command{
		Use:   "link",
		Short: "Bind this agent to a human-controlled account",
		Long: `Opens a deep-link the human visits in their browser. After they
confirm, the binding token is fetched and persisted at
~/.afauth/trust.json.

The CLI polls the attestor in the background until the human confirms,
so the link completes even when the agent runs headless — e.g. you're
SSH'd into a remote host and confirm in your laptop's browser. On a
local desktop it additionally starts a tiny loopback server so the
browser can ping back the instant you confirm, skipping the poll wait.

A remote SSH session or a display-less Linux box is detected
automatically and the loopback shortcut is skipped (it could never be
reached). Pass --no-loopback to force polling-only mode anywhere.

  afauth trust link                                 # uses trust.afauth.org
  afauth trust link --base http://localhost:3001    # dev / staging
  afauth trust link --label "claude on wen-mbp"     # shown on the confirm page
  afauth trust link --no-loopback                   # polling only (auto under SSH)
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutSec)*time.Second)
			defer cancel()

			id, err := loadIdentity(keyPath)
			if err != nil {
				return err
			}
			did, err := id.DID()
			if err != nil {
				return err
			}

			var callback *loopbackCallback
			callbackURL := ""
			if !noLoopback {
				if reason := headlessReason(); reason != "" {
					// No local browser can reach our loopback port. Most
					// commonly the agent is SSH'd into a remote host: the
					// human confirms in their own browser, whose
					// post-confirm redirect targets THEIR loopback, not
					// ours — so the callback could never fire. Starting it
					// would also make the confirm page offer a dead "Return
					// to the agent" button. Skip it; the poll loop completes
					// the link either way.
					fmt.Fprintf(cmd.ErrOrStderr(),
						"%s — using polling (a loopback callback can't be reached from here)\n", reason)
				} else if cb, err := startLoopbackCallback(ctx); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"loopback callback unavailable (%v); falling back to polling\n", err)
				} else {
					callback = cb
					callbackURL = cb.URL()
					defer cb.Close()
				}
			}

			start, err := trustLinkStart(ctx, base, did, id.PublicKey, label, callbackURL)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Open this URL in a browser to link your agent:")
			fmt.Fprintln(cmd.OutOrStdout(), "")
			fmt.Fprintln(cmd.OutOrStdout(), "  "+start.LinkURL)
			fmt.Fprintln(cmd.OutOrStdout(), "")
			if !noBrowser {
				if err := openBrowser(start.LinkURL); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "(could not auto-open browser: %v — copy the URL above)\n", err)
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "(opened in your browser)")
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "First time at trust.afauth.org? You'll be prompted to create an account.")
			fmt.Fprintf(cmd.OutOrStdout(), "Waiting (expires in %ds)…\n", start.ExpiresIn)

			binding, err := trustWaitForConfirmation(
				ctx, base, start.ReqID, id.Seed, callback,
				time.Duration(pollSec)*time.Second,
				time.Duration(start.ExpiresIn)*time.Second,
				func(phase string) {
					// One-shot upgrade — the only transition that's
					// worth surfacing is "browser landed on the
					// confirm page; now waiting on the human's click."
					if phase == "awaiting_confirm" {
						fmt.Fprintln(cmd.OutOrStdout(),
							"→ Browser opened; waiting for you to click Confirm…")
					}
				},
			)
			if err != nil {
				return err
			}

			if err := saveTrustState(&trustState{
				BaseURL:                 trustBase(base),
				AgentDID:                did,
				BindingID:               binding.BindingID,
				BindingToken:            binding.BindingToken,
				BindingTokenExpiresUnix: binding.BindingTokenExpiresAt,
			}); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "linked ✓")
			fmt.Fprintf(cmd.OutOrStdout(), "binding_id  %s\n", binding.BindingID)
			fmt.Fprintf(cmd.OutOrStdout(), "expires     %s\n",
				time.Unix(binding.BindingTokenExpiresAt, 0).Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", "", "trust attestor base URL (default https://trust.afauth.org)")
	cmd.Flags().StringVar(&label, "label", "", "short label shown on the confirm page")
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	cmd.Flags().IntVar(&pollSec, "poll", 3, "seconds between poll attempts")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 600, "give up after N seconds")
	cmd.Flags().BoolVar(&noLoopback, "no-loopback", false, "force polling-only; skip the loopback callback shortcut (auto-skipped when headless)")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not auto-open the link in a browser (just print it)")
	return cmd
}

// ---------------------------------------------------------------------
// Browser auto-open
// ---------------------------------------------------------------------

// openBrowser launches the OS's default browser at url. Best-effort:
// returns a descriptive error when no display is available or the
// underlying command fails. Callers print the URL anyway so the human
// can fall back to copy/paste — e.g. when SSH'd into a remote box
// without an X server.
func openBrowser(url string) error {
	if reason := headlessReason(); reason != "" {
		return fmt.Errorf("no display (%s)", reason)
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default: // linux, freebsd, openbsd
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// headlessReason returns a short string when the current process has
// no realistic way to open a browser locally: a remote SSH session,
// or Linux with no X / Wayland display. Empty string means "go ahead
// and try."
func headlessReason() string {
	if os.Getenv("SSH_CONNECTION") != "" ||
		os.Getenv("SSH_CLIENT") != "" ||
		os.Getenv("SSH_TTY") != "" {
		return "remote SSH session"
	}
	if runtime.GOOS == "linux" &&
		os.Getenv("DISPLAY") == "" &&
		os.Getenv("WAYLAND_DISPLAY") == "" {
		return "no DISPLAY/WAYLAND_DISPLAY"
	}
	return ""
}

// ---------------------------------------------------------------------
// token
// ---------------------------------------------------------------------

func newTrustTokenCmd() *cobra.Command {
	var (
		timeoutSec int
		keyPath    string
	)
	cmd := &cobra.Command{
		Use:   "token <service-did>",
		Short: "Mint a §10 attestation JWT for the given service",
		Long: `Calls /v1/token at the trust attestor with the cached binding
token and prints the resulting JWT to stdout. The JWT is short-lived
(≤15 min) and audience-bound — only the named service will accept it.

  afauth trust token did:web:tavily.com
  ATTEST=$(afauth trust token did:web:tavily.com)
  afauth signup --attest "$ATTEST" https://tavily.com
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutSec)*time.Second)
			defer cancel()

			st, err := loadTrustState()
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("no binding — run `afauth trust link` first")
				}
				return err
			}
			// Refuse to mint from a binding that belongs to a different
			// key: the JWT's sub would be the old DID while the agent
			// signs requests with the active key, so any service would
			// reject the pair. Catch it locally with an actionable hint.
			id, err := loadIdentity(keyPath)
			if err != nil {
				return err
			}
			activeDID, err := id.DID()
			if err != nil {
				return err
			}
			if bindingIsOrphaned(st, activeDID) {
				return fmt.Errorf("trust token: binding is for %s, but the active key is %s — re-link with `afauth trust link`", st.AgentDID, activeDID)
			}
			tok, err := trustToken(ctx, st.BaseURL, st.BindingToken, args[0])
			if err != nil {
				return explainTrustError(err)
			}
			cacheVerification(st, tok.Verification)
			fmt.Fprintln(cmd.OutOrStdout(), tok.JWT)
			return nil
		},
	}
	cmd.Flags().IntVar(&timeoutSec, "timeout", 30, "request timeout in seconds")
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	return cmd
}

// explainTrustError replaces a generic trust API error with an
// actionable hint when the upstream code tells us what the user
// should do next.
func explainTrustError(err error) error {
	var apiErr *trustAPIError
	if !errors.As(err, &apiErr) {
		return err
	}
	switch apiErr.Code {
	case "binding_expired":
		return fmt.Errorf("binding token expired — run `afauth trust link` to re-link this agent")
	case "binding_revoked":
		return fmt.Errorf("binding was revoked from the human dashboard at trust.afauth.org/account; ask the human to re-link or use a different agent")
	case "verification_required":
		return fmt.Errorf("this account has no active verification methods — sign in at trust.afauth.org/account to add one")
	}
	return err
}

// ---------------------------------------------------------------------
// status
// ---------------------------------------------------------------------

func newTrustStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the cached trust-attestor binding",
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadTrustState()
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					fmt.Fprintln(cmd.OutOrStdout(), "no binding (run `afauth trust link`)")
					return nil
				}
				return err
			}
			exp := time.Unix(st.BindingTokenExpiresUnix, 0)
			fmt.Fprintf(cmd.OutOrStdout(), "base        %s\n", st.BaseURL)
			fmt.Fprintf(cmd.OutOrStdout(), "agent       %s\n", st.AgentDID)
			fmt.Fprintf(cmd.OutOrStdout(), "binding_id  %s\n", st.BindingID)
			fmt.Fprintf(cmd.OutOrStdout(), "expires     %s (in %s)\n",
				exp.Format(time.RFC3339), time.Until(exp).Round(time.Second))
			return nil
		},
	}
}

// ---------------------------------------------------------------------
// forget
// ---------------------------------------------------------------------

func newTrustForgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forget",
		Short: "Delete the local binding (server-side revocation: visit trust.afauth.org/account)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := trustStatePath()
			if err != nil {
				return err
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("trust forget: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "local binding cleared")
			fmt.Fprintln(cmd.OutOrStdout(), "to revoke server-side, sign in at https://trust.afauth.org/account")
			return nil
		},
	}
}

// ---------------------------------------------------------------------
// HTTP — small inline client, no signed requests (trust attestor uses
// bearer tokens and a per-poll Ed25519 raw signature).
// ---------------------------------------------------------------------

type trustLinkStartResp struct {
	ReqID     string `json:"req_id"`
	LinkURL   string `json:"link_url"`
	PollURL   string `json:"poll_url"`
	ExpiresIn int    `json:"expires_in"`
}

type trustBindingResp struct {
	BindingID             string `json:"binding_id"`
	BindingToken          string `json:"binding_token"`
	BindingTokenExpiresAt int64  `json:"binding_token_expires_at"`
}

type trustTokenResp struct {
	JWT          string `json:"jwt"`
	ExpiresAt    int64  `json:"expires_at"`
	Verification string `json:"verification"`
}

type trustErrEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// trustAPIError carries the upstream error envelope so callers can
// branch on `binding_expired` vs `binding_revoked` vs others and
// surface tailored prompts to the user.
type trustAPIError struct {
	URL     string
	Status  int
	Code    string
	Message string
}

func (e *trustAPIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("trust %s: %d %s", e.URL, e.Status, e.Message)
	}
	return fmt.Sprintf("trust %s: %s: %s", e.URL, e.Code, e.Message)
}

func trustBase(override string) string {
	if override != "" {
		return override
	}
	if env := os.Getenv("AFAUTH_TRUST_BASE"); env != "" {
		return env
	}
	return defaultTrustBase
}

func trustLinkStart(
	ctx context.Context,
	base, agentDID string,
	agentPubKey ed25519.PublicKey,
	label, callbackURL string,
) (*trustLinkStartResp, error) {
	body := map[string]any{
		"agent_did":        agentDID,
		"agent_pubkey_b64": base64URLNoPad(agentPubKey),
	}
	if label != "" {
		body["agent_label"] = label
	}
	if callbackURL != "" {
		body["callback_url"] = callbackURL
	}
	var out trustLinkStartResp
	if err := trustPostJSON(ctx, trustBase(base)+"/v1/link/start", "", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// trustWaitForConfirmation drives the poll loop, optionally accelerated
// by a loopback callback. Polling is the source of truth: it is what
// actually fetches the binding token from /v1/link/poll, and it completes
// the link whether or not the callback ever fires. When a callback is
// present, its Done channel only wakes the loop early — collapsing
// typical wall-clock latency from "next poll tick" to "the human's click
// time" — without being load-bearing for correctness.
//
// That distinction matters for split-machine setups. When the agent is
// SSH'd into a remote host and the human confirms in their laptop's
// browser, the browser's post-confirm redirect hits the LAPTOP's loopback
// port, not the agent's — so the callback never fires. Because the poll
// loop runs regardless, the link still completes. (An earlier version
// waited on the callback alone, which hung until timeout in exactly this
// case.)
//
// onPhase, when non-nil, is invoked each time the server-reported phase
// changes (`awaiting_signin` → `awaiting_confirm`), letting the caller
// render a tighter waiting message.
func trustWaitForConfirmation(
	ctx context.Context,
	base, reqID string,
	seed []byte,
	callback *loopbackCallback,
	interval, total time.Duration,
	onPhase func(phase string),
) (*trustBindingResp, error) {
	var wake <-chan struct{}
	if callback != nil {
		wake = callback.Done()
	}
	return trustPollUntilConfirmed(ctx, base, reqID, seed, interval, total, onPhase, wake)
}

// trustPollUntilConfirmed polls /v1/link/poll until the request is
// confirmed, the deadline passes, or ctx is cancelled. If wake is
// non-nil, a signal on it triggers an immediate poll instead of waiting
// out the interval (used by the loopback callback). wake fires at most
// once per call: after it does, it's dropped so a closed channel can't
// busy-loop the select.
func trustPollUntilConfirmed(
	ctx context.Context,
	base, reqID string,
	seed []byte,
	interval, total time.Duration,
	onPhase func(phase string),
	wake <-chan struct{},
) (*trustBindingResp, error) {
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, []byte(reqID))
	body := map[string]string{
		"req_id":  reqID,
		"sig_b64": base64URLNoPad(sig),
	}
	url := trustBase(base) + "/v1/link/poll"
	deadline := time.Now().Add(total)
	var lastPhase string
	for {
		var raw json.RawMessage
		status, err := trustPostJSONStatus(ctx, url, "", body, &raw)
		switch {
		case err != nil && status == 0:
			// Network error — keep retrying until the deadline.
		case err != nil:
			// Terminal HTTP error (auth, gone, not found). Surface as-is.
			return nil, err
		default:
			var probe struct {
				State string `json:"state"`
				Phase string `json:"phase"`
			}
			if jerr := json.Unmarshal(raw, &probe); jerr != nil {
				return nil, jerr
			}
			if probe.State == "confirmed" {
				var b trustBindingResp
				if jerr := json.Unmarshal(raw, &b); jerr != nil {
					return nil, jerr
				}
				return &b, nil
			}
			// pending — emit phase if it changed and a listener is wired.
			if onPhase != nil && probe.Phase != "" && probe.Phase != lastPhase {
				lastPhase = probe.Phase
				onPhase(probe.Phase)
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("trust link: timed out waiting for human confirmation")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wake:
			// Loopback callback fired — poll immediately rather than
			// waiting out the interval. Drop the channel so the now-closed
			// channel doesn't spin the select on subsequent iterations.
			wake = nil
		case <-time.After(interval):
		}
	}
}

func trustToken(ctx context.Context, base, bindingToken, aud string) (*trustTokenResp, error) {
	var out trustTokenResp
	if err := trustPostJSON(ctx, base+"/v1/token", bindingToken, map[string]string{"aud": aud}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func trustPostJSON(ctx context.Context, url, bearer string, body any, out any) error {
	_, err := trustPostJSONStatus(ctx, url, bearer, body, out)
	return err
}

// trustPostJSONStatus is like trustPostJSON but also returns the HTTP
// status code on protocol errors (status > 0). On network errors,
// status is 0 — used by the poll loop to distinguish "retry" (network)
// from "give up" (HTTP error envelope).
func trustPostJSONStatus(ctx context.Context, url, bearer string, body any, out any) (int, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return 0, err
	}
	req.Header.Set("content-type", "application/json")
	if bearer != "" {
		req.Header.Set("authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var env trustErrEnvelope
		_ = json.Unmarshal(respBody, &env)
		return resp.StatusCode, &trustAPIError{
			URL:     url,
			Status:  resp.StatusCode,
			Code:    env.Error.Code,
			Message: env.Error.Message,
		}
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp.StatusCode, fmt.Errorf("trust %s: decode response: %w", url, err)
		}
	}
	return resp.StatusCode, nil
}

// ---------------------------------------------------------------------
// Local state
// ---------------------------------------------------------------------

type trustState struct {
	Version                 int    `json:"version"`
	BaseURL                 string `json:"base_url"`
	AgentDID                string `json:"agent_did"`
	BindingID               string `json:"binding_id"`
	BindingToken            string `json:"binding_token"`
	BindingTokenExpiresUnix int64  `json:"binding_token_expires_at"`
	// Verification is the strongest human-verification method the
	// attestor reported at the most recent /v1/token mint (email,
	// oauth, payment). Cached so `afauth status` can show how the agent
	// is linked without a network call; it may lag the attestor, since
	// it is only refreshed when a token is minted.
	Verification         string `json:"verification,omitempty"`
	VerificationSeenUnix int64  `json:"verification_seen_at,omitempty"`
}

const trustStateVersion = 1

func trustStatePath() (string, error) {
	if h := os.Getenv("AFAUTH_HOME"); h != "" {
		return filepath.Join(h, "trust.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("trust: locate home: %w", err)
	}
	return filepath.Join(home, ".afauth", "trust.json"), nil
}

func saveTrustState(st *trustState) error {
	st.Version = trustStateVersion
	path, err := trustStatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("trust: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("trust: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("trust: rename: %w", err)
	}
	return nil
}

func loadTrustState() (*trustState, error) {
	path, err := trustStatePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st trustState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	return &st, nil
}

// cacheVerification records the verification method returned by a
// successful /v1/token mint into the local binding, so `afauth status`
// can report how the agent is linked without a network round-trip.
// Best-effort: a persistence failure must never fail a mint that has
// already succeeded, so the error is swallowed.
func cacheVerification(st *trustState, verification string) {
	if st == nil || verification == "" || verification == st.Verification {
		return
	}
	st.Verification = verification
	st.VerificationSeenUnix = time.Now().Unix()
	_ = saveTrustState(st)
}

// bindingIsOrphaned reports whether the cached binding belongs to a
// DIFFERENT key than the active one — e.g. one left behind by a key
// rotation or import. An orphaned binding MUST NOT be used to mint or
// send an attestation: the JWT would assert the old DID while requests
// are signed by the new key, so the service rejects it. A binding with
// no recorded agent_did (legacy/hand-edited) is treated as not-orphaned,
// matching `afauth status`.
func bindingIsOrphaned(st *trustState, activeDID string) bool {
	return st != nil && st.AgentDID != "" && st.AgentDID != activeDID
}

// warnIfBindingStale prints a non-fatal notice when the local trust
// binding no longer matches the active key (after a key change), so the
// operator knows to re-link. Deliberately NON-destructive: it does not
// clear the binding, because the binding_token remains a live
// attestation-minting credential at the attestor (~90 days) until
// revoked THERE — clearing it locally would only hide that exposure.
func warnIfBindingStale(w io.Writer, activeDID string) {
	st, err := loadTrustState()
	if err != nil {
		return // no binding (or unreadable) — nothing to warn about
	}
	if bindingIsOrphaned(st, activeDID) {
		fmt.Fprintf(w, "⚠ trust binding is for a previous key (%s); re-link with `afauth trust link`.\n", st.AgentDID)
		fmt.Fprintln(w, "  the old binding stays live at the attestor (~90d) — revoke it at trust.afauth.org/account")
	}
}

func base64URLNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---------------------------------------------------------------------
// Loopback callback — opens a random local port, the trust attestor
// redirects the browser there after the human confirms.
// ---------------------------------------------------------------------

type loopbackCallback struct {
	server *http.Server
	url    string
	done   chan struct{}
	once   sync.Once
}

func startLoopbackCallback(ctx context.Context) (*loopbackCallback, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := ln.Addr().(*net.TCPAddr)
	cb := &loopbackCallback{
		url:  fmt.Sprintf("http://127.0.0.1:%d/done", addr.Port),
		done: make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		cb.once.Do(func() { close(cb.done) })
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body style="font-family:ui-serif;color:#1c1816;padding:40px;max-width:480px;margin:0 auto"><h1 style="color:#B83227">Linked.</h1><p>You can close this tab and return to your terminal.</p></body></html>`))
	})
	cb.server = &http.Server{Handler: mux}
	go func() {
		// Stops when cb.Close() is called or ctx cancels.
		_ = cb.server.Serve(ln)
	}()
	go func() {
		<-ctx.Done()
		cb.Close()
	}()
	return cb, nil
}

func (c *loopbackCallback) URL() string           { return c.url }
func (c *loopbackCallback) Done() <-chan struct{} { return c.done }
func (c *loopbackCallback) Close() {
	if c.server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = c.server.Shutdown(shutdownCtx)
	}
}
