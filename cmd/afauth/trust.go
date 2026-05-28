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
// Binding state lives at ~/.config/afauth/trust.json with chmod 600
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
~/.config/afauth/trust.json.

By default the CLI starts a tiny loopback HTTP server on a random
local port; the browser hits it after the human confirms, and this
process returns immediately. Pass --no-loopback to fall back to
fixed-interval polling (useful for headless / sandboxed agents that
cannot bind a local port).

  afauth trust link                                 # uses trust.afauth.org
  afauth trust link --base http://localhost:3001    # dev / staging
  afauth trust link --label "claude on wen-mbp"     # shown on the confirm page
  afauth trust link --no-loopback                   # polling only
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
				cb, err := startLoopbackCallback(ctx)
				if err != nil {
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
			fmt.Fprintf(cmd.OutOrStdout(), "Waiting (expires in %ds)…\n", start.ExpiresIn)

			binding, err := trustWaitForConfirmation(
				ctx, base, start.ReqID, id.Seed, callback,
				time.Duration(pollSec)*time.Second,
				time.Duration(start.ExpiresIn)*time.Second,
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
	cmd.Flags().IntVar(&pollSec, "poll", 3, "seconds between poll attempts (loopback fallback)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 600, "give up after N seconds")
	cmd.Flags().BoolVar(&noLoopback, "no-loopback", false, "disable the loopback callback shortcut")
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
	var timeoutSec int
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
			tok, err := trustToken(ctx, st.BaseURL, st.BindingToken, args[0])
			if err != nil {
				return explainTrustError(err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), tok.JWT)
			return nil
		},
	}
	cmd.Flags().IntVar(&timeoutSec, "timeout", 30, "request timeout in seconds")
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

// trustWaitForConfirmation races the polling loop against an optional
// loopback callback. The first to fire ends the wait — the callback
// short-circuits typical wall-clock latency to "human's click time"
// instead of "next poll tick", at the cost of binding to a local port.
//
// When callback is nil, this degrades to pure polling (the previous
// behavior). When the loopback fires, we still do a single /v1/link/
// poll to actually fetch the binding token (the callback only signals
// readiness; the token is delivered via /v1/link/poll).
func trustWaitForConfirmation(
	ctx context.Context,
	base, reqID string,
	seed []byte,
	callback *loopbackCallback,
	interval, total time.Duration,
) (*trustBindingResp, error) {
	if callback == nil {
		return trustPollUntilConfirmed(ctx, base, reqID, seed, interval, total)
	}
	// Race the callback against the poll loop. Whichever signals first
	// wins; the loser is cancelled via ctx.
	waitCtx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	select {
	case <-callback.Done():
		// One immediate poll to pull the binding token.
		return trustPollOnce(waitCtx, base, reqID, seed)
	case <-waitCtx.Done():
		return nil, fmt.Errorf("trust link: timed out waiting for human confirmation")
	}
}

func trustPollOnce(ctx context.Context, base, reqID string, seed []byte) (*trustBindingResp, error) {
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, []byte(reqID))
	body := map[string]string{
		"req_id":  reqID,
		"sig_b64": base64URLNoPad(sig),
	}
	var raw json.RawMessage
	_, err := trustPostJSONStatus(ctx, trustBase(base)+"/v1/link/poll", "", body, &raw)
	if err != nil {
		return nil, err
	}
	var probe struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	if probe.State != "confirmed" {
		return nil, fmt.Errorf("trust link: callback fired but server still reports %q", probe.State)
	}
	var b trustBindingResp
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func trustPollUntilConfirmed(
	ctx context.Context,
	base, reqID string,
	seed []byte,
	interval, total time.Duration,
) (*trustBindingResp, error) {
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, []byte(reqID))
	body := map[string]string{
		"req_id":  reqID,
		"sig_b64": base64URLNoPad(sig),
	}
	url := trustBase(base) + "/v1/link/poll"
	deadline := time.Now().Add(total)
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
			// pending — keep polling.
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("trust link: timed out waiting for human confirmation")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
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

func (c *loopbackCallback) URL() string         { return c.url }
func (c *loopbackCallback) Done() <-chan struct{} { return c.done }
func (c *loopbackCallback) Close() {
	if c.server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = c.server.Shutdown(shutdownCtx)
	}
}
