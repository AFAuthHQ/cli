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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/afauthhq/cli/internal/httpx"
	"github.com/afauthhq/cli/internal/signing"
	"github.com/spf13/cobra"
)

// trustHTTPClient is used for all outbound trust-attestor calls. It
// refuses cross-origin redirects so a redirect can't forward the agent's
// signed mint request / bearer to another origin (audit #3).
var trustHTTPClient = httpx.Client(30 * time.Second)

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
			fmt.Fprintf(cmd.OutOrStdout(), "First time at %s? You'll be prompted to create an account.\n", attestorHost(trustBase(base)))
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

			// Upsert into the existing set so linking a second attestor adds
			// a binding rather than replacing the first (#4 multi-binding).
			st, err := loadTrustState()
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return err
				}
				st = newTrustState()
			}
			st.upsert(&trustBinding{
				BaseURL:                 trustBase(base),
				AgentDID:                did,
				BindingID:               binding.BindingID,
				BindingTokenExpiresUnix: binding.BindingTokenExpiresAt,
			})
			if err := saveTrustState(st); err != nil {
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
		attestor   string
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

			id, err := loadIdentity(keyPath)
			if err != nil {
				return err
			}
			activeDID, err := id.DID()
			if err != nil {
				return err
			}
			st, err := loadTrustState()
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("no binding — run `afauth trust link` first")
				}
				return err
			}
			// `trust token` carries only the service DID (no discovery doc),
			// so there's no accepted_attestors list to filter on — selection
			// is the explicit --attestor/env override or the sole binding.
			// selectAttestorBinding also refuses an orphaned/expired binding
			// (the JWT's sub would be the old DID, which the service rejects).
			b, err := selectAttestorBinding(st, nil, attestorOverride(attestor), activeDID)
			if err != nil {
				return err
			}
			tok, err := trustToken(ctx, b.BaseURL, activeDID, id.Seed, args[0])
			if err != nil {
				return explainTrustError(err)
			}
			learnIss(st, b, tok.JWT)
			cacheVerification(st, b, tok.Verification)
			cacheBindingExpiry(st, b, tok.BindingExpiresUnix)
			fmt.Fprintln(cmd.OutOrStdout(), tok.JWT)
			return nil
		},
	}
	cmd.Flags().IntVar(&timeoutSec, "timeout", 30, "request timeout in seconds")
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	cmd.Flags().StringVar(&attestor, "attestor", "", "which linked attestor to mint from (iss or base URL); default: the only binding")
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
		Short: "Show the cached trust-attestor binding(s)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadTrustState()
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					fmt.Fprintln(cmd.OutOrStdout(), "no binding (run `afauth trust link`)")
					return nil
				}
				return err
			}
			if len(st.Bindings) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no binding (run `afauth trust link`)")
				return nil
			}
			for i, b := range st.Bindings {
				if i > 0 {
					fmt.Fprintln(cmd.OutOrStdout())
				}
				fmt.Fprintf(cmd.OutOrStdout(), "attestor    %s\n", attestorLabel(b))
				fmt.Fprintf(cmd.OutOrStdout(), "base        %s\n", b.BaseURL)
				fmt.Fprintf(cmd.OutOrStdout(), "agent       %s\n", b.AgentDID)
				fmt.Fprintf(cmd.OutOrStdout(), "binding_id  %s\n", b.BindingID)
				exp := time.Unix(b.BindingTokenExpiresUnix, 0)
				fmt.Fprintf(cmd.OutOrStdout(), "expires     %s (in %s)\n",
					exp.Format(time.RFC3339), time.Until(exp).Round(time.Second))
				if b.Verification != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "verified    %s\n", b.Verification)
				}
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------
// forget
// ---------------------------------------------------------------------

func newTrustForgetCmd() *cobra.Command {
	var attestor string
	cmd := &cobra.Command{
		Use:   "forget",
		Short: "Delete a local binding (server-side revocation: visit trust.afauth.org/account)",
		Long: `Removes locally-cached trust binding state. By default forgets ALL
bindings; pass --attestor to drop just one (matched by iss or base URL).

This clears local state only. The binding stays live at the attestor
(~90 days) until revoked there — sign in at trust.afauth.org/account.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := trustStatePath()
			if err != nil {
				return err
			}
			const revokeHint = "to revoke server-side, sign in at https://trust.afauth.org/account"

			if attestor == "" {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("trust forget: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "local binding(s) cleared")
				fmt.Fprintln(cmd.OutOrStdout(), revokeHint)
				return nil
			}

			st, err := loadTrustState()
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("no binding to forget")
				}
				return err
			}
			b := st.find(attestor)
			if b == nil {
				return fmt.Errorf("no linked attestor matches %q (linked: %s)", attestor, attestorList(st.Bindings))
			}
			label := attestorLabel(b)
			kept := st.Bindings[:0]
			for _, x := range st.Bindings {
				if x != b {
					kept = append(kept, x)
				}
			}
			st.Bindings = kept
			if len(st.Bindings) == 0 {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("trust forget: %w", err)
				}
			} else if err := saveTrustState(st); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "forgot local binding for %s\n", label)
			fmt.Fprintln(cmd.OutOrStdout(), revokeHint)
			return nil
		},
	}
	cmd.Flags().StringVar(&attestor, "attestor", "", "forget only this attestor (iss or base URL); default: all bindings")
	return cmd
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
	BindingTokenExpiresAt int64  `json:"binding_token_expires_at"`
}

type trustTokenResp struct {
	JWT          string `json:"jwt"`
	ExpiresAt    int64  `json:"expires_at"`
	Verification string `json:"verification"`
	// BindingExpiresUnix is when the binding lapses if left unused. The
	// attestor re-arms it on every mint (inactivity window); the CLI
	// refreshes its cached copy from this so `afauth status` and the
	// signup pre-check don't treat the link-time deadline as fixed.
	// Absent (0) from older attestors.
	BindingExpiresUnix int64 `json:"binding_expires_at"`
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

// trustToken mints a §10 attestation JWT for aud. §3.1 keyless mint: the
// request is signed per §5 with the agent's account key (did + seed)
// instead of presenting a bearer binding_token — the keypair is the sole
// credential. The agent signs `${base}/v1/token`, which MUST match the
// attestor's configured public base URL (the default trust.afauth.org
// matches out of the box).
func trustToken(ctx context.Context, base, did string, seed []byte, aud string) (*trustTokenResp, error) {
	url := base + "/v1/token"
	buf, err := json.Marshal(map[string]string{"aud": aud})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	if err := signing.Sign(req, did, seed, nil); err != nil {
		return nil, fmt.Errorf("trust token: sign mint request: %w", err)
	}
	var out trustTokenResp
	if _, err := trustDo(req, &out); err != nil {
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
	return trustDo(req, out)
}

// trustDo executes a prepared trust-API request and decodes the JSON
// response, or a trustAPIError envelope on status >= 400 (status 0 on a
// network error). Shared by the §3.1 signed mint path and the
// bearer-authenticated link/poll calls.
func trustDo(req *http.Request, out any) (int, error) {
	resp, err := trustHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var env trustErrEnvelope
		_ = json.Unmarshal(respBody, &env)
		return resp.StatusCode, &trustAPIError{
			URL:     req.URL.String(),
			Status:  resp.StatusCode,
			Code:    env.Error.Code,
			Message: env.Error.Message,
		}
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp.StatusCode, fmt.Errorf("trust %s: decode response: %w", req.URL.String(), err)
		}
	}
	return resp.StatusCode, nil
}

// ---------------------------------------------------------------------
// Local state
// ---------------------------------------------------------------------

// trustBinding is the agent's link to a single trust attestor. An agent
// may hold several at once (e.g. the public afauth-trust plus a private
// enterprise attestor); the consuming command picks the one a given
// service accepts.
type trustBinding struct {
	BaseURL string `json:"base_url"`
	// Iss is the attestor's issuer identifier — the JWT `iss` claim, e.g.
	// "afauth-trust". This is exactly what a service lists in
	// billing.accepted_attestors (§4.4), so it's the key we reconcile a
	// binding against. The attestor does not announce it at link time, so
	// it is learned from the first minted token (issFromJWT) and cached
	// here; empty until the first mint.
	Iss       string `json:"iss,omitempty"`
	AgentDID  string `json:"agent_did"`
	BindingID string `json:"binding_id"`
	// BindingTokenExpiresUnix is when the binding lapses if left unused.
	// The attestor slides it forward on every mint (inactivity window);
	// cacheBindingExpiry refreshes this from the mint response so it
	// tracks the live expiry rather than the link-time deadline.
	BindingTokenExpiresUnix int64 `json:"binding_token_expires_at"`
	// Verification is the strongest human-verification method the
	// attestor reported at the most recent /v1/token mint (email,
	// oauth, payment). Cached so `afauth status` can show how the agent
	// is linked without a network call; it may lag the attestor, since
	// it is only refreshed when a token is minted.
	Verification         string `json:"verification,omitempty"`
	VerificationSeenUnix int64  `json:"verification_seen_at,omitempty"`
}

// trustState is the on-disk shape of ~/.afauth/trust.json: a set of
// attestor bindings keyed (logically) by base URL. v1 files held a single
// binding inline at the top level; loadTrustState migrates them forward.
type trustState struct {
	Version  int             `json:"version"`
	Bindings []*trustBinding `json:"bindings"`
}

const trustStateVersion = 2

// newTrustState wraps zero or more bindings into a versioned state.
func newTrustState(bindings ...*trustBinding) *trustState {
	return &trustState{Version: trustStateVersion, Bindings: bindings}
}

// find returns the binding whose base URL or iss equals sel, or nil. The
// match is exact on base URL (trailing slash ignored) and on iss, so a
// user can disambiguate with whichever identifier they have at hand.
func (s *trustState) find(sel string) *trustBinding {
	sel = strings.TrimRight(sel, "/")
	for _, b := range s.Bindings {
		if strings.TrimRight(b.BaseURL, "/") == sel || (b.Iss != "" && b.Iss == sel) {
			return b
		}
	}
	return nil
}

// upsert replaces the binding for the same base URL in place, or appends a
// new one, returning the stored pointer. Re-linking an attestor refreshes
// it rather than accumulating duplicates; a previously-learned iss is
// preserved when the incoming binding doesn't carry one.
func (s *trustState) upsert(b *trustBinding) *trustBinding {
	key := strings.TrimRight(b.BaseURL, "/")
	for i, existing := range s.Bindings {
		if strings.TrimRight(existing.BaseURL, "/") == key {
			if b.Iss == "" {
				b.Iss = existing.Iss
			}
			s.Bindings[i] = b
			return b
		}
	}
	s.Bindings = append(s.Bindings, b)
	return b
}

// usable returns the bindings minted for activeDID that are neither
// orphaned (bound to a different key) nor expired — the candidates a mint
// can actually use.
func (s *trustState) usable(activeDID string) []*trustBinding {
	out := make([]*trustBinding, 0, len(s.Bindings))
	for _, b := range s.Bindings {
		if !bindingIsOrphaned(b, activeDID) && !b.expired() {
			out = append(out, b)
		}
	}
	return out
}

// expired reports whether the binding token has lapsed. A zero expiry
// (older attestor that never reported one) is treated as not-expired.
func (b *trustBinding) expired() bool {
	return b.BindingTokenExpiresUnix > 0 && time.Now().Unix() >= b.BindingTokenExpiresUnix
}

// attestorLabel names a binding for humans and error messages: its iss
// when known, else the host of its base URL.
func attestorLabel(b *trustBinding) string {
	if b.Iss != "" {
		return b.Iss
	}
	return attestorHost(b.BaseURL)
}

// attestorList renders a comma-separated list of binding labels.
func attestorList(bindings []*trustBinding) string {
	parts := make([]string, 0, len(bindings))
	for _, b := range bindings {
		parts = append(parts, attestorLabel(b))
	}
	return strings.Join(parts, ", ")
}

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
	if st.Bindings == nil {
		st.Bindings = []*trustBinding{}
	}
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

// loadTrustState reads ~/.afauth/trust.json, transparently migrating a v1
// single-binding file (binding fields inline at the top level) to the v2
// multi-binding shape. Returns os.ErrNotExist when no file is present; a
// present-but-empty file yields a state with zero bindings.
func loadTrustState() (*trustState, error) {
	path, err := trustStatePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Decode the v2 `bindings` array and the v1 inline fields at once. A v1
	// file carries no `bindings`, so its inline binding is folded in below.
	var raw struct {
		Version                 int             `json:"version"`
		Bindings                []*trustBinding `json:"bindings"`
		BaseURL                 string          `json:"base_url"`
		Iss                     string          `json:"iss"`
		AgentDID                string          `json:"agent_did"`
		BindingID               string          `json:"binding_id"`
		BindingTokenExpiresUnix int64           `json:"binding_token_expires_at"`
		Verification            string          `json:"verification"`
		VerificationSeenUnix    int64           `json:"verification_seen_at"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	st := &trustState{Version: trustStateVersion, Bindings: raw.Bindings}
	if len(st.Bindings) == 0 && (raw.BaseURL != "" || raw.BindingID != "") {
		st.Bindings = []*trustBinding{{
			BaseURL:                 raw.BaseURL,
			Iss:                     raw.Iss,
			AgentDID:                raw.AgentDID,
			BindingID:               raw.BindingID,
			BindingTokenExpiresUnix: raw.BindingTokenExpiresUnix,
			Verification:            raw.Verification,
			VerificationSeenUnix:    raw.VerificationSeenUnix,
		}}
	}
	if st.Bindings == nil {
		st.Bindings = []*trustBinding{}
	}
	return st, nil
}

// cacheVerification records the verification method returned by a
// successful /v1/token mint onto the binding, so `afauth status` can
// report how the agent is linked without a network round-trip.
// Best-effort: a persistence failure must never fail a mint that has
// already succeeded, so the error is swallowed.
func cacheVerification(st *trustState, b *trustBinding, verification string) {
	if st == nil || b == nil || verification == "" || verification == b.Verification {
		return
	}
	b.Verification = verification
	b.VerificationSeenUnix = time.Now().Unix()
	_ = saveTrustState(st)
}

// cacheBindingExpiry records the binding expiry the attestor reported at
// the most recent /v1/token mint. The attestor slides this forward on
// every mint (inactivity window), so refreshing the cached copy keeps
// `afauth status` and the signup pre-check from treating the link-time
// deadline as fixed. Throttled to ≥1h of advance so an actively-minting
// agent doesn't rewrite trust.json on every call. Best-effort: a
// persistence failure must never fail a mint that already succeeded.
func cacheBindingExpiry(st *trustState, b *trustBinding, expiresUnix int64) {
	if st == nil || b == nil || expiresUnix <= 0 || expiresUnix <= b.BindingTokenExpiresUnix+3600 {
		return
	}
	b.BindingTokenExpiresUnix = expiresUnix
	_ = saveTrustState(st)
}

// issFromJWT extracts the `iss` claim from a JWT payload WITHOUT verifying
// its signature. It's used only to learn which attestor minted a token we
// just requested — for local bookkeeping and §4.4 reconciliation — never
// as a trust decision. Returns "" when the token can't be parsed.
func issFromJWT(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Iss
}

// learnIss records the attestor's iss (decoded from a freshly minted
// token) onto the binding when newly known, persisting it so future mints
// can reconcile against §4.4 accepted_attestors before the network call.
// Best-effort: a save failure never fails the mint that already succeeded.
func learnIss(st *trustState, b *trustBinding, jwt string) {
	iss := issFromJWT(jwt)
	if iss == "" || iss == b.Iss {
		return
	}
	b.Iss = iss
	_ = saveTrustState(st)
}

// bindingIsOrphaned reports whether a binding belongs to a DIFFERENT key
// than the active one — e.g. one left behind by a key rotation or import.
// An orphaned binding MUST NOT be used to mint or send an attestation: the
// JWT would assert the old DID while requests are signed by the new key,
// so the service rejects it. A binding with no recorded agent_did
// (legacy/hand-edited) is treated as not-orphaned, matching `afauth status`.
func bindingIsOrphaned(b *trustBinding, activeDID string) bool {
	return b != nil && b.AgentDID != "" && b.AgentDID != activeDID
}

// attestorOverride resolves an explicit attestor selector: the --attestor
// flag when set, else the AFAUTH_TRUST_BASE env var (which also seeds the
// link default). Empty means "let the service's accepted_attestors, or the
// sole binding, decide".
func attestorOverride(flag string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv("AFAUTH_TRUST_BASE")
}

// selectAttestorBinding picks which linked attestor to mint from for a
// request to a service.
//
//	accepted  — the service's §4.4 billing.accepted_attestors (may be empty)
//	override  — explicit --attestor / AFAUTH_TRUST_BASE (matched by iss or base URL)
//	activeDID — the agent's current key; bindings for other keys are unusable
//
// An explicit override wins outright. Otherwise, when the service names
// accepted attestors, the usable binding whose iss is on that list is
// chosen; with no constraint, the sole usable binding is chosen. Ambiguity
// or a known mismatch returns an actionable error rather than a silent
// wrong choice.
//
// Wrinkle: a freshly-linked binding has no cached iss yet (it's learned at
// the first mint). When the only candidate is such a binding it's returned
// optimistically — the caller mints, learns the iss via learnIss, then
// re-checks against accepted before sending, so a true mismatch still
// fails locally instead of as an opaque service rejection.
func selectAttestorBinding(st *trustState, accepted []string, override, activeDID string) (*trustBinding, error) {
	if st == nil || len(st.Bindings) == 0 {
		return nil, errNotLinked()
	}
	if override != "" {
		b := st.find(override)
		if b == nil {
			return nil, fmt.Errorf("no linked attestor matches %q.\n  linked: %s\n  link it with: afauth trust link --base <url>", override, attestorList(st.Bindings))
		}
		if err := bindingUsableErr(b, activeDID); err != nil {
			return nil, err
		}
		return b, nil
	}
	usable := st.usable(activeDID)
	if len(usable) == 0 {
		return nil, unusableErr(st, activeDID)
	}
	if len(accepted) == 0 {
		// Service did not constrain attestors.
		if len(usable) == 1 {
			return usable[0], nil
		}
		return nil, ambiguousErr(usable)
	}
	var matched, unknown []*trustBinding
	for _, b := range usable {
		switch {
		case b.Iss != "" && slices.Contains(accepted, b.Iss):
			matched = append(matched, b)
		case b.Iss == "":
			unknown = append(unknown, b)
		}
	}
	switch {
	case len(matched) == 1:
		return matched[0], nil
	case len(matched) > 1:
		return nil, ambiguousErr(matched)
	case len(unknown) == 1 && len(usable) == 1:
		return unknown[0], nil // sole binding, iss not yet learned — caller re-checks post-mint
	case len(unknown) >= 1:
		return nil, ambiguousErr(unknown)
	default:
		// Every usable binding has a known iss and none is accepted (#1).
		return nil, notAcceptedErr(accepted, usable)
	}
}

func errNotLinked() error {
	return errors.New("no agent is linked.\n  run: afauth trust link")
}

// bindingUsableErr returns a targeted error when a specifically-selected
// binding can't be used by the active key, or nil when it's fine.
func bindingUsableErr(b *trustBinding, activeDID string) error {
	if bindingIsOrphaned(b, activeDID) {
		return fmt.Errorf("trust binding for %s is for a different key (%s) than this agent (%s).\n  run: afauth trust link", attestorLabel(b), b.AgentDID, activeDID)
	}
	if b.expired() {
		return fmt.Errorf("trust binding for %s expired.\n  run: afauth trust link", attestorLabel(b))
	}
	return nil
}

// unusableErr explains why no binding is usable when at least one exists,
// preferring expiry guidance (matching the historical precedence) then
// orphaned-key guidance.
func unusableErr(st *trustState, activeDID string) error {
	for _, b := range st.Bindings {
		if b.expired() {
			return errors.New("trust binding expired.\n  run: afauth trust link\n  then re-run this command")
		}
	}
	for _, b := range st.Bindings {
		if bindingIsOrphaned(b, activeDID) {
			return fmt.Errorf("trust binding is for a different key (%s) than this agent (%s).\n  run: afauth trust link\n  then re-run this command", b.AgentDID, activeDID)
		}
	}
	return errNotLinked()
}

// ambiguousErr asks the user to disambiguate among several applicable
// bindings with --attestor.
func ambiguousErr(candidates []*trustBinding) error {
	return fmt.Errorf("multiple linked attestors could apply [%s]; choose one with --attestor <iss-or-url>", attestorList(candidates))
}

// notAcceptedErr is the §4.4 reconciliation failure: the agent is linked,
// but to attestor(s) this service does not accept. Surfaced locally before
// any request so the user gets a fix rather than an opaque rejection.
func notAcceptedErr(accepted []string, linked []*trustBinding) error {
	return fmt.Errorf(
		"this service accepts attestations from [%s], but this agent is linked to [%s].\n  re-link to an accepted attestor: afauth trust link --base <url>",
		strings.Join(accepted, ", "), attestorList(linked))
}

// warnIfBindingStale prints a non-fatal notice for each local binding that
// no longer matches the active key (after a key change), so the operator
// knows to re-link. Deliberately NON-destructive: it does not clear the
// binding, because the binding for the previous agent key remains live at
// the attestor (~90 days) until revoked THERE — anyone still holding that
// key can mint with it, and clearing the local pointer would only hide
// that exposure.
func warnIfBindingStale(w io.Writer, activeDID string) {
	st, err := loadTrustState()
	if err != nil {
		return // no binding (or unreadable) — nothing to warn about
	}
	for _, b := range st.Bindings {
		if bindingIsOrphaned(b, activeDID) {
			fmt.Fprintf(w, "⚠ trust binding for %s is for a previous key (%s); re-link with `afauth trust link`.\n", attestorLabel(b), b.AgentDID)
			fmt.Fprintln(w, "  the old binding stays live at the attestor (~90d) — revoke it at trust.afauth.org/account")
		}
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
