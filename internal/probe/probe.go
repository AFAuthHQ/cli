// Package probe runs the AFAuth Protocol v0.1 conformance suite
// against a live URL. Each probe is a small, deterministic check that
// asserts one §-level invariant — discovery shape, signature checks,
// replay protection, owner-invitation behaviour, and so on.
//
// The runner uses a FRESH did:key per Run so probes start against a
// virgin UNCLAIMED account; this keeps the probe idempotent and safe
// to run repeatedly against the same service.
//
// Output goes to either a human-readable stream (one line per probe)
// or JSON; the binary's exit code is 0 only when every executed probe
// passes.
package probe

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/afauthhq/cli/internal/client"
	"github.com/afauthhq/cli/internal/discovery"
	"github.com/afauthhq/cli/internal/identity"
	"github.com/afauthhq/cli/internal/proto"
	"github.com/afauthhq/cli/internal/signing"
)

// Status is the outcome of one probe.
type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

// Probe is one check's name + outcome + supporting detail.
type Probe struct {
	Name     string        `json:"name"`
	Section  string        `json:"section"`
	Status   Status        `json:"status"`
	Detail   string        `json:"detail,omitempty"`
	Duration time.Duration `json:"duration_ms"`
}

// MarshalJSON formats Duration as integer milliseconds for JSON output.
func (p Probe) MarshalJSON() ([]byte, error) {
	type alias Probe
	out := struct {
		alias
		DurationMS int64 `json:"duration_ms"`
	}{alias(p), p.Duration.Milliseconds()}
	out.alias.Duration = 0
	return json.Marshal(out)
}

// Result is the full set of probe outcomes for one Run.
type Result struct {
	BaseURL string  `json:"base_url"`
	Probes  []Probe `json:"probes"`
}

// Failed reports whether any probe in Result has StatusFail.
func (r *Result) Failed() bool {
	for _, p := range r.Probes {
		if p.Status == StatusFail {
			return true
		}
	}
	return false
}

// Counts returns the (pass, fail, skip) tallies for Result.
func (r *Result) Counts() (pass, fail, skip int) {
	for _, p := range r.Probes {
		switch p.Status {
		case StatusPass:
			pass++
		case StatusFail:
			fail++
		case StatusSkip:
			skip++
		}
	}
	return
}

// Runner carries the per-Run state — the fresh agent identity, the
// HTTP client, and the discovery document fetched on the first probe.
type Runner struct {
	HTTP    *http.Client
	probes  []Probe
	agent   *identity.Identity
	client  *client.Client
	doc     *discovery.Document
	baseURL string
}

// Run executes every probe in order against baseURL. The returned
// Result contains the per-probe outcomes; the caller decides how to
// render and what exit code to use.
func Run(ctx context.Context, baseURL string, hc *http.Client) (*Result, error) {
	r := &Runner{HTTP: hc, baseURL: strings.TrimRight(baseURL, "/")}
	if r.HTTP == nil {
		r.HTTP = &http.Client{Timeout: 15 * time.Second}
	}

	agent, err := identity.Generate()
	if err != nil {
		return nil, fmt.Errorf("probe: generate probe identity: %w", err)
	}
	r.agent = agent
	r.client = client.New(agent)
	r.client.HTTP = r.HTTP

	for _, step := range r.steps() {
		t0 := time.Now()
		p := step(ctx)
		p.Duration = time.Since(t0)
		r.probes = append(r.probes, p)
	}
	return &Result{BaseURL: r.baseURL, Probes: r.probes}, nil
}

// steps returns the ordered probe functions for one Run. Earlier
// probes set up state used by later probes (discovery → signup →
// signature checks → invitation).
func (r *Runner) steps() []func(ctx context.Context) Probe {
	return []func(ctx context.Context) Probe{
		r.probeDiscovery,
		r.probeImplicitSignup,
		r.probeExpiredSignature,
		r.probeReplayedNonce,
		r.probeInvalidSignature,
		r.probeOwnerInvitation,
		r.probeUnsupportedRecipient,
	}
}

func pass(name, section, detail string) Probe {
	return Probe{Name: name, Section: section, Status: StatusPass, Detail: detail}
}
func fail(name, section, detail string) Probe {
	return Probe{Name: name, Section: section, Status: StatusFail, Detail: detail}
}
func skip(name, section, detail string) Probe {
	return Probe{Name: name, Section: section, Status: StatusSkip, Detail: detail}
}

func (r *Runner) probeDiscovery(ctx context.Context) Probe {
	doc, err := discovery.Fetch(ctx, r.baseURL, r.HTTP)
	if err != nil {
		return fail("discovery", "§4.3, §4.5", err.Error())
	}
	r.doc = doc
	return pass("discovery", "§4.3, §4.5", fmt.Sprintf("service_did=%s recipient_types=%v", doc.ServiceDID, doc.RecipientTypeOrDefault()))
}

func (r *Runner) probeImplicitSignup(ctx context.Context) Probe {
	if r.doc == nil {
		return skip("implicit_signup", "§6.3", "discovery failed")
	}
	if r.doc.Billing != nil && r.doc.Billing.UnclaimedMode == "attested_only" {
		return skip("implicit_signup", "§6.3", "service is attested_only; cannot probe without an attestation token")
	}
	url := r.accountsMeURL()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := r.client.Do(ctx, req)
	if err != nil {
		return fail("implicit_signup", "§6.3", err.Error())
	}
	if resp.HTTPResponse.StatusCode != http.StatusOK {
		if resp.IsAFAuthError() {
			return fail("implicit_signup", "§6.3",
				fmt.Sprintf("expected 200; got %d %s: %s", resp.HTTPResponse.StatusCode, resp.Err.Code, resp.Err.Message))
		}
		return fail("implicit_signup", "§6.3", fmt.Sprintf("expected 200; got %d", resp.HTTPResponse.StatusCode))
	}
	var body struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return fail("implicit_signup", "§6.5", fmt.Sprintf("body did not parse: %v", err))
	}
	if body.State != "UNCLAIMED" {
		return fail("implicit_signup", "§6.3",
			fmt.Sprintf("expected fresh account state=UNCLAIMED; got %q", body.State))
	}
	return pass("implicit_signup", "§6.3", "fresh signed request created UNCLAIMED account")
}

func (r *Runner) probeExpiredSignature(ctx context.Context) Probe {
	if r.doc == nil {
		return skip("expired_signature", "§5.6", "discovery failed")
	}
	url := r.accountsMeURL()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	// Signature created 600s in the past, expired 540s ago.
	did, _ := r.agent.DID()
	past := time.Now().Unix() - 600
	if err := signing.Sign(req, did, r.agent.Seed, &signing.SignOptions{
		Created:   past,
		ExpiresIn: 60,
		Nonce:     "deadbeefdeadbeef",
	}); err != nil {
		return fail("expired_signature", "§5.6", "failed to construct expired signature: "+err.Error())
	}
	resp, err := r.HTTP.Do(req.WithContext(ctx))
	if err != nil {
		return fail("expired_signature", "§5.6", err.Error())
	}
	defer resp.Body.Close()
	return assertAFAuthCode(resp, "expired_signature", proto.ErrExpiredSignature, "§5.6", []int{http.StatusUnauthorized})
}

func (r *Runner) probeReplayedNonce(ctx context.Context) Probe {
	if r.doc == nil {
		return skip("replayed_nonce", "§5.6", "discovery failed")
	}
	url := r.accountsMeURL()
	did, _ := r.agent.DID()

	// Send the same canonical request twice. The second must fail.
	build := func() *http.Request {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		_ = signing.Sign(req, did, r.agent.Seed, &signing.SignOptions{
			Nonce:     "feedface0123abcd",
			ExpiresIn: 60,
		})
		return req
	}

	first := build()
	resp1, err := r.HTTP.Do(first.WithContext(ctx))
	if err != nil {
		return fail("replayed_nonce", "§5.6", "first send: "+err.Error())
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		return fail("replayed_nonce", "§5.6",
			fmt.Sprintf("first send must succeed for the replay check; got %d", resp1.StatusCode))
	}

	// Replay the same nonce: the service must reject.
	second := build()
	resp2, err := r.HTTP.Do(second.WithContext(ctx))
	if err != nil {
		return fail("replayed_nonce", "§5.6", "second send: "+err.Error())
	}
	defer resp2.Body.Close()
	return assertAFAuthCode(resp2, "replayed_nonce", proto.ErrReplayedNonce, "§5.6", []int{http.StatusUnauthorized})
}

func (r *Runner) probeInvalidSignature(ctx context.Context) Probe {
	if r.doc == nil {
		return skip("invalid_signature", "§5.5, §11.3", "discovery failed")
	}
	url := r.accountsMeURL()
	did, _ := r.agent.DID()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if err := signing.Sign(req, did, r.agent.Seed, &signing.SignOptions{ExpiresIn: 60}); err != nil {
		return fail("invalid_signature", "§5.5", err.Error())
	}
	// Replace the signature with one made of zero bytes — still valid base64,
	// still the right size, but cryptographically invalid.
	garbage := make([]byte, ed25519.SignatureSize)
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(garbage)+":")
	resp, err := r.HTTP.Do(req.WithContext(ctx))
	if err != nil {
		return fail("invalid_signature", "§5.5", err.Error())
	}
	defer resp.Body.Close()
	return assertAFAuthCode(resp, "invalid_signature", proto.ErrInvalidSignature, "§5.5, §11.3", []int{http.StatusUnauthorized})
}

func (r *Runner) probeOwnerInvitation(ctx context.Context) Probe {
	if r.doc == nil {
		return skip("owner_invitation", "§7.2", "discovery failed")
	}
	url := endpointJoin(r.baseURL, r.doc.Endpoints.OwnerInvitation)
	body := map[string]any{
		"recipient": map[string]any{"type": "email", "value": "probe@example.com"},
	}
	resp, err := r.client.PostJSON(ctx, url, body)
	if err != nil {
		return fail("owner_invitation", "§7.2", err.Error())
	}
	if resp.IsAFAuthError() {
		return fail("owner_invitation", "§7.2",
			fmt.Sprintf("expected 202; got %d %s: %s", resp.HTTPResponse.StatusCode, resp.Err.Code, resp.Err.Message))
	}
	if resp.HTTPResponse.StatusCode != http.StatusAccepted {
		return fail("owner_invitation", "§7.2", fmt.Sprintf("expected 202 Accepted; got %d", resp.HTTPResponse.StatusCode))
	}
	var out struct {
		InvitationID string `json:"invitation_id"`
		State        string `json:"state"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return fail("owner_invitation", "§7.2", "body did not parse: "+err.Error())
	}
	if out.State != "INVITED" || out.InvitationID == "" {
		return fail("owner_invitation", "§7.2",
			fmt.Sprintf("expected state=INVITED, non-empty invitation_id; got state=%q id=%q", out.State, out.InvitationID))
	}
	return pass("owner_invitation", "§7.2", "service issued an INVITED-state invitation")
}

func (r *Runner) probeUnsupportedRecipient(ctx context.Context) Probe {
	if r.doc == nil {
		return skip("unsupported_recipient_type", "§7.2, §7.7", "discovery failed")
	}
	declared := r.doc.RecipientTypeOrDefault()
	// Pick a type the service didn't declare.
	missing := ""
	for _, candidate := range []string{"phone", "oidc", "did"} {
		if !containsString(declared, candidate) {
			missing = candidate
			break
		}
	}
	if missing == "" {
		return skip("unsupported_recipient_type", "§7.2, §7.7", "service declared all four recipient types; nothing to probe")
	}
	url := endpointJoin(r.baseURL, r.doc.Endpoints.OwnerInvitation)
	body := map[string]any{
		"recipient": map[string]any{"type": missing, "value": "anything"},
	}
	resp, err := r.client.PostJSON(ctx, url, body)
	if err != nil {
		return fail("unsupported_recipient_type", "§7.2, §7.7", err.Error())
	}
	defer resp.HTTPResponse.Body.Close()
	if resp.IsAFAuthError() && resp.Err.Code == proto.ErrUnsupportedRecipientType {
		return pass("unsupported_recipient_type", "§7.2, §7.7",
			fmt.Sprintf("service rejected %q with %s as required", missing, resp.Err.Code))
	}
	if resp.IsAFAuthError() {
		return fail("unsupported_recipient_type", "§7.2, §7.7",
			fmt.Sprintf("expected unsupported_recipient_type; got %s (%d)", resp.Err.Code, resp.HTTPResponse.StatusCode))
	}
	return fail("unsupported_recipient_type", "§7.2, §7.7",
		fmt.Sprintf("expected 400 + unsupported_recipient_type; got %d", resp.HTTPResponse.StatusCode))
}

func (r *Runner) accountsMeURL() string {
	return strings.TrimRight(endpointJoin(r.baseURL, r.doc.Endpoints.Accounts), "/") + "/me"
}

func endpointJoin(baseURL, endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	return strings.TrimRight(baseURL, "/") + endpoint
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// assertAFAuthCode parses an §11.1 envelope from resp and reports
// PASS if the code is wantCode AND the status is in wantStatuses;
// otherwise FAIL with a descriptive message.
func assertAFAuthCode(resp *http.Response, probeName string, wantCode proto.ErrorCode, section string, wantStatuses []int) Probe {
	// Drain & parse body.
	bodyBytes, _ := readAll(resp.Body)
	parsed := parseEnvelopeFromBody(resp.Header.Get("Content-Type"), bodyBytes)
	if parsed == nil {
		return fail(string(probeName), section,
			fmt.Sprintf("expected §11.1 envelope; got %d non-JSON body", resp.StatusCode))
	}
	if parsed.Code != wantCode {
		return fail(string(probeName), section,
			fmt.Sprintf("expected code=%s; got %s (%d): %s", wantCode, parsed.Code, resp.StatusCode, parsed.Message))
	}
	if !containsInt(wantStatuses, resp.StatusCode) {
		return fail(string(probeName), section,
			fmt.Sprintf("code=%s ok but status %d not in expected set %v", parsed.Code, resp.StatusCode, wantStatuses))
	}
	return pass(string(probeName), section,
		fmt.Sprintf("service correctly returned %s (%d)", parsed.Code, resp.StatusCode))
}

// parseEnvelopeFromBody is a local copy of the parser in
// internal/client; duplicated to avoid exposing the package's internals.
func parseEnvelopeFromBody(contentType string, body []byte) *proto.Error {
	ct := strings.TrimSpace(strings.ToLower(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct != "application/json" {
		return nil
	}
	var env struct {
		Error *struct {
			Code    string          `json:"code"`
			Message string          `json:"message"`
			Details json.RawMessage `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Error == nil {
		return nil
	}
	return &proto.Error{Code: proto.ErrorCode(env.Error.Code), Message: env.Error.Message}
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}

func readAll(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil body")
	}
	const chunk = 4 * 1024
	var out []byte
	buf := make([]byte, chunk)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}
