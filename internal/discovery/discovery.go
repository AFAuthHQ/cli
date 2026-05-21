// Package discovery fetches and validates the AFAuth /.well-known/afauth
// document per §4.1–§4.5 of the protocol spec.
//
// Validation is strict on required fields and the §4.5 agent
// obligation that the service advertise ed25519. Optional fields
// are decoded when present and ignored when absent; unknown fields
// at every level are accepted per the §4.2 forward-compatibility rule
// (Go's json.Unmarshal already discards them when decoding into a
// struct).
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Document is the v0.1 /.well-known/afauth shape (§4.3, §4.4).
type Document struct {
	AFAuthVersion       string    `json:"afauth_version"`
	ServiceDID          string    `json:"service_did"`
	Endpoints           Endpoints `json:"endpoints"`
	SignatureAlgorithms []string  `json:"signature_algorithms"`

	// Optional fields (§4.4).
	Features       []string `json:"features,omitempty"`
	RecipientTypes []string `json:"recipient_types,omitempty"`
	Limits         *Limits  `json:"limits,omitempty"`
	Billing        *Billing `json:"billing,omitempty"`
}

// Endpoints carries the URLs from §4.3.
type Endpoints struct {
	Accounts        string `json:"accounts"`
	OwnerInvitation string `json:"owner_invitation"`
	ClaimPage       string `json:"claim_page"`
	ClaimCompletion string `json:"claim_completion"`
	KeyRotation     string `json:"key_rotation,omitempty"`
}

// Limits carries §4.4 service-declared limits. Optional.
type Limits struct {
	UnclaimedTTLSeconds        int `json:"unclaimed_ttl_seconds,omitempty"`
	UnclaimedRateLimitPerHour  int `json:"unclaimed_rate_limit_per_hour,omitempty"`
}

// Billing carries §4.4 / §9 billing declarations. Optional.
type Billing struct {
	UnclaimedMode     string   `json:"unclaimed_mode,omitempty"`
	AcceptedAttestors []string `json:"accepted_attestors,omitempty"`
}

// RecipientTypeOrDefault returns the service's declared recipient
// types, applying the §4.4 default of ["email"] when the field is
// absent.
func (d *Document) RecipientTypeOrDefault() []string {
	if len(d.RecipientTypes) == 0 {
		return []string{"email"}
	}
	return append([]string(nil), d.RecipientTypes...)
}

// Parse decodes the raw bytes into a Document AND enforces the §4.3
// required-field rules + the §4.5 agent obligation that the service
// advertise ed25519. Use this for offline validation (e.g., over the
// committed C.3 vectors); for live fetches, see Fetch.
func Parse(raw []byte) (*Document, error) {
	if len(raw) == 0 {
		return nil, errors.New("discovery: empty document")
	}
	// Defensive shape check before targeted decode: the C.3 vectors
	// include a "signature_algorithms must be an array" case where the
	// field is a string. We want to surface that as a validation error
	// rather than a json type-mismatch with a less informative message.
	var raw1 map[string]any
	if err := json.Unmarshal(raw, &raw1); err != nil {
		return nil, fmt.Errorf("discovery: malformed JSON: %w", err)
	}

	if v, ok := raw1["signature_algorithms"]; ok {
		if _, isArr := v.([]any); !isArr {
			return nil, errors.New("discovery: signature_algorithms must be an array")
		}
	}

	var d Document
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("discovery: parse: %w", err)
	}
	if err := validate(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

func validate(d *Document) error {
	if d.AFAuthVersion != "0.1" {
		return fmt.Errorf("discovery: unsupported afauth_version %q (this build speaks 0.1)", d.AFAuthVersion)
	}
	if d.ServiceDID == "" {
		return errors.New("discovery: missing required field service_did")
	}
	if d.Endpoints.Accounts == "" {
		return errors.New("discovery: missing required endpoints.accounts")
	}
	if d.Endpoints.OwnerInvitation == "" {
		return errors.New("discovery: missing required endpoints.owner_invitation")
	}
	if d.Endpoints.ClaimPage == "" {
		return errors.New("discovery: missing required endpoints.claim_page")
	}
	if d.Endpoints.ClaimCompletion == "" {
		return errors.New("discovery: missing required endpoints.claim_completion")
	}
	if len(d.SignatureAlgorithms) == 0 {
		return errors.New("discovery: signature_algorithms must be an array")
	}
	hasEd25519 := false
	for _, a := range d.SignatureAlgorithms {
		if a == "ed25519" {
			hasEd25519 = true
			break
		}
	}
	if !hasEd25519 {
		// §4.5: agents MUST honour signature_algorithms; v0.1 requires ed25519.
		return errors.New("discovery: service does not advertise ed25519 (v0.1 requires it)")
	}
	return nil
}

// Fetch performs an unsigned GET of /.well-known/afauth against baseURL,
// validates the response, and returns the parsed document.
//
// baseURL MAY be the service's origin (e.g. "https://api.example.com")
// or an explicit URL ending in /.well-known/afauth; Fetch handles both.
func Fetch(ctx context.Context, baseURL string, hc *http.Client) (*Document, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	u := strings.TrimRight(baseURL, "/")
	if !strings.HasSuffix(u, "/.well-known/afauth") {
		u = u + "/.well-known/afauth"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("discovery: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: GET %s: HTTP %d", u, resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !isJSONContentType(ct) {
		return nil, fmt.Errorf("discovery: GET %s: content-type %q is not application/json", u, ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("discovery: read body: %w", err)
	}
	return Parse(body)
}

func isJSONContentType(ct string) bool {
	ct = strings.TrimSpace(strings.ToLower(ct))
	if ct == "" {
		return false
	}
	semi := strings.IndexByte(ct, ';')
	if semi >= 0 {
		ct = strings.TrimSpace(ct[:semi])
	}
	return ct == "application/json"
}
