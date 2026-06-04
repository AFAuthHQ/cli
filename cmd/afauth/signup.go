package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/afauthhq/cli/internal/accounts"
	"github.com/afauthhq/cli/internal/client"
	"github.com/afauthhq/cli/internal/discovery"
	"github.com/afauthhq/cli/internal/identity"
	"github.com/spf13/cobra"
)

func newSignupCmd() *cobra.Command {
	var (
		keyPath      string
		explicit     bool
		termsVersion string
		attestation  string
		attestor     string
		timeoutSec   int
	)
	cmd := &cobra.Command{
		Use:   "signup <service-url>",
		Short: "Create an account on an AFAuth-enabled service",
		Long: `Creates an AFAuth account on the named service.

By default uses implicit signup (§6.3) — a signed GET of /accounts/me
auto-creates the account in UNCLAIMED state. If the service requires
explicit signup, retries with POST /accounts.

When the service's discovery doc declares §9.2 attested_only mode and
--attest is NOT set, signup automatically mints an attestation JWT
from the cached trust binding (audience-bound to the service's DID).
If no binding exists or the binding has expired, signup exits with
instructions to run "afauth trust link" first.

  afauth signup https://api.example.com
  afauth signup --explicit --terms-version 2026-05-01 https://api.example.com
  afauth signup --attest <jwt> https://api.example.com  # bypass auto-mint`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutSec)*time.Second)
			defer cancel()

			serviceURL := args[0]
			id, err := loadIdentity(keyPath)
			if err != nil {
				return err
			}

			doc, err := discovery.Fetch(ctx, serviceURL, nil)
			if err != nil {
				return fmt.Errorf("signup: discovery: %w", err)
			}
			did, err := id.DID()
			if err != nil {
				return err
			}

			// Discovery-driven attestation: §9.2 attested_only services
			// MUST receive a valid AFAuth-Attestation header. When the
			// caller didn't pass --attest, the CLI auto-mints one from
			// the cached trust binding. If the service doesn't require
			// attestation, this branch is skipped (existing behaviour).
			if attestation == "" && requiresAttestation(doc) {
				attestation, err = autoAttest(ctx, doc, serviceURL, did, id.Seed, attestorOverride(attestor), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
			}

			c := client.New(id)
			ledgerPath, err := accounts.DefaultPath()
			if err != nil {
				return err
			}
			ledger, err := accounts.Load(ledgerPath)
			if err != nil {
				return err
			}

			var (
				accountState string
			)

			if explicit {
				accountState, err = explicitSignup(ctx, c, serviceURL, doc, termsVersion, attestation)
			} else {
				accountState, err = implicitSignup(ctx, c, serviceURL, doc, attestation)
			}
			if err != nil {
				return err
			}
			ledger.Upsert(serviceURL, func(e *accounts.Entry) {
				e.AgentDID = did
				e.State = accountState
			})
			if err := ledger.Save(ledgerPath); err != nil {
				return fmt.Errorf("signup: save ledger: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "signed up to %s as %s (%s)\n", serviceURL, did, accountState)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	cmd.Flags().BoolVar(&explicit, "explicit", false, "use the §6.4 POST /accounts flow instead of implicit signup")
	cmd.Flags().StringVar(&termsVersion, "terms-version", "", "terms version to send with explicit signup")
	cmd.Flags().StringVar(&attestation, "attest", "", "AFAuth-Attestation JWT (overrides the auto-mint from `afauth trust link`)")
	cmd.Flags().StringVar(&attestor, "attestor", "", "which linked attestor to mint from (iss or base URL); default: the one this service accepts")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 30, "request timeout in seconds")
	return cmd
}

func loadIdentity(keyPath string) (*identity.Identity, error) {
	if keyPath == "" {
		p, err := identity.DefaultPath()
		if err != nil {
			return nil, err
		}
		keyPath = p
	}
	return identity.Load(keyPath)
}

func implicitSignup(ctx context.Context, c *client.Client, baseURL string, doc *discovery.Document, attestation string) (string, error) {
	url := endpointURL(baseURL, doc.Endpoints.Accounts) + "/me"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if attestation != "" {
		req.Header.Set("AFAuth-Attestation", attestation)
	}
	resp, err := c.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.HTTPResponse.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("signup: service requires explicit signup (got 404); retry with --explicit")
	}
	if resp.IsAFAuthError() {
		return "", fmt.Errorf("signup: %s (%d): %s", resp.Err.Code, resp.Err.HTTPStatus, resp.Err.Message)
	}
	if resp.HTTPResponse.StatusCode >= 300 {
		return "", fmt.Errorf("signup: GET /accounts/me returned %d", resp.HTTPResponse.StatusCode)
	}
	state, _ := readAccountState(resp.Body)
	return state, nil
}

func explicitSignup(ctx context.Context, c *client.Client, baseURL string, doc *discovery.Document, termsVersion, attestation string) (string, error) {
	url := endpointURL(baseURL, doc.Endpoints.Accounts)
	body := map[string]any{}
	if termsVersion != "" {
		body["terms_version"] = termsVersion
	}
	if attestation != "" {
		body["attestation"] = attestation
	}
	resp, err := c.PostJSON(ctx, url, body)
	if err != nil {
		return "", err
	}
	if resp.IsAFAuthError() {
		return "", fmt.Errorf("signup: %s (%d): %s", resp.Err.Code, resp.Err.HTTPStatus, resp.Err.Message)
	}
	if resp.HTTPResponse.StatusCode >= 300 {
		return "", fmt.Errorf("signup: POST /accounts returned %d", resp.HTTPResponse.StatusCode)
	}
	state, _ := readAccountState(resp.Body)
	return state, nil
}

func readAccountState(body []byte) (string, error) {
	var out struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	return out.State, nil
}

// requiresAttestation reports whether the service's discovery doc
// declares §9.2 attested_only mode. Services in other modes (open,
// denied, or unset) do not require an AFAuth-Attestation header on
// implicit signup.
func requiresAttestation(doc *discovery.Document) bool {
	return doc != nil && doc.Billing != nil && doc.Billing.UnclaimedMode == "attested_only"
}

// autoAttest mints a fresh §10 attestation JWT from a linked trust
// binding, audience-bound to doc.ServiceDID, and returns it.
//
// It picks the binding the service accepts: when the discovery doc's
// §4.4 billing.accepted_attestors names attestors, the binding whose iss
// is on that list is used; override forces a specific one. When the
// chosen attestor isn't accepted, autoAttest fails with an actionable
// error BEFORE sending anything to the service (#1), rather than letting
// the service reject an unrecognized token. Returns a friendly error
// pointing at `afauth trust link` when no usable binding exists.
func autoAttest(ctx context.Context, doc *discovery.Document, serviceURL, activeDID string, seed []byte, override string, stderr interface{ Write([]byte) (int, error) }) (string, error) {
	// Confused-deputy guard (audit #4): the attestation is audience-bound
	// to doc.ServiceDID, which we read from a document served by
	// serviceURL's host. Before minting, require a did:web service DID to
	// be anchored at that same host — otherwise a hostile host could
	// advertise another service's DID and harvest a token replayable
	// against it. A non-did:web (e.g. did:key) DID has no DNS anchor; warn.
	originHost := serviceURL
	if u, perr := url.Parse(serviceURL); perr == nil && u.Host != "" {
		originHost = u.Host
	}
	if err := discovery.VerifyServiceDIDOrigin(doc.ServiceDID, originHost); err != nil {
		return "", err
	}
	if !discovery.IsDIDWeb(doc.ServiceDID) {
		fmt.Fprintf(stderr, "warning: service_did %s is not did:web — it has no DNS/TLS anchor; minting an attestation bound to it on the trust of %s\n", doc.ServiceDID, originHost)
	}

	st, err := loadTrustState()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errNotLinkedForService()
		}
		return "", fmt.Errorf("signup: load trust binding: %w", err)
	}
	if len(st.Bindings) == 0 {
		return "", errNotLinkedForService()
	}

	var accepted []string
	if doc.Billing != nil {
		accepted = doc.Billing.AcceptedAttestors
	}
	b, err := selectAttestorBinding(st, accepted, override, activeDID)
	if err != nil {
		return "", err
	}
	tok, err := trustToken(ctx, b.BaseURL, activeDID, seed, doc.ServiceDID)
	if err != nil {
		return "", fmt.Errorf("mint attestation: %w", explainTrustError(err))
	}
	// Learn the attestor's iss from the freshly minted token (#5), then —
	// now that it's known — reconcile against the service's accepted list
	// before sending (#1). This catches the optimistic single-binding case
	// where the iss wasn't cached at selection time, turning what would be
	// an opaque server rejection into a local, actionable error.
	learnIss(st, b, tok.JWT)
	if len(accepted) > 0 && b.Iss != "" && !slices.Contains(accepted, b.Iss) {
		return "", notAcceptedErr(accepted, []*trustBinding{b})
	}
	cacheVerification(st, b, tok.Verification)
	cacheBindingExpiry(st, b, tok.BindingExpiresUnix)
	fmt.Fprintf(stderr, "attested via %s\n", attestorLabel(b))
	return tok.JWT, nil
}

// errNotLinkedForService is the not-linked error in the signup/call
// context: a service requires an attestation but the agent has no binding.
func errNotLinkedForService() error {
	return fmt.Errorf("service requires a trust attestation, but no agent is linked.\n  run: afauth trust link\n  then re-run this command")
}
