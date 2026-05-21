package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
		timeoutSec   int
	)
	cmd := &cobra.Command{
		Use:   "signup <service-url>",
		Short: "Create an account on an AFAuth-enabled service",
		Long: `Creates an AFAuth account on the named service.

By default uses implicit signup (§6.3) — a signed GET of /accounts/me
auto-creates the account in UNCLAIMED state. If the service requires
explicit signup, retries with POST /accounts.

  afauth signup https://api.example.com
  afauth signup --explicit --terms-version 2026-05-01 https://api.example.com
  afauth signup --attest <jwt> https://api.example.com  # for attested_only services`,
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
			did, _ := id.DID()
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
	cmd.Flags().StringVar(&attestation, "attest", "", "AFAuth-Attestation JWT (for attested_only services)")
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
