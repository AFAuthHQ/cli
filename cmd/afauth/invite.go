package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/afauthhq/cli/internal/client"
	"github.com/afauthhq/cli/internal/discovery"
	"github.com/afauthhq/cli/internal/recipient"
	"github.com/spf13/cobra"
)

func newInviteCmd() *cobra.Command {
	var (
		serviceURL  string
		typeFlag    string
		valueFlag   string
		issuer      string
		sub         string
		redirectURL string
		keyPath     string
		timeoutSec  int
	)
	cmd := &cobra.Command{
		Use:   "invite [recipient]",
		Short: "Invite a human to claim ownership of an account (§7.2)",
		Long: `Sends an owner invitation to the agent's account on --service.

The recipient may be supplied positionally:

  afauth invite alice@example.com --service https://api.example.com
  afauth invite phone:+14155550173 --service ...
  afauth invite did:key:z6Mk... --service ...

Or with explicit flags (required for oidc):

  afauth invite --type oidc --issuer https://accounts.google.com --sub 12345 \
                --service https://api.example.com

The recipient is normalised per §7.7 before sending.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if serviceURL == "" {
				return errors.New("invite: --service is required")
			}
			r, err := resolveRecipient(args, typeFlag, valueFlag, issuer, sub)
			if err != nil {
				return err
			}
			r, err = recipient.Normalise(r)
			if err != nil {
				return fmt.Errorf("invite: recipient: %w", err)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutSec)*time.Second)
			defer cancel()

			id, err := loadIdentity(keyPath)
			if err != nil {
				return err
			}
			doc, err := discovery.Fetch(ctx, serviceURL, nil)
			if err != nil {
				return fmt.Errorf("invite: discovery: %w", err)
			}

			// §4.4: services MUST declare supported recipient types; agents
			// MUST choose from that list.
			declared := doc.RecipientTypeOrDefault()
			if !containsString(declared, string(r.Type)) {
				return fmt.Errorf("invite: service does not declare support for recipient type %q (declared: %v)", r.Type, declared)
			}

			c := client.New(id)
			body := map[string]any{"recipient": r}
			if redirectURL != "" {
				body["redirect_url"] = redirectURL
			}
			url := endpointURL(serviceURL, doc.Endpoints.OwnerInvitation)
			resp, err := c.PostJSON(ctx, url, body)
			if err != nil {
				return err
			}
			if resp.IsAFAuthError() {
				return fmt.Errorf("invite: %s (%d): %s", resp.Err.Code, resp.Err.HTTPStatus, resp.Err.Message)
			}
			if resp.HTTPResponse.StatusCode >= 300 {
				return fmt.Errorf("invite: %s returned %d: %s", url, resp.HTTPResponse.StatusCode, string(resp.Body))
			}
			var out struct {
				InvitationID string `json:"invitation_id"`
				ExpiresAt    string `json:"expires_at"`
				State        string `json:"state"`
			}
			_ = json.Unmarshal(resp.Body, &out)
			fmt.Fprintf(cmd.OutOrStdout(), "invitation %s (state=%s, expires=%s)\n", out.InvitationID, out.State, out.ExpiresAt)
			return nil
		},
	}
	cmd.Flags().StringVar(&serviceURL, "service", "", "AFAuth service URL (required)")
	cmd.Flags().StringVar(&typeFlag, "type", "", "recipient type override (email|phone|oidc|did)")
	cmd.Flags().StringVar(&valueFlag, "value", "", "recipient value (paired with --type)")
	cmd.Flags().StringVar(&issuer, "issuer", "", "OIDC issuer URL (--type oidc)")
	cmd.Flags().StringVar(&sub, "sub", "", "OIDC subject identifier (--type oidc)")
	cmd.Flags().StringVar(&redirectURL, "redirect-url", "", "post-claim redirect URL (must match service allow-list)")
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 30, "request timeout in seconds")
	return cmd
}

func resolveRecipient(args []string, typeFlag, valueFlag, issuer, sub string) (recipient.Recipient, error) {
	if typeFlag != "" {
		switch recipient.Type(typeFlag) {
		case recipient.TypeOIDC:
			if issuer == "" || sub == "" {
				return recipient.Recipient{}, errors.New("invite: --type oidc requires --issuer and --sub")
			}
			return recipient.Recipient{
				Type:  recipient.TypeOIDC,
				Value: recipient.OIDCValue{Issuer: issuer, Sub: sub},
			}, nil
		case recipient.TypeEmail, recipient.TypePhone, recipient.TypeDID:
			if valueFlag == "" {
				return recipient.Recipient{}, fmt.Errorf("invite: --type %s requires --value", typeFlag)
			}
			return recipient.Recipient{Type: recipient.Type(typeFlag), Value: valueFlag}, nil
		default:
			return recipient.Recipient{}, fmt.Errorf("invite: unknown --type %q", typeFlag)
		}
	}
	if len(args) == 1 {
		return recipient.Parse(args[0])
	}
	return recipient.Recipient{}, errors.New("invite: provide a recipient as positional arg or use --type/--value")
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// endpointURL joins a base URL with an endpoint path from discovery.
// The path MAY be absolute (e.g. "https://claim.example.com") or
// relative (e.g. "/afauth/v1/accounts").
func endpointURL(baseURL, endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	return strings.TrimRight(baseURL, "/") + endpoint
}
