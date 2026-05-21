package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/afauthhq/cli/internal/discovery"
	"github.com/spf13/cobra"
)

func newDiscoverCmd() *cobra.Command {
	var (
		asJSON bool
		timeoutSec int
	)
	cmd := &cobra.Command{
		Use:   "discover <service-url>",
		Short: "Fetch and validate /.well-known/afauth from a service",
		Long: `Fetches the discovery document from <service-url>/.well-known/afauth,
validates it per §4.3 (required fields) and §4.5 (ed25519 advertised),
and prints the parsed result. Exits non-zero if the document is invalid
or unreachable.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutSec)*time.Second)
			defer cancel()
			doc, err := discovery.Fetch(ctx, args[0], nil)
			if err != nil {
				return err
			}
			if asJSON {
				out, _ := json.MarshalIndent(doc, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
				return nil
			}
			renderDiscoveryHuman(cmd, doc)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON instead of human-readable text")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 10, "request timeout in seconds")
	return cmd
}

func renderDiscoveryHuman(cmd *cobra.Command, d *discovery.Document) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "afauth %s @ %s\n", d.AFAuthVersion, d.ServiceDID)
	fmt.Fprintln(w, "endpoints:")
	fmt.Fprintf(w, "  accounts          %s\n", d.Endpoints.Accounts)
	fmt.Fprintf(w, "  owner_invitation  %s\n", d.Endpoints.OwnerInvitation)
	fmt.Fprintf(w, "  claim_page        %s\n", d.Endpoints.ClaimPage)
	fmt.Fprintf(w, "  claim_completion  %s\n", d.Endpoints.ClaimCompletion)
	if d.Endpoints.KeyRotation != "" {
		fmt.Fprintf(w, "  key_rotation      %s\n", d.Endpoints.KeyRotation)
	}
	fmt.Fprintf(w, "signature_algorithms: %v\n", d.SignatureAlgorithms)
	if len(d.Features) > 0 {
		fmt.Fprintf(w, "features:             %v\n", d.Features)
	}
	if len(d.RecipientTypes) > 0 {
		fmt.Fprintf(w, "recipient_types:      %v\n", d.RecipientTypes)
	} else {
		fmt.Fprintln(w, "recipient_types:      [email] (default per §4.4)")
	}
	if d.Billing != nil && d.Billing.UnclaimedMode != "" {
		fmt.Fprintf(w, "billing.unclaimed_mode: %s\n", d.Billing.UnclaimedMode)
	}
}
