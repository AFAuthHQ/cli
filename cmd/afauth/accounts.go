package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/afauthhq/cli/internal/accounts"
	"github.com/afauthhq/cli/internal/client"
	"github.com/afauthhq/cli/internal/discovery"
	"github.com/spf13/cobra"
)

func newAccountsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "Inspect accounts this agent has created",
	}
	cmd.AddCommand(newAccountsListCmd(), newAccountsShowCmd())
	return cmd
}

func newAccountsListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List accounts known to this agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			ledgerPath, err := accounts.DefaultPath()
			if err != nil {
				return err
			}
			l, err := accounts.Load(ledgerPath)
			if err != nil {
				return err
			}
			entries := l.Sorted()
			if asJSON {
				out, _ := json.MarshalIndent(entries, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
				return nil
			}
			if len(entries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no accounts — try `afauth signup <service-url>`)")
				return nil
			}
			for _, e := range entries {
				state := e.State
				if state == "" {
					state = "?"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-12s  %s  %s\n", state, e.ServiceURL, e.AgentDID)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func newAccountsShowCmd() *cobra.Command {
	var (
		keyPath    string
		refresh    bool
		timeoutSec int
	)
	cmd := &cobra.Command{
		Use:   "show <service-url>",
		Short: "Show one account, optionally refreshing state from the service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ledgerPath, err := accounts.DefaultPath()
			if err != nil {
				return err
			}
			ledger, err := accounts.Load(ledgerPath)
			if err != nil {
				return err
			}
			serviceURL := args[0]

			if refresh {
				if err := refreshAccount(cmd.Context(), serviceURL, keyPath, ledger, time.Duration(timeoutSec)*time.Second); err != nil {
					return err
				}
				if err := ledger.Save(ledgerPath); err != nil {
					return err
				}
			}

			e := ledger.Get(serviceURL)
			if e == nil {
				return fmt.Errorf("accounts: no entry for %s (try `afauth signup %s`)", serviceURL, serviceURL)
			}
			out, _ := json.MarshalIndent(e, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	cmd.Flags().BoolVar(&refresh, "refresh", false, "GET /accounts/me to refresh local state before printing")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 30, "request timeout in seconds")
	return cmd
}

func refreshAccount(parentCtx context.Context, serviceURL, keyPath string, ledger *accounts.Ledger, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	id, err := loadIdentity(keyPath)
	if err != nil {
		return err
	}
	doc, err := discovery.Fetch(ctx, serviceURL, nil)
	if err != nil {
		return fmt.Errorf("accounts: discovery: %w", err)
	}
	c := client.New(id)
	url := strings.TrimRight(endpointURL(serviceURL, doc.Endpoints.Accounts), "/") + "/me"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(ctx, req)
	if err != nil {
		return err
	}
	if resp.IsAFAuthError() {
		return fmt.Errorf("accounts: %s (%d): %s", resp.Err.Code, resp.Err.HTTPStatus, resp.Err.Message)
	}
	if resp.HTTPResponse.StatusCode >= 300 {
		return fmt.Errorf("accounts: GET %s returned %d", url, resp.HTTPResponse.StatusCode)
	}
	var body struct {
		AccountDID string          `json:"account_did"`
		State      string          `json:"state"`
		Owner      json.RawMessage `json:"owner"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return fmt.Errorf("accounts: parse /accounts/me: %w", err)
	}
	did, _ := id.DID()
	ledger.Upsert(serviceURL, func(e *accounts.Entry) {
		e.AgentDID = did
		e.State = body.State
		if len(body.Owner) > 0 && string(body.Owner) != "null" {
			var owner accounts.Owner
			if err := json.Unmarshal(body.Owner, &owner); err == nil {
				e.Owner = &owner
			}
		}
	})
	return nil
}
