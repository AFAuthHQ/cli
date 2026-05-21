package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/afauthhq/cli/internal/accounts"
	"github.com/afauthhq/cli/internal/client"
	"github.com/afauthhq/cli/internal/discovery"
	"github.com/afauthhq/cli/internal/identity"
	"github.com/spf13/cobra"
)

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage agent keypairs",
	}
	cmd.AddCommand(newKeysRotateCmd(), newKeysExportCmd(), newKeysImportCmd())
	return cmd
}

func newKeysRotateCmd() *cobra.Command {
	var (
		serviceURL string
		keyPath    string
		timeoutSec int
	)
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the active key against an AFAuth service (§8.1 pre-claim)",
		Long: `Generates a fresh keypair, signs a key-rotation request to the
service with the OLD key per §8.1, and on success swaps the new key
into ~/.afauth/key.json. The previous key is preserved as a sibling
backup file with a unix-second suffix.

Only pre-claim rotation is supported in v0.1. Post-claim rotation
requires owner approval and a side-channel ceremony that the protocol
does not specify here.

  afauth keys rotate --service https://api.example.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if serviceURL == "" {
				return fmt.Errorf("keys rotate: --service is required")
			}
			path := keyPath
			if path == "" {
				p, err := identity.DefaultPath()
				if err != nil {
					return err
				}
				path = p
			}
			id, err := identity.Load(path)
			if err != nil {
				return err
			}
			oldDID, _ := id.DID()

			newID, err := identity.Generate()
			if err != nil {
				return fmt.Errorf("keys rotate: generate new key: %w", err)
			}
			newDID, _ := newID.DID()

			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutSec)*time.Second)
			defer cancel()

			doc, err := discovery.Fetch(ctx, serviceURL, nil)
			if err != nil {
				return fmt.Errorf("keys rotate: discovery: %w", err)
			}
			endpoint := doc.Endpoints.KeyRotation
			if endpoint == "" {
				endpoint = "/afauth/v1/accounts/me/keys/rotate"
			}
			url := endpointURL(serviceURL, endpoint)

			c := client.New(id) // sign with OLD key per §8.1
			resp, err := c.PostJSON(ctx, url, map[string]string{"new_account_did": newDID})
			if err != nil {
				return err
			}
			if resp.IsAFAuthError() {
				return fmt.Errorf("keys rotate: %s (%d): %s", resp.Err.Code, resp.Err.HTTPStatus, resp.Err.Message)
			}
			if resp.HTTPResponse.StatusCode >= 300 {
				return fmt.Errorf("keys rotate: %s returned %d: %s", url, resp.HTTPResponse.StatusCode, string(resp.Body))
			}

			if err := newID.Replace(path); err != nil {
				return fmt.Errorf("keys rotate: install new key (service rotated; please recover from %s.<unix>.bak): %w", path, err)
			}

			// Update the local ledger to point at the new DID.
			ledgerPath, err := accounts.DefaultPath()
			if err == nil {
				if l, err := accounts.Load(ledgerPath); err == nil {
					l.Upsert(serviceURL, func(e *accounts.Entry) {
						e.AgentDID = newDID
					})
					_ = l.Save(ledgerPath)
				}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "rotated %s\n  old: %s\n  new: %s\n", serviceURL, oldDID, newDID)
			return nil
		},
	}
	cmd.Flags().StringVar(&serviceURL, "service", "", "AFAuth service URL (required)")
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 30, "request timeout in seconds")
	return cmd
}

func newKeysExportCmd() *cobra.Command {
	var (
		keyPath string
		outPath string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the active key (stdout by default, or to --out)",
		Long: `Writes the active key file verbatim to stdout. With --out, writes
to that path with mode 0600 instead. The exported file contains the
RAW Ed25519 seed — keep it secret.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := keyPath
			if path == "" {
				p, err := identity.DefaultPath()
				if err != nil {
					return err
				}
				path = p
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("keys export: %w", err)
			}
			if outPath != "" {
				if err := os.WriteFile(outPath, data, 0o600); err != nil {
					return fmt.Errorf("keys export: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "exported %s -> %s\n", path, outPath)
				return nil
			}
			if _, err := cmd.OutOrStdout().Write(data); err != nil {
				return err
			}
			if !bytes.HasSuffix(data, []byte("\n")) {
				fmt.Fprintln(cmd.OutOrStdout())
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	cmd.Flags().StringVar(&outPath, "out", "", "output file path (default stdout)")
	return cmd
}

func newKeysImportCmd() *cobra.Command {
	var (
		keyPath string
		force   bool
	)
	cmd := &cobra.Command{
		Use:   "import <path>",
		Short: "Install a key file as the active key",
		Long: `Copies <path> into ~/.afauth/key.json. The source file must be a
valid AFAuth key.json (Load is run before installation). Refuses to
overwrite an existing active key unless --force.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src := args[0]
			id, err := identity.Load(src)
			if err != nil {
				return fmt.Errorf("keys import: %w", err)
			}

			dest := keyPath
			if dest == "" {
				p, err := identity.DefaultPath()
				if err != nil {
					return err
				}
				dest = p
			}

			if force {
				if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("keys import: remove existing: %w", err)
				}
			}
			if err := id.Save(dest); err != nil {
				return fmt.Errorf("keys import: %w", err)
			}
			did, _ := id.DID()
			fmt.Fprintf(cmd.OutOrStdout(), "imported %s\n%s\n", dest, did)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "destination key path (default ~/.afauth/key.json)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing destination key")
	return cmd
}

