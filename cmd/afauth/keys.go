package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
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
	cmd.AddCommand(
		newKeysRotateCmd(),
		newKeysExportCmd(),
		newKeysImportCmd(),
		newKeysBackupsCmd(),
		newKeysForgetBackupCmd(),
	)
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
			defer id.Destroy() // zero the old seed once the command returns
			oldDID, _ := id.DID()

			newID, err := identity.Generate()
			if err != nil {
				return fmt.Errorf("keys rotate: generate new key: %w", err)
			}
			defer newID.Destroy()
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

			backup, err := newID.Replace(path)
			if err != nil {
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

			warnIfBindingStale(cmd.ErrOrStderr(), newDID)
			fmt.Fprintf(cmd.OutOrStdout(), "rotated %s\n  old: %s\n  new: %s\n", serviceURL, oldDID, newDID)
			if backup != "" {
				// The backup exists only to recover from a rotation the
				// service later disputes; once it confirms the new key, the
				// backup is a live private key with no further use. Tie its
				// lifetime to that confirmation window.
				fmt.Fprintf(cmd.OutOrStdout(), "  old key archived at %s\n  once the service confirms the new key, shred the backup:\n    afauth keys forget-backup %s\n", backup, backup)
			}
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
		keyPath  string
		outPath  string
		toStdout bool
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the active key to a 0600 file (or --stdout)",
		Long: `Copies the active key to a file with mode 0600 (--out PATH). The file
contains the RAW Ed25519 seed — anyone who reads it can act as this
agent, so keep it secret.

export will NOT write the seed to the terminal by default, where it
would leak into scrollback, tmux/screen capture, and CI logs. Pass
--stdout to print the raw key anyway (e.g. to pipe into an encryptor):

  afauth keys export --out ./backup.json
  afauth keys export --stdout | gpg -e -r you@example.com > key.json.gpg`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if outPath != "" && toStdout {
				return fmt.Errorf("keys export: pass only one of --out or --stdout")
			}
			if outPath == "" && !toStdout {
				return fmt.Errorf("keys export: refusing to write your private key to the terminal by default\n  use --out <file> to save it (mode 0600), or --stdout to print the raw seed anyway")
			}
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
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s holds your RAW private key (mode 0600) — keep it secret\n", outPath)
				fmt.Fprintf(cmd.OutOrStdout(), "exported %s -> %s\n", path, outPath)
				return nil
			}
			// --stdout: explicit opt-in. Warn on stderr (not stdout, so a
			// pipe stays clean) before emitting the raw seed.
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: writing your RAW private key to stdout — it will be in your terminal scrollback")
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
	cmd.Flags().StringVar(&outPath, "out", "", "write the key to this file (mode 0600)")
	cmd.Flags().BoolVar(&toStdout, "stdout", false, "print the raw key to stdout (leaks into scrollback/CI logs)")
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
			defer id.Destroy() // zero the imported seed once the command returns

			dest := keyPath
			if dest == "" {
				p, err := identity.DefaultPath()
				if err != nil {
					return err
				}
				dest = p
			}

			// --force archives the existing key as a .bak; without it,
			// Save refuses to overwrite.
			if force {
				if _, err := id.Replace(dest); err != nil {
					return fmt.Errorf("keys import: %w", err)
				}
			} else {
				if err := id.Save(dest); err != nil {
					return fmt.Errorf("keys import: %w", err)
				}
			}
			did, _ := id.DID()
			warnIfBindingStale(cmd.ErrOrStderr(), did)
			fmt.Fprintf(cmd.OutOrStdout(), "imported %s\n%s\n", dest, did)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "destination key path (default ~/.afauth/key.json)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing destination key")
	return cmd
}

func newKeysBackupsCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "backups",
		Short: "List archived key backups sitting next to the active key",
		Long: `Lists the archived key backups alongside the active key. Each backup
holds a complete private key (the raw Ed25519 seed): rotation and
'keys import --force' preserve the old key here so you can recover from
a swap the service later disputes.

Backups accumulate with no automatic pruning, so a long-lived agent ends
up with a pile of live private keys on disk. Once a rotation is
confirmed, shred the stale backup with 'afauth keys forget-backup'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := keyPath
			if path == "" {
				p, err := identity.DefaultPath()
				if err != nil {
					return err
				}
				path = p
			}
			backups, err := identity.Backups(path)
			if err != nil {
				return err
			}
			if len(backups) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no key backups found")
				return nil
			}
			for _, b := range backups {
				line := b
				if id, err := identity.Load(b); err == nil {
					if did, err := id.DID(); err == nil {
						line = fmt.Sprintf("%s  %s", b, did)
					}
					id.Destroy()
				} else {
					line = fmt.Sprintf("%s  (unreadable: %v)", b, err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), line)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	return cmd
}

func newKeysForgetBackupCmd() *cobra.Command {
	var (
		keyPath string
		shred   bool
		all     bool
	)
	cmd := &cobra.Command{
		Use:   "forget-backup [path...]",
		Short: "Shred and remove archived key backups",
		Long: `Securely removes one or more key backups. By default each file's
bytes are overwritten with zeros before it is unlinked (--shred, on by
default); pass --shred=false for a plain unlink.

Give explicit backup paths (see 'afauth keys backups'), or --all to
remove every backup of the active key. Refuses to touch anything that is
not a *.bak file, so the active key can't be shredded by mistake.

Shredding is best-effort: on SSD/copy-on-write filesystems the overwrite
may not land on the original blocks. Full-disk encryption is the real
backstop.

  afauth keys forget-backup ~/.afauth/key.json.1700000000.bak
  afauth keys forget-backup --all`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := keyPath
			if path == "" {
				p, err := identity.DefaultPath()
				if err != nil {
					return err
				}
				path = p
			}

			targets := append([]string{}, args...)
			if all {
				backups, err := identity.Backups(path)
				if err != nil {
					return err
				}
				targets = append(targets, backups...)
			}
			if len(targets) == 0 {
				return fmt.Errorf("keys forget-backup: pass a backup path or --all")
			}
			// Validate everything before removing anything, so a bad target
			// can't leave us half-done.
			for _, t := range targets {
				if !strings.HasSuffix(t, ".bak") {
					return fmt.Errorf("keys forget-backup: refusing to remove %q (not a .bak backup)", t)
				}
			}
			for _, t := range targets {
				if shred {
					if err := identity.ShredFile(t); err != nil {
						return fmt.Errorf("keys forget-backup: %w", err)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "shredded %s\n", t)
				} else {
					if err := os.Remove(t); err != nil {
						return fmt.Errorf("keys forget-backup: %w", err)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", t)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	cmd.Flags().BoolVar(&shred, "shred", true, "overwrite the file's bytes before unlinking")
	cmd.Flags().BoolVar(&all, "all", false, "remove every backup of the active key")
	return cmd
}
