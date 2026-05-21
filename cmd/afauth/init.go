package main

import (
	"fmt"
	"os"

	"github.com/afauthhq/cli/internal/identity"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var (
		keyPath string
		force   bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a new Ed25519 keypair and write it to ~/.afauth/key.json",
		Long: `Generates a fresh Ed25519 keypair and persists it to disk.

By default the key is written to $AFAUTH_HOME/key.json if $AFAUTH_HOME
is set, otherwise to ~/.afauth/key.json. The file is created with
mode 0600. Refuses to overwrite an existing key unless --force.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := keyPath
			if path == "" {
				p, err := identity.DefaultPath()
				if err != nil {
					return err
				}
				path = p
			}

			if force {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("init: remove existing key: %w", err)
				}
			}

			id, err := identity.Generate()
			if err != nil {
				return err
			}
			if err := id.Save(path); err != nil {
				return err
			}
			did, _ := id.DID()
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n%s\n", path, did)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default $AFAUTH_HOME/key.json or ~/.afauth/key.json)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing key file")
	return cmd
}
