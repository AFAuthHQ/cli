package main

import (
	"fmt"

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

			id, err := identity.Generate()
			if err != nil {
				return err
			}
			defer id.Destroy() // zero the new seed once the command returns
			// --force archives any existing key as a .bak rather than
			// destroying it; without --force, Save refuses to overwrite.
			if force {
				if _, err := id.Replace(path); err != nil {
					return err
				}
			} else {
				if err := id.Save(path); err != nil {
					return err
				}
			}
			did, _ := id.DID()
			warnIfBindingStale(cmd.ErrOrStderr(), did)
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n%s\n", path, did)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default $AFAUTH_HOME/key.json or ~/.afauth/key.json)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing key (the old key is archived as a .bak)")
	return cmd
}
