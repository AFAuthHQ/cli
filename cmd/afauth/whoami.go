package main

import (
	"fmt"

	"github.com/afauthhq/cli/internal/identity"
	"github.com/spf13/cobra"
)

func newWhoamiCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Print this agent's did:key identifier",
		RunE: func(cmd *cobra.Command, args []string) error {
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
			did, err := id.DID()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), did)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default $AFAUTH_HOME/key.json or ~/.afauth/key.json)")
	return cmd
}
