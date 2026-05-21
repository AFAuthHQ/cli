// Package main is the entry point for the afauth CLI — the reference
// implementation of the AFAuth Protocol.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.0.1"

func main() {
	root := &cobra.Command{
		Use:     "afauth",
		Short:   "AFAuth — Agent-First Auth CLI",
		Long:    `afauth is the reference command-line interface for the AFAuth Protocol.`,
		Version: version,
	}

	root.AddCommand(
		newInitCmd(),
		newWhoamiCmd(),
		newDiscoverCmd(),
		newCallCmd(),
		newSignupCmd(),
		newInviteCmd(),
		newAccountsCmd(),
		newKeysCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newSignupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "signup <service-url>",
		Short: "Create an account on an AFAuth-enabled service",
		Args:  cobra.ExactArgs(1),
		RunE:  notImpl,
	}
}

func newInviteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "invite <email>",
		Short: "Invite a human to claim ownership of an account",
		Args:  cobra.ExactArgs(1),
		RunE:  notImpl,
	}
}

func newAccountsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "Inspect accounts this agent has created",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List accounts", RunE: notImpl},
		&cobra.Command{Use: "show <id>", Short: "Show account details", Args: cobra.ExactArgs(1), RunE: notImpl},
	)
	return cmd
}

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage agent keypairs",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "rotate", Short: "Rotate the active key", RunE: notImpl},
		&cobra.Command{Use: "export", Short: "Export the active key", RunE: notImpl},
		&cobra.Command{Use: "import <path>", Short: "Import a key", Args: cobra.ExactArgs(1), RunE: notImpl},
	)
	return cmd
}

func notImpl(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("%s: not yet implemented", cmd.CommandPath())
}
