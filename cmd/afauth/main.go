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
		newCallCmd(),
		newSignupCmd(),
		newInviteCmd(),
		newAccountsCmd(),
		newKeysCmd(),
		newMcpCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Generate a new Ed25519 keypair and write it to ~/.afauth/key.json",
		RunE:  notImpl,
	}
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Print this agent's did:key identifier",
		RunE:  notImpl,
	}
}

func newCallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "call <url>",
		Short: "Sign and send an HTTP request to an AFAuth-enabled service",
		Args:  cobra.ExactArgs(1),
		RunE:  notImpl,
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

func newMcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run as an MCP server exposing afauth tools to MCP-aware hosts",
		RunE:  notImpl,
	}
}

func notImpl(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("%s: not yet implemented", cmd.CommandPath())
}
