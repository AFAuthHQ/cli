// Package main is the entry point for the afauth CLI — the reference
// implementation of the AFAuth Protocol.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is overridden at link time by goreleaser via
// `-ldflags "-X main.version=<tag>"`. The default here is the stable
// release that ships from this branch, so a hand-built binary still
// reports a sensible value.
var version = "0.1.0"

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
		newProbeCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

