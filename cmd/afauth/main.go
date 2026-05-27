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
var version = "0.2.0"

func main() {
	root := newRootCmd()
	root.SetArgs(normalizeArgs(os.Args[1:]))
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// newRootCmd builds the afauth cobra root and wires every subcommand.
// Extracted from main so tests can drive the whole command tree
// without spawning a subprocess.
func newRootCmd() *cobra.Command {
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
		newTrustCmd(),
	)
	return root
}

// normalizeArgs translates Go-stdlib-style single-dash long flags
// ("-help", "-version") to their POSIX equivalents ("--help",
// "--version"). Without this, Cobra cluster-parses "-help" as
// `-h -e -l -p` and reports a confusing "unknown shorthand flag:
// 'e' in -elp" — users coming from CLIs built on the `flag`
// package have no way to map that error back to their input.
//
// Exact match only: "-helpme" and "-help=foo" are left untouched.
func normalizeArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		switch a {
		case "-help":
			out[i] = "--help"
		case "-version":
			out[i] = "--version"
		default:
			out[i] = a
		}
	}
	return out
}

