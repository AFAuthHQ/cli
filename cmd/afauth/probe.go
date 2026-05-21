package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/afauthhq/cli/internal/probe"
	"github.com/spf13/cobra"
)

func newProbeCmd() *cobra.Command {
	var (
		asJSON     bool
		timeoutSec int
	)
	cmd := &cobra.Command{
		Use:   "probe <service-url>",
		Short: "Run the v0.1 conformance probes against a live AFAuth service",
		Long: `Runs a deterministic battery of probes against the named service:

  discovery                       §4.3, §4.5  /.well-known/afauth shape
  implicit_signup                 §6.3        signed GET /accounts/me → 200 UNCLAIMED
  expired_signature               §5.6        old signature → 401 expired_signature
  replayed_nonce                  §5.6        nonce reuse → 401 replayed_nonce
  invalid_signature               §5.5, §11.3 garbage sig → 401 invalid_signature
  owner_invitation                §7.2        email recipient → 202 INVITED
  unsupported_recipient_type      §7.2, §7.7  undeclared type → 400 unsupported_recipient_type

A fresh did:key is generated per run, so probes operate against a
virgin UNCLAIMED account. Exits 0 only when every executed probe
passes.

  afauth probe https://api.example.com
  afauth probe --json https://api.example.com | jq .`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutSec)*time.Second)
			defer cancel()
			result, err := probe.Run(ctx, args[0], nil)
			if err != nil {
				return err
			}
			if asJSON {
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
			} else {
				renderProbeHuman(cmd, result)
			}
			if result.Failed() {
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON instead of human-readable text")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 60, "overall probe timeout in seconds")
	return cmd
}

func renderProbeHuman(cmd *cobra.Command, r *probe.Result) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "probing %s\n", r.BaseURL)
	for _, p := range r.Probes {
		fmt.Fprintf(w, "  %-30s %-5s %3dms  %s\n",
			p.Name, p.Status, p.Duration.Milliseconds(), p.Detail)
	}
	pass, fail, skip := r.Counts()
	fmt.Fprintf(w, "summary: %d pass, %d fail, %d skip\n", pass, fail, skip)
}
