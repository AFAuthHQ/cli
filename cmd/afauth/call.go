package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/afauthhq/cli/internal/client"
	"github.com/afauthhq/cli/internal/discovery"
	"github.com/afauthhq/cli/internal/identity"
	"github.com/afauthhq/cli/internal/proto"
	"github.com/spf13/cobra"
)

func newCallCmd() *cobra.Command {
	var (
		method     string
		data       string
		headers    []string
		keyPath    string
		attest     string
		showHeads  bool
		timeoutSec int
	)
	cmd := &cobra.Command{
		Use:   "call <url>",
		Short: "Sign and send an HTTP request to an AFAuth-enabled service",
		Long: `Builds an AFAuth-signed HTTP request and prints the response.

The agent's identity is loaded from --key (default ~/.afauth/key.json).
Use --method, --data and --header to control the request shape.

  afauth call https://api.example.com/afauth/v1/accounts/me
  afauth call --method POST --data '{"x":1}' https://api.example.com/x
  afauth call --method POST --data @body.json --header 'X-Trace: foo' https://...`,
		Args: cobra.ExactArgs(1),
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
			body, err := resolveDataFlag(data)
			if err != nil {
				return err
			}
			did, err := id.DID()
			if err != nil {
				return err
			}
			// buildReq produces a fresh request per attempt — the §10.7
			// retry must re-sign (new nonce) and re-read the body, so a
			// single *http.Request can't be reused.
			buildReq := func() (*http.Request, error) {
				var r io.Reader
				if len(body) > 0 {
					r = bytes.NewReader(body)
				}
				req, err := http.NewRequest(strings.ToUpper(method), args[0], r)
				if err != nil {
					return nil, fmt.Errorf("call: build request: %w", err)
				}
				for _, h := range headers {
					k, v, ok := strings.Cut(h, ":")
					if !ok {
						return nil, fmt.Errorf("call: --header must be 'Name: value', got %q", h)
					}
					req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
				}
				return req, nil
			}

			c := client.New(id)
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutSec)*time.Second)
			defer cancel()
			resp, err := attestedCall(ctx, c, buildReq, args[0], did, attest, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s %s\n", resp.HTTPResponse.Proto, resp.HTTPResponse.Status)
			if showHeads {
				for k, vs := range resp.HTTPResponse.Header {
					for _, v := range vs {
						fmt.Fprintf(w, "%s: %s\n", k, v)
					}
				}
				fmt.Fprintln(w)
			}
			if len(resp.Body) > 0 {
				if _, err := w.Write(resp.Body); err != nil {
					return err
				}
				if !bytes.HasSuffix(resp.Body, []byte("\n")) {
					fmt.Fprintln(w)
				}
			}
			if resp.IsAFAuthError() {
				// Mirror the §11.3 code on stderr so scripts can branch on it.
				fmt.Fprintf(cmd.ErrOrStderr(), "afauth error: %s\n", resp.Err.Code)
				os.Exit(2)
			}
			if resp.HTTPResponse.StatusCode >= 400 {
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&method, "method", "X", "GET", "HTTP method")
	cmd.Flags().StringVarP(&data, "data", "d", "", "request body (prefix with @ to read from file)")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "extra header (repeatable, 'Name: value')")
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default ~/.afauth/key.json)")
	cmd.Flags().StringVar(&attest, "attest", "", "attach an AFAuth-Attestation JWT proactively (otherwise minted on a §10.7 challenge)")
	cmd.Flags().BoolVarP(&showHeads, "show-headers", "i", false, "print response headers")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 30, "request timeout in seconds")
	return cmd
}

func resolveDataFlag(d string) ([]byte, error) {
	if d == "" {
		return nil, nil
	}
	if strings.HasPrefix(d, "@") {
		path := d[1:]
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("call: open --data file %s: %w", path, err)
		}
		defer f.Close()
		return io.ReadAll(f)
	}
	return []byte(d), nil
}

// attestedCall sends a signed request and, on a §10.7 `401
// attestation_required` challenge, mints a fresh attestation
// (audience-bound to the service) and retries ONCE — the agent side of
// the refresh-on-challenge loop. A proactively supplied --attest token
// is attached on the first attempt. A revoked/expired binding surfaces
// from autoAttest with re-link guidance rather than an unbounded retry.
func attestedCall(
	ctx context.Context,
	c *client.Client,
	build func() (*http.Request, error),
	serviceURL, did, attest string,
	stderr io.Writer,
) (*client.Response, error) {
	req, err := build()
	if err != nil {
		return nil, err
	}
	if attest != "" {
		req.Header.Set("AFAuth-Attestation", attest)
	}
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if !attestationRequired(resp) {
		return resp, nil
	}

	// §10.7 challenge: the attested session lapsed. Discover the
	// service's DID (the attestation audience), mint a fresh
	// attestation from the cached trust binding, and retry once. If the
	// §5.7 challenge named the accepted attestors, surface them.
	if ch := proto.ParseChallenge(resp.HTTPResponse.Header.Get("WWW-Authenticate")); ch != nil && len(ch.Attestors) > 0 {
		fmt.Fprintf(stderr, "attestation_required — service accepts %s; minting a fresh attestation and retrying (§10.7)\n", strings.Join(ch.Attestors, ", "))
	} else {
		fmt.Fprintln(stderr, "attestation_required — minting a fresh attestation and retrying (§10.7)")
	}
	doc, err := discovery.Fetch(ctx, serviceOrigin(serviceURL), nil)
	if err != nil {
		return nil, fmt.Errorf("call: discovery for attestation refresh: %w", err)
	}
	jwt, err := autoAttest(ctx, doc, serviceURL, did, c.Identity.Seed, attestorOverride(""), stderr)
	if err != nil {
		return nil, err
	}
	req2, err := build()
	if err != nil {
		return nil, err
	}
	req2.Header.Set("AFAuth-Attestation", jwt)
	return c.Do(ctx, req2)
}

// attestationRequired reports whether resp is an `attestation_required`
// challenge. It prefers the §5.7 `WWW-Authenticate` header (robust even when the
// body is missing or not JSON) and falls back to the §11.1 error envelope for
// services that predate the challenge.
func attestationRequired(resp *client.Response) bool {
	if resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusUnauthorized {
		if ch := proto.ParseChallenge(resp.HTTPResponse.Header.Get("WWW-Authenticate")); ch != nil && ch.Error != "" {
			return ch.Error == proto.ErrAttestationRequired
		}
	}
	return resp.Err != nil && resp.Err.Code == proto.ErrAttestationRequired
}

// serviceOrigin reduces a request URL to scheme://host so discovery can
// fetch /.well-known/afauth — the call URL usually carries a path.
func serviceOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}
