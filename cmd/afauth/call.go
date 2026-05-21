package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/afauthhq/cli/internal/client"
	"github.com/afauthhq/cli/internal/identity"
	"github.com/spf13/cobra"
)

func newCallCmd() *cobra.Command {
	var (
		method     string
		data       string
		headers    []string
		keyPath    string
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
			req, err := http.NewRequest(strings.ToUpper(method), args[0], bytes.NewReader(body))
			if err != nil {
				return fmt.Errorf("call: build request: %w", err)
			}
			if len(body) == 0 {
				req.Body = nil
			}
			for _, h := range headers {
				k, v, ok := strings.Cut(h, ":")
				if !ok {
					return fmt.Errorf("call: --header must be 'Name: value', got %q", h)
				}
				req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
			}

			c := client.New(id)
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutSec)*time.Second)
			defer cancel()
			resp, err := c.Do(ctx, req)
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
