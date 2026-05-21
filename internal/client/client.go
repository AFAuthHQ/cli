// Package client implements the AFAuth-signed HTTP client used by the
// CLI's call/signup/invite/keys/probe commands. It owns the agent's
// identity, an http.Client, and the §11 error-envelope parser.
//
// Higher-level command-specific behaviour (typed-recipient invitations,
// key-rotation flows, account ledger persistence) lives in callers;
// this package is intentionally the smallest surface that signs +
// sends one HTTP request and surfaces a parseable response.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/afauthhq/cli/internal/identity"
	"github.com/afauthhq/cli/internal/proto"
	"github.com/afauthhq/cli/internal/signing"
)

// Client holds the agent's identity and an http.Client.
type Client struct {
	Identity *identity.Identity
	HTTP     *http.Client
}

// New constructs a Client with the given identity and a 30-second
// default HTTP timeout.
func New(id *identity.Identity) *Client {
	return &Client{
		Identity: id,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Response carries the relevant bits of a successful or failed HTTP
// response, after error-envelope parsing. Body is the raw response
// body bytes; if the response carries an §11.1 error envelope, Err is
// populated as well.
type Response struct {
	HTTPResponse *http.Response
	Body         []byte
	Err          *proto.Error
}

// IsAFAuthError reports whether the response carried a parseable §11.1
// error envelope.
func (r *Response) IsAFAuthError() bool {
	return r.Err != nil
}

// Do signs the request with the client's identity and sends it. The
// returned Response carries the raw response and, if the body parses
// as an §11.1 error envelope, a populated Err.
func (c *Client) Do(ctx context.Context, req *http.Request) (*Response, error) {
	if c.Identity == nil {
		return nil, errors.New("client: nil identity")
	}
	did, err := c.Identity.DID()
	if err != nil {
		return nil, fmt.Errorf("client: derive did: %w", err)
	}
	req = req.WithContext(ctx)
	if err := signing.Sign(req, did, c.Identity.Seed, nil); err != nil {
		return nil, fmt.Errorf("client: sign: %w", err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: %s %s: %w", req.Method, req.URL.String(), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("client: read body: %w", err)
	}
	out := &Response{HTTPResponse: resp, Body: body}
	if resp.StatusCode >= 400 {
		out.Err = parseErrorEnvelope(resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	return out, nil
}

// GetJSON sends a signed GET. The response body is returned as-is.
func (c *Client) GetJSON(ctx context.Context, rawURL string) (*Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("client: build GET %s: %w", rawURL, err)
	}
	return c.Do(ctx, req)
}

// PostJSON sends a signed POST with a JSON body. body MAY be a typed
// value; it is marshalled with encoding/json before signing.
func (c *Client) PostJSON(ctx context.Context, rawURL string, body any) (*Response, error) {
	var data []byte
	switch v := body.(type) {
	case nil:
		// allow caller to mean "POST with empty body"
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("client: marshal POST body: %w", err)
		}
		data = b
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("client: build POST %s: %w", rawURL, err)
	}
	return c.Do(ctx, req)
}

// parseErrorEnvelope tries to decode body as a §11.1 envelope. Returns
// nil if the body is not a recognizable AFAuth error.
func parseErrorEnvelope(status int, contentType string, body []byte) *proto.Error {
	ct := strings.TrimSpace(strings.ToLower(contentType))
	if semi := strings.IndexByte(ct, ';'); semi >= 0 {
		ct = strings.TrimSpace(ct[:semi])
	}
	if ct != "application/json" {
		return nil
	}
	var env struct {
		Error *struct {
			Code    string          `json:"code"`
			Message string          `json:"message"`
			Details json.RawMessage `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Error == nil {
		return nil
	}
	out := &proto.Error{
		HTTPStatus: status,
		Code:       proto.ErrorCode(env.Error.Code),
		Message:    env.Error.Message,
	}
	if len(env.Error.Details) > 0 && string(env.Error.Details) != "null" {
		var details any
		if err := json.Unmarshal(env.Error.Details, &details); err == nil {
			out.Details = details
		}
	}
	return out
}
