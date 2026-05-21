package client_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/afauthhq/cli/internal/client"
	"github.com/afauthhq/cli/internal/identity"
	"github.com/afauthhq/cli/internal/signing"
)

func newTestClient(t *testing.T) *client.Client {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return client.New(id)
}

func TestGetSignedAndVerifiable(t *testing.T) {
	c := newTestClient(t)
	captured := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- cloneServerSideRequest(r, nil)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	resp, err := c.GetJSON(context.Background(), srv.URL+"/afauth/v1/accounts/me")
	if err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if resp.HTTPResponse.StatusCode != 200 {
		t.Fatalf("status: %d", resp.HTTPResponse.StatusCode)
	}
	seen := <-captured
	if seen.Header.Get("Signature-Input") == "" {
		t.Fatalf("client did not attach Signature-Input header")
	}
	if _, err := signing.Verify(seen); err != nil {
		t.Fatalf("server-side Verify on captured request: %v", err)
	}
}

func TestPostJSONIncludesContentDigest(t *testing.T) {
	c := newTestClient(t)
	captured := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured <- cloneServerSideRequest(r, body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	body := map[string]any{"recipient": map[string]string{"type": "email", "value": "alice@example.com"}}
	resp, err := c.PostJSON(context.Background(), srv.URL+"/afauth/v1/accounts/me/owner-invitation", body)
	if err != nil {
		t.Fatalf("PostJSON: %v", err)
	}
	if resp.HTTPResponse.StatusCode != 200 {
		t.Fatalf("status: %d", resp.HTTPResponse.StatusCode)
	}
	seen := <-captured
	if seen.Header.Get("Content-Digest") == "" {
		t.Fatalf("missing Content-Digest on POST")
	}
	gotBody, _ := io.ReadAll(seen.Body)
	if !strings.Contains(string(gotBody), `"alice@example.com"`) {
		t.Fatalf("body was not transmitted: %q", gotBody)
	}
	seen.Body = io.NopCloser(strings.NewReader(string(gotBody)))
	if _, err := signing.Verify(seen); err != nil {
		t.Fatalf("server-side Verify: %v", err)
	}
}

// cloneServerSideRequest returns a copy of r whose Header and Body
// are owned by the test goroutine, so we can verify and mutate without
// racing with the http server's connection bookkeeping. body MAY be nil
// for body-less requests.
func cloneServerSideRequest(r *http.Request, body []byte) *http.Request {
	out := &http.Request{
		Method: r.Method,
		URL:    r.URL,
		Host:   r.Host,
		Header: r.Header.Clone(),
		TLS:    r.TLS,
	}
	if body != nil {
		out.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	return out
}

func TestParsesAFAuthErrorEnvelope(t *testing.T) {
	c := newTestClient(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":{"code":"invalid_signature","message":"bad sig","details":{"hint":"check keyid"}}}`))
	}))
	defer srv.Close()

	resp, err := c.GetJSON(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if !resp.IsAFAuthError() {
		t.Fatalf("expected parsed AFAuth error")
	}
	if string(resp.Err.Code) != "invalid_signature" {
		t.Fatalf("error code = %q; want invalid_signature", resp.Err.Code)
	}
	if resp.Err.HTTPStatus != 401 {
		t.Fatalf("error status = %d; want 401", resp.Err.HTTPStatus)
	}
	if resp.Err.Message != "bad sig" {
		t.Fatalf("error message = %q", resp.Err.Message)
	}
	if resp.Err.Details == nil {
		t.Fatalf("error details should be parsed")
	}
}

func TestNonJSONErrorIsNotAFAuthError(t *testing.T) {
	c := newTestClient(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	resp, err := c.GetJSON(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if resp.HTTPResponse.StatusCode != 500 {
		t.Fatalf("status: %d", resp.HTTPResponse.StatusCode)
	}
	if resp.IsAFAuthError() {
		t.Fatalf("non-JSON 500 should NOT parse as AFAuth error")
	}
}
