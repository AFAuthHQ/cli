package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNoCrossOriginRedirect(t *testing.T) {
	orig, _ := http.NewRequest(http.MethodGet, "https://api.example.com/afauth/v1/x", nil)

	t.Run("allows same-origin redirect", func(t *testing.T) {
		next, _ := http.NewRequest(http.MethodGet, "https://api.example.com/afauth/v1/y", nil)
		if err := NoCrossOriginRedirect(next, []*http.Request{orig}); err != nil {
			t.Fatalf("same-origin redirect should be allowed, got %v", err)
		}
	})

	t.Run("refuses cross-host redirect", func(t *testing.T) {
		next, _ := http.NewRequest(http.MethodGet, "https://evil.example/y", nil)
		if err := NoCrossOriginRedirect(next, []*http.Request{orig}); err == nil {
			t.Fatal("cross-host redirect must be refused")
		}
	})

	t.Run("refuses scheme downgrade", func(t *testing.T) {
		next, _ := http.NewRequest(http.MethodGet, "http://api.example.com/y", nil)
		if err := NoCrossOriginRedirect(next, []*http.Request{orig}); err == nil {
			t.Fatal("scheme change must be refused")
		}
	})
}

// TestClientDoesNotLeakHeaderAcrossOrigins is the headline regression: a
// service that redirects to an attacker origin must NOT cause the client
// to forward the AFAuth-Attestation header to that origin.
func TestClientDoesNotLeakHeaderAcrossOrigins(t *testing.T) {
	var attackerSawAttestation string
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerSawAttestation = r.Header.Get("AFAuth-Attestation")
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/done", http.StatusFound)
	}))
	defer service.Close()

	c := Client(5 * time.Second)
	req, _ := http.NewRequest(http.MethodGet, service.URL+"/op", nil)
	req.Header.Set("AFAuth-Attestation", "SECRET.JWT.TOKEN")
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected the cross-origin redirect to be refused with an error")
	}
	if attackerSawAttestation != "" {
		t.Fatalf("attestation JWT leaked to attacker origin: %q", attackerSawAttestation)
	}
}
