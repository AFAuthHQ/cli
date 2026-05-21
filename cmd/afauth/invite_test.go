package main

import (
	"testing"

	"github.com/afauthhq/cli/internal/recipient"
)

func TestResolveRecipientPositional(t *testing.T) {
	r, err := resolveRecipient([]string{"alice@example.com"}, "", "", "", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Type != recipient.TypeEmail {
		t.Fatalf("type = %q; want email", r.Type)
	}
	if r.Value.(string) != "alice@example.com" {
		t.Fatalf("value = %v", r.Value)
	}
}

func TestResolveRecipientOIDCFlags(t *testing.T) {
	r, err := resolveRecipient(nil, "oidc", "", "https://accounts.google.com", "12345")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Type != recipient.TypeOIDC {
		t.Fatalf("type = %q; want oidc", r.Type)
	}
	v, ok := r.Value.(recipient.OIDCValue)
	if !ok {
		t.Fatalf("value type = %T; want OIDCValue", r.Value)
	}
	if v.Issuer != "https://accounts.google.com" || v.Sub != "12345" {
		t.Fatalf("OIDCValue = %+v", v)
	}
}

func TestResolveRecipientOIDCMissingFields(t *testing.T) {
	if _, err := resolveRecipient(nil, "oidc", "", "https://accounts.google.com", ""); err == nil {
		t.Fatalf("expected error when --sub missing")
	}
}

func TestResolveRecipientTypedFlagOverridesPositional(t *testing.T) {
	r, err := resolveRecipient([]string{"alice@example.com"}, "phone", "+14155550173", "", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Type != recipient.TypePhone {
		t.Fatalf("type = %q; want phone", r.Type)
	}
	if r.Value.(string) != "+14155550173" {
		t.Fatalf("value = %v", r.Value)
	}
}

func TestEndpointURLAbsolute(t *testing.T) {
	if got := endpointURL("https://api.example.com", "https://claim.example.com"); got != "https://claim.example.com" {
		t.Fatalf("absolute endpoint not passed through: %q", got)
	}
}

func TestEndpointURLRelative(t *testing.T) {
	if got := endpointURL("https://api.example.com/", "/afauth/v1/accounts"); got != "https://api.example.com/afauth/v1/accounts" {
		t.Fatalf("relative endpoint mishandled: %q", got)
	}
}
