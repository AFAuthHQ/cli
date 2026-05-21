package discovery_test

import (
	"encoding/json"
	"testing"

	"github.com/afauthhq/cli/internal/discovery"
	"github.com/afauthhq/cli/internal/specvectors"
)

// TestSpecVectors loads every committed C.3 vector and confirms the
// parser's accept/reject decision matches the vector's expected outcome.
// This is the cross-language gate for §4.3 + §4.5.
func TestSpecVectors(t *testing.T) {
	files, names, err := specvectors.LoadAll("discovery")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, name := range names {
		var v struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Section     string          `json:"section"`
			Document    json.RawMessage `json:"document"`
			Expected    struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(files[name], &v); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		t.Run(v.Name, func(t *testing.T) {
			_, err := discovery.Parse([]byte(v.Document))
			gotOutcome := "accept"
			if err != nil {
				gotOutcome = "reject"
			}
			if gotOutcome != v.Expected.Type {
				t.Fatalf("vector %q: got outcome=%s err=%v; want=%s (reason: %s)",
					v.Name, gotOutcome, err, v.Expected.Type, v.Expected.Reason)
			}
		})
	}
}

func TestForwardCompatPreservesKnownFields(t *testing.T) {
	doc, err := specvectors.LoadFile("discovery/forward-compat-unknown-top-level-field.json")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var v struct {
		Document json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal(doc, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	d, err := discovery.Parse([]byte(v.Document))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if d.AFAuthVersion != "0.1" {
		t.Fatalf("AFAuthVersion = %q; want %q", d.AFAuthVersion, "0.1")
	}
	if d.Endpoints.Accounts == "" {
		t.Fatalf("known field discarded by forward-compat decode")
	}
}

func TestRecipientTypeOrDefault(t *testing.T) {
	d := &discovery.Document{}
	got := d.RecipientTypeOrDefault()
	if len(got) != 1 || got[0] != "email" {
		t.Fatalf("default = %v; want [email]", got)
	}

	d.RecipientTypes = []string{"email", "oidc"}
	got = d.RecipientTypeOrDefault()
	if len(got) != 2 || got[0] != "email" || got[1] != "oidc" {
		t.Fatalf("with declared list, got %v", got)
	}
}
