package recipient_test

import (
	"encoding/json"
	"testing"

	"github.com/afauthhq/cli/internal/recipient"
	"github.com/afauthhq/cli/internal/specvectors"
)

// TestSpecVectors loads every C.4 vector and confirms our normaliser's
// accept/reject decision (and canonical form, on accept) matches. This
// is the cross-language gate for §7.7.
func TestSpecVectors(t *testing.T) {
	files, names, err := specvectors.LoadAll("recipients")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, name := range names {
		raw := files[name]
		var v struct {
			Name          string             `json:"name"`
			Description   string             `json:"description"`
			RecipientType string             `json:"recipient_type"`
			Input         recipient.Recipient `json:"input"`
			Expected      struct {
				Type      string             `json:"type"`
				Reason    string             `json:"reason"`
				Canonical *recipient.Recipient `json:"canonical,omitempty"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		t.Run(v.Name, func(t *testing.T) {
			got, err := recipient.Normalise(v.Input)
			gotOutcome := "accept"
			if err != nil {
				gotOutcome = "reject"
			}
			if gotOutcome != v.Expected.Type {
				t.Fatalf("got outcome=%s err=%v; want %s (reason: %s)",
					gotOutcome, err, v.Expected.Type, v.Expected.Reason)
			}
			if v.Expected.Type == "accept" && v.Expected.Canonical != nil {
				gotJSON, _ := json.Marshal(got)
				wantJSON, _ := json.Marshal(*v.Expected.Canonical)
				if string(gotJSON) != string(wantJSON) {
					t.Fatalf("canonical mismatch:\n got: %s\nwant: %s", gotJSON, wantJSON)
				}
			}
		})
	}
}

func TestParseCLI(t *testing.T) {
	cases := []struct {
		in        string
		wantType  recipient.Type
		wantValue string
		wantErr   bool
	}{
		{"alice@example.com", recipient.TypeEmail, "alice@example.com", false},
		{"email:alice@example.com", recipient.TypeEmail, "alice@example.com", false},
		{"phone:+14155550173", recipient.TypePhone, "+14155550173", false},
		{"did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr", recipient.TypeDID, "did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr", false},
		{"", "", "", true},
		{"random", "", "", true}, // no @ and no prefix
	}
	for _, c := range cases {
		c := c
		t.Run(c.in, func(t *testing.T) {
			got, err := recipient.Parse(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Type != c.wantType {
				t.Fatalf("type = %q; want %q", got.Type, c.wantType)
			}
			if got.Value.(string) != c.wantValue {
				t.Fatalf("value = %q; want %q", got.Value, c.wantValue)
			}
		})
	}
}

func TestNormaliseIdempotent(t *testing.T) {
	r1, err := recipient.Normalise(recipient.Recipient{Type: recipient.TypeEmail, Value: "Alice@Example.COM"})
	if err != nil {
		t.Fatalf("Normalise: %v", err)
	}
	r2, err := recipient.Normalise(r1)
	if err != nil {
		t.Fatalf("Normalise(Normalise): %v", err)
	}
	v1, _ := json.Marshal(r1)
	v2, _ := json.Marshal(r2)
	if string(v1) != string(v2) {
		t.Fatalf("normalise is not idempotent:\n once: %s\ntwice: %s", v1, v2)
	}
}
