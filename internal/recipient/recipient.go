// Package recipient implements the §7.7 recipient registry: the
// per-type value shape, parser, normaliser, and wire-format JSON
// marshaller used by the owner-invitation flow.
//
// Normalisation rules per §7.7:
//
//   email — NFKC + ASCII case-fold (lowercase).
//   phone — MUST match ^\+[0-9]+$; extension syntax rejected.
//   oidc  — issuer + sub byte-exact; fragment/query in issuer rejected.
//   did   — bare DID; path/query/fragment rejected. did:key canonical
//           per §3.1.1; did:web host MUST be lowercase.
package recipient

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/afauthhq/cli/internal/proto"
	"golang.org/x/text/unicode/norm"
)

// Type is one of the v0.1 reserved recipient types.
type Type string

const (
	TypeEmail Type = "email"
	TypePhone Type = "phone"
	TypeOIDC  Type = "oidc"
	TypeDID   Type = "did"
)

// Recipient is the §7.7 wire shape carried in the owner-invitation
// body. For email/phone/did, Value is a string. For oidc, Value is an
// OIDCValue. Other shapes are rejected at Normalise time.
type Recipient struct {
	Type  Type
	Value any
}

// OIDCValue is the inner shape for oidc recipients.
type OIDCValue struct {
	Issuer string `json:"issuer"`
	Sub    string `json:"sub"`
}

// MarshalJSON emits the §7.7 wire form: {"type":..., "value":...}.
func (r Recipient) MarshalJSON() ([]byte, error) {
	out := struct {
		Type  Type `json:"type"`
		Value any  `json:"value"`
	}{Type: r.Type, Value: r.Value}
	return json.Marshal(out)
}

// UnmarshalJSON decodes the §7.7 wire form. The result is not yet
// normalised — call Normalise on the value to validate per-type rules.
func (r *Recipient) UnmarshalJSON(data []byte) error {
	var raw struct {
		Type  Type            `json:"type"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Type = raw.Type
	switch raw.Type {
	case TypeEmail, TypePhone, TypeDID:
		var s string
		if err := json.Unmarshal(raw.Value, &s); err != nil {
			return fmt.Errorf("recipient.%s.value must be a string: %w", raw.Type, err)
		}
		r.Value = s
	case TypeOIDC:
		var v OIDCValue
		if err := json.Unmarshal(raw.Value, &v); err != nil {
			return fmt.Errorf("recipient.oidc.value must be {issuer, sub}: %w", err)
		}
		r.Value = v
	default:
		return fmt.Errorf("unknown recipient type: %q", raw.Type)
	}
	return nil
}

var phoneRe = regexp.MustCompile(`^\+[0-9]+$`)
var extensionMarkRe = regexp.MustCompile(`[;,xX]`)

// Normalise applies the §7.7 per-type normalisation. Returns a new
// Recipient with canonical Value. Idempotent: Normalise(Normalise(r))
// == Normalise(r).
func Normalise(r Recipient) (Recipient, error) {
	switch r.Type {
	case TypeEmail:
		s, ok := r.Value.(string)
		if !ok {
			return Recipient{}, errors.New("email.value must be a string")
		}
		canon := strings.ToLower(norm.NFKC.String(s))
		return Recipient{Type: TypeEmail, Value: canon}, nil

	case TypePhone:
		s, ok := r.Value.(string)
		if !ok {
			return Recipient{}, errors.New("phone.value must be a string")
		}
		if !phoneRe.MatchString(s) {
			if extensionMarkRe.MatchString(s) {
				return Recipient{}, errors.New("phone contains E.164 extension syntax")
			}
			if !strings.HasPrefix(s, "+") {
				return Recipient{}, errors.New("phone is not E.164 (missing leading +)")
			}
			return Recipient{}, errors.New("phone contains characters other than + and 0-9")
		}
		return Recipient{Type: TypePhone, Value: s}, nil

	case TypeOIDC:
		v, ok := r.Value.(OIDCValue)
		if !ok {
			return Recipient{}, errors.New("oidc.value must be {issuer, sub}")
		}
		if v.Issuer == "" || v.Sub == "" {
			return Recipient{}, errors.New("oidc.value must include both issuer and sub")
		}
		if strings.Contains(v.Issuer, "#") {
			return Recipient{}, errors.New("oidc issuer contains fragment")
		}
		if strings.Contains(v.Issuer, "?") {
			return Recipient{}, errors.New("oidc issuer contains query")
		}
		// Issuer is opaque per §7.7.3 — no normalisation.
		return Recipient{Type: TypeOIDC, Value: v}, nil

	case TypeDID:
		s, ok := r.Value.(string)
		if !ok {
			return Recipient{}, errors.New("did.value must be a string")
		}
		if !strings.HasPrefix(s, "did:") {
			return Recipient{}, errors.New("did.value must start with 'did:'")
		}
		methodAndID := s[len("did:"):]
		if strings.Contains(methodAndID, "/") {
			return Recipient{}, errors.New("did contains DID URL component (path)")
		}
		if strings.Contains(methodAndID, "#") {
			return Recipient{}, errors.New("did contains DID URL component (fragment)")
		}
		if strings.Contains(methodAndID, "?") {
			return Recipient{}, errors.New("did contains DID URL component (query)")
		}
		if strings.HasPrefix(s, "did:key:") {
			// decodeDidKey rejects any non-canonical encoding.
			if _, err := proto.DecodeDidKey(s); err != nil {
				return Recipient{}, fmt.Errorf("did:key not in canonical form: %w", err)
			}
			return Recipient{Type: TypeDID, Value: s}, nil
		}
		if strings.HasPrefix(s, "did:web:") {
			host := s[len("did:web:"):]
			if host != strings.ToLower(host) {
				return Recipient{}, errors.New("did:web host MUST be lowercase")
			}
			return Recipient{Type: TypeDID, Value: s}, nil
		}
		colon := strings.IndexByte(methodAndID, ':')
		method := methodAndID
		if colon >= 0 {
			method = methodAndID[:colon]
		}
		return Recipient{}, fmt.Errorf("unsupported did method in v0.1: %s", method)

	default:
		return Recipient{}, fmt.Errorf("unknown recipient type: %q", r.Type)
	}
}

// Parse converts a CLI-friendly string into a Recipient. Forms:
//
//	"alice@example.com"            → email shorthand (contains @)
//	"email:alice@example.com"      → explicit
//	"phone:+14155550173"
//	"did:key:z6Mk..."              → bare did:key
//	"did:did:key:z6Mk..."          → explicit did:<method>:<id>
//
// oidc is not parseable from a single string — use the type+issuer+sub
// flags on the command line.
//
// The returned Recipient is NOT yet normalised; call Normalise.
func Parse(s string) (Recipient, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Recipient{}, errors.New("recipient: empty")
	}
	if strings.HasPrefix(s, "email:") {
		return Recipient{Type: TypeEmail, Value: s[len("email:"):]}, nil
	}
	if strings.HasPrefix(s, "phone:") {
		return Recipient{Type: TypePhone, Value: s[len("phone:"):]}, nil
	}
	if strings.HasPrefix(s, "did:did:") {
		return Recipient{Type: TypeDID, Value: s[len("did:"):]}, nil
	}
	if strings.HasPrefix(s, "did:") {
		// `did:key:...` etc — type is implied by the value itself.
		return Recipient{Type: TypeDID, Value: s}, nil
	}
	if strings.Contains(s, "@") {
		return Recipient{Type: TypeEmail, Value: s}, nil
	}
	return Recipient{}, fmt.Errorf("recipient: cannot infer type from %q — use email:, phone:, did:, or pass --type", s)
}
