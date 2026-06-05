package proto

import (
	"reflect"
	"testing"
)

func TestParseChallenge(t *testing.T) {
	const disc = "https://api.example.com/.well-known/afauth"
	tests := []struct {
		name string
		in   string
		want *Challenge
	}{
		{
			name: "no AFAuth scheme",
			in:   `Bearer realm="x", error="invalid_token"`,
			want: nil,
		},
		{
			name: "empty header",
			in:   "",
			want: nil,
		},
		{
			name: "discovery + token error",
			in:   `AFAuth discovery="` + disc + `", error=invalid_signature`,
			want: &Challenge{Discovery: disc, Error: ErrInvalidSignature},
		},
		{
			name: "attestation_required with multi-attestor list",
			in:   `AFAuth discovery="` + disc + `", error=attestation_required, attestors="afauth-trust microsoft-entra-agent-id"`,
			want: &Challenge{Discovery: disc, Error: ErrAttestationRequired, Attestors: []string{"afauth-trust", "microsoft-entra-agent-id"}},
		},
		{
			name: "coexists with another scheme",
			in:   `Bearer realm="x", AFAuth discovery="` + disc + `", error=revoked_key`,
			want: &Challenge{Discovery: disc, Error: ErrRevokedKey},
		},
		{
			name: "unknown params ignored",
			in:   `AFAuth discovery="` + disc + `", future_param=xyz`,
			want: &Challenge{Discovery: disc},
		},
		{
			name: "escaped quoted value",
			in:   `AFAuth error="weird \"q\" value"`,
			want: &Challenge{Error: `weird "q" value`},
		},
		{
			name: "bare advertisement",
			in:   "AFAuth",
			want: &Challenge{},
		},
		{
			name: "case-insensitive scheme",
			in:   `afauth error=expired_signature`,
			want: &Challenge{Error: ErrExpiredSignature},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseChallenge(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseChallenge(%q)\n  got  %+v\n  want %+v", tt.in, got, tt.want)
			}
		})
	}
}
