package discovery

import "testing"

func TestVerifyServiceDIDOrigin(t *testing.T) {
	cases := []struct {
		name       string
		serviceDID string
		host       string
		wantErr    bool
	}{
		{"did:web matches host", "did:web:api.example.com", "api.example.com", false},
		{"did:web case-insensitive", "did:web:API.Example.COM", "api.example.com", false},
		{"did:web mismatch is the confused-deputy", "did:web:bank.com", "evil.example", true},
		{"did:web with path segment matches on host", "did:web:api.example.com:tenant1", "api.example.com", false},
		{"did:web with encoded port matches host:port", "did:web:localhost%3A8443", "localhost:8443", false},
		{"did:key has no DNS anchor — not rejected here", "did:key:z6Mkabc", "evil.example", false},
		{"empty did is not a did:web mismatch", "", "evil.example", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyServiceDIDOrigin(tc.serviceDID, tc.host)
			if tc.wantErr && err == nil {
				t.Fatalf("VerifyServiceDIDOrigin(%q,%q) = nil, want error", tc.serviceDID, tc.host)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("VerifyServiceDIDOrigin(%q,%q) = %v, want nil", tc.serviceDID, tc.host, err)
			}
		})
	}
}

func TestIsDIDWeb(t *testing.T) {
	if !IsDIDWeb("did:web:x.com") {
		t.Fatal("did:web should be recognised")
	}
	if IsDIDWeb("did:key:z6Mk") {
		t.Fatal("did:key is not did:web")
	}
}
