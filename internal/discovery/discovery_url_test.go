package discovery

import "testing"

// TestDiscoveryURL pins the §4.1 rule that a service reference resolves to
// its absolute /.well-known/afauth URL, defaulting to HTTPS when the caller
// passes a bare host. The bare-host cases capture the bug where
// `afauth signup api.example.com` failed with `unsupported protocol scheme ""`
// because no scheme was prepended.
func TestDiscoveryURL(t *testing.T) {
	const want = "https://api.example.com/.well-known/afauth"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare host defaults to https", "api.example.com", want},
		{"bare host trailing slash", "api.example.com/", want},
		{"https origin", "https://api.example.com", want},
		{"https origin trailing slash", "https://api.example.com/", want},
		{"already a well-known url", "https://api.example.com/.well-known/afauth", want},
		{"bare host with well-known path", "api.example.com/.well-known/afauth", want},
		// An explicit scheme is honoured, never silently upgraded — http
		// stays http (e.g. for local testing against a dev server).
		{"explicit http preserved", "http://localhost:8080", "http://localhost:8080/.well-known/afauth"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := discoveryURL(c.in); got != c.want {
				t.Fatalf("discoveryURL(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}
