package proto

import "strings"

// Challenge is a parsed §5.7 `WWW-Authenticate: AFAuth` challenge. A service
// returns it on a 401 so an agent can self-bootstrap (Discovery) and route its
// recovery (Error, Attestors) without out-of-band knowledge.
type Challenge struct {
	// Discovery is the absolute URL of the service's /.well-known/afauth doc.
	Discovery string
	// Error mirrors the §11.1 body's error.code (a §11.3 reserved code).
	Error ErrorCode
	// Attestors is the accepted attestor identifier set (§10.3), if advertised.
	Attestors []string
	// OwnerLogin is a URL a human owner visits to authenticate, if advertised.
	OwnerLogin string
	// Realm is the RFC 9110 realm, conventionally the service_did, if present.
	Realm string
}

// ParseChallenge extracts the AFAuth challenge from a `WWW-Authenticate` header
// value (§5.7). It returns nil when no `AFAuth` scheme is present. It tolerates
// other auth-schemes sharing the header, quoted-string values, escapes, and
// comma/whitespace separation; unknown auth-params are ignored. A bare `AFAuth`
// advertisement (no params) yields a non-nil, empty Challenge.
func ParseChallenge(headerValue string) *Challenge {
	rest, ok := afterAuthScheme(headerValue, "afauth")
	if !ok {
		return nil
	}
	c := &Challenge{}
	for name, val := range parseAuthParams(rest) {
		switch name {
		case "discovery":
			c.Discovery = val
		case "error":
			c.Error = ErrorCode(val)
		case "attestors":
			c.Attestors = strings.Fields(val)
		case "owner_login":
			c.OwnerLogin = val
		case "realm":
			c.Realm = val
		}
	}
	return c
}

// afterAuthScheme returns the substring following the first whole-word match of
// scheme (lowercased) in s, and whether it was found. The scheme token must be
// at the start or preceded by space/tab/comma, and followed by space/tab/end.
func afterAuthScheme(s, scheme string) (string, bool) {
	ls := strings.ToLower(s)
	for i := 0; i+len(scheme) <= len(ls); i++ {
		if ls[i:i+len(scheme)] != scheme {
			continue
		}
		if i > 0 {
			if p := ls[i-1]; p != ' ' && p != '\t' && p != ',' {
				continue
			}
		}
		j := i + len(scheme)
		if j < len(ls) {
			if nx := ls[j]; nx != ' ' && nx != '\t' {
				continue
			}
		}
		return s[j:], true
	}
	return "", false
}

func isAuthTokenByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	default:
		return strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0
	}
}

// parseAuthParams scans `name=value` auth-params (RFC 9110 §11.2) into a map.
// Values are tokens or quoted-strings; a bare token without '=' is treated as
// the start of a different auth-scheme and stops the scan.
func parseAuthParams(s string) map[string]string {
	out := map[string]string{}
	pos, n := 0, len(s)
	for pos < n {
		for pos < n && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == ',') {
			pos++
		}
		if pos >= n {
			break
		}
		start := pos
		for pos < n && isAuthTokenByte(s[pos]) {
			pos++
		}
		name := strings.ToLower(s[start:pos])
		if name == "" {
			break
		}
		for pos < n && (s[pos] == ' ' || s[pos] == '\t') {
			pos++
		}
		if pos >= n || s[pos] != '=' {
			break // bare token w/o '=' → a different scheme; stop
		}
		pos++ // consume '='
		for pos < n && (s[pos] == ' ' || s[pos] == '\t') {
			pos++
		}
		var val string
		if pos < n && s[pos] == '"' {
			pos++
			var b strings.Builder
			for pos < n && s[pos] != '"' {
				if s[pos] == '\\' && pos+1 < n {
					pos++
				}
				b.WriteByte(s[pos])
				pos++
			}
			pos++ // closing quote
			val = b.String()
		} else {
			vs := pos
			for pos < n && isAuthTokenByte(s[pos]) {
				pos++
			}
			val = s[vs:pos]
		}
		out[name] = val
	}
	return out
}
