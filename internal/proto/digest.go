package proto

import (
	"crypto/sha256"
	"encoding/base64"
)

// SHA256ContentDigest returns the RFC 9530 §2 Content-Digest header
// value 'sha-256=:<base64>:' for the given body bytes.
func SHA256ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}
