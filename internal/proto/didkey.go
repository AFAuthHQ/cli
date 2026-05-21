package proto

import (
	"fmt"
	"math/big"
)

// Ed25519PubKeyLen is the size of a raw Ed25519 public key in bytes.
const Ed25519PubKeyLen = 32

// ed25519PubMulticodec is the unsigned-varint encoding of the multicodec
// code 0xed (ed25519-pub). Per the multicodec registry, 0xed is a
// single-byte value but it is published as a two-byte LEB128 form
// 0xed 0x01 to match the on-wire encoding used by did:key.
var ed25519PubMulticodec = []byte{0xed, 0x01}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58Index = func() map[byte]int {
	m := make(map[byte]int, len(base58Alphabet))
	for i := 0; i < len(base58Alphabet); i++ {
		m[base58Alphabet[i]] = i
	}
	return m
}()

// base58btcEncode encodes a byte slice using the Bitcoin base58 alphabet.
// Leading zero bytes are preserved as leading '1' characters per the
// multibase encoding rules.
func base58btcEncode(in []byte) string {
	leadingZeros := 0
	for _, b := range in {
		if b == 0 {
			leadingZeros++
			continue
		}
		break
	}
	n := new(big.Int).SetBytes(in)
	fiftyEight := big.NewInt(58)
	mod := new(big.Int)
	var body []byte
	for n.Sign() > 0 {
		n.QuoRem(n, fiftyEight, mod)
		body = append([]byte{base58Alphabet[mod.Int64()]}, body...)
	}
	out := make([]byte, 0, leadingZeros+len(body))
	for i := 0; i < leadingZeros; i++ {
		out = append(out, '1')
	}
	out = append(out, body...)
	return string(out)
}

// base58btcDecode is the inverse of base58btcEncode. Returns an error
// if the input contains any character not in the base58 alphabet.
func base58btcDecode(s string) ([]byte, error) {
	leadingZeros := 0
	for _, ch := range []byte(s) {
		if ch == '1' {
			leadingZeros++
			continue
		}
		break
	}
	n := new(big.Int)
	fiftyEight := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		v, ok := base58Index[s[i]]
		if !ok {
			return nil, fmt.Errorf("invalid base58 character at index %d: %q", i, s[i])
		}
		n.Mul(n, fiftyEight)
		n.Add(n, big.NewInt(int64(v)))
	}
	body := n.Bytes()
	out := make([]byte, leadingZeros+len(body))
	copy(out[leadingZeros:], body)
	return out, nil
}

// EncodeDidKey wraps a raw Ed25519 public key in the did:key canonical
// form: "did:key:z" + base58btc(0xed 0x01 || pubkey). Per §3.1.1.
func EncodeDidKey(pubkey []byte) (string, error) {
	if len(pubkey) != Ed25519PubKeyLen {
		return "", fmt.Errorf("ed25519 public key must be %d bytes, got %d", Ed25519PubKeyLen, len(pubkey))
	}
	buf := make([]byte, 0, len(ed25519PubMulticodec)+Ed25519PubKeyLen)
	buf = append(buf, ed25519PubMulticodec...)
	buf = append(buf, pubkey...)
	return "did:key:z" + base58btcEncode(buf), nil
}

// DecodeDidKey extracts the raw Ed25519 public key from a did:key string.
// Returns an error if the prefix is not "did:key:z", the base58btc body
// is malformed, the multicodec is not ed25519-pub (0xed 0x01), or the
// trailing payload is not 32 bytes.
func DecodeDidKey(did string) ([]byte, error) {
	const prefix = "did:key:z"
	if len(did) <= len(prefix) || did[:len(prefix)] != prefix {
		return nil, fmt.Errorf("not a did:key:z... value: %q", did)
	}
	decoded, err := base58btcDecode(did[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("did:key base58 decode: %w", err)
	}
	if len(decoded) < len(ed25519PubMulticodec)+Ed25519PubKeyLen {
		return nil, fmt.Errorf("did:key payload too short: %d bytes", len(decoded))
	}
	if decoded[0] != ed25519PubMulticodec[0] || decoded[1] != ed25519PubMulticodec[1] {
		return nil, fmt.Errorf("unsupported multicodec prefix: 0x%02x%02x (only ed25519-pub 0xed01 in v0.1)", decoded[0], decoded[1])
	}
	pubkey := decoded[len(ed25519PubMulticodec):]
	if len(pubkey) != Ed25519PubKeyLen {
		return nil, fmt.Errorf("ed25519 public key must be %d bytes, got %d", Ed25519PubKeyLen, len(pubkey))
	}
	return pubkey, nil
}
