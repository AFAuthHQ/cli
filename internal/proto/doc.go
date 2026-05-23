// Package proto implements the AFAuth Protocol v0.1 wire primitives:
// did:key codec (§3.1.1), RFC 9421 canonical input construction (§5.2),
// and RFC 9530 content-digest (§5.2). These functions take and return
// raw bytes and strings only — they do no I/O, hold no state, and have
// no exposure to HTTP handler types — so the same code paths are used
// by signing, verification, and the offline test harness.
//
// The Go primitives in this package are a clean-room reimplementation
// of @afauth/core's wire layer. They MUST produce byte-identical output
// to the TypeScript SDK and to the Node harness for every committed
// signature vector under testdata/spec-vectors/signatures/.
package proto
