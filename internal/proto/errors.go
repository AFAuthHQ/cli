package proto

import "fmt"

// ErrorCode is one of the §11.3 reserved AFAuth error codes.
type ErrorCode string

const (
	ErrInvalidSignature            ErrorCode = "invalid_signature"
	ErrExpiredSignature            ErrorCode = "expired_signature"
	ErrReplayedNonce               ErrorCode = "replayed_nonce"
	ErrUnknownAccount              ErrorCode = "unknown_account"
	ErrRevokedKey                  ErrorCode = "revoked_key"
	ErrInvalidAttestation          ErrorCode = "invalid_attestation"
	ErrAttestationRequired         ErrorCode = "attestation_required"
	ErrInvitationExpired           ErrorCode = "invitation_expired"
	ErrInvitationNotFound          ErrorCode = "invitation_not_found"
	ErrAlreadyClaimed              ErrorCode = "already_claimed"
	ErrNotClaimed                  ErrorCode = "not_claimed"
	ErrOwnerAuthenticationRequired ErrorCode = "owner_authentication_required"
	ErrOwnerBindingBlocked         ErrorCode = "owner_binding_blocked"
	ErrAccountExpired              ErrorCode = "account_expired"
	ErrRateLimitExceeded           ErrorCode = "rate_limit_exceeded"
	ErrMalformedRequest            ErrorCode = "malformed_request"
	ErrUnsupportedRecipientType    ErrorCode = "unsupported_recipient_type"
	// §7.5 freshness floor — owner-authenticated session present but stale.
	ErrOwnerSessionTooStale ErrorCode = "owner_session_too_stale"
)

// Error is the parsed AFAuth error envelope from §11.1. It is returned
// by the CLI's HTTP layer when a service responds with an AFAuth error
// shape; non-AFAuth HTTP errors are surfaced as plain Go errors.
type Error struct {
	HTTPStatus int       `json:"-"`
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	Details    any       `json:"details,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("afauth %d %s: %s", e.HTTPStatus, e.Code, e.Message)
}
