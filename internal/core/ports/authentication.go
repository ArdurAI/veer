// Package ports defines core-owned boundaries implemented by external
// adapters.
package ports

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArdurAI/veer/internal/core/domain/authentication"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
)

const (
	// MaxBearerTokenBytes preserves the port-level name for the shared core
	// credential bound.
	MaxBearerTokenBytes = authentication.MaxBearerTokenBytes
)

var (
	// ErrInvalidBearerCredential preserves the port-level classification for
	// callers while authentication owns the shared value object.
	ErrInvalidBearerCredential = authentication.ErrInvalidBearerCredential
	// ErrCredentialSerializationForbidden preserves the port-level
	// serialization canary for source compatibility.
	ErrCredentialSerializationForbidden = authentication.ErrCredentialSerializationForbidden
)

// AuthenticationError is one stable, token-free authentication outcome. Its
// numeric representation cannot itself retain untrusted diagnostic text.
type AuthenticationError uint8

const (
	// ErrAuthenticationInvalid means a credential was presented but did not
	// authenticate. It is intentionally indistinguishable across parse,
	// signature, key, issuer, audience, kind, and claim-validation failures.
	ErrAuthenticationInvalid AuthenticationError = iota + 1
	// ErrAuthenticationUnavailable means configured trust data could not be
	// obtained or used. Callers may retry within their overall deadline.
	ErrAuthenticationUnavailable
)

// Error returns only a closed stable classification.
func (failure AuthenticationError) Error() string {
	switch failure {
	case ErrAuthenticationInvalid:
		return "authentication-invalid"
	case ErrAuthenticationUnavailable:
		return "authentication-unavailable"
	default:
		return "authentication-error"
	}
}

// String returns only a closed stable classification.
func (failure AuthenticationError) String() string { return failure.Error() }

// GoString prevents an invalid underlying value from entering diagnostics.
func (failure AuthenticationError) GoString() string {
	return "ports.AuthenticationError(" + failure.Error() + ")"
}

// ClassifyAuthenticationError recognizes the two port-level failure classes,
// including safely wrapped instances.
func ClassifyAuthenticationError(err error) (AuthenticationError, bool) {
	switch {
	case errors.Is(err, ErrAuthenticationInvalid):
		return ErrAuthenticationInvalid, true
	case errors.Is(err, ErrAuthenticationUnavailable):
		return ErrAuthenticationUnavailable, true
	default:
		return 0, false
	}
}

// BearerCredential is the exact shared core bearer value. The alias keeps
// existing port and adapter signatures source-compatible.
type BearerCredential = authentication.BearerCredential

// NewBearerCredential validates the RFC 6750 b64token character envelope and
// takes an immutable string value. Scheme parsing remains a transport concern.
func NewBearerCredential(token string) (BearerCredential, error) {
	return authentication.NewBearerCredential(token)
}

// Authenticator validates one explicitly present bearer credential and returns
// a complete Principal. Missing credentials are represented by the transport
// layer and must not call this port; there is no anonymous Principal.
//
// Implementations return ErrAuthenticationInvalid for rejected credentials,
// ErrAuthenticationUnavailable for non-context trust-data failures, and the
// caller's context error when cancellation or deadline expiry wins. Returned
// errors must never wrap token, claim, endpoint, or provider response values.
type Authenticator interface {
	Authenticate(
		ctx context.Context,
		credential BearerCredential,
	) (identity.Principal, error)
}

// Compile-time guards keep safe diagnostic behavior part of the port contract.
var (
	_ error          = ErrAuthenticationInvalid
	_ error          = BearerCredential{}
	_ fmt.Formatter  = BearerCredential{}
	_ fmt.Stringer   = BearerCredential{}
	_ fmt.GoStringer = BearerCredential{}
)
