package authentication

import (
	"errors"
	"fmt"
)

// StrongAuthenticationError is one stable, claim-free verifier outcome.
type StrongAuthenticationError uint8

const (
	// ErrStrongAuthenticationInvalid covers absent, mismatched, insufficient,
	// stale, or otherwise rejected strong-authentication evidence. Verifiers do
	// not expose which auth_time, acr, amr, identity, or proof check failed.
	ErrStrongAuthenticationInvalid StrongAuthenticationError = iota + 1
	// ErrStrongAuthenticationUnavailable means configured strong-auth trust or
	// verification infrastructure could not be used. Callers may retry within
	// their overall deadline without weakening the required policy.
	ErrStrongAuthenticationUnavailable
)

func (failure StrongAuthenticationError) Error() string {
	switch failure {
	case ErrStrongAuthenticationInvalid:
		return "strong-authentication-invalid"
	case ErrStrongAuthenticationUnavailable:
		return "strong-authentication-unavailable"
	default:
		return "strong-authentication-error"
	}
}

func (failure StrongAuthenticationError) String() string { return failure.Error() }
func (failure StrongAuthenticationError) GoString() string {
	// Preserve the long-standing port diagnostic now that ports re-exports this
	// core-owned type as an alias.
	return "ports.StrongAuthenticationError(" + failure.Error() + ")"
}

// ClassifyStrongAuthenticationError recognizes only the two closed verifier
// failure classes, including safely wrapped instances.
func ClassifyStrongAuthenticationError(err error) (StrongAuthenticationError, bool) {
	switch {
	case errors.Is(err, ErrStrongAuthenticationInvalid):
		return ErrStrongAuthenticationInvalid, true
	case errors.Is(err, ErrStrongAuthenticationUnavailable):
		return ErrStrongAuthenticationUnavailable, true
	default:
		return 0, false
	}
}

var (
	_ error          = ErrStrongAuthenticationInvalid
	_ fmt.Stringer   = ErrStrongAuthenticationInvalid
	_ fmt.GoStringer = ErrStrongAuthenticationInvalid
)
