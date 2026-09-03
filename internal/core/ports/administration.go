package ports

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArdurAI/veer/internal/core/domain/administration"
)

// StrongAuthenticationError is one stable, claim-free verifier outcome.
type StrongAuthenticationError uint8

const (
	// ErrStrongAuthenticationInvalid covers absent, mismatched, insufficient,
	// stale, or otherwise rejected strong-authentication evidence. Adapters do
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

// StrongAuthenticationVerifier revalidates one bearer credential against the
// exact Principal and elevation challenge, including the deployment's strong
// auth_time, acr, and amr policy, then returns a bound domain receipt.
//
// Principal intentionally lacks those strong-authentication claims. Merely
// receiving a valid Principal, or inspecting its groups or fingerprint, can
// never substitute for this port. No adapter implementation is supplied or
// implied by the reference interface.
//
// Implementations return ErrStrongAuthenticationInvalid for rejected proof,
// ErrStrongAuthenticationUnavailable for non-context verifier failures, and
// the caller's context error when cancellation or deadline expiry wins. Errors
// must not include credentials, claims, IDs, reasons, verifier responses, or
// endpoints.
type StrongAuthenticationVerifier interface {
	VerifyStrongAuthentication(
		ctx context.Context,
		credential BearerCredential,
		request administration.ElevationRequest,
	) (administration.StrongAuthReceipt, error)
}

var (
	_ error          = ErrStrongAuthenticationInvalid
	_ fmt.Stringer   = ErrStrongAuthenticationInvalid
	_ fmt.GoStringer = ErrStrongAuthenticationInvalid
)
