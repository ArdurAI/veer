package ports

import (
	"github.com/ArdurAI/veer/internal/core/domain/administration"
	"github.com/ArdurAI/veer/internal/core/domain/authentication"
)

// StrongAuthenticationError preserves the port-level name for the
// authentication-owned closed verifier outcome.
type StrongAuthenticationError = authentication.StrongAuthenticationError

const (
	// ErrStrongAuthenticationInvalid covers absent, mismatched, insufficient,
	// stale, or otherwise rejected strong-authentication evidence. Adapters do
	// not expose which auth_time, acr, amr, identity, or proof check failed.
	ErrStrongAuthenticationInvalid = authentication.ErrStrongAuthenticationInvalid
	// ErrStrongAuthenticationUnavailable means configured strong-auth trust or
	// verification infrastructure could not be used. Callers may retry within
	// their overall deadline without weakening the required policy.
	ErrStrongAuthenticationUnavailable = authentication.ErrStrongAuthenticationUnavailable
)

// ClassifyStrongAuthenticationError recognizes only the two closed verifier
// failure classes, including safely wrapped instances.
func ClassifyStrongAuthenticationError(err error) (StrongAuthenticationError, bool) {
	return authentication.ClassifyStrongAuthenticationError(err)
}

// StrongAuthenticationVerifier revalidates one bearer credential against the
// exact Principal and elevation challenge, including the deployment's strong
// auth_time, acr, and amr policy, then returns inert proof metadata consumed
// only by the configured Ledger.
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
type StrongAuthenticationVerifier = administration.StrongAuthenticationVerifier
