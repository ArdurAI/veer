package administration

import (
	"context"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authentication"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

type StrongAuthenticationError = authentication.StrongAuthenticationError

const (
	ErrStrongAuthenticationInvalid     = authentication.ErrStrongAuthenticationInvalid
	ErrStrongAuthenticationUnavailable = authentication.ErrStrongAuthenticationUnavailable
)

func ClassifyStrongAuthenticationError(err error) (StrongAuthenticationError, bool) {
	return authentication.ClassifyStrongAuthenticationError(err)
}

// StrongAuthenticationVerifier revalidates one exact bearer credential
// against the exact immutable elevation challenge and the deployment's
// auth_time, acr, and amr policy. A successful result contains only inert
// proof metadata; Ledger is the sole consumer and issuance authority.
//
// Implementations return ErrStrongAuthenticationInvalid for rejected proof,
// ErrStrongAuthenticationUnavailable for non-context verifier failures, and
// the caller's context error when cancellation or deadline expiry wins. Errors
// must not include credentials, claims, IDs, reasons, verifier responses, or
// endpoints. Implementations must honor ctx and be safe for concurrent calls
// from shared Ledger copies.
type StrongAuthenticationVerifier interface {
	VerifyStrongAuthentication(
		ctx context.Context,
		credential authentication.BearerCredential,
		request ElevationRequest,
	) (proofID resource.ID, authenticatedAt time.Time, err error)
}

// Clock is the ledger's sole authority for strong-authentication verification
// and grant-issuance time. Implementations must be safe for concurrent calls
// and return promptly without re-entering the Ledger. Tests use deterministic
// implementations; runtime wiring must provide its trusted clock explicitly.
type Clock interface {
	Now() time.Time
}
