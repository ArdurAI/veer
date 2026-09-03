package ports

import (
	"context"
	"fmt"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
)

// SecretReadPriority selects one of the durable cost-ledger partitions. A
// normal cache miss uses General; an explicit credential rotation uses
// Critical so recovery work cannot consume the general request partition.
type SecretReadPriority uint8

const (
	SecretReadGeneral SecretReadPriority = iota + 1
	SecretReadCritical
)

// Valid reports whether priority is part of the closed broker contract.
func (priority SecretReadPriority) Valid() bool {
	return priority == SecretReadGeneral || priority == SecretReadCritical
}

func (priority SecretReadPriority) String() string {
	switch priority {
	case SecretReadGeneral:
		return "secret-read-general"
	case SecretReadCritical:
		return "secret-read-critical"
	default:
		return "secret-read-priority-invalid"
	}
}

func (priority SecretReadPriority) GoString() string {
	return "ports.SecretReadPriority(" + priority.String() + ")"
}

// SecretReadOutcome records whether an already-claimed external-secret read
// consumed durable budget. Uncertain dispatch is retained, never released.
type SecretReadOutcome uint8

const (
	// SecretReadConsumed means the backend definitely received the read or
	// returned a response, including a provider-declared error response.
	SecretReadConsumed SecretReadOutcome = iota + 1
	// SecretReadReleased means the resolver can prove that no backend request
	// was dispatched, so the durable claim may be returned to its partition.
	SecretReadReleased
	// SecretReadRetained means dispatch is uncertain. The durable claim must be
	// retained to prevent retries from bypassing the cost cap.
	SecretReadRetained
)

// Valid reports whether outcome is part of the closed settlement contract.
func (outcome SecretReadOutcome) Valid() bool {
	switch outcome {
	case SecretReadConsumed, SecretReadReleased, SecretReadRetained:
		return true
	default:
		return false
	}
}

func (outcome SecretReadOutcome) String() string {
	switch outcome {
	case SecretReadConsumed:
		return "secret-read-consumed"
	case SecretReadReleased:
		return "secret-read-released"
	case SecretReadRetained:
		return "secret-read-retained"
	default:
		return "secret-read-outcome-invalid"
	}
}

func (outcome SecretReadOutcome) GoString() string {
	return "ports.SecretReadOutcome(" + outcome.String() + ")"
}

// SecretReadClaim is one durable reservation returned by SecretReadBudget.
// The broker calls Settle exactly once after a successful Claim. Implementors
// must make settlement idempotent because a process can stop after dispatch.
// A settlement error is interpreted as retained, never as released.
type SecretReadClaim interface {
	Settle(ctx context.Context, outcome SecretReadOutcome) error
}

// SecretReadBudget is the durable, region/profile/window cost-control gate.
// An in-memory cache or single-flight group is not a substitute for this port.
// Claim must fail closed when its durable state is missing or too stale.
type SecretReadBudget interface {
	Claim(
		ctx context.Context,
		lookup credential.SourceLookup,
		priority SecretReadPriority,
	) (SecretReadClaim, error)
}

// SecretResolver reads exactly one versioned source reference. Ownership of a
// non-nil result transfers to the broker on every return path; implementations
// must not retain or destroy it after returning. A successful result requires
// SecretReadConsumed. On failure the outcome says how the durable claim must
// be settled. Context cancellation must be returned as ctx.Err().
type SecretResolver interface {
	Resolve(
		ctx context.Context,
		lookup credential.SourceLookup,
	) (*credential.SourceMaterial, SecretReadOutcome, error)
}

// RevocationResult is a closed aggregate describing the strongest remaining
// upstream authority after local invalidation. Ordering is intentionally not
// encoded in the numeric values; callers must use broker lifecycle results.
type RevocationResult uint8

const (
	// RevocationNotRequired means no live issued session required a provider
	// revocation attempt.
	RevocationNotRequired RevocationResult = iota + 1
	// RevocationProviderConfirmed means every attempted provider revocation was
	// confirmed by its issuer.
	RevocationProviderConfirmed
	// RevocationExpiryBound means upstream authority cannot be revoked, but all
	// affected sessions remain bounded by their provider expiration.
	RevocationExpiryBound
	// RevocationPending means at least one revocation is unconfirmed or failed.
	RevocationPending
)

// Valid reports whether result belongs to the closed revocation vocabulary.
func (result RevocationResult) Valid() bool {
	switch result {
	case RevocationNotRequired, RevocationProviderConfirmed,
		RevocationExpiryBound, RevocationPending:
		return true
	default:
		return false
	}
}

func (result RevocationResult) String() string {
	switch result {
	case RevocationNotRequired:
		return "revocation-not-required"
	case RevocationProviderConfirmed:
		return "revocation-provider-confirmed"
	case RevocationExpiryBound:
		return "revocation-expiry-bound"
	case RevocationPending:
		return "revocation-pending"
	default:
		return "revocation-result-invalid"
	}
}

func (result RevocationResult) GoString() string {
	return "ports.RevocationResult(" + result.String() + ")"
}

// SessionIssuer exchanges borrowed source material for one bounded provider
// session. Issue-result ownership always transfers to the broker, including
// when err is non-nil. The issuer borrows source and must neither retain nor
// destroy it. Revoke similarly borrows session for one bounded call.
// Implementations may honestly return RevocationExpiryBound when their
// provider exposes no immediate revocation primitive. Context cancellation
// must be returned as ctx.Err().
type SessionIssuer interface {
	Issue(
		ctx context.Context,
		request credential.Request,
		source *credential.SourceMaterial,
	) (*credential.IssuedSession, error)
	Revoke(
		ctx context.Context,
		request credential.Request,
		session *credential.IssuedSession,
	) (RevocationResult, error)
}

var (
	_ fmt.Stringer   = SecretReadGeneral
	_ fmt.GoStringer = SecretReadGeneral
	_ fmt.Stringer   = SecretReadConsumed
	_ fmt.GoStringer = SecretReadConsumed
	_ fmt.Stringer   = RevocationNotRequired
	_ fmt.GoStringer = RevocationNotRequired
)
