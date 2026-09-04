// Package reconciliation defines Veer's provider-free reliability reference
// model. It performs no persistence, queue I/O, provider calls, or retries.
package reconciliation

import "errors"

var (
	// ErrInvalidEvidence marks incomplete, forged, or mismatched plan evidence.
	ErrInvalidEvidence = errors.New("invalid reconciliation evidence")
	// ErrEvidenceTooLarge marks evidence whose canonical input exceeds the alpha bound.
	ErrEvidenceTooLarge = errors.New("reconciliation evidence exceeds alpha size limit")
	// ErrInvalidVersion marks an empty or non-canonical contract version.
	ErrInvalidVersion = errors.New("invalid reconciliation evidence version")
	// ErrInvalidDigest marks an uninitialized or malformed typed digest.
	ErrInvalidDigest = errors.New("invalid reconciliation digest")
	// ErrInvalidPlan marks an incomplete or internally inconsistent plan.
	ErrInvalidPlan = errors.New("invalid reconciliation plan")
	// ErrPlanMismatch marks plan, operation, or provider-binding disagreement.
	ErrPlanMismatch = errors.New("reconciliation plan binding mismatch")
	// ErrReplanBlocked marks a material replan whose predecessor is not definitive.
	ErrReplanBlocked = errors.New("reconciliation replan is blocked")
	// ErrCompletedEffectMissing marks a replan that would forget applied work.
	ErrCompletedEffectMissing = errors.New("completed reconciliation effect is missing")
	// ErrInvalidIdempotency marks an invalid scope, key, fingerprint, or result.
	ErrInvalidIdempotency = errors.New("invalid idempotency state")
	// ErrIdempotencyConflict marks a live key reused with different intent.
	ErrIdempotencyConflict = errors.New("idempotency key is bound to different intent")
	// ErrReservationOutstanding marks an unresolved reservation, including after expiry.
	ErrReservationOutstanding = errors.New("idempotency reservation outcome is unresolved")
	// ErrReservationLost marks a stale epoch attempting to complete a replacement record.
	ErrReservationLost = errors.New("idempotency reservation is no longer current")
	// ErrInvalidLease marks an invalid lease binding or token.
	ErrInvalidLease = errors.New("invalid reconciliation lease")
	// ErrLeaseHeld marks a lineage with a still-live owner.
	ErrLeaseHeld = errors.New("reconciliation lease is already held")
	// ErrLeaseLost marks an expired, surrendered, or superseded lease token.
	ErrLeaseLost = errors.New("reconciliation lease is no longer authoritative")
	// ErrFenceExhausted prevents a signed PostgreSQL bigint fence from wrapping.
	ErrFenceExhausted = errors.New("reconciliation fence is exhausted")
	// ErrDispatchWindow marks a lease too short for the RPC deadline and safety margin.
	ErrDispatchWindow = errors.New("provider dispatch window is insufficient")
	// ErrDispatchAuthority marks stale or mismatched execution-time evidence.
	ErrDispatchAuthority = errors.New("provider dispatch authority is invalid")
	// ErrInvalidAttempt marks an incomplete or internally inconsistent physical attempt.
	ErrInvalidAttempt = errors.New("invalid reconciliation attempt")
	// ErrInvalidTransition marks a forbidden attempt-state transition.
	ErrInvalidTransition = errors.New("invalid reconciliation transition")
	// ErrAttemptNotDefinitive marks active physical work or non-definitive logical effect truth.
	ErrAttemptNotDefinitive = errors.New("reconciliation attempt is not definitive")
	// ErrRetryForbidden marks a retry without proven no-effect or qualified idempotency.
	ErrRetryForbidden = errors.New("reconciliation retry is forbidden")
	// ErrGenerationBlocked marks a newer conflicting effect fenced by older uncertainty.
	ErrGenerationBlocked = errors.New("reconciliation generation is blocked by prior effect")
	// ErrInvalidSupersessionProof marks adapter evidence that does not bind both effects.
	ErrInvalidSupersessionProof = errors.New("invalid safe-supersession proof")
	// ErrInvalidObservation marks an invalid or regressing observation budget transition.
	ErrInvalidObservation = errors.New("invalid reconciliation observation")
	// ErrObservationExhausted marks work routed exactly once to quarantine/manual recovery.
	ErrObservationExhausted = errors.New("reconciliation observation budget is exhausted")
	// ErrInvalidDelivery marks an invalid work or queue delivery identity.
	ErrInvalidDelivery = errors.New("invalid reconciliation delivery")
	// ErrCapacity marks a bounded reference ledger with no remaining entries.
	ErrCapacity = errors.New("reconciliation reference capacity exceeded")
	// ErrInvalidRetention marks an invalid effect-evidence retention input.
	ErrInvalidRetention = errors.New("invalid reconciliation retention input")
	// ErrInvalidTime marks zero, out-of-range, or non-canonical model time.
	ErrInvalidTime = errors.New("invalid reconciliation time")
	// ErrClockRegressed marks authoritative database time moving behind prior evidence.
	ErrClockRegressed = errors.New("reconciliation clock regressed")
	// ErrSerializationForbidden prevents opaque runtime state from becoming a wire contract.
	ErrSerializationForbidden = errors.New("reconciliation serialization forbidden")
)
