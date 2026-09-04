package reconciliation

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// AttemptInput supplies one unique physical call prepared under an exact plan and fence.
type AttemptInput struct {
	ID        resource.ID
	Ordinal   uint32
	Admission AttemptAdmission
	OwnerID   resource.ID
	Fence     int64
}

// Attempt is one immutable snapshot of a physical provider call. Prepared and
// Dispatched are unresolved; Indeterminate is resolved but not definitive.
type Attempt struct {
	initialized         bool
	id                  resource.ID
	ordinal             uint32
	planDigest          PlanDigest
	planKind            PlanKind
	effect              EffectKey
	purpose             AttemptPurpose
	ownerID             resource.ID
	fence               int64
	requestFingerprint  RequestFingerprint
	compensation        *CompensationStep
	observationTarget   *EffectProjection
	cancellationTarget  *EffectProjection
	retryValidUntil     time.Time
	observationBinding  digestValue
	observationDeadline time.Time
	admissionBinding    digestValue
	state               AttemptState
	preparedAt          time.Time
	dispatchedAt        time.Time
	resolvedAt          time.Time
}

// NewPreparedAttempt creates the durable state required before any provider call.
func NewPreparedAttempt(input AttemptInput) (Attempt, error) {
	if !validID(input.ID) || input.Ordinal == 0 || validateAttemptAdmission(input.Admission) != nil ||
		!validID(input.OwnerID) || input.Fence < 1 {
		return Attempt{}, ErrInvalidAttempt
	}
	var compensation *CompensationStep
	if input.Admission.compensation != nil {
		copy := *input.Admission.compensation
		compensation = &copy
	}
	var cancellationTarget *EffectProjection
	if input.Admission.cancellationTarget != nil {
		copy := cloneEffectProjection(*input.Admission.cancellationTarget)
		cancellationTarget = &copy
	}
	var observationTarget *EffectProjection
	if input.Admission.observationTarget != nil {
		copy := cloneEffectProjection(*input.Admission.observationTarget)
		observationTarget = &copy
	}
	if input.Admission.replacementTransition != nil {
		if !input.Admission.replacementTransition.CompareAndSwap(1, 2) {
			return Attempt{}, ErrInvalidAttempt
		}
	} else if input.Admission.observationTransition != nil {
		if !input.Admission.observationTransition.CompareAndSwap(observationAdmitted, observationPrepared) {
			return Attempt{}, ErrInvalidAttempt
		}
	} else if !input.Admission.use.CompareAndSwap(false, true) {
		return Attempt{}, ErrInvalidAttempt
	}
	return Attempt{
		initialized:         true,
		id:                  input.ID,
		ordinal:             input.Ordinal,
		planDigest:          input.Admission.planDigest,
		planKind:            input.Admission.planKind,
		effect:              input.Admission.effect,
		purpose:             input.Admission.purpose,
		ownerID:             input.OwnerID,
		fence:               input.Fence,
		requestFingerprint:  input.Admission.requestFingerprint,
		compensation:        compensation,
		observationTarget:   observationTarget,
		cancellationTarget:  cancellationTarget,
		retryValidUntil:     input.Admission.retryValidUntil,
		observationBinding:  input.Admission.observationBinding,
		observationDeadline: input.Admission.observationDeadline,
		admissionBinding:    input.Admission.binding,
		state:               AttemptStatePrepared,
		preparedAt:          input.Admission.authorizedAt,
	}, nil
}

// MarkAttemptDispatched records the physical-call boundary only while the
// permit's exact lease row is still live. Surrender, replacement, and takeover
// serialize with this check through the LeaseTable lock.
func (table *LeaseTable) MarkAttemptDispatched(
	before Attempt,
	permit DispatchPermit,
	dispatchedAt time.Time,
) (Attempt, error) {
	if table == nil || !table.initialized || ValidateAttempt(before) != nil || before.state != AttemptStatePrepared ||
		validateDispatchPermit(permit) != nil ||
		!equalDigest(permit.attemptBinding, deriveAttemptDispatchBinding(before)) ||
		!permit.token.binding.planDigest.Equal(before.planDigest) ||
		permit.token.ownerID != before.ownerID || permit.token.fence != before.fence {
		return before, ErrInvalidTransition
	}
	if permit.token.table != table.identity {
		return before, ErrLeaseLost
	}
	at, err := normalizeTime(dispatchedAt)
	if err != nil || at.Before(before.preparedAt) || at.Before(permit.authorizedAt) || !at.Before(permit.deadline) ||
		(!before.retryValidUntil.IsZero() && !at.Before(before.retryValidUntil)) ||
		(!before.observationDeadline.IsZero() && !at.Before(before.observationDeadline)) {
		return before, ErrInvalidTransition
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	key := leaseRowKey(permit.token.binding)
	if err := table.observeNowLocked(key, at); err != nil {
		return before, err
	}
	if _, ok := table.currentRowLocked(at, permit.token); !ok {
		return before, ErrLeaseLost
	}
	if !permit.use.CompareAndSwap(false, true) {
		return before, ErrInvalidTransition
	}
	after := before
	after.state = AttemptStateDispatched
	after.dispatchedAt = at
	return after, nil
}

// ResolveAttempt records one provider-effect truth after a dispatched call.
func ResolveAttempt(before Attempt, outcome EffectState, resolvedAt time.Time) (Attempt, error) {
	if ValidateAttempt(before) != nil || before.state != AttemptStateDispatched || !validEffectState(outcome) {
		return before, ErrInvalidTransition
	}
	at, err := normalizeTime(resolvedAt)
	if err != nil || at.Before(before.dispatchedAt) {
		return before, ErrInvalidTransition
	}
	after := before
	after.state = AttemptState(outcome)
	after.resolvedAt = at
	return after, nil
}

// RecoverAttempt applies the conservative owner-loss rule. Only a live proof
// that dispatch never began can turn Prepared into NoEffect.
func RecoverAttempt(before Attempt, proof DispatchProof, recoveredAt time.Time) (Attempt, error) {
	if ValidateAttempt(before) != nil || before.Resolved() {
		return before, ErrInvalidTransition
	}
	at, err := normalizeTime(recoveredAt)
	if err != nil || at.Before(attemptLatestAt(before)) {
		return before, ErrInvalidTransition
	}
	after := before
	switch {
	case before.state == AttemptStatePrepared && proof == DispatchProofNeverBegan:
		after.state = AttemptStateNoEffect
	case (before.state == AttemptStatePrepared || before.state == AttemptStateDispatched) && proof == DispatchProofUnknown:
		after.state = AttemptStateIndeterminate
	default:
		return before, ErrInvalidTransition
	}
	after.resolvedAt = at
	return after, nil
}

// ApplyMaintenanceOutcome fails closed on store-lease or visibility ambiguity.
// Maintenance failure alone never proves that a prepared provider call did not
// begin, so every unresolved attempt becomes Indeterminate.
func ApplyMaintenanceOutcome(
	before Attempt,
	kind MaintenanceKind,
	outcome MaintenanceOutcome,
	observedAt time.Time,
) (Attempt, MaintenanceDirective, error) {
	if ValidateAttempt(before) != nil || !validMaintenanceKind(kind) || !validMaintenanceOutcome(outcome) {
		return before, "", ErrInvalidTransition
	}
	at, err := normalizeTime(observedAt)
	if err != nil || at.Before(attemptLatestAt(before)) {
		return before, "", ErrInvalidTransition
	}
	if outcome == MaintenanceSucceeded {
		return before, MaintenanceContinue, nil
	}
	if before.Resolved() {
		return before, MaintenanceStopAndSurrender, nil
	}
	after, err := RecoverAttempt(before, DispatchProofUnknown, at)
	if err != nil {
		return before, "", err
	}
	return after, MaintenanceStopAndSurrender, nil
}

func attemptLatestAt(value Attempt) time.Time {
	if !value.resolvedAt.IsZero() {
		return value.resolvedAt
	}
	if !value.dispatchedAt.IsZero() {
		return value.dispatchedAt
	}
	return value.preparedAt
}

// ValidateAttempt checks one complete physical-attempt snapshot.
func ValidateAttempt(value Attempt) error {
	if !value.initialized || !validID(value.id) || value.ordinal == 0 || !value.planDigest.initialized ||
		ValidateEffectKey(value.effect) != nil || !validID(value.ownerID) || value.fence < 1 ||
		!value.requestFingerprint.initialized || !value.admissionBinding.initialized || value.preparedAt.IsZero() {
		return ErrInvalidAttempt
	}
	if _, err := ParsePlanKind(value.planKind.String()); err != nil {
		return ErrInvalidAttempt
	}
	if _, err := ParseAttemptPurpose(value.purpose.String()); err != nil {
		return ErrInvalidAttempt
	}
	if _, err := ParseAttemptState(value.state.String()); err != nil {
		return ErrInvalidAttempt
	}
	if !attemptPurposeMatchesPlan(value.purpose, value.planKind) {
		return ErrInvalidAttempt
	}
	if value.purpose == AttemptPurposeCompensation {
		if value.compensation == nil || !validCompensationStep(*value.compensation) ||
			!value.compensation.planDigest.Equal(value.planDigest) ||
			!value.compensation.inverse.Equal(value.effect) {
			return ErrInvalidAttempt
		}
	} else if value.compensation != nil {
		return ErrInvalidAttempt
	}
	if value.purpose == AttemptPurposeProviderCancel {
		if value.cancellationTarget == nil ||
			!validCancellationTarget(*value.cancellationTarget, value.planDigest, value.planKind, value.effect) {
			return ErrInvalidAttempt
		}
	} else if value.cancellationTarget != nil {
		return ErrInvalidAttempt
	}
	if !value.retryValidUntil.IsZero() {
		until, err := normalizeTime(value.retryValidUntil)
		if err != nil || !until.Equal(value.retryValidUntil) || !until.After(value.preparedAt) ||
			(value.purpose != AttemptPurposeForward && value.purpose != AttemptPurposeCompensation &&
				value.purpose != AttemptPurposeProviderCancel) {
			return ErrInvalidAttempt
		}
	}
	if value.purpose == AttemptPurposeObservation {
		deadline, err := normalizeTime(value.observationDeadline)
		if !value.observationBinding.initialized || value.observationTarget == nil ||
			err != nil || !deadline.Equal(value.observationDeadline) ||
			!value.preparedAt.Before(value.observationDeadline) ||
			!validObservationTarget(*value.observationTarget, value.planDigest, value.planKind, value.effect) {
			return ErrInvalidAttempt
		}
	} else if value.observationBinding.initialized || !value.observationDeadline.IsZero() ||
		value.observationTarget != nil {
		return ErrInvalidAttempt
	}
	switch value.state {
	case AttemptStatePrepared:
		if !value.dispatchedAt.IsZero() || !value.resolvedAt.IsZero() {
			return ErrInvalidAttempt
		}
	case AttemptStateDispatched:
		if value.dispatchedAt.Before(value.preparedAt) || value.dispatchedAt.IsZero() || !value.resolvedAt.IsZero() {
			return ErrInvalidAttempt
		}
	case AttemptStateApplied:
		if value.dispatchedAt.IsZero() || value.resolvedAt.Before(value.dispatchedAt) {
			return ErrInvalidAttempt
		}
	case AttemptStateNoEffect, AttemptStateIndeterminate:
		latestRequired := value.preparedAt
		if !value.dispatchedAt.IsZero() {
			latestRequired = value.dispatchedAt
		}
		if value.resolvedAt.Before(latestRequired) || value.resolvedAt.IsZero() {
			return ErrInvalidAttempt
		}
	}
	return nil
}

func (value Attempt) ID() resource.ID                        { return value.id }
func (value Attempt) Ordinal() uint32                        { return value.ordinal }
func (value Attempt) PlanDigest() PlanDigest                 { return value.planDigest }
func (value Attempt) Effect() EffectKey                      { return value.effect }
func (value Attempt) Purpose() AttemptPurpose                { return value.purpose }
func (value Attempt) OwnerID() resource.ID                   { return value.ownerID }
func (value Attempt) Fence() int64                           { return value.fence }
func (value Attempt) RequestFingerprint() RequestFingerprint { return value.requestFingerprint }
func (value Attempt) CompensationStep() (CompensationStep, bool) {
	if value.compensation == nil {
		return CompensationStep{}, false
	}
	return *value.compensation, true
}

// CancellationTarget identifies the separate business effect targeted by a
// provider-cancellation attempt.
func (value Attempt) CancellationTarget() (EffectKey, bool) {
	if value.cancellationTarget == nil {
		return EffectKey{}, false
	}
	return value.cancellationTarget.key, true
}
func (value Attempt) State() AttemptState   { return value.state }
func (value Attempt) PreparedAt() time.Time { return value.preparedAt }
func (value Attempt) DispatchedAt() (time.Time, bool) {
	return value.dispatchedAt, !value.dispatchedAt.IsZero()
}
func (value Attempt) ResolvedAt() (time.Time, bool) {
	return value.resolvedAt, !value.resolvedAt.IsZero()
}

// ObservationDeadline returns the finite dispatch boundary carried only by an
// observation attempt. Equality with the deadline is not dispatchable.
func (value Attempt) ObservationDeadline() (time.Time, bool) {
	return value.observationDeadline, !value.observationDeadline.IsZero()
}

// Resolved reports whether no further state transition is accepted for this attempt.
func (value Attempt) Resolved() bool {
	switch value.state {
	case AttemptStateApplied, AttemptStateNoEffect, AttemptStateIndeterminate:
		return true
	default:
		return false
	}
}

// Definitive reports whether provider effect truth is proven rather than unknown.
func (value Attempt) Definitive() bool {
	return value.state == AttemptStateApplied || value.state == AttemptStateNoEffect
}

func (value Attempt) String() string {
	if ValidateAttempt(value) != nil {
		return "reconciliation-attempt(invalid)"
	}
	return fmt.Sprintf("reconciliation-attempt(state=%s,purpose=%s,ordinal=%d,identity=redacted)", value.state, value.purpose, value.ordinal)
}
func (value Attempt) GoString() string                  { return value.String() }
func (value Attempt) Format(state fmt.State, verb rune) { writeSafeFormat(state, verb, value.String()) }
func (value Attempt) LogValue() slog.Value              { return redactedLogValue(value.String()) }

// EffectProjection is the bounded current truth used for retry, generation,
// observation, and provider-cancellation gates.
type EffectProjection struct {
	initialized        bool
	key                EffectKey
	planDigest         PlanDigest
	sourceAttemptID    resource.ID
	purpose            AttemptPurpose
	compensation       *CompensationStep
	cancellationTarget *EffectKey
	state              AttemptState
	updatedAt          time.Time
}

// EffectProjectionFromAttempt reduces one non-observation attempt to current
// provider-effect evidence. Observation results must pass through
// CompleteObservation's exact-current-effect compare-and-swap transition.
func EffectProjectionFromAttempt(attempt Attempt) (EffectProjection, error) {
	if ValidateAttempt(attempt) != nil {
		return EffectProjection{}, ErrInvalidAttempt
	}
	updatedAt := attempt.preparedAt
	if !attempt.resolvedAt.IsZero() {
		updatedAt = attempt.resolvedAt
	} else if !attempt.dispatchedAt.IsZero() {
		updatedAt = attempt.dispatchedAt
	}
	if attempt.purpose == AttemptPurposeObservation {
		return EffectProjection{}, ErrInvalidObservation
	}
	var compensation *CompensationStep
	if attempt.compensation != nil {
		copy := *attempt.compensation
		compensation = &copy
	}
	var cancellationTarget *EffectKey
	if attempt.cancellationTarget != nil {
		copy := attempt.cancellationTarget.key
		cancellationTarget = &copy
	}
	return EffectProjection{
		initialized:        true,
		key:                attempt.effect,
		planDigest:         attempt.planDigest,
		sourceAttemptID:    attempt.id,
		purpose:            attempt.purpose,
		compensation:       compensation,
		cancellationTarget: cancellationTarget,
		state:              attempt.state,
		updatedAt:          updatedAt,
	}, nil
}

func cloneEffectProjection(value EffectProjection) EffectProjection {
	copy := value
	if value.compensation != nil {
		step := *value.compensation
		copy.compensation = &step
	}
	if value.cancellationTarget != nil {
		target := *value.cancellationTarget
		copy.cancellationTarget = &target
	}
	return copy
}

func effectProjectionIdentityEqual(left, right EffectProjection) bool {
	if !left.key.Equal(right.key) || !left.planDigest.Equal(right.planDigest) ||
		left.purpose != right.purpose || !optionalEffectKeysEqual(left.cancellationTarget, right.cancellationTarget) {
		return false
	}
	if left.compensation == nil || right.compensation == nil {
		return left.compensation == nil && right.compensation == nil
	}
	return compensationStepsEqual(*left.compensation, *right.compensation)
}

func effectProjectionsEqual(left, right EffectProjection) bool {
	return effectProjectionIdentityEqual(left, right) && left.state == right.state &&
		left.sourceAttemptID == right.sourceAttemptID && left.updatedAt.Equal(right.updatedAt)
}

func optionalEffectKeysEqual(left, right *EffectKey) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func compensationStepsEqual(left, right CompensationStep) bool {
	return left.planDigest.Equal(right.planDigest) && left.original.Equal(right.original) &&
		left.inverse.Equal(right.inverse) && left.dependencyOrder == right.dependencyOrder &&
		left.position == right.position && left.total == right.total &&
		equalDigest(left.proofEvidence, right.proofEvidence) && equalDigest(left.schedule, right.schedule)
}

func (value EffectProjection) Key() EffectKey               { return value.key }
func (value EffectProjection) SourceAttemptID() resource.ID { return value.sourceAttemptID }
func (value EffectProjection) State() AttemptState          { return value.state }
func (value EffectProjection) UpdatedAt() time.Time         { return value.updatedAt }

// CancellationTarget identifies the separate business effect targeted by a
// provider-cancellation effect.
func (value EffectProjection) CancellationTarget() (EffectKey, bool) {
	if value.cancellationTarget == nil {
		return EffectKey{}, false
	}
	return *value.cancellationTarget, true
}

// RetryProof binds an adapter's durable idempotency qualification to the exact
// logical effect, request fingerprint, and validity window.
type RetryProof struct {
	initialized    bool
	effect         EffectKey
	fingerprint    RequestFingerprint
	adapterVersion string
	validUntil     time.Time
	evidence       digestValue
}

// NewRetryProof constructs bounded adapter qualification evidence.
func NewRetryProof(
	effect EffectKey,
	fingerprint RequestFingerprint,
	adapterVersion string,
	validUntil time.Time,
	canonicalEvidence []byte,
) (RetryProof, error) {
	until, err := normalizeTime(validUntil)
	if err != nil || ValidateEffectKey(effect) != nil || !fingerprint.initialized ||
		!validVersion(adapterVersion) || len(canonicalEvidence) == 0 || len(canonicalEvidence) > MaxEvidenceBytes {
		return RetryProof{}, ErrRetryForbidden
	}
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.retry-proof.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashBytes(hasher, effect.digest.digest[:])
	writeHashBytes(hasher, fingerprint.digest[:])
	writeHashFrame(hasher, adapterVersion)
	writeHashInt64(hasher, until.UnixMilli())
	writeHashBytes(hasher, canonicalEvidence)
	return RetryProof{
		initialized:    true,
		effect:         effect,
		fingerprint:    fingerprint,
		adapterVersion: adapterVersion,
		validUntil:     until,
		evidence:       digestFromHasher(hasher),
	}, nil
}

// CheckRetry permits only proven NoEffect or exact live durable-idempotency evidence.
func CheckRetry(
	databaseTime time.Time,
	projection EffectProjection,
	fingerprint RequestFingerprint,
	proof *RetryProof,
) error {
	now, err := normalizeTime(databaseTime)
	if err != nil || validateEffectProjection(projection) != nil || !fingerprint.initialized ||
		now.Before(projection.updatedAt) {
		return ErrRetryForbidden
	}
	switch projection.state {
	case AttemptStateNoEffect:
		if proof != nil {
			return ErrRetryForbidden
		}
		return nil
	case AttemptStateIndeterminate:
		if proof == nil || !validRetryProof(*proof) || !proof.effect.Equal(projection.key) ||
			!proof.fingerprint.Equal(fingerprint) || !now.Before(proof.validUntil) {
			return ErrRetryForbidden
		}
		return nil
	default:
		return ErrRetryForbidden
	}
}

// SafeSupersessionProof binds adapter-qualified non-conflict evidence to one
// older uncertain effect and one newer candidate effect.
type SafeSupersessionProof struct {
	initialized    bool
	prior          EffectKey
	candidate      EffectKey
	adapterVersion string
	evidence       digestValue
}

// NewSafeSupersessionProof constructs exact bounded supersession evidence.
func NewSafeSupersessionProof(
	prior EffectKey,
	candidate EffectKey,
	adapterVersion string,
	canonicalEvidence []byte,
) (SafeSupersessionProof, error) {
	if ValidateEffectKey(prior) != nil || ValidateEffectKey(candidate) != nil ||
		prior.workspaceID != candidate.workspaceID || prior.resourceID != candidate.resourceID ||
		prior.generation >= candidate.generation || !validVersion(adapterVersion) ||
		len(canonicalEvidence) == 0 || len(canonicalEvidence) > MaxEvidenceBytes {
		return SafeSupersessionProof{}, ErrInvalidSupersessionProof
	}
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.supersession-proof.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashBytes(hasher, prior.digest.digest[:])
	writeHashBytes(hasher, candidate.digest.digest[:])
	writeHashFrame(hasher, adapterVersion)
	writeHashBytes(hasher, canonicalEvidence)
	return SafeSupersessionProof{
		initialized:    true,
		prior:          prior,
		candidate:      candidate,
		adapterVersion: adapterVersion,
		evidence:       digestFromHasher(hasher),
	}, nil
}

// CheckGenerationDispatch gates conflicting newer-generation dispatch while
// older effects remain prepared, dispatched, or indeterminate.
func CheckGenerationDispatch(
	candidate EffectKey,
	prior []EffectProjection,
	proofs []SafeSupersessionProof,
) error {
	if ValidateEffectKey(candidate) != nil || len(prior) > MaxEffectsPerOperation ||
		len(proofs) > MaxEffectsPerOperation {
		return ErrGenerationBlocked
	}
	proofByPrior := make(map[string]SafeSupersessionProof, len(proofs))
	for _, proof := range proofs {
		if !validSupersessionProof(proof) || !proof.candidate.Equal(candidate) {
			return ErrGenerationBlocked
		}
		key := proof.prior.String()
		if _, duplicate := proofByPrior[key]; duplicate {
			return ErrGenerationBlocked
		}
		proofByPrior[key] = proof
	}
	seen := make(map[string]struct{}, len(prior))
	for _, projection := range prior {
		if validateEffectProjection(projection) != nil ||
			projection.key.workspaceID != candidate.workspaceID ||
			projection.key.resourceID != candidate.resourceID ||
			projection.key.generation >= candidate.generation {
			return ErrGenerationBlocked
		}
		key := projection.key.String()
		if _, duplicate := seen[key]; duplicate {
			return ErrGenerationBlocked
		}
		seen[key] = struct{}{}
		if projection.state == AttemptStateApplied || projection.state == AttemptStateNoEffect {
			continue
		}
		proof, qualified := proofByPrior[key]
		if !qualified || !proof.prior.Equal(projection.key) {
			return ErrGenerationBlocked
		}
		delete(proofByPrior, key)
	}
	if len(proofByPrior) != 0 {
		return ErrGenerationBlocked
	}
	return nil
}

func validateEffectProjection(value EffectProjection) error {
	if !value.initialized || ValidateEffectKey(value.key) != nil || !value.planDigest.initialized ||
		!validID(value.sourceAttemptID) || value.updatedAt.IsZero() {
		return ErrInvalidAttempt
	}
	if _, err := ParseAttemptPurpose(value.purpose.String()); err != nil {
		return ErrInvalidAttempt
	}
	if value.purpose == AttemptPurposeCompensation {
		if value.compensation == nil || !validCompensationStep(*value.compensation) ||
			!value.compensation.planDigest.Equal(value.planDigest) ||
			!value.compensation.inverse.Equal(value.key) {
			return ErrInvalidAttempt
		}
	} else if value.compensation != nil {
		return ErrInvalidAttempt
	}
	if value.purpose == AttemptPurposeProviderCancel {
		if value.cancellationTarget == nil || ValidateEffectKey(*value.cancellationTarget) != nil ||
			value.cancellationTarget.Equal(value.key) ||
			!effectKeysShareExactScope(*value.cancellationTarget, value.key) {
			return ErrInvalidAttempt
		}
	} else if value.cancellationTarget != nil {
		return ErrInvalidAttempt
	}
	if _, err := ParseAttemptState(value.state.String()); err != nil {
		return ErrInvalidAttempt
	}
	return nil
}

func validRetryProof(value RetryProof) bool {
	return value.initialized && ValidateEffectKey(value.effect) == nil && value.fingerprint.initialized &&
		validVersion(value.adapterVersion) && !value.validUntil.IsZero() && value.evidence.initialized
}

func validSupersessionProof(value SafeSupersessionProof) bool {
	return value.initialized && ValidateEffectKey(value.prior) == nil && ValidateEffectKey(value.candidate) == nil &&
		value.prior.workspaceID == value.candidate.workspaceID &&
		value.prior.resourceID == value.candidate.resourceID &&
		value.prior.generation < value.candidate.generation && validVersion(value.adapterVersion) && value.evidence.initialized
}

func validEffectState(value EffectState) bool {
	switch value {
	case EffectStateApplied, EffectStateNoEffect, EffectStateIndeterminate:
		return true
	default:
		return false
	}
}

func attemptPurposeMatchesPlan(purpose AttemptPurpose, kind PlanKind) bool {
	switch purpose {
	case AttemptPurposeForward:
		return kind == PlanKindForward
	case AttemptPurposeCompensation:
		return kind == PlanKindCompensation
	case AttemptPurposeObservation, AttemptPurposeProviderCancel:
		return kind == PlanKindForward || kind == PlanKindCompensation
	default:
		return false
	}
}

func businessPurposeMatchesPlan(purpose AttemptPurpose, kind PlanKind) bool {
	return (purpose == AttemptPurposeForward && kind == PlanKindForward) ||
		(purpose == AttemptPurposeCompensation && kind == PlanKindCompensation)
}

func effectKeysShareExactScope(left, right EffectKey) bool {
	return ValidateEffectKey(left) == nil && ValidateEffectKey(right) == nil &&
		left.workspaceID == right.workspaceID && left.resourceID == right.resourceID &&
		left.operationID == right.operationID && left.generation == right.generation
}

func validCancellationTarget(
	target EffectProjection,
	planDigest PlanDigest,
	planKind PlanKind,
	cancellationEffect EffectKey,
) bool {
	return validateEffectProjection(target) == nil &&
		!target.key.Equal(cancellationEffect) && target.planDigest.Equal(planDigest) &&
		effectKeysShareExactScope(target.key, cancellationEffect) &&
		businessPurposeMatchesPlan(target.purpose, planKind) &&
		(target.state == AttemptStateDispatched || target.state == AttemptStateIndeterminate)
}

func validObservationTarget(
	target EffectProjection,
	planDigest PlanDigest,
	planKind PlanKind,
	effect EffectKey,
) bool {
	return validateEffectProjection(target) == nil && target.state == AttemptStateIndeterminate &&
		target.purpose != AttemptPurposeObservation && target.key.Equal(effect) &&
		target.planDigest.Equal(planDigest) && attemptPurposeMatchesPlan(target.purpose, planKind)
}

func validMaintenanceKind(value MaintenanceKind) bool {
	return value == MaintenanceStoreLease || value == MaintenanceQueueVisibility
}

func validMaintenanceOutcome(value MaintenanceOutcome) bool {
	return value == MaintenanceSucceeded || value == MaintenanceFailed || value == MaintenanceUnknown
}

func effectMatchesPlan(effect EffectKey, plan Plan) bool {
	return effect.workspaceID == plan.workspaceID && effect.resourceID == plan.resourceID &&
		effect.operationID == plan.operationID && effect.generation == plan.generation
}

func deriveAttemptDispatchBinding(value Attempt) digestValue {
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.attempt-dispatch.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashFrame(hasher, value.id.String())
	writeHashUint64(hasher, uint64(value.ordinal))
	writeHashBytes(hasher, value.planDigest.digest[:])
	writeHashFrame(hasher, value.planKind.String())
	writeHashBytes(hasher, value.effect.digest.digest[:])
	writeHashFrame(hasher, value.purpose.String())
	writeHashFrame(hasher, value.ownerID.String())
	writeHashInt64(hasher, value.fence)
	writeHashBytes(hasher, value.requestFingerprint.digest[:])
	writeHashBytes(hasher, value.admissionBinding.digest[:])
	if value.retryValidUntil.IsZero() {
		writeHashFrame(hasher, "no-retry-expiry")
	} else {
		writeHashInt64(hasher, value.retryValidUntil.UnixMilli())
	}
	if value.observationBinding.initialized {
		writeHashBytes(hasher, value.observationBinding.digest[:])
	} else {
		writeHashFrame(hasher, "no-observation")
	}
	if value.observationDeadline.IsZero() {
		writeHashFrame(hasher, "no-observation-deadline")
	} else {
		writeHashInt64(hasher, value.observationDeadline.UnixMilli())
	}
	if value.observationTarget == nil {
		writeHashFrame(hasher, "no-observation-target")
	} else {
		writeEffectProjection(hasher, *value.observationTarget)
	}
	if value.cancellationTarget == nil {
		writeHashFrame(hasher, "no-cancellation-target")
	} else {
		writeEffectProjection(hasher, *value.cancellationTarget)
	}
	writeHashInt64(hasher, value.preparedAt.UnixMilli())
	if value.compensation == nil {
		writeHashFrame(hasher, "0")
	} else {
		writeHashFrame(hasher, "1")
		writeHashBytes(hasher, value.compensation.schedule.digest[:])
		writeHashBytes(hasher, value.compensation.proofEvidence.digest[:])
		writeHashUint64(hasher, uint64(value.compensation.position))
		writeHashUint64(hasher, uint64(value.compensation.dependencyOrder))
	}
	return digestFromHasher(hasher)
}

func compensationStepMatchesPlan(step CompensationStep, plan Plan, effect EffectKey) bool {
	if !validCompensationStep(step) || plan.kind != PlanKindCompensation ||
		!step.planDigest.Equal(plan.digest) || !step.inverse.Equal(effect) {
		return false
	}
	originalFound := false
	for _, original := range plan.compensates {
		if original.Equal(step.inverse) {
			return false
		}
		if original.Equal(step.original) {
			originalFound = true
		}
	}
	return originalFound
}

func (Attempt) MarshalJSON() ([]byte, error)                 { return nil, ErrSerializationForbidden }
func (Attempt) MarshalText() ([]byte, error)                 { return nil, ErrSerializationForbidden }
func (Attempt) MarshalBinary() ([]byte, error)               { return nil, ErrSerializationForbidden }
func (Attempt) GobEncode() ([]byte, error)                   { return nil, ErrSerializationForbidden }
func (EffectProjection) MarshalJSON() ([]byte, error)        { return nil, ErrSerializationForbidden }
func (EffectProjection) MarshalText() ([]byte, error)        { return nil, ErrSerializationForbidden }
func (EffectProjection) MarshalBinary() ([]byte, error)      { return nil, ErrSerializationForbidden }
func (EffectProjection) GobEncode() ([]byte, error)          { return nil, ErrSerializationForbidden }
func (RetryProof) MarshalJSON() ([]byte, error)              { return nil, ErrSerializationForbidden }
func (RetryProof) MarshalText() ([]byte, error)              { return nil, ErrSerializationForbidden }
func (RetryProof) MarshalBinary() ([]byte, error)            { return nil, ErrSerializationForbidden }
func (RetryProof) GobEncode() ([]byte, error)                { return nil, ErrSerializationForbidden }
func (SafeSupersessionProof) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (SafeSupersessionProof) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (SafeSupersessionProof) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (SafeSupersessionProof) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
