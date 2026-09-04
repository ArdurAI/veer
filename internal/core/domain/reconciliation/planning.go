package reconciliation

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"math"
	"sync/atomic"
	"time"
)

// LeaseReplacementAuthority is a one-use proof that an exact plan lineage
// transition passed the required planning checks. Same-generation values are
// created only by SelectPlan; generation changes use
// AuthorizeGenerationReplacement.
type LeaseReplacementAuthority struct {
	initialized          bool
	expected             LeaseBinding
	replacement          LeaseBinding
	replacementKind      PlanKind
	compensationSchedule digestValue
	admissionBinding     digestValue
	transition           *atomic.Uint32
	use                  *atomic.Bool
}

// SelectPlan deterministically reuses identical inputs or validates one
// same-generation immutable supersession. Physical attempt history proves that
// no call remains active, while currentEffects supplies the authoritative
// logical outcome after retries or observations. A forward-to-compensation
// supersession additionally binds the complete qualified inverse schedule
// before replacement authority can be minted. It never mutates either plan.
func SelectPlan(
	current Plan,
	candidate Plan,
	priorAttempts []Attempt,
	currentEffects []EffectProjection,
	freshObservation bool,
	compensationProofs []CompensationProof,
) (Plan, PlanSelection, LeaseReplacementAuthority, error) {
	if ValidatePlan(current) != nil || ValidatePlan(candidate) != nil ||
		current.operationID != candidate.operationID || current.workspaceID != candidate.workspaceID ||
		current.resourceID != candidate.resourceID || current.generation != candidate.generation {
		return Plan{}, "", LeaseReplacementAuthority{}, ErrPlanMismatch
	}
	if current.digest.Equal(candidate.digest) {
		return current, PlanSelectionReuse, LeaseReplacementAuthority{}, nil
	}
	if (current.kind != candidate.kind &&
		(current.kind != PlanKindForward || candidate.kind != PlanKindCompensation)) ||
		candidate.revision != current.revision+1 ||
		candidate.supersedes == nil || !candidate.supersedes.Equal(current.digest) ||
		!freshObservation || candidate.observed.Equal(current.observed) {
		return Plan{}, "", LeaseReplacementAuthority{}, ErrReplanBlocked
	}
	var compensationSchedule digestValue
	if candidate.kind == PlanKindCompensation {
		if ValidateCompensationPlan(candidate, compensationProofs) != nil {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrInvalidPlan
		}
		compensationSchedule = deriveCompensationSchedule(candidate, compensationProofs)
	} else if len(compensationProofs) != 0 {
		return Plan{}, "", LeaseReplacementAuthority{}, ErrInvalidPlan
	}

	if len(currentEffects) > MaxEffectsPerOperation {
		return Plan{}, "", LeaseReplacementAuthority{}, ErrInvalidAttempt
	}
	wantCompleted := make(map[string]EffectKey, len(current.completedEffects)+len(currentEffects))
	for _, effect := range current.completedEffects {
		wantCompleted[effect.String()] = effect
	}
	seenAttempts := make(map[string]struct{}, len(priorAttempts))
	seenOrdinals := make(map[uint32]struct{}, len(priorAttempts))
	attemptEffects := make(map[string]EffectProjection, len(priorAttempts))
	effectFloors := make(map[string]time.Time, len(priorAttempts))
	for _, attempt := range priorAttempts {
		if ValidateAttempt(attempt) != nil {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrInvalidAttempt
		}
		if !attempt.planDigest.Equal(current.digest) {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrPlanMismatch
		}
		if !attempt.Resolved() {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrAttemptNotDefinitive
		}
		attemptKey := attempt.id.String()
		if _, duplicate := seenAttempts[attemptKey]; duplicate {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrInvalidAttempt
		}
		if _, duplicate := seenOrdinals[attempt.ordinal]; duplicate {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrInvalidAttempt
		}
		seenAttempts[attemptKey] = struct{}{}
		seenOrdinals[attempt.ordinal] = struct{}{}
		identity, err := logicalEffectIdentityFromAttempt(attempt)
		if err != nil {
			return Plan{}, "", LeaseReplacementAuthority{}, err
		}
		effectKey := attempt.effect.String()
		if prior, exists := attemptEffects[effectKey]; exists &&
			!effectProjectionIdentityEqual(prior, identity) {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrInvalidAttempt
		}
		attemptEffects[effectKey] = identity
		floor := attemptLatestAt(attempt)
		if attempt.purpose == AttemptPurposeObservation {
			floor = attempt.observationTarget.updatedAt
		}
		if prior, exists := effectFloors[effectKey]; !exists || floor.After(prior) {
			effectFloors[effectKey] = floor
		}
	}
	seenEffects := make(map[string]struct{}, len(currentEffects))
	for _, projection := range currentEffects {
		if validateEffectProjection(projection) != nil {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrInvalidAttempt
		}
		if !projection.planDigest.Equal(current.digest) {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrPlanMismatch
		}
		key := projection.key.String()
		if _, duplicate := seenEffects[key]; duplicate {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrInvalidAttempt
		}
		identity, exists := attemptEffects[key]
		if !exists || !effectProjectionIdentityEqual(projection, identity) {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrInvalidAttempt
		}
		if projection.updatedAt.Before(effectFloors[key]) {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrAttemptNotDefinitive
		}
		if projection.state != AttemptStateApplied && projection.state != AttemptStateNoEffect {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrAttemptNotDefinitive
		}
		seenEffects[key] = struct{}{}
		if projection.state == AttemptStateApplied {
			wantCompleted[key] = projection.key
		}
	}
	if len(seenEffects) != len(attemptEffects) {
		return Plan{}, "", LeaseReplacementAuthority{}, ErrAttemptNotDefinitive
	}
	if len(wantCompleted) != len(candidate.completedEffects) {
		return Plan{}, "", LeaseReplacementAuthority{}, ErrCompletedEffectMissing
	}
	for _, effect := range candidate.completedEffects {
		want, exists := wantCompleted[effect.String()]
		if !exists || !want.Equal(effect) {
			return Plan{}, "", LeaseReplacementAuthority{}, ErrCompletedEffectMissing
		}
	}
	authority, err := newLeaseReplacementAuthority(
		current,
		candidate,
		compensationSchedule,
		digestValue{},
		nil,
	)
	if err != nil {
		return Plan{}, "", LeaseReplacementAuthority{}, err
	}
	return candidate, PlanSelectionSupersede, authority, nil
}

func logicalEffectIdentityFromAttempt(attempt Attempt) (EffectProjection, error) {
	if ValidateAttempt(attempt) != nil {
		return EffectProjection{}, ErrInvalidAttempt
	}
	if attempt.purpose == AttemptPurposeObservation {
		if attempt.observationTarget == nil {
			return EffectProjection{}, ErrInvalidObservation
		}
		return cloneEffectProjection(*attempt.observationTarget), nil
	}
	projection, err := EffectProjectionFromAttempt(attempt)
	if err != nil {
		return EffectProjection{}, err
	}
	return projection, nil
}

// AuthorizeGenerationReplacement seals an exact next-generation, revision-one
// plan transition only after the exact first mutation passed retry and
// prior-generation effect admission. This prevents lease replacement from
// removing the only observation path for an unresolved predecessor.
func AuthorizeGenerationReplacement(
	current Plan,
	candidate Plan,
	input AttemptAdmissionInput,
) (LeaseReplacementAuthority, AttemptAdmission, error) {
	if ValidatePlan(current) != nil || ValidatePlan(candidate) != nil ||
		current.workspaceID != candidate.workspaceID || current.resourceID != candidate.resourceID ||
		current.generation == math.MaxInt64 || candidate.generation != current.generation+1 ||
		candidate.operationID == current.operationID || candidate.revision != 1 || candidate.supersedes != nil ||
		ValidatePlan(input.Plan) != nil || !input.Plan.digest.Equal(candidate.digest) ||
		(input.Purpose != AttemptPurposeForward && input.Purpose != AttemptPurposeCompensation) {
		return LeaseReplacementAuthority{}, AttemptAdmission{}, ErrInvalidLease
	}
	admission, err := NewAttemptAdmission(input)
	if err != nil {
		return LeaseReplacementAuthority{}, AttemptAdmission{}, err
	}
	transition := &atomic.Uint32{}
	admission.replacementTransition = transition
	authority, err := newLeaseReplacementAuthority(
		current,
		candidate,
		digestValue{},
		admission.binding,
		transition,
	)
	if err != nil {
		return LeaseReplacementAuthority{}, AttemptAdmission{}, err
	}
	return authority, admission, nil
}

func newLeaseReplacementAuthority(
	current Plan,
	candidate Plan,
	compensationSchedule digestValue,
	admissionBinding digestValue,
	transition *atomic.Uint32,
) (LeaseReplacementAuthority, error) {
	expected, err := LeaseBindingFromPlan(current)
	if err != nil {
		return LeaseReplacementAuthority{}, ErrInvalidLease
	}
	replacement, err := LeaseBindingFromPlan(candidate)
	if err != nil || expected.Equal(replacement) || leaseRowKey(expected) != leaseRowKey(replacement) ||
		!leaseBindingMovesForward(expected, replacement) ||
		(candidate.kind == PlanKindCompensation) != compensationSchedule.initialized {
		return LeaseReplacementAuthority{}, ErrInvalidLease
	}
	return LeaseReplacementAuthority{
		initialized:          true,
		expected:             expected,
		replacement:          replacement,
		replacementKind:      candidate.kind,
		compensationSchedule: compensationSchedule,
		admissionBinding:     admissionBinding,
		transition:           transition,
		use:                  &atomic.Bool{},
	}, nil
}

func validateLeaseReplacementAuthority(value LeaseReplacementAuthority) error {
	if !value.initialized || validateLeaseBinding(value.expected) != nil ||
		validateLeaseBinding(value.replacement) != nil || value.use == nil ||
		(value.replacementKind != PlanKindForward && value.replacementKind != PlanKindCompensation) ||
		(value.replacementKind == PlanKindCompensation) != value.compensationSchedule.initialized ||
		leaseRowKey(value.expected) != leaseRowKey(value.replacement) ||
		!leaseBindingMovesForward(value.expected, value.replacement) ||
		(value.expected.generation < value.replacement.generation) != value.admissionBinding.initialized ||
		(value.expected.generation < value.replacement.generation) != (value.transition != nil) {
		return ErrInvalidLease
	}
	return nil
}

func (value LeaseReplacementAuthority) String() string {
	if validateLeaseReplacementAuthority(value) != nil {
		return "reconciliation-lease-replacement-authority(invalid)"
	}
	return "reconciliation-lease-replacement-authority(identity=redacted)"
}
func (value LeaseReplacementAuthority) GoString() string { return value.String() }
func (value LeaseReplacementAuthority) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value LeaseReplacementAuthority) LogValue() slog.Value {
	return redactedLogValue(value.String())
}
func (LeaseReplacementAuthority) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
func (LeaseReplacementAuthority) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }
func (LeaseReplacementAuthority) MarshalBinary() ([]byte, error) {
	return nil, ErrSerializationForbidden
}
func (LeaseReplacementAuthority) GobEncode() ([]byte, error) { return nil, ErrSerializationForbidden }

// CompensationProof binds one confirmed-applied original effect to an
// adapter-qualified inverse and its reverse dependency order.
type CompensationProof struct {
	initialized     bool
	original        EffectProjection
	inverse         EffectKey
	dependencyOrder uint32
	adapterVersion  string
	evidence        digestValue
}

// CompensationStep is the next qualified inverse in one fully validated
// reverse-order compensation schedule.
type CompensationStep struct {
	initialized     bool
	planDigest      PlanDigest
	original        EffectKey
	inverse         EffectKey
	dependencyOrder uint32
	position        uint32
	total           uint32
	proofEvidence   digestValue
	schedule        digestValue
}

// NewCompensationProof constructs exact inverse, ownership, and precondition evidence.
func NewCompensationProof(
	original EffectProjection,
	inverse EffectKey,
	dependencyOrder uint32,
	adapterVersion string,
	canonicalEvidence []byte,
) (CompensationProof, error) {
	if validateEffectProjection(original) != nil || original.state != AttemptStateApplied ||
		ValidateEffectKey(inverse) != nil || original.key.Equal(inverse) ||
		dependencyOrder == 0 || !validVersion(adapterVersion) ||
		len(canonicalEvidence) == 0 || len(canonicalEvidence) > MaxEvidenceBytes ||
		original.key.workspaceID != inverse.workspaceID || original.key.resourceID != inverse.resourceID ||
		original.key.operationID != inverse.operationID || original.key.generation != inverse.generation {
		return CompensationProof{}, ErrInvalidPlan
	}
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.compensation-proof.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashBytes(hasher, original.key.digest.digest[:])
	writeHashBytes(hasher, inverse.digest.digest[:])
	writeHashUint64(hasher, uint64(dependencyOrder))
	writeHashFrame(hasher, adapterVersion)
	writeHashBytes(hasher, canonicalEvidence)
	return CompensationProof{
		initialized:     true,
		original:        original,
		inverse:         inverse,
		dependencyOrder: dependencyOrder,
		adapterVersion:  adapterVersion,
		evidence:        digestFromHasher(hasher),
	}, nil
}

// ValidateCompensationPlan enforces confirmed effects, qualified inverses,
// and strict reverse dependency order. Dispatch still requires fresh authority.
func ValidateCompensationPlan(plan Plan, proofs []CompensationProof) error {
	if ValidatePlan(plan) != nil || plan.kind != PlanKindCompensation ||
		len(proofs) > MaxEffectsPerOperation || len(proofs) != len(plan.compensates) {
		return ErrInvalidPlan
	}
	want := make(map[string]EffectKey, len(plan.compensates))
	originals := make(map[string]struct{}, len(plan.compensates))
	for _, effect := range plan.compensates {
		want[effect.String()] = effect
		originals[effect.String()] = struct{}{}
	}
	seenInverse := make(map[string]struct{}, len(proofs))
	previousOrder := uint32(0)
	for index, proof := range proofs {
		if !validCompensationProof(proof) || !effectMatchesPlan(proof.inverse, plan) ||
			(index > 0 && proof.dependencyOrder >= previousOrder) {
			return ErrInvalidPlan
		}
		if _, aliasesOriginal := originals[proof.inverse.String()]; aliasesOriginal {
			return ErrInvalidPlan
		}
		original, exists := want[proof.original.key.String()]
		if !exists || !original.Equal(proof.original.key) {
			return ErrInvalidPlan
		}
		if _, duplicate := seenInverse[proof.inverse.String()]; duplicate {
			return ErrInvalidPlan
		}
		delete(want, proof.original.key.String())
		seenInverse[proof.inverse.String()] = struct{}{}
		previousOrder = proof.dependencyOrder
	}
	if len(want) != 0 {
		return ErrInvalidPlan
	}
	return nil
}

// NextCompensationStep validates the complete inverse schedule and advances
// only past exact Applied projections for its preceding steps.
func NextCompensationStep(
	plan Plan,
	proofs []CompensationProof,
	completed []EffectProjection,
) (CompensationStep, error) {
	if ValidateCompensationPlan(plan, proofs) != nil || len(completed) >= len(proofs) {
		return CompensationStep{}, ErrInvalidPlan
	}
	schedule := deriveCompensationSchedule(plan, proofs)
	for index, projection := range completed {
		if validateEffectProjection(projection) != nil || projection.state != AttemptStateApplied ||
			projection.purpose != AttemptPurposeCompensation ||
			!projection.planDigest.Equal(plan.digest) || projection.compensation == nil ||
			!projection.key.Equal(proofs[index].inverse) ||
			!projection.compensation.original.Equal(proofs[index].original.key) ||
			!projection.compensation.inverse.Equal(proofs[index].inverse) ||
			projection.compensation.dependencyOrder != proofs[index].dependencyOrder ||
			projection.compensation.position != uint32(index+1) ||
			projection.compensation.total != uint32(len(proofs)) ||
			!equalDigest(projection.compensation.proofEvidence, proofs[index].evidence) ||
			!equalDigest(projection.compensation.schedule, schedule) {
			return CompensationStep{}, ErrInvalidPlan
		}
	}
	proof := proofs[len(completed)]
	return CompensationStep{
		initialized:     true,
		planDigest:      plan.digest,
		original:        proof.original.key,
		inverse:         proof.inverse,
		dependencyOrder: proof.dependencyOrder,
		position:        uint32(len(completed) + 1),
		total:           uint32(len(proofs)),
		proofEvidence:   proof.evidence,
		schedule:        schedule,
	}, nil
}

func deriveCompensationSchedule(plan Plan, proofs []CompensationProof) digestValue {
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.compensation-schedule.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashBytes(hasher, plan.digest.digest[:])
	for _, proof := range proofs {
		writeHashBytes(hasher, proof.evidence.digest[:])
	}
	return digestFromHasher(hasher)
}

func (value CompensationStep) Original() EffectKey     { return value.original }
func (value CompensationStep) Inverse() EffectKey      { return value.inverse }
func (value CompensationStep) DependencyOrder() uint32 { return value.dependencyOrder }
func (value CompensationStep) Position() uint32        { return value.position }
func (value CompensationStep) Total() uint32           { return value.total }

func validCompensationStep(value CompensationStep) bool {
	return value.initialized && value.planDigest.initialized &&
		ValidateEffectKey(value.original) == nil && ValidateEffectKey(value.inverse) == nil &&
		!value.original.Equal(value.inverse) && value.dependencyOrder > 0 &&
		value.position > 0 && value.position <= value.total &&
		value.proofEvidence.initialized && value.schedule.initialized
}

func validCompensationProof(value CompensationProof) bool {
	return value.initialized && validateEffectProjection(value.original) == nil &&
		value.original.state == AttemptStateApplied && ValidateEffectKey(value.inverse) == nil &&
		value.dependencyOrder > 0 && validVersion(value.adapterVersion) && value.evidence.initialized
}

func (CompensationProof) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (CompensationProof) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (CompensationProof) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (CompensationProof) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (CompensationStep) MarshalJSON() ([]byte, error)    { return nil, ErrSerializationForbidden }
func (CompensationStep) MarshalText() ([]byte, error)    { return nil, ErrSerializationForbidden }
func (CompensationStep) MarshalBinary() ([]byte, error)  { return nil, ErrSerializationForbidden }
func (CompensationStep) GobEncode() ([]byte, error)      { return nil, ErrSerializationForbidden }
