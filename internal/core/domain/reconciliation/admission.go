package reconciliation

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"log/slog"
	"sync/atomic"
	"time"
)

// AttemptAdmissionInput supplies the authoritative state needed to decide
// whether one physical attempt may be prepared. The future StateStore adapter
// must load and commit these inputs atomically with the prepared attempt.
type AttemptAdmissionInput struct {
	DatabaseTime           time.Time
	Plan                   Plan
	Effect                 EffectKey
	Purpose                AttemptPurpose
	RequestFingerprint     RequestFingerprint
	CancellationRequested  bool
	CurrentEffect          *EffectProjection
	CancellationTarget     *EffectProjection
	RetryProof             *RetryProof
	PriorGenerationEffects []EffectProjection
	SafeSupersessionProofs []SafeSupersessionProof
	Observation            *ObservationPermit
	Compensation           *CompensationStep
}

// AttemptAdmission is a process-local one-use capability binding every
// preparation gate to one exact plan, effect, purpose, fingerprint, and time.
type AttemptAdmission struct {
	initialized           bool
	planDigest            PlanDigest
	planKind              PlanKind
	effect                EffectKey
	purpose               AttemptPurpose
	requestFingerprint    RequestFingerprint
	compensation          *CompensationStep
	observationTarget     *EffectProjection
	cancellationTarget    *EffectProjection
	retryValidUntil       time.Time
	observationBinding    digestValue
	observationDeadline   time.Time
	observationTransition *atomic.Uint32
	authorizedAt          time.Time
	binding               digestValue
	replacementTransition *atomic.Uint32
	use                   *atomic.Bool
}

// NewAttemptAdmission performs cancellation, retry, generation, compensation,
// and observation-budget checks that callers previously could omit.
func NewAttemptAdmission(input AttemptAdmissionInput) (AttemptAdmission, error) {
	now, err := normalizeTime(input.DatabaseTime)
	if err != nil || ValidatePlan(input.Plan) != nil || ValidateEffectKey(input.Effect) != nil ||
		!effectMatchesPlan(input.Effect, input.Plan) || !input.RequestFingerprint.initialized {
		return AttemptAdmission{}, ErrInvalidAttempt
	}
	if _, err := ParseAttemptPurpose(input.Purpose.String()); err != nil {
		return AttemptAdmission{}, ErrInvalidAttempt
	}
	if !attemptPurposeMatchesPlan(input.Purpose, input.Plan.kind) {
		return AttemptAdmission{}, ErrInvalidAttempt
	}
	if effectSetContains(input.Plan.completedEffects, input.Effect) {
		return AttemptAdmission{}, ErrRetryForbidden
	}
	if input.CancellationRequested {
		if err := canPrepareAfterCancellation(input.Purpose); err != nil {
			return AttemptAdmission{}, err
		}
	}

	var compensation *CompensationStep
	if input.Purpose == AttemptPurposeCompensation {
		if input.Compensation == nil ||
			!compensationStepMatchesPlan(*input.Compensation, input.Plan, input.Effect) {
			return AttemptAdmission{}, ErrInvalidAttempt
		}
		copy := *input.Compensation
		compensation = &copy
	} else if input.Compensation != nil {
		return AttemptAdmission{}, ErrInvalidAttempt
	}

	retryBinding, retryValidUntil, generationBinding, err := mutationAdmissionBindings(now, input)
	if err != nil {
		return AttemptAdmission{}, err
	}

	var observationBinding digestValue
	var observationDeadline time.Time
	var observationTransition *atomic.Uint32
	var observationTarget *EffectProjection
	var cancellationTarget *EffectProjection
	switch input.Purpose {
	case AttemptPurposeObservation:
		if input.Observation == nil || validateObservationPermit(*input.Observation) != nil ||
			!input.Observation.effect.Equal(input.Effect) || !input.Observation.reservedAt.Equal(now) ||
			input.CurrentEffect == nil ||
			!validObservationTarget(*input.CurrentEffect, input.Plan.digest, input.Plan.kind, input.Effect) ||
			now.Before(input.CurrentEffect.updatedAt) || input.CancellationTarget != nil {
			return AttemptAdmission{}, ErrInvalidObservation
		}
		observationBinding = input.Observation.binding
		observationDeadline = input.Observation.deadline
		observationTransition = input.Observation.transition
		copy := cloneEffectProjection(*input.CurrentEffect)
		observationTarget = &copy
	case AttemptPurposeProviderCancel:
		if !input.CancellationRequested || input.Observation != nil || input.CancellationTarget == nil ||
			!validCancellationTarget(*input.CancellationTarget, input.Plan.digest, input.Plan.kind, input.Effect) ||
			now.Before(input.CancellationTarget.updatedAt) {
			return AttemptAdmission{}, ErrInvalidAttempt
		}
		if input.CurrentEffect != nil {
			priorTarget, ok := input.CurrentEffect.CancellationTarget()
			if !ok || !priorTarget.Equal(input.CancellationTarget.key) {
				return AttemptAdmission{}, ErrRetryForbidden
			}
		}
		copy := cloneEffectProjection(*input.CancellationTarget)
		cancellationTarget = &copy
	default:
		if input.Observation != nil || input.CancellationTarget != nil {
			return AttemptAdmission{}, ErrInvalidAttempt
		}
	}

	binding := deriveAttemptAdmissionBinding(
		input.Plan,
		input.Effect,
		input.Purpose,
		input.RequestFingerprint,
		input.CancellationRequested,
		retryBinding,
		generationBinding,
		observationBinding,
		observationDeadline,
		observationTarget,
		compensation,
		cancellationTarget,
		now,
	)
	if input.Purpose == AttemptPurposeObservation &&
		!input.Observation.transition.CompareAndSwap(observationReserved, observationAdmitted) {
		return AttemptAdmission{}, ErrInvalidObservation
	}
	return AttemptAdmission{
		initialized:           true,
		planDigest:            input.Plan.digest,
		planKind:              input.Plan.kind,
		effect:                input.Effect,
		purpose:               input.Purpose,
		requestFingerprint:    input.RequestFingerprint,
		compensation:          compensation,
		observationTarget:     observationTarget,
		cancellationTarget:    cancellationTarget,
		retryValidUntil:       retryValidUntil,
		observationBinding:    observationBinding,
		observationDeadline:   observationDeadline,
		observationTransition: observationTransition,
		authorizedAt:          now,
		binding:               binding,
		use:                   &atomic.Bool{},
	}, nil
}

func mutationAdmissionBindings(
	now time.Time,
	input AttemptAdmissionInput,
) (digestValue, time.Time, digestValue, error) {
	if input.Purpose == AttemptPurposeProviderCancel {
		if len(input.PriorGenerationEffects) != 0 || len(input.SafeSupersessionProofs) != 0 {
			return digestValue{}, time.Time{}, digestValue{}, ErrInvalidAttempt
		}
		retryBinding, retryValidUntil, err := checkRetryAdmission(
			now,
			input.Effect,
			input.CurrentEffect,
			input.RequestFingerprint,
			input.RetryProof,
		)
		if err != nil {
			return digestValue{}, time.Time{}, digestValue{}, err
		}
		return retryBinding, retryValidUntil,
			deriveDigest("veer.reconciliation.no-generation-gate.v1", []byte(input.Purpose)), nil
	}
	if input.Purpose != AttemptPurposeForward && input.Purpose != AttemptPurposeCompensation {
		if input.RetryProof != nil || len(input.PriorGenerationEffects) != 0 ||
			len(input.SafeSupersessionProofs) != 0 {
			return digestValue{}, time.Time{}, digestValue{}, ErrInvalidAttempt
		}
		return deriveDigest("veer.reconciliation.nonmutation-admission.v1", []byte(input.Purpose)),
			time.Time{}, deriveDigest("veer.reconciliation.no-generation-gate.v1", []byte(input.Purpose)), nil
	}
	retryBinding, retryValidUntil, err := checkRetryAdmission(
		now,
		input.Effect,
		input.CurrentEffect,
		input.RequestFingerprint,
		input.RetryProof,
	)
	if err != nil {
		return digestValue{}, time.Time{}, digestValue{}, err
	}
	if err := CheckGenerationDispatch(
		input.Effect,
		input.PriorGenerationEffects,
		input.SafeSupersessionProofs,
	); err != nil {
		return digestValue{}, time.Time{}, digestValue{}, err
	}
	return retryBinding, retryValidUntil, deriveGenerationAdmissionBinding(
		input.Effect,
		input.PriorGenerationEffects,
		input.SafeSupersessionProofs,
	), nil
}

func checkRetryAdmission(
	now time.Time,
	effect EffectKey,
	projection *EffectProjection,
	fingerprint RequestFingerprint,
	proof *RetryProof,
) (digestValue, time.Time, error) {
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.retry-admission.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashBytes(hasher, effect.digest.digest[:])
	writeHashBytes(hasher, fingerprint.digest[:])
	writeHashInt64(hasher, now.UnixMilli())
	if projection == nil {
		if proof != nil {
			return digestValue{}, time.Time{}, ErrRetryForbidden
		}
		writeHashFrame(hasher, "initial")
		return digestFromHasher(hasher), time.Time{}, nil
	}
	if validateEffectProjection(*projection) != nil || !projection.key.Equal(effect) ||
		now.Before(projection.updatedAt) {
		return digestValue{}, time.Time{}, ErrRetryForbidden
	}
	if err := CheckRetry(now, *projection, fingerprint, proof); err != nil {
		return digestValue{}, time.Time{}, err
	}
	writeEffectProjection(hasher, *projection)
	if proof == nil {
		writeHashFrame(hasher, "no-proof")
	} else {
		writeHashBytes(hasher, proof.evidence.digest[:])
	}
	if proof != nil {
		return digestFromHasher(hasher), proof.validUntil, nil
	}
	return digestFromHasher(hasher), time.Time{}, nil
}

func deriveGenerationAdmissionBinding(
	candidate EffectKey,
	prior []EffectProjection,
	proofs []SafeSupersessionProof,
) digestValue {
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.generation-admission.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashBytes(hasher, candidate.digest.digest[:])
	writeHashUint64(hasher, uint64(len(prior)))
	for _, projection := range prior {
		writeEffectProjection(hasher, projection)
	}
	writeHashUint64(hasher, uint64(len(proofs)))
	for _, proof := range proofs {
		writeHashBytes(hasher, proof.evidence.digest[:])
	}
	return digestFromHasher(hasher)
}

func writeEffectProjection(hasher hash.Hash, value EffectProjection) {
	writeHashBytes(hasher, value.key.digest.digest[:])
	writeHashBytes(hasher, value.planDigest.digest[:])
	writeHashFrame(hasher, value.sourceAttemptID.String())
	writeHashFrame(hasher, value.purpose.String())
	writeHashFrame(hasher, value.state.String())
	writeHashInt64(hasher, value.updatedAt.UnixMilli())
	if value.cancellationTarget == nil {
		writeHashFrame(hasher, "no-cancellation-target")
	} else {
		writeHashBytes(hasher, value.cancellationTarget.digest.digest[:])
	}
	if value.compensation == nil {
		writeHashFrame(hasher, "no-compensation")
	} else {
		writeCompensationStep(hasher, *value.compensation)
	}
}

func writeCompensationStep(hasher hash.Hash, value CompensationStep) {
	writeHashBytes(hasher, value.planDigest.digest[:])
	writeHashBytes(hasher, value.original.digest.digest[:])
	writeHashBytes(hasher, value.inverse.digest.digest[:])
	writeHashUint64(hasher, uint64(value.dependencyOrder))
	writeHashUint64(hasher, uint64(value.position))
	writeHashUint64(hasher, uint64(value.total))
	writeHashBytes(hasher, value.proofEvidence.digest[:])
	writeHashBytes(hasher, value.schedule.digest[:])
}

func deriveAttemptAdmissionBinding(
	plan Plan,
	effect EffectKey,
	purpose AttemptPurpose,
	fingerprint RequestFingerprint,
	cancellationRequested bool,
	retryBinding digestValue,
	generationBinding digestValue,
	observationBinding digestValue,
	observationDeadline time.Time,
	observationTarget *EffectProjection,
	compensation *CompensationStep,
	cancellationTarget *EffectProjection,
	authorizedAt time.Time,
) digestValue {
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.attempt-admission.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashBytes(hasher, plan.digest.digest[:])
	writeHashBytes(hasher, effect.digest.digest[:])
	writeHashFrame(hasher, purpose.String())
	writeHashBytes(hasher, fingerprint.digest[:])
	if cancellationRequested {
		writeHashFrame(hasher, "cancel-requested")
	} else {
		writeHashFrame(hasher, "not-canceled")
	}
	writeHashBytes(hasher, retryBinding.digest[:])
	writeHashBytes(hasher, generationBinding.digest[:])
	if observationBinding.initialized {
		writeHashBytes(hasher, observationBinding.digest[:])
	} else {
		writeHashFrame(hasher, "no-observation")
	}
	if observationDeadline.IsZero() {
		writeHashFrame(hasher, "no-observation-deadline")
	} else {
		writeHashInt64(hasher, observationDeadline.UnixMilli())
	}
	if observationTarget == nil {
		writeHashFrame(hasher, "no-observation-target")
	} else {
		writeEffectProjection(hasher, *observationTarget)
	}
	if compensation == nil {
		writeHashFrame(hasher, "no-compensation")
	} else {
		writeHashBytes(hasher, compensation.schedule.digest[:])
		writeHashBytes(hasher, compensation.proofEvidence.digest[:])
		writeHashUint64(hasher, uint64(compensation.position))
	}
	if cancellationTarget == nil {
		writeHashFrame(hasher, "no-cancellation-target")
	} else {
		writeEffectProjection(hasher, *cancellationTarget)
	}
	writeHashInt64(hasher, authorizedAt.UnixMilli())
	return digestFromHasher(hasher)
}

func validateAttemptAdmission(value AttemptAdmission) error {
	if !value.initialized || !value.planDigest.initialized ||
		ValidateEffectKey(value.effect) != nil || !value.requestFingerprint.initialized ||
		value.authorizedAt.IsZero() || !value.binding.initialized || value.use == nil ||
		(value.replacementTransition != nil && value.observationTransition != nil) {
		return ErrInvalidAttempt
	}
	if _, err := ParsePlanKind(value.planKind.String()); err != nil {
		return ErrInvalidAttempt
	}
	if _, err := ParseAttemptPurpose(value.purpose.String()); err != nil ||
		!attemptPurposeMatchesPlan(value.purpose, value.planKind) {
		return ErrInvalidAttempt
	}
	if value.replacementTransition != nil &&
		value.purpose != AttemptPurposeForward && value.purpose != AttemptPurposeCompensation {
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
		if err != nil || !until.Equal(value.retryValidUntil) || !until.After(value.authorizedAt) ||
			(value.purpose != AttemptPurposeForward && value.purpose != AttemptPurposeCompensation &&
				value.purpose != AttemptPurposeProviderCancel) {
			return ErrInvalidAttempt
		}
	}
	if value.purpose == AttemptPurposeObservation {
		deadline, err := normalizeTime(value.observationDeadline)
		if !value.observationBinding.initialized || value.observationTransition == nil ||
			err != nil || !deadline.Equal(value.observationDeadline) ||
			!value.authorizedAt.Before(value.observationDeadline) ||
			value.observationTarget == nil ||
			!validObservationTarget(*value.observationTarget, value.planDigest, value.planKind, value.effect) {
			return ErrInvalidAttempt
		}
	} else if value.observationBinding.initialized || !value.observationDeadline.IsZero() ||
		value.observationTransition != nil ||
		value.observationTarget != nil {
		return ErrInvalidAttempt
	}
	return nil
}

func (value AttemptAdmission) AuthorizedAt() time.Time { return value.authorizedAt }

func (value AttemptAdmission) String() string {
	if validateAttemptAdmission(value) != nil {
		return "reconciliation-attempt-admission(invalid)"
	}
	return "reconciliation-attempt-admission(evidence=redacted)"
}
func (value AttemptAdmission) GoString() string { return value.String() }
func (value AttemptAdmission) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value AttemptAdmission) LogValue() slog.Value     { return redactedLogValue(value.String()) }
func (AttemptAdmission) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (AttemptAdmission) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (AttemptAdmission) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (AttemptAdmission) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
