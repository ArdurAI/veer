package reconciliation

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// RecoveryForCrash returns the adopted fail-safe action for every enumerated boundary.
func RecoveryForCrash(point CrashPoint) (RecoveryAction, error) {
	switch point {
	case CrashBeforeAPICommit:
		return RecoveryNoAcceptedWork, nil
	case CrashAfterAPICommit:
		return RecoveryReplayDurableResult, nil
	case CrashBeforeOutboxPublish:
		return RecoveryReclaimOutbox, nil
	case CrashAfterOutboxPublish:
		return RecoveryRepublishAllowed, nil
	case CrashDeliveryBeforeFence:
		return RecoveryNoProviderEffect, nil
	case CrashAfterAttemptPreparation:
		return RecoveryRecordIndeterminate, nil
	case CrashAfterResultCommit:
		return RecoveryDurableNoOp, nil
	case CrashLeaseLostDuringDispatch:
		return RecoveryStopAndObserve, nil
	default:
		return "", ErrInvalidTransition
	}
}

// TransitionBundle describes one atomic worker commit. It contains only
// cardinality and dispatch facts; actual StateStore persistence belongs to #30.
type TransitionBundle struct {
	initialized                bool
	operationWrite             bool
	attemptWrite               bool
	observationWrite           bool
	providerPossiblyDispatched bool
	providerAttemptAuditEvents uint8
	successorOutboxRecords     uint8
}

// TransitionBundleInput supplies the writes that must commit all-or-nothing.
type TransitionBundleInput struct {
	OperationWrite             bool
	AttemptWrite               bool
	ObservationWrite           bool
	ProviderPossiblyDispatched bool
	ProviderAttemptAuditEvents uint8
	SuccessorOutboxRecords     uint8
}

// NewTransitionBundle enforces exactly one provider-attempt audit event per
// actual or conservatively possibly-dispatched physical attempt and at most
// one successor outbox record.
func NewTransitionBundle(input TransitionBundleInput) (TransitionBundle, error) {
	if !input.OperationWrite && !input.AttemptWrite && !input.ObservationWrite {
		return TransitionBundle{}, ErrInvalidTransition
	}
	if input.SuccessorOutboxRecords > 1 {
		return TransitionBundle{}, ErrInvalidTransition
	}
	if input.ProviderPossiblyDispatched && !input.AttemptWrite {
		return TransitionBundle{}, ErrInvalidTransition
	}
	wantAudit := uint8(0)
	if input.ProviderPossiblyDispatched {
		wantAudit = 1
	}
	if input.ProviderAttemptAuditEvents != wantAudit {
		return TransitionBundle{}, ErrInvalidTransition
	}
	return TransitionBundle{
		initialized:                true,
		operationWrite:             input.OperationWrite,
		attemptWrite:               input.AttemptWrite,
		observationWrite:           input.ObservationWrite,
		providerPossiblyDispatched: input.ProviderPossiblyDispatched,
		providerAttemptAuditEvents: input.ProviderAttemptAuditEvents,
		successorOutboxRecords:     input.SuccessorOutboxRecords,
	}, nil
}

func (value TransitionBundle) SuccessorOutboxRecords() uint8 {
	return value.successorOutboxRecords
}
func (value TransitionBundle) ProviderAttemptAuditEvents() uint8 {
	return value.providerAttemptAuditEvents
}

// AuthorizeCommit verifies that all authoritative writes still use the exact
// current lineage owner and fence. The bundle itself is only a reference oracle.
func (table *LeaseTable) AuthorizeCommit(
	databaseTime time.Time,
	token LeaseToken,
	bundle TransitionBundle,
) error {
	if table == nil || !table.initialized || validateLeaseToken(token) != nil || !bundle.initialized {
		return ErrInvalidTransition
	}
	if token.table != table.identity {
		return ErrLeaseLost
	}
	now, err := normalizeTime(databaseTime)
	if err != nil {
		return err
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	if err := table.observeNowLocked(leaseRowKey(token.binding), now); err != nil {
		return err
	}
	if _, ok := table.currentRowLocked(now, token); !ok {
		return ErrLeaseLost
	}
	return nil
}

// DeliveryLedger is a bounded process-local duplicate-delivery oracle. It
// records work identity, never an SQS receipt handle or transport authority.
type DeliveryLedger struct {
	mu          sync.Mutex
	initialized bool
	maximum     int
	records     map[string]deliveryRecord
}

type deliveryRecord struct {
	binding   LeaseBinding
	ownerID   resource.ID
	fence     int64
	completed bool
}

// NewDeliveryLedger creates a bounded at-least-once delivery oracle.
func NewDeliveryLedger(maximum int) (*DeliveryLedger, error) {
	if maximum < 1 {
		return nil, ErrInvalidDelivery
	}
	return &DeliveryLedger{
		initialized: true,
		maximum:     maximum,
		records:     make(map[string]deliveryRecord, maximum),
	}, nil
}

// Begin classifies the first and subsequent deliveries of the same durable work.
func (ledger *DeliveryLedger) Begin(
	work WorkKey,
	deliveryID resource.ID,
	token LeaseToken,
) (DeliveryDisposition, error) {
	if ledger == nil || !ledger.initialized || !validWorkKey(work) || !validID(deliveryID) ||
		validateLeaseToken(token) != nil || !work.planDigest.Equal(token.binding.planDigest) {
		return "", ErrInvalidDelivery
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := work.String()
	current, exists := ledger.records[key]
	if exists {
		if current.completed {
			return DeliveryDuplicateCompleted, nil
		}
		if !current.binding.Equal(token.binding) {
			return "", ErrInvalidDelivery
		}
		if token.fence > current.fence {
			current.ownerID = token.ownerID
			current.fence = token.fence
			ledger.records[key] = current
			return DeliveryAccepted, nil
		}
		return DeliveryDuplicateActive, nil
	}
	if len(ledger.records) >= ledger.maximum {
		return "", ErrCapacity
	}
	ledger.records[key] = deliveryRecord{
		binding: token.binding,
		ownerID: token.ownerID,
		fence:   token.fence,
	}
	return DeliveryAccepted, nil
}

// Complete marks one exactly-owned durable work identity terminal; redelivery
// becomes a no-op.
func (ledger *DeliveryLedger) Complete(work WorkKey, token LeaseToken) error {
	if ledger == nil || !ledger.initialized || !validWorkKey(work) || validateLeaseToken(token) != nil ||
		!work.planDigest.Equal(token.binding.planDigest) {
		return ErrInvalidDelivery
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := work.String()
	current, exists := ledger.records[key]
	if !exists {
		return ErrInvalidDelivery
	}
	if !current.binding.Equal(token.binding) || current.ownerID != token.ownerID || current.fence != token.fence {
		return ErrReservationLost
	}
	current.completed = true
	ledger.records[key] = current
	return nil
}

// CancellationPublicState maps durable cancel state onto the unchanged public
// Operation phase vocabulary. It adds no Conditions field.
func CancellationPublicState(
	current operation.Operation,
	ownerActive bool,
	attempts []Attempt,
	cleanupDurable bool,
	quarantineDurable bool,
) (operation.Phase, WorkReason, error) {
	if operation.Validate(current) != nil {
		return "", WorkReasonNone, ErrInvalidAttempt
	}
	if terminalOperation(current.Phase) {
		return current.Phase, WorkReasonNone, nil
	}
	hasUnresolved := false
	hasIndeterminate := false
	seen := make(map[string]struct{}, len(attempts))
	seenOrdinals := make(map[uint32]struct{}, len(attempts))
	for _, attempt := range attempts {
		if ValidateAttempt(attempt) != nil ||
			attempt.effect.operationID != current.ID ||
			attempt.effect.workspaceID != current.WorkspaceID ||
			attempt.effect.resourceID != current.ResourceID ||
			attempt.effect.generation != current.Generation {
			return "", WorkReasonNone, ErrInvalidAttempt
		}
		if _, duplicate := seen[attempt.id.String()]; duplicate {
			return "", WorkReasonNone, ErrInvalidAttempt
		}
		if _, duplicate := seenOrdinals[attempt.ordinal]; duplicate {
			return "", WorkReasonNone, ErrInvalidAttempt
		}
		seen[attempt.id.String()] = struct{}{}
		seenOrdinals[attempt.ordinal] = struct{}{}
		switch attempt.state {
		case AttemptStatePrepared, AttemptStateDispatched:
			hasUnresolved = true
		case AttemptStateIndeterminate:
			hasIndeterminate = true
		}
	}
	if !cleanupDurable || hasUnresolved || (hasIndeterminate && !quarantineDurable) {
		if ownerActive {
			return operation.PhaseRunning, WorkReasonCancelPending, nil
		}
		return operation.PhaseWaiting, WorkReasonCancelPending, nil
	}
	return operation.PhaseCanceled, WorkReasonNone, nil
}

// canPrepareAfterCancellation allows only observation or an explicitly
// recorded provider-cancel effect. NewAttemptAdmission invokes it so callers
// cannot bypass the cancellation gate at attempt construction.
func canPrepareAfterCancellation(purpose AttemptPurpose) error {
	switch purpose {
	case AttemptPurposeObservation, AttemptPurposeProviderCancel:
		return nil
	case AttemptPurposeForward, AttemptPurposeCompensation:
		return ErrInvalidTransition
	default:
		return ErrInvalidAttempt
	}
}

// IndeterminatePublicState keeps unknown external truth visible and nonterminal.
func IndeterminatePublicState() (operation.Phase, WorkReason) {
	return operation.PhaseWaiting, WorkReasonProviderOutcomeIndeterminate
}

// ObservationBudget is a finite attempt-and-time budget for resolving one
// indeterminate provider effect.
type ObservationBudget struct {
	initialized bool
	effect      EffectKey
	maximum     uint32
	used        uint32
	deadline    time.Time
	lastAt      time.Time
	version     uint64
	inFlight    bool
	binding     digestValue
	transition  *atomic.Bool
	done        bool
	quarantined bool
}

// ObservationPermit is one process-local, one-use reservation for an exact
// observation attempt. Copies share their use state.
type ObservationPermit struct {
	initialized bool
	effect      EffectKey
	version     uint64
	reservedAt  time.Time
	deadline    time.Time
	binding     digestValue
	transition  *atomic.Uint32
}

const (
	observationReserved uint32 = iota
	observationAdmitted
	observationPrepared
	observationReleased
)

// NewObservationBudget creates a finite nonzero resolution budget.
func NewObservationBudget(effect EffectKey, maximum uint32, deadline time.Time) (ObservationBudget, error) {
	until, err := normalizeTime(deadline)
	if err != nil || ValidateEffectKey(effect) != nil || maximum == 0 || maximum > MaxObservationAttempts {
		return ObservationBudget{}, ErrInvalidObservation
	}
	return ObservationBudget{
		initialized: true,
		effect:      effect,
		maximum:     maximum,
		deadline:    until,
		version:     1,
		transition:  &atomic.Bool{},
	}, nil
}

// ReserveObservation atomically consumes one live budget slot before an
// observation attempt can be constructed. Stale copies of before cannot mint
// a second permit.
func ReserveObservation(
	before ObservationBudget,
	reservedAt time.Time,
) (ObservationBudget, ObservationPermit, error) {
	if validateObservationBudget(before) != nil {
		return before, ObservationPermit{}, ErrInvalidObservation
	}
	at, err := normalizeTime(reservedAt)
	if err != nil || (!before.lastAt.IsZero() && at.Before(before.lastAt)) {
		return before, ObservationPermit{}, ErrInvalidObservation
	}
	if before.done || before.inFlight || before.used >= before.maximum ||
		!at.Before(before.deadline) || before.version == ^uint64(0) {
		return before, ObservationPermit{}, ErrObservationExhausted
	}
	if !before.transition.CompareAndSwap(false, true) {
		return before, ObservationPermit{}, ErrInvalidObservation
	}
	after := before
	after.lastAt = at
	after.used++
	after.version++
	after.inFlight = true
	after.binding = deriveObservationBinding(after.effect, after.version, after.used, at, after.deadline)
	after.transition = &atomic.Bool{}
	return after, ObservationPermit{
		initialized: true,
		effect:      after.effect,
		version:     after.version,
		reservedAt:  at,
		deadline:    after.deadline,
		binding:     after.binding,
		transition:  &atomic.Uint32{},
	}, nil
}

// ReleaseObservation retires one exact reserved or admitted observation when
// no attempt was prepared. The used slot remains charged, while later budget
// slots and exact-deadline quarantine become reachable again.
func ReleaseObservation(
	before ObservationBudget,
	permit ObservationPermit,
	releasedAt time.Time,
) (ObservationBudget, error) {
	if validateObservationBudget(before) != nil || !before.inFlight ||
		validateObservationPermit(permit) != nil || !permit.effect.Equal(before.effect) ||
		permit.version != before.version || !permit.reservedAt.Equal(before.lastAt) ||
		!permit.deadline.Equal(before.deadline) ||
		!equalDigest(permit.binding, before.binding) ||
		before.version == ^uint64(0) {
		return before, ErrInvalidObservation
	}
	at, err := normalizeTime(releasedAt)
	if err != nil || at.Before(before.lastAt) {
		return before, ErrInvalidObservation
	}
	for {
		state := permit.transition.Load()
		if state != observationReserved && state != observationAdmitted {
			return before, ErrInvalidObservation
		}
		if permit.transition.CompareAndSwap(state, observationReleased) {
			break
		}
	}
	if !before.transition.CompareAndSwap(false, true) {
		return before, ErrInvalidObservation
	}
	after := before
	after.version++
	after.inFlight = false
	after.binding = digestValue{}
	after.lastAt = at
	after.transition = &atomic.Bool{}
	return after, nil
}

// CompleteObservation closes one reserved slot from the exact resolved
// observation attempt and the authoritative current logical effect. A
// definitive dispatched result updates only the exact target captured during
// admission; a concurrently advanced effect or an undispatched recovery is
// returned unchanged. A future StateStore must compare and commit the budget
// and current effect atomically. Otherwise the count/time boundary quarantines
// the still-indeterminate effect exactly once.
func CompleteObservation(
	before ObservationBudget,
	current EffectProjection,
	attempt Attempt,
) (ObservationBudget, EffectProjection, ObservationDecision, error) {
	if validateObservationBudget(before) != nil || !before.inFlight ||
		validateEffectProjection(current) != nil ||
		ValidateAttempt(attempt) != nil || attempt.purpose != AttemptPurposeObservation ||
		!attempt.effect.Equal(before.effect) || !attempt.observationBinding.initialized ||
		!attempt.observationDeadline.Equal(before.deadline) || attempt.observationTarget == nil ||
		!effectProjectionIdentityEqual(current, *attempt.observationTarget) ||
		current.updatedAt.Before(attempt.observationTarget.updatedAt) ||
		!equalDigest(attempt.observationBinding, before.binding) || !attempt.Resolved() ||
		attempt.resolvedAt.Before(before.lastAt) || before.version == ^uint64(0) {
		return before, cloneEffectProjection(current), "", ErrInvalidObservation
	}
	if !before.transition.CompareAndSwap(false, true) {
		return before, cloneEffectProjection(current), "", ErrInvalidObservation
	}
	after := before
	after.version++
	after.inFlight = false
	after.binding = digestValue{}
	completionAt := attempt.resolvedAt
	if current.updatedAt.After(completionAt) {
		completionAt = current.updatedAt
	}
	after.lastAt = completionAt
	after.transition = &atomic.Bool{}
	projection := cloneEffectProjection(current)
	exactTarget := effectProjectionsEqual(current, *attempt.observationTarget)
	if exactTarget && attempt.Definitive() && !attempt.dispatchedAt.IsZero() {
		projection.state = attempt.state
		projection.sourceAttemptID = attempt.id
		projection.updatedAt = attempt.resolvedAt
		after.done = true
		return after, projection, ObservationResolved, nil
	}
	if projection.state == AttemptStateApplied || projection.state == AttemptStateNoEffect {
		after.done = true
		return after, projection, ObservationResolved, nil
	}
	if after.used >= after.maximum || !completionAt.Before(after.deadline) {
		after.done = true
		after.quarantined = true
		return after, projection, ObservationQuarantine, nil
	}
	return after, projection, ObservationContinue, nil
}

// ExpireObservationBudget records time-bound quarantine when no attempt is in
// flight. Equality with the deadline is expired.
func ExpireObservationBudget(
	before ObservationBudget,
	observedAt time.Time,
) (ObservationBudget, ObservationDecision, error) {
	if validateObservationBudget(before) != nil {
		return before, "", ErrInvalidObservation
	}
	if before.done {
		return before, ObservationAlreadyDone, nil
	}
	at, err := normalizeTime(observedAt)
	if err != nil || before.inFlight || at.Before(before.lastAt) || at.Before(before.deadline) ||
		before.version == ^uint64(0) {
		return before, "", ErrInvalidObservation
	}
	if !before.transition.CompareAndSwap(false, true) {
		return before, "", ErrInvalidObservation
	}
	after := before
	after.version++
	after.lastAt = at
	after.done = true
	after.quarantined = true
	after.transition = &atomic.Bool{}
	return after, ObservationQuarantine, nil
}

func (value ObservationBudget) Used() uint32      { return value.used }
func (value ObservationBudget) Quarantined() bool { return value.quarantined }

// EffectRetentionInput supplies every reference that can keep current provider
// ownership/effect evidence alive after deletion.
type EffectRetentionInput struct {
	Projection          EffectProjection
	DeletedAt           *time.Time
	EvaluatedAt         time.Time
	OperationReferences bool
	OutboxReferences    bool
	DeliveryReferences  bool
	RedriveAuthority    bool
}

// EvaluateEffectRetention requires both the 90-day minimum and complete proof
// that no operation, outbox, delivery, redrive, or unknown effect remains.
func EvaluateEffectRetention(input EffectRetentionInput) (RetentionDisposition, error) {
	if validateEffectProjection(input.Projection) != nil {
		return "", ErrInvalidRetention
	}
	now, err := normalizeTime(input.EvaluatedAt)
	if err != nil || now.Before(input.Projection.updatedAt) {
		return "", ErrInvalidRetention
	}
	if input.DeletedAt == nil {
		return RetentionKeep, nil
	}
	deletedAt, err := normalizeTime(*input.DeletedAt)
	if err != nil || deletedAt.After(now) {
		return "", ErrInvalidRetention
	}
	if input.Projection.state == AttemptStatePrepared || input.Projection.state == AttemptStateDispatched ||
		input.Projection.state == AttemptStateIndeterminate || input.OperationReferences || input.OutboxReferences ||
		input.DeliveryReferences || input.RedriveAuthority || now.Sub(deletedAt) < MinimumEffectTombstoneRetention {
		return RetentionKeep, nil
	}
	return RetentionEligible, nil
}

func validateObservationBudget(value ObservationBudget) error {
	if !value.initialized || ValidateEffectKey(value.effect) != nil || value.maximum == 0 ||
		value.maximum > MaxObservationAttempts || value.used > value.maximum || value.deadline.IsZero() ||
		value.version == 0 || value.transition == nil || value.quarantined && !value.done ||
		value.inFlight != value.binding.initialized || value.done && value.inFlight ||
		value.used > 0 && value.lastAt.IsZero() {
		return ErrInvalidObservation
	}
	return nil
}

func validateObservationPermit(value ObservationPermit) error {
	deadline, err := normalizeTime(value.deadline)
	if !value.initialized || ValidateEffectKey(value.effect) != nil || value.version < 2 ||
		value.reservedAt.IsZero() || err != nil || !deadline.Equal(value.deadline) ||
		!value.reservedAt.Before(value.deadline) || !value.binding.initialized || value.transition == nil {
		return ErrInvalidObservation
	}
	return nil
}

func deriveObservationBinding(
	effect EffectKey,
	version uint64,
	used uint32,
	reservedAt time.Time,
	deadline time.Time,
) digestValue {
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.observation-admission.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashBytes(hasher, effect.digest.digest[:])
	writeHashUint64(hasher, version)
	writeHashUint64(hasher, uint64(used))
	writeHashInt64(hasher, reservedAt.UnixMilli())
	writeHashInt64(hasher, deadline.UnixMilli())
	return digestFromHasher(hasher)
}

func (value ObservationPermit) Deadline() time.Time { return value.deadline }

func (value ObservationBudget) String() string {
	if validateObservationBudget(value) != nil {
		return "reconciliation-observation-budget(invalid)"
	}
	return fmt.Sprintf("reconciliation-observation-budget(used=%d,maximum=%d,done=%t,identity=redacted)", value.used, value.maximum, value.done)
}
func (value ObservationBudget) GoString() string { return value.String() }
func (value ObservationBudget) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value ObservationBudget) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (value ObservationPermit) String() string {
	if validateObservationPermit(value) != nil {
		return "reconciliation-observation-permit(invalid)"
	}
	return "reconciliation-observation-permit(evidence=redacted)"
}
func (value ObservationPermit) GoString() string { return value.String() }
func (value ObservationPermit) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value ObservationPermit) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (TransitionBundle) MarshalJSON() ([]byte, error)    { return nil, ErrSerializationForbidden }
func (TransitionBundle) MarshalText() ([]byte, error)    { return nil, ErrSerializationForbidden }
func (TransitionBundle) MarshalBinary() ([]byte, error)  { return nil, ErrSerializationForbidden }
func (TransitionBundle) GobEncode() ([]byte, error)      { return nil, ErrSerializationForbidden }
func (*DeliveryLedger) MarshalJSON() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (*DeliveryLedger) MarshalText() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (*DeliveryLedger) MarshalBinary() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (*DeliveryLedger) GobEncode() ([]byte, error)       { return nil, ErrSerializationForbidden }
func (ObservationBudget) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ObservationBudget) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ObservationBudget) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (ObservationBudget) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (ObservationPermit) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ObservationPermit) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ObservationPermit) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (ObservationPermit) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
