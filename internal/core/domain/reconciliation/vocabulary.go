package reconciliation

import (
	"math"
	"slices"
	"time"
)

const (
	// ContractVersion binds this package's vocabulary, digest framing, and transitions.
	ContractVersion = "veer.reconciliation.v1alpha1"
	// MaxEvidenceBytes bounds one canonical input before it is reduced to a digest.
	MaxEvidenceBytes = 262_144
	// MaxEvidenceVersionBytes bounds one opaque evidence-version label.
	MaxEvidenceVersionBytes = 128
	// MaxSemanticEffectBytes bounds one canonical provider-neutral effect description.
	MaxSemanticEffectBytes = 65_536
	// MaxEffectsPerOperation bounds logical plan, compensation, and conflict sets.
	MaxEffectsPerOperation = 1_000
	// MaxObservationAttempts bounds one finite unknown-outcome resolution budget.
	MaxObservationAttempts = 1_000
	// MinIdempotencyKeyBytes matches the v1alpha1 HTTP contract.
	MinIdempotencyKeyBytes = 16
	// MaxIdempotencyKeyBytes matches the v1alpha1 HTTP contract.
	MaxIdempotencyKeyBytes = 128
	// HTTPIdempotencyWindow is fixed and never slides on replay.
	HTTPIdempotencyWindow = 24 * time.Hour
	// MinimumEffectTombstoneRetention fences deleted provider ownership evidence.
	MinimumEffectTombstoneRetention = 90 * 24 * time.Hour
	// StoreLeaseDuration is the target authoritative ownership interval.
	StoreLeaseDuration = 60 * time.Second
	// QueueVisibilityDuration is the duplicate-load suppression interval.
	QueueVisibilityDuration = 60 * time.Second
	// RenewalJitterMinimum is the earliest stable per-work renewal target.
	RenewalJitterMinimum = 15 * time.Second
	// RenewalDeadline is the latest allowed store/visibility renewal target.
	RenewalDeadline = 20 * time.Second
	// DispatchSafetyMargin reserves cleanup time before lease expiry.
	DispatchSafetyMargin = 10 * time.Second
	// MaxFence is the largest positive PostgreSQL bigint fence.
	MaxFence int64 = math.MaxInt64

	// SmallActiveLeaseLimit is ADR 0001's small-profile nonterminal bound.
	SmallActiveLeaseLimit = 100
	// TargetActiveLeaseLimit is ADR 0001's target-profile nonterminal bound.
	TargetActiveLeaseLimit = 1_000
	// MonthlyHours is the accepted deterministic 31-day cost envelope.
	MonthlyHours = 744
	// SmallMonthlyLeaseRenewals bounds 100 continuously active 15-second heartbeats.
	SmallMonthlyLeaseRenewals = 17_856_000
	// TargetMonthlyLeaseRenewals bounds 1,000 continuously active 15-second heartbeats.
	TargetMonthlyLeaseRenewals = 178_560_000
	// SmallMonthlyVisibilityRequests reserves worst-case small-profile extensions.
	SmallMonthlyVisibilityRequests = 3_546_645
	// TargetMonthlyVisibilityRequests reserves worst-case target-profile extensions.
	TargetMonthlyVisibilityRequests = 17_608_245 * 3
	// SmallMonthlyQueueRequestCap includes the visibility partition.
	SmallMonthlyQueueRequestCap = 20_000_000 + SmallMonthlyVisibilityRequests
	// TargetMonthlyQueueRequestCap includes the visibility partition.
	TargetMonthlyQueueRequestCap = 100_000_000 + TargetMonthlyVisibilityRequests
)

// EvidenceKind identifies one input dimension bound into a plan digest.
type EvidenceKind string

const (
	EvidenceDesiredIntent       EvidenceKind = "DesiredIntent"
	EvidenceObservedSnapshot    EvidenceKind = "ObservedSnapshot"
	EvidenceProviderConnection  EvidenceKind = "ProviderConnection"
	EvidenceCredentialReference EvidenceKind = "CredentialReference"
	EvidenceCapability          EvidenceKind = "Capability"
	EvidenceQuota               EvidenceKind = "Quota"
	EvidenceCost                EvidenceKind = "Cost"
)

var evidenceKinds = []EvidenceKind{
	EvidenceDesiredIntent,
	EvidenceObservedSnapshot,
	EvidenceProviderConnection,
	EvidenceCredentialReference,
	EvidenceCapability,
	EvidenceQuota,
	EvidenceCost,
}

func (kind EvidenceKind) String() string { return string(kind) }
func ParseEvidenceKind(value string) (EvidenceKind, error) {
	for _, candidate := range evidenceKinds {
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return "", ErrInvalidEvidence
}
func EvidenceKinds() []EvidenceKind { return slices.Clone(evidenceKinds) }

// PlanKind separates ordinary forward work from an explicit forward compensation plan.
type PlanKind string

const (
	PlanKindForward      PlanKind = "Forward"
	PlanKindCompensation PlanKind = "Compensation"
)

var planKinds = []PlanKind{PlanKindForward, PlanKindCompensation}

func (kind PlanKind) String() string { return string(kind) }
func ParsePlanKind(value string) (PlanKind, error) {
	for _, candidate := range planKinds {
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return "", ErrInvalidPlan
}
func PlanKinds() []PlanKind { return slices.Clone(planKinds) }

// PlanSelection describes whether candidate inputs reuse or supersede a plan.
type PlanSelection string

const (
	PlanSelectionReuse     PlanSelection = "Reuse"
	PlanSelectionSupersede PlanSelection = "Supersede"
)

var planSelections = []PlanSelection{PlanSelectionReuse, PlanSelectionSupersede}

func (value PlanSelection) String() string { return string(value) }
func ParsePlanSelection(value string) (PlanSelection, error) {
	return parseClosed(PlanSelection(value), planSelections, ErrInvalidPlan)
}
func PlanSelections() []PlanSelection { return slices.Clone(planSelections) }

// IdempotencyDisposition distinguishes a new fixed-window reservation from replay.
type IdempotencyDisposition string

const (
	IdempotencyReserved IdempotencyDisposition = "Reserved"
	IdempotencyReplay   IdempotencyDisposition = "Replay"
)

var idempotencyDispositions = []IdempotencyDisposition{IdempotencyReserved, IdempotencyReplay}

func (value IdempotencyDisposition) String() string { return string(value) }
func ParseIdempotencyDisposition(value string) (IdempotencyDisposition, error) {
	return parseClosed(IdempotencyDisposition(value), idempotencyDispositions, ErrInvalidIdempotency)
}
func IdempotencyDispositions() []IdempotencyDisposition {
	return slices.Clone(idempotencyDispositions)
}

// AttemptPurpose separates forward mutation, observation, cancellation, and compensation calls.
type AttemptPurpose string

const (
	AttemptPurposeForward        AttemptPurpose = "Forward"
	AttemptPurposeObservation    AttemptPurpose = "Observation"
	AttemptPurposeProviderCancel AttemptPurpose = "ProviderCancel"
	AttemptPurposeCompensation   AttemptPurpose = "Compensation"
)

var attemptPurposes = []AttemptPurpose{
	AttemptPurposeForward,
	AttemptPurposeObservation,
	AttemptPurposeProviderCancel,
	AttemptPurposeCompensation,
}

func (purpose AttemptPurpose) String() string { return string(purpose) }
func ParseAttemptPurpose(value string) (AttemptPurpose, error) {
	for _, candidate := range attemptPurposes {
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return "", ErrInvalidAttempt
}
func AttemptPurposes() []AttemptPurpose { return slices.Clone(attemptPurposes) }

// AttemptState is the physical-call state. Indeterminate is resolved but not definitive.
type AttemptState string

const (
	AttemptStatePrepared      AttemptState = "Prepared"
	AttemptStateDispatched    AttemptState = "Dispatched"
	AttemptStateApplied       AttemptState = "Applied"
	AttemptStateNoEffect      AttemptState = "NoEffect"
	AttemptStateIndeterminate AttemptState = "Indeterminate"
)

var attemptStates = []AttemptState{
	AttemptStatePrepared,
	AttemptStateDispatched,
	AttemptStateApplied,
	AttemptStateNoEffect,
	AttemptStateIndeterminate,
}

func (state AttemptState) String() string { return string(state) }
func ParseAttemptState(value string) (AttemptState, error) {
	for _, candidate := range attemptStates {
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return "", ErrInvalidAttempt
}
func AttemptStates() []AttemptState { return slices.Clone(attemptStates) }

// EffectState is durable provider-effect truth, independent from retry eligibility.
type EffectState string

const (
	EffectStateApplied       EffectState = "Applied"
	EffectStateNoEffect      EffectState = "NoEffect"
	EffectStateIndeterminate EffectState = "Indeterminate"
)

var effectStates = []EffectState{
	EffectStateApplied,
	EffectStateNoEffect,
	EffectStateIndeterminate,
}

func (state EffectState) String() string { return string(state) }
func ParseEffectState(value string) (EffectState, error) {
	return parseClosed(EffectState(value), effectStates, ErrInvalidAttempt)
}
func EffectStates() []EffectState { return slices.Clone(effectStates) }

// DispatchProof distinguishes a proven absent call from uncertainty after owner loss.
type DispatchProof string

const (
	DispatchProofNeverBegan DispatchProof = "NeverBegan"
	DispatchProofUnknown    DispatchProof = "Unknown"
)

var dispatchProofs = []DispatchProof{DispatchProofNeverBegan, DispatchProofUnknown}

func (proof DispatchProof) String() string { return string(proof) }
func ParseDispatchProof(value string) (DispatchProof, error) {
	return parseClosed(DispatchProof(value), dispatchProofs, ErrInvalidAttempt)
}
func DispatchProofs() []DispatchProof { return slices.Clone(dispatchProofs) }

// WorkReason is the stable internal reason projected through existing Operation phases.
type WorkReason string

const (
	WorkReasonNone                         WorkReason = ""
	WorkReasonCancelPending                WorkReason = "CancelPending"
	WorkReasonProviderOutcomeIndeterminate WorkReason = "ProviderOutcomeIndeterminate"
	WorkReasonProviderEffectConflict       WorkReason = "ProviderEffectConflict"
	WorkReasonQuarantined                  WorkReason = "Quarantined"
)

var workReasons = []WorkReason{
	WorkReasonCancelPending,
	WorkReasonProviderOutcomeIndeterminate,
	WorkReasonProviderEffectConflict,
	WorkReasonQuarantined,
}

func (reason WorkReason) String() string { return string(reason) }
func ParseWorkReason(value string) (WorkReason, error) {
	return parseClosed(WorkReason(value), workReasons, ErrInvalidTransition)
}
func WorkReasons() []WorkReason { return slices.Clone(workReasons) }

// DeliveryDisposition classifies duplicate at-least-once deliveries without granting authority.
type DeliveryDisposition string

const (
	DeliveryAccepted           DeliveryDisposition = "Accepted"
	DeliveryDuplicateActive    DeliveryDisposition = "DuplicateActive"
	DeliveryDuplicateCompleted DeliveryDisposition = "DuplicateCompleted"
)

var deliveryDispositions = []DeliveryDisposition{
	DeliveryAccepted,
	DeliveryDuplicateActive,
	DeliveryDuplicateCompleted,
}

func (value DeliveryDisposition) String() string { return string(value) }
func ParseDeliveryDisposition(value string) (DeliveryDisposition, error) {
	return parseClosed(DeliveryDisposition(value), deliveryDispositions, ErrInvalidDelivery)
}
func DeliveryDispositions() []DeliveryDisposition { return slices.Clone(deliveryDispositions) }

// MaintenanceKind identifies the authoritative lease or transport visibility heartbeat.
type MaintenanceKind string

const (
	MaintenanceStoreLease      MaintenanceKind = "StoreLease"
	MaintenanceQueueVisibility MaintenanceKind = "QueueVisibility"
)

var maintenanceKinds = []MaintenanceKind{MaintenanceStoreLease, MaintenanceQueueVisibility}

func (kind MaintenanceKind) String() string { return string(kind) }
func ParseMaintenanceKind(value string) (MaintenanceKind, error) {
	return parseClosed(MaintenanceKind(value), maintenanceKinds, ErrInvalidTransition)
}
func MaintenanceKinds() []MaintenanceKind { return slices.Clone(maintenanceKinds) }

// MaintenanceOutcome is a closed result; Unknown is never treated as success.
type MaintenanceOutcome string

const (
	MaintenanceSucceeded MaintenanceOutcome = "Succeeded"
	MaintenanceFailed    MaintenanceOutcome = "Failed"
	MaintenanceUnknown   MaintenanceOutcome = "Unknown"
)

var maintenanceOutcomes = []MaintenanceOutcome{
	MaintenanceSucceeded,
	MaintenanceFailed,
	MaintenanceUnknown,
}

func (outcome MaintenanceOutcome) String() string { return string(outcome) }
func ParseMaintenanceOutcome(value string) (MaintenanceOutcome, error) {
	return parseClosed(MaintenanceOutcome(value), maintenanceOutcomes, ErrInvalidTransition)
}
func MaintenanceOutcomes() []MaintenanceOutcome { return slices.Clone(maintenanceOutcomes) }

// MaintenanceDirective tells the worker whether dispatch authority remains usable.
type MaintenanceDirective string

const (
	MaintenanceContinue         MaintenanceDirective = "Continue"
	MaintenanceStopAndSurrender MaintenanceDirective = "StopAndSurrender"
)

var maintenanceDirectives = []MaintenanceDirective{MaintenanceContinue, MaintenanceStopAndSurrender}

func (directive MaintenanceDirective) String() string { return string(directive) }
func ParseMaintenanceDirective(value string) (MaintenanceDirective, error) {
	return parseClosed(MaintenanceDirective(value), maintenanceDirectives, ErrInvalidTransition)
}
func MaintenanceDirectives() []MaintenanceDirective { return slices.Clone(maintenanceDirectives) }

// ObservationDecision makes finite uncertainty handling explicit.
type ObservationDecision string

const (
	ObservationContinue    ObservationDecision = "Continue"
	ObservationResolved    ObservationDecision = "Resolved"
	ObservationQuarantine  ObservationDecision = "Quarantine"
	ObservationAlreadyDone ObservationDecision = "AlreadyDone"
)

var observationDecisions = []ObservationDecision{
	ObservationContinue,
	ObservationResolved,
	ObservationQuarantine,
	ObservationAlreadyDone,
}

func (decision ObservationDecision) String() string { return string(decision) }
func ParseObservationDecision(value string) (ObservationDecision, error) {
	return parseClosed(ObservationDecision(value), observationDecisions, ErrInvalidObservation)
}
func ObservationDecisions() []ObservationDecision { return slices.Clone(observationDecisions) }

// RetentionDisposition reports whether current provider-effect evidence may be removed.
type RetentionDisposition string

const (
	RetentionKeep     RetentionDisposition = "Keep"
	RetentionEligible RetentionDisposition = "Eligible"
)

var retentionDispositions = []RetentionDisposition{RetentionKeep, RetentionEligible}

func (disposition RetentionDisposition) String() string { return string(disposition) }
func ParseRetentionDisposition(value string) (RetentionDisposition, error) {
	return parseClosed(RetentionDisposition(value), retentionDispositions, ErrInvalidRetention)
}
func RetentionDispositions() []RetentionDisposition { return slices.Clone(retentionDispositions) }

// CrashPoint enumerates every adopted API/outbox/delivery/provider crash boundary.
type CrashPoint string

const (
	CrashBeforeAPICommit         CrashPoint = "BeforeAPICommit"
	CrashAfterAPICommit          CrashPoint = "AfterAPICommitBeforeResponse"
	CrashBeforeOutboxPublish     CrashPoint = "BeforeOutboxPublish"
	CrashAfterOutboxPublish      CrashPoint = "AfterOutboxPublishBeforeReceipt"
	CrashDeliveryBeforeFence     CrashPoint = "DeliveryBeforeFence"
	CrashAfterAttemptPreparation CrashPoint = "AfterAttemptPreparationBeforeResult"
	CrashAfterResultCommit       CrashPoint = "AfterResultCommitBeforeAcknowledgement"
	CrashLeaseLostDuringDispatch CrashPoint = "LeaseLostDuringDispatch"
)

var crashPoints = []CrashPoint{
	CrashBeforeAPICommit,
	CrashAfterAPICommit,
	CrashBeforeOutboxPublish,
	CrashAfterOutboxPublish,
	CrashDeliveryBeforeFence,
	CrashAfterAttemptPreparation,
	CrashAfterResultCommit,
	CrashLeaseLostDuringDispatch,
}

func (point CrashPoint) String() string { return string(point) }
func ParseCrashPoint(value string) (CrashPoint, error) {
	return parseClosed(CrashPoint(value), crashPoints, ErrInvalidTransition)
}
func CrashPoints() []CrashPoint { return slices.Clone(crashPoints) }

// RecoveryAction is the only safe action at one enumerated crash boundary.
type RecoveryAction string

const (
	RecoveryNoAcceptedWork      RecoveryAction = "NoAcceptedWork"
	RecoveryReplayDurableResult RecoveryAction = "ReplayDurableResult"
	RecoveryReclaimOutbox       RecoveryAction = "ReclaimOutbox"
	RecoveryRepublishAllowed    RecoveryAction = "RepublishAllowed"
	RecoveryNoProviderEffect    RecoveryAction = "NoProviderEffect"
	RecoveryRecordIndeterminate RecoveryAction = "RecordIndeterminate"
	RecoveryDurableNoOp         RecoveryAction = "DurableNoOp"
	RecoveryStopAndObserve      RecoveryAction = "StopAndObserve"
)

var recoveryActions = []RecoveryAction{
	RecoveryNoAcceptedWork,
	RecoveryReplayDurableResult,
	RecoveryReclaimOutbox,
	RecoveryRepublishAllowed,
	RecoveryNoProviderEffect,
	RecoveryRecordIndeterminate,
	RecoveryDurableNoOp,
	RecoveryStopAndObserve,
}

func (action RecoveryAction) String() string { return string(action) }
func ParseRecoveryAction(value string) (RecoveryAction, error) {
	return parseClosed(RecoveryAction(value), recoveryActions, ErrInvalidTransition)
}
func RecoveryActions() []RecoveryAction { return slices.Clone(recoveryActions) }

func parseClosed[T comparable](value T, candidates []T, invalid error) (T, error) {
	for _, candidate := range candidates {
		if value == candidate {
			return value, nil
		}
	}
	var zero T
	return zero, invalid
}
