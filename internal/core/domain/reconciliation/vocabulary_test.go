package reconciliation

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestContractConstants(t *testing.T) {
	t.Parallel()
	if ContractVersion != "veer.reconciliation.v1alpha1" {
		t.Fatalf("ContractVersion = %q", ContractVersion)
	}
	if HTTPIdempotencyWindow != 24*time.Hour ||
		MinimumEffectTombstoneRetention != 90*24*time.Hour ||
		StoreLeaseDuration != time.Minute || QueueVisibilityDuration != time.Minute ||
		RenewalJitterMinimum != 15*time.Second || RenewalDeadline != 20*time.Second ||
		DispatchSafetyMargin != 10*time.Second {
		t.Fatal("reliability timing contract drifted")
	}
	if MaxFence <= 0 || SmallActiveLeaseLimit != 100 || TargetActiveLeaseLimit != 1_000 {
		t.Fatal("lease bounds drifted")
	}
	if SmallMonthlyLeaseRenewals != 17_856_000 || TargetMonthlyLeaseRenewals != 178_560_000 ||
		SmallMonthlyVisibilityRequests != 3_546_645 || TargetMonthlyVisibilityRequests != 52_824_735 ||
		SmallMonthlyQueueRequestCap != 23_546_645 || TargetMonthlyQueueRequestCap != 152_824_735 {
		t.Fatal("cost reservation contract drifted")
	}
}

func TestClosedVocabularyRegistries(t *testing.T) {
	t.Parallel()
	testClosedVocabulary(t, "evidence", EvidenceKinds, ParseEvidenceKind, []EvidenceKind{
		EvidenceDesiredIntent, EvidenceObservedSnapshot, EvidenceProviderConnection,
		EvidenceCredentialReference, EvidenceCapability, EvidenceQuota, EvidenceCost,
	}, ErrInvalidEvidence)
	testClosedVocabulary(t, "plan-kind", PlanKinds, ParsePlanKind,
		[]PlanKind{PlanKindForward, PlanKindCompensation}, ErrInvalidPlan)
	testClosedVocabulary(t, "plan-selection", PlanSelections, ParsePlanSelection,
		[]PlanSelection{PlanSelectionReuse, PlanSelectionSupersede}, ErrInvalidPlan)
	testClosedVocabulary(t, "idempotency", IdempotencyDispositions, ParseIdempotencyDisposition,
		[]IdempotencyDisposition{IdempotencyReserved, IdempotencyReplay}, ErrInvalidIdempotency)
	testClosedVocabulary(t, "attempt-purpose", AttemptPurposes, ParseAttemptPurpose, []AttemptPurpose{
		AttemptPurposeForward, AttemptPurposeObservation, AttemptPurposeProviderCancel, AttemptPurposeCompensation,
	}, ErrInvalidAttempt)
	testClosedVocabulary(t, "attempt-state", AttemptStates, ParseAttemptState, []AttemptState{
		AttemptStatePrepared, AttemptStateDispatched, AttemptStateApplied,
		AttemptStateNoEffect, AttemptStateIndeterminate,
	}, ErrInvalidAttempt)
	testClosedVocabulary(t, "effect-state", EffectStates, ParseEffectState,
		[]EffectState{EffectStateApplied, EffectStateNoEffect, EffectStateIndeterminate}, ErrInvalidAttempt)
	testClosedVocabulary(t, "dispatch-proof", DispatchProofs, ParseDispatchProof,
		[]DispatchProof{DispatchProofNeverBegan, DispatchProofUnknown}, ErrInvalidAttempt)
	testClosedVocabulary(t, "work-reason", WorkReasons, ParseWorkReason, []WorkReason{
		WorkReasonCancelPending, WorkReasonProviderOutcomeIndeterminate,
		WorkReasonProviderEffectConflict, WorkReasonQuarantined,
	}, ErrInvalidTransition)
	testClosedVocabulary(t, "delivery", DeliveryDispositions, ParseDeliveryDisposition, []DeliveryDisposition{
		DeliveryAccepted, DeliveryDuplicateActive, DeliveryDuplicateCompleted,
	}, ErrInvalidDelivery)
	testClosedVocabulary(t, "maintenance-kind", MaintenanceKinds, ParseMaintenanceKind,
		[]MaintenanceKind{MaintenanceStoreLease, MaintenanceQueueVisibility}, ErrInvalidTransition)
	testClosedVocabulary(t, "maintenance-outcome", MaintenanceOutcomes, ParseMaintenanceOutcome,
		[]MaintenanceOutcome{MaintenanceSucceeded, MaintenanceFailed, MaintenanceUnknown}, ErrInvalidTransition)
	testClosedVocabulary(t, "maintenance-directive", MaintenanceDirectives, ParseMaintenanceDirective,
		[]MaintenanceDirective{MaintenanceContinue, MaintenanceStopAndSurrender}, ErrInvalidTransition)
	testClosedVocabulary(t, "observation", ObservationDecisions, ParseObservationDecision, []ObservationDecision{
		ObservationContinue, ObservationResolved, ObservationQuarantine, ObservationAlreadyDone,
	}, ErrInvalidObservation)
	testClosedVocabulary(t, "retention", RetentionDispositions, ParseRetentionDisposition,
		[]RetentionDisposition{RetentionKeep, RetentionEligible}, ErrInvalidRetention)
	testClosedVocabulary(t, "crash", CrashPoints, ParseCrashPoint, []CrashPoint{
		CrashBeforeAPICommit, CrashAfterAPICommit, CrashBeforeOutboxPublish, CrashAfterOutboxPublish,
		CrashDeliveryBeforeFence, CrashAfterAttemptPreparation, CrashAfterResultCommit, CrashLeaseLostDuringDispatch,
	}, ErrInvalidTransition)
	testClosedVocabulary(t, "recovery", RecoveryActions, ParseRecoveryAction, []RecoveryAction{
		RecoveryNoAcceptedWork, RecoveryReplayDurableResult, RecoveryReclaimOutbox, RecoveryRepublishAllowed,
		RecoveryNoProviderEffect, RecoveryRecordIndeterminate, RecoveryDurableNoOp, RecoveryStopAndObserve,
	}, ErrInvalidTransition)
}

type closedString interface {
	~string
	String() string
}

func testClosedVocabulary[T closedString](
	t *testing.T,
	name string,
	registry func() []T,
	parse func(string) (T, error),
	want []T,
	invalid error,
) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		values := registry()
		if !slices.Equal(values, want) {
			t.Fatalf("registry = %#v, want %#v", values, want)
		}
		for _, value := range want {
			parsed, err := parse(string(value))
			if err != nil || parsed != value || parsed.String() != string(value) {
				t.Fatalf("parse %q = %q, %v", value, parsed, err)
			}
		}
		values[0] = T("mutated")
		if slices.Equal(registry(), values) {
			t.Fatal("registry returned mutable package storage")
		}
		if parsed, err := parse("invalid"); !errors.Is(err, invalid) || parsed != "" {
			t.Fatalf("invalid parse = %q, %v", parsed, err)
		}
	})
}
