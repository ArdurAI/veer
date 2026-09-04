package reconciliation

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/operation"
)

func TestEveryApprovedCrashBoundaryHasOneSafeRecoveryAction(t *testing.T) {
	t.Parallel()
	want := map[CrashPoint]RecoveryAction{
		CrashBeforeAPICommit:         RecoveryNoAcceptedWork,
		CrashAfterAPICommit:          RecoveryReplayDurableResult,
		CrashBeforeOutboxPublish:     RecoveryReclaimOutbox,
		CrashAfterOutboxPublish:      RecoveryRepublishAllowed,
		CrashDeliveryBeforeFence:     RecoveryNoProviderEffect,
		CrashAfterAttemptPreparation: RecoveryRecordIndeterminate,
		CrashAfterResultCommit:       RecoveryDurableNoOp,
		CrashLeaseLostDuringDispatch: RecoveryStopAndObserve,
	}
	if len(CrashPoints()) != len(want) {
		t.Fatalf("crash point count = %d, want %d", len(CrashPoints()), len(want))
	}
	for _, point := range CrashPoints() {
		got, err := RecoveryForCrash(point)
		if err != nil || got != want[point] {
			t.Fatalf("RecoveryForCrash(%s) = %s, %v", point, got, err)
		}
	}
	if _, err := RecoveryForCrash("future"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unknown crash point error = %v", err)
	}
}

func TestAttemptPreparationDispatchAndOwnerLossAreFailClosed(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 50, false)
	effect := mustEffect(t, fixture.plan, "apply")
	table, token := mustLease(t, fixture, fixtureTime.Add(time.Second))
	prepared := mustPreparedAttempt(
		t, fixture, effect, AttemptPurposeForward, 1, token, fixtureTime.Add(time.Second),
	)
	if prepared.state != AttemptStatePrepared {
		t.Fatalf("NewPreparedAttempt() = %#v", prepared)
	}
	_, permit := mustPermit(
		t,
		fixture,
		fixture.op,
		fixtureTime.Add(time.Second),
		table,
		token,
		prepared,
		5*time.Second,
	)
	provedNoEffect, err := RecoverAttempt(prepared, DispatchProofNeverBegan, fixtureTime.Add(2*time.Second))
	if err != nil || provedNoEffect.state != AttemptStateNoEffect || !provedNoEffect.Definitive() {
		t.Fatalf("proved no-effect recovery = %#v, %v", provedNoEffect, err)
	}
	unknownPrepared, err := RecoverAttempt(prepared, DispatchProofUnknown, fixtureTime.Add(2*time.Second))
	if err != nil || unknownPrepared.state != AttemptStateIndeterminate || unknownPrepared.Definitive() {
		t.Fatalf("unknown prepared recovery = %#v, %v", unknownPrepared, err)
	}
	delayedPermit := permit
	delayedPermit.authorizedAt = fixtureTime.Add(2 * time.Second)
	if _, err := table.MarkAttemptDispatched(
		prepared,
		delayedPermit,
		fixtureTime.Add(time.Second+time.Millisecond),
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("pre-authorization dispatch error = %v", err)
	}
	dispatched, err := table.MarkAttemptDispatched(prepared, permit, fixtureTime.Add(time.Second+time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	unknownDispatched, err := RecoverAttempt(dispatched, DispatchProofUnknown, fixtureTime.Add(2*time.Second))
	if err != nil || unknownDispatched.state != AttemptStateIndeterminate {
		t.Fatalf("unknown dispatched recovery = %#v, %v", unknownDispatched, err)
	}
	if _, err := RecoverAttempt(
		dispatched,
		DispatchProofUnknown,
		fixtureTime.Add(time.Second),
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("pre-dispatch recovery time error = %v", err)
	}
	malformedChronology := unknownDispatched
	malformedChronology.resolvedAt = fixtureTime.Add(time.Second)
	if err := ValidateAttempt(malformedChronology); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("malformed recovery chronology error = %v", err)
	}
	if _, err := RecoverAttempt(dispatched, DispatchProofNeverBegan, fixtureTime.Add(2*time.Second)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("false no-dispatch proof error = %v", err)
	}
}

func TestDispatchAuthorityAndPermitAreExactOneUseCapabilities(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 150, false)
	effect := mustEffect(t, fixture.plan, "one-use-dispatch")
	table, token := mustLease(t, fixture, fixtureTime)
	first := mustPreparedAttempt(t, fixture, effect, AttemptPurposeForward, 150, token, fixtureTime)
	second := mustPreparedAttempt(t, fixture, effect, AttemptPurposeForward, 151, token, fixtureTime)

	authority, err := NewDispatchAuthority(
		fixtureTime,
		fixture.plan,
		first,
		fixture.op,
		fixture.decision,
		fixture.provider,
		fixture.capability,
		fixture.quota,
		fixture.cost,
	)
	if err != nil {
		t.Fatal(err)
	}

	const contenders = 32
	start := make(chan struct{})
	permits := make(chan DispatchPermit, contenders)
	errorsSeen := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func(candidate DispatchAuthority) {
			defer wait.Done()
			<-start
			permit, callErr := table.AuthorizeDispatch(fixtureTime, token, 5*time.Second, candidate)
			if callErr != nil {
				errorsSeen <- callErr
				return
			}
			permits <- permit
		}(authority)
	}
	close(start)
	wait.Wait()
	close(permits)
	close(errorsSeen)
	if len(permits) != 1 || len(errorsSeen) != contenders-1 {
		t.Fatalf("authorized permits/errors = %d/%d", len(permits), len(errorsSeen))
	}
	for callErr := range errorsSeen {
		if !errors.Is(callErr, ErrDispatchAuthority) {
			t.Fatalf("copied authority error = %v", callErr)
		}
	}
	permit := <-permits

	if _, err := table.MarkAttemptDispatched(second, permit, fixtureTime); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cross-attempt permit error = %v", err)
	}

	start = make(chan struct{})
	var dispatched atomic.Int32
	var rejected atomic.Int32
	wait = sync.WaitGroup{}
	for range contenders {
		wait.Add(1)
		go func(candidate DispatchPermit) {
			defer wait.Done()
			<-start
			if _, callErr := table.MarkAttemptDispatched(first, candidate, fixtureTime); callErr == nil {
				dispatched.Add(1)
			} else if errors.Is(callErr, ErrInvalidTransition) {
				rejected.Add(1)
			} else {
				t.Errorf("copied permit error = %v", callErr)
			}
		}(permit)
	}
	close(start)
	wait.Wait()
	if dispatched.Load() != 1 || rejected.Load() != contenders-1 {
		t.Fatalf("dispatched/rejected = %d/%d", dispatched.Load(), rejected.Load())
	}
}

func TestUnknownLeaseOrVisibilityMaintenanceStopsAndClassifiesEffect(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 51, false)
	effect := mustEffect(t, fixture.plan, "apply")
	prepared := mustAttempt(t, fixture, effect, AttemptStatePrepared, 1)
	after, directive, err := ApplyMaintenanceOutcome(
		prepared,
		MaintenanceQueueVisibility,
		MaintenanceUnknown,
		fixtureTime.Add(3*time.Second),
	)
	if err != nil || directive != MaintenanceStopAndSurrender || after.state != AttemptStateIndeterminate {
		t.Fatalf("prepared visibility ambiguity = %s/%s, %v", after.state, directive, err)
	}
	projection, err := EffectProjectionFromAttempt(after)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckRetry(
		fixtureTime.Add(4*time.Second),
		projection,
		prepared.requestFingerprint,
		nil,
	); !errors.Is(err, ErrRetryForbidden) {
		t.Fatalf("unproven prepared retry error = %v", err)
	}
	dispatched := mustAttempt(t, fixture, effect, AttemptStateDispatched, 2)
	after, directive, err = ApplyMaintenanceOutcome(
		dispatched,
		MaintenanceStoreLease,
		MaintenanceFailed,
		fixtureTime.Add(3*time.Second),
	)
	if err != nil || directive != MaintenanceStopAndSurrender || after.state != AttemptStateIndeterminate {
		t.Fatalf("dispatched lease ambiguity = %s/%s, %v", after.state, directive, err)
	}
	if _, _, err := ApplyMaintenanceOutcome(
		prepared,
		MaintenanceStoreLease,
		MaintenanceSucceeded,
		time.Time{},
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("zero successful-maintenance time error = %v", err)
	}
	if _, _, err := ApplyMaintenanceOutcome(
		dispatched,
		MaintenanceQueueVisibility,
		MaintenanceSucceeded,
		fixtureTime.Add(time.Second),
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("pre-dispatch successful-maintenance time error = %v", err)
	}
	unchanged, directive, err := ApplyMaintenanceOutcome(
		dispatched,
		MaintenanceQueueVisibility,
		MaintenanceSucceeded,
		fixtureTime.Add(3*time.Second),
	)
	if err != nil || directive != MaintenanceContinue || unchanged.state != AttemptStateDispatched {
		t.Fatalf("valid visibility maintenance = %s/%s, %v", unchanged.state, directive, err)
	}
}

func TestRetryRequiresNoEffectOrExactLiveAdapterIdempotencyProof(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 52, false)
	effect := mustEffect(t, fixture.plan, "apply")
	fingerprint := mustRequestFingerprint(t, "request")
	noEffect, _ := EffectProjectionFromAttempt(mustAttempt(t, fixture, effect, AttemptStateNoEffect, 1))
	if err := CheckRetry(fixtureTime.Add(2*time.Second), noEffect, fingerprint, nil); err != nil {
		t.Fatalf("NoEffect retry: %v", err)
	}
	if err := CheckRetry(fixtureTime, noEffect, fingerprint, nil); !errors.Is(err, ErrRetryForbidden) {
		t.Fatalf("pre-evidence retry time error = %v", err)
	}
	unknown, _ := EffectProjectionFromAttempt(mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 2))
	if err := CheckRetry(fixtureTime, unknown, fingerprint, nil); !errors.Is(err, ErrRetryForbidden) {
		t.Fatalf("blind unknown retry error = %v", err)
	}
	proof, err := NewRetryProof(
		effect,
		fingerprint,
		"fake-adapter-v1",
		fixtureTime.Add(time.Hour),
		[]byte("durable-provider-idempotency"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckRetry(fixtureTime.Add(time.Hour-time.Millisecond), unknown, fingerprint, &proof); err != nil {
		t.Fatalf("qualified retry: %v", err)
	}
	if err := CheckRetry(fixtureTime.Add(time.Hour), unknown, fingerprint, &proof); !errors.Is(err, ErrRetryForbidden) {
		t.Fatalf("expired proof error = %v", err)
	}
	if err := CheckRetry(
		fixtureTime,
		unknown,
		mustRequestFingerprint(t, "different"),
		&proof,
	); !errors.Is(err, ErrRetryForbidden) {
		t.Fatalf("mismatched request proof error = %v", err)
	}
}

func TestAttemptAdmissionBindsCancellationRetryGenerationAndObservation(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 252, false)
	effect := mustEffect(t, fixture.plan, "qualified-attempt")
	fingerprint := mustRequestFingerprint(t, "qualified-attempt")
	table, token := mustLease(t, fixture, fixtureTime)
	if _, err := NewPreparedAttempt(AttemptInput{
		ID: indexedID("att", 25_200), Ordinal: 1, OwnerID: token.ownerID, Fence: token.fence,
	}); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("missing admission error = %v", err)
	}
	if _, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime: fixtureTime, Plan: fixture.plan, Effect: effect,
		Purpose: AttemptPurposeForward, RequestFingerprint: fingerprint, CancellationRequested: true,
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("canceled forward admission error = %v", err)
	}

	unknown, err := EffectProjectionFromAttempt(
		mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 25_201),
	)
	if err != nil {
		t.Fatal(err)
	}
	checkedAt := fixtureTime.Add(2 * time.Second)
	base := AttemptAdmissionInput{
		DatabaseTime: checkedAt, Plan: fixture.plan, Effect: effect,
		Purpose: AttemptPurposeForward, RequestFingerprint: fingerprint, CurrentEffect: &unknown,
	}
	if _, err := NewAttemptAdmission(base); !errors.Is(err, ErrRetryForbidden) {
		t.Fatalf("missing retry proof error = %v", err)
	}
	proof, err := NewRetryProof(
		effect,
		fingerprint,
		"fake-adapter-v1",
		checkedAt.Add(30*time.Second),
		[]byte("exact-durable-idempotency"),
	)
	if err != nil {
		t.Fatal(err)
	}
	base.RetryProof = &proof
	admission, err := NewAttemptAdmission(base)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := NewPreparedAttempt(AttemptInput{
		ID: indexedID("att", 25_202), Ordinal: 2, Admission: admission,
		OwnerID: token.ownerID, Fence: token.fence,
	})
	if err != nil || !prepared.preparedAt.Equal(checkedAt) {
		t.Fatalf("qualified retry preparation = %#v, %v", prepared, err)
	}
	authority, err := NewDispatchAuthority(
		proof.validUntil.Add(-time.Millisecond), fixture.plan, prepared, fixture.op, fixture.decision,
		fixture.provider, fixture.capability, fixture.quota, fixture.cost,
	)
	if err != nil {
		t.Fatalf("live retry proof dispatch authority: %v", err)
	}
	permit, err := table.AuthorizeDispatch(
		proof.validUntil.Add(-time.Millisecond), token, time.Second, authority,
	)
	if err != nil {
		t.Fatalf("live retry proof dispatch permit: %v", err)
	}
	if _, err := table.MarkAttemptDispatched(
		prepared, permit, proof.validUntil,
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retry proof expired before call boundary error = %v", err)
	}
	if permit.use.Load() {
		t.Fatal("expired retry proof consumed dispatch permit")
	}
	if _, err := NewDispatchAuthority(
		proof.validUntil, fixture.plan, prepared, fixture.op, fixture.decision,
		fixture.provider, fixture.capability, fixture.quota, fixture.cost,
	); !errors.Is(err, ErrDispatchAuthority) {
		t.Fatalf("expired prepared retry dispatch error = %v", err)
	}
	if _, err := NewPreparedAttempt(AttemptInput{
		ID: indexedID("att", 25_203), Ordinal: 3, Admission: admission,
		OwnerID: token.ownerID, Fence: token.fence,
	}); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("reused admission error = %v", err)
	}
	expired := base
	expired.DatabaseTime = proof.validUntil
	if _, err := NewAttemptAdmission(expired); !errors.Is(err, ErrRetryForbidden) {
		t.Fatalf("expired proof admission error = %v", err)
	}

	next := nextGenerationFixture(t, fixture, 2, 253)
	nextEffect := mustEffect(t, next.plan, "qualified-attempt")
	prior := []EffectProjection{unknown}
	generation := AttemptAdmissionInput{
		DatabaseTime: checkedAt, Plan: next.plan, Effect: nextEffect,
		Purpose: AttemptPurposeForward, RequestFingerprint: mustRequestFingerprint(t, "next-generation"),
		PriorGenerationEffects: prior,
	}
	if _, err := NewAttemptAdmission(generation); !errors.Is(err, ErrGenerationBlocked) {
		t.Fatalf("missing safe-supersession proof error = %v", err)
	}
	safe, err := NewSafeSupersessionProof(
		effect,
		nextEffect,
		"fake-adapter-v1",
		[]byte("provider-proves-non-conflict"),
	)
	if err != nil {
		t.Fatal(err)
	}
	generation.SafeSupersessionProofs = []SafeSupersessionProof{safe}
	if _, err := NewAttemptAdmission(generation); err != nil {
		t.Fatalf("qualified next-generation admission: %v", err)
	}

	observationBudget, err := NewObservationBudget(effect, 1, checkedAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, observationPermit, err := ReserveObservation(observationBudget, checkedAt)
	if err != nil {
		t.Fatal(err)
	}
	observation := AttemptAdmissionInput{
		DatabaseTime: checkedAt, Plan: fixture.plan, Effect: effect,
		Purpose: AttemptPurposeObservation, RequestFingerprint: fingerprint, CurrentEffect: &unknown,
	}
	if _, err := NewAttemptAdmission(observation); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("missing observation permit error = %v", err)
	}
	observation.Observation = &observationPermit
	if _, err := NewAttemptAdmission(observation); err != nil {
		t.Fatalf("qualified observation admission: %v", err)
	}
	if _, err := NewAttemptAdmission(observation); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("reused observation permit error = %v", err)
	}
}

func TestAttemptAdmissionRejectsEffectAlreadyCompletedByPlan(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 25_500, false)
	effect := mustEffect(t, fixture.plan, "completed-effect")
	appliedAttempt := mustAttempt(t, fixture, effect, AttemptStateApplied, 25_501)
	applied, err := EffectProjectionFromAttempt(appliedAttempt)
	if err != nil {
		t.Fatal(err)
	}
	observed := mustEvidence(
		t,
		EvidenceObservedSnapshot,
		"observation-completed-effect",
		[]byte(`{"completed":true}`),
	)
	candidate := fixture.candidate(t, 2, PlanKindForward, observed, []EffectKey{effect}, nil)
	selected, disposition, _, err := SelectPlan(
		fixture.plan,
		candidate,
		[]Attempt{appliedAttempt},
		[]EffectProjection{applied},
		true,
		nil,
	)
	if err != nil || disposition != PlanSelectionSupersede {
		t.Fatalf("completed-effect plan selection = %s, %v", disposition, err)
	}

	if _, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       fixtureTime.Add(time.Second),
		Plan:               selected,
		Effect:             effect,
		Purpose:            AttemptPurposeForward,
		RequestFingerprint: mustRequestFingerprint(t, "completed-effect-replay"),
	}); !errors.Is(err, ErrRetryForbidden) {
		t.Fatalf("completed effect admission error = %v", err)
	}
	pending := mustEffect(t, selected, "pending-effect")
	if _, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       fixtureTime.Add(2 * time.Second),
		Plan:               selected,
		Effect:             pending,
		Purpose:            AttemptPurposeForward,
		RequestFingerprint: mustRequestFingerprint(t, "pending-effect"),
	}); err != nil {
		t.Fatalf("new effect admission error = %v", err)
	}
}

func TestCompensationPlanAllowsObservationAndProviderCancellation(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 152, false)
	original := mustEffect(t, fixture.plan, "apply")
	observed := mustEvidence(t, EvidenceObservedSnapshot, "observation-2", []byte("changed"))
	compensation := fixture.candidate(
		t,
		2,
		PlanKindCompensation,
		observed,
		[]EffectKey{original},
		[]EffectKey{original},
	)
	effect := mustEffect(t, compensation, "undo")
	originalProjection, err := EffectProjectionFromAttempt(
		mustAttempt(t, fixture, original, AttemptStateApplied, 490),
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := NewCompensationProof(
		originalProjection,
		effect,
		1,
		"fake-adapter-v1",
		[]byte("qualified-inverse"),
	)
	if err != nil {
		t.Fatal(err)
	}
	step, err := NextCompensationStep(compensation, []CompensationProof{proof}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index, purpose := range []AttemptPurpose{
		AttemptPurposeCompensation,
		AttemptPurposeObservation,
		AttemptPurposeProviderCancel,
	} {
		admissionInput := AttemptAdmissionInput{
			DatabaseTime:       fixtureTime,
			Plan:               compensation,
			Effect:             effect,
			Purpose:            purpose,
			RequestFingerprint: mustRequestFingerprint(t, purpose.String()),
		}
		if purpose == AttemptPurposeCompensation {
			admissionInput.Compensation = &step
		} else {
			current := EffectProjection{
				initialized:     true,
				key:             effect,
				planDigest:      compensation.digest,
				sourceAttemptID: indexedID("att", 489),
				purpose:         AttemptPurposeCompensation,
				compensation:    &step,
				state:           AttemptStateIndeterminate,
				updatedAt:       fixtureTime.Add(-time.Millisecond),
			}
			admissionInput.CurrentEffect = &current
			if purpose == AttemptPurposeObservation {
				budget, budgetErr := NewObservationBudget(effect, 2, fixtureTime.Add(time.Hour))
				if budgetErr != nil {
					t.Fatal(budgetErr)
				}
				_, observation, budgetErr := ReserveObservation(budget, fixtureTime)
				if budgetErr != nil {
					t.Fatal(budgetErr)
				}
				admissionInput.Observation = &observation
			} else {
				admissionInput.CancellationRequested = true
				admissionInput.Effect = mustEffect(t, compensation, "cancel-undo")
				admissionInput.CurrentEffect = nil
				admissionInput.CancellationTarget = &current
			}
		}
		admission, err := NewAttemptAdmission(admissionInput)
		if err != nil {
			t.Fatalf("%s admission: %v", purpose, err)
		}
		attempt, err := NewPreparedAttempt(AttemptInput{
			ID:        indexedID("att", 500+index),
			Ordinal:   uint32(index + 1),
			Admission: admission,
			OwnerID:   indexedID("owner", 1),
			Fence:     1,
		})
		if err != nil || attempt.Purpose() != purpose {
			t.Fatalf("purpose %s = %#v, %v", purpose, attempt, err)
		}
		if purpose == AttemptPurposeProviderCancel {
			target, ok := attempt.CancellationTarget()
			if !ok || !target.Equal(effect) || attempt.Effect().Equal(effect) {
				t.Fatalf("provider cancellation identity = %#v, %#v", attempt.Effect(), target)
			}
		}
	}
	if _, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       fixtureTime,
		Plan:               compensation,
		Effect:             effect,
		Purpose:            AttemptPurposeCompensation,
		RequestFingerprint: mustRequestFingerprint(t, "unqualified-compensation"),
	}); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("unqualified compensation error = %v", err)
	}
	if _, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       fixtureTime,
		Plan:               compensation,
		Effect:             effect,
		Purpose:            AttemptPurposeForward,
		RequestFingerprint: mustRequestFingerprint(t, "forward"),
	}); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("forward purpose on compensation plan error = %v", err)
	}
}

func TestProviderCancellationUsesDistinctEffectAndBindsCanceledEffect(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 25_300, false)
	targetEffect := mustEffect(t, fixture.plan, "create-provider-resource")
	cancelEffect := mustEffect(t, fixture.plan, "cancel-create-provider-resource")
	targetAttempt := mustAttempt(t, fixture, targetEffect, AttemptStateIndeterminate, 25_301)
	target, err := EffectProjectionFromAttempt(targetAttempt)
	if err != nil {
		t.Fatal(err)
	}
	input := AttemptAdmissionInput{
		DatabaseTime:          target.updatedAt.Add(time.Millisecond),
		Plan:                  fixture.plan,
		Effect:                cancelEffect,
		Purpose:               AttemptPurposeProviderCancel,
		RequestFingerprint:    mustRequestFingerprint(t, "cancel-create-provider-resource"),
		CancellationRequested: true,
		CancellationTarget:    &target,
	}
	admission, err := NewAttemptAdmission(input)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := NewPreparedAttempt(AttemptInput{
		ID:        indexedID("att", 25_302),
		Ordinal:   2,
		Admission: admission,
		OwnerID:   indexedID("wrk", 25_300),
		Fence:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	canceled, ok := prepared.CancellationTarget()
	if !ok || !canceled.Equal(targetEffect) || prepared.Effect().Equal(targetEffect) {
		t.Fatalf("prepared cancellation identity = %#v, %#v", prepared.Effect(), canceled)
	}
	projection, err := EffectProjectionFromAttempt(prepared)
	if err != nil {
		t.Fatal(err)
	}
	projectedTarget, ok := projection.CancellationTarget()
	if !ok || !projectedTarget.Equal(targetEffect) || !projection.Key().Equal(cancelEffect) {
		t.Fatalf("projected cancellation identity = %#v, %#v", projection.Key(), projectedTarget)
	}

	unknownCancellation, err := RecoverAttempt(
		prepared,
		DispatchProofUnknown,
		input.DatabaseTime.Add(time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	unknownProjection, err := EffectProjectionFromAttempt(unknownCancellation)
	if err != nil {
		t.Fatal(err)
	}
	retry := input
	retry.DatabaseTime = unknownProjection.updatedAt.Add(time.Millisecond)
	retry.CurrentEffect = &unknownProjection
	if _, err := NewAttemptAdmission(retry); !errors.Is(err, ErrRetryForbidden) {
		t.Fatalf("blind cancellation retry error = %v", err)
	}
	proof, err := NewRetryProof(
		cancelEffect,
		input.RequestFingerprint,
		"fake-adapter-v1",
		retry.DatabaseTime.Add(time.Hour),
		[]byte("provider-cancellation-is-idempotent"),
	)
	if err != nil {
		t.Fatal(err)
	}
	retry.RetryProof = &proof
	qualified, err := NewAttemptAdmission(retry)
	if err != nil {
		t.Fatalf("qualified cancellation retry: %v", err)
	}
	qualifiedAttempt, err := NewPreparedAttempt(AttemptInput{
		ID:        indexedID("att", 25_303),
		Ordinal:   3,
		Admission: qualified,
		OwnerID:   indexedID("wrk", 25_300),
		Fence:     1,
	})
	if err != nil || ValidateAttempt(qualifiedAttempt) != nil {
		t.Fatalf("qualified cancellation retry preparation = %#v, %v", qualifiedAttempt, err)
	}
	otherTarget := target
	otherTarget.key = mustEffect(t, fixture.plan, "different-provider-effect")
	retry.CancellationTarget = &otherTarget
	if _, err := NewAttemptAdmission(retry); !errors.Is(err, ErrRetryForbidden) {
		t.Fatalf("cancellation retry target mismatch error = %v", err)
	}

	for name, mutate := range map[string]func(*AttemptAdmissionInput){
		"same effect": func(candidate *AttemptAdmissionInput) {
			candidate.Effect = targetEffect
		},
		"no cancellation request": func(candidate *AttemptAdmissionInput) {
			candidate.CancellationRequested = false
		},
		"definitive target": func(candidate *AttemptAdmissionInput) {
			copy := target
			copy.state = AttemptStateApplied
			candidate.CancellationTarget = &copy
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := input
			mutate(&candidate)
			if _, err := NewAttemptAdmission(candidate); !errors.Is(err, ErrInvalidAttempt) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestObservationAdmissionRequiresIndeterminateTarget(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 25_400, false)
	effect := mustEffect(t, fixture.plan, "observe-only-after-unknown")
	for _, state := range []AttemptState{AttemptStatePrepared, AttemptStateDispatched} {
		state := state
		t.Run(state.String(), func(t *testing.T) {
			budget, err := NewObservationBudget(effect, 2, fixtureTime.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			_, permit, err := ReserveObservation(budget, fixtureTime)
			if err != nil {
				t.Fatal(err)
			}
			current := EffectProjection{
				initialized:     true,
				key:             effect,
				planDigest:      fixture.plan.digest,
				sourceAttemptID: indexedID("att", 25_402),
				purpose:         AttemptPurposeForward,
				state:           state,
				updatedAt:       fixtureTime.Add(-time.Millisecond),
			}
			input := AttemptAdmissionInput{
				DatabaseTime:       fixtureTime,
				Plan:               fixture.plan,
				Effect:             effect,
				Purpose:            AttemptPurposeObservation,
				RequestFingerprint: mustRequestFingerprint(t, "observe-only-after-unknown"),
				CurrentEffect:      &current,
				Observation:        &permit,
			}
			if _, err := NewAttemptAdmission(input); !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("%s target error = %v", state, err)
			}
			current.state = AttemptStateIndeterminate
			if _, err := NewAttemptAdmission(input); err != nil {
				t.Fatalf("indeterminate target after %s rejection: %v", state, err)
			}
		})
	}
	other := nextGenerationFixture(t, fixture, 2, 25_401)
	for _, test := range []struct {
		name   string
		mutate func(*EffectProjection)
	}{
		{name: "different plan", mutate: func(current *EffectProjection) {
			current.planDigest = other.plan.digest
		}},
		{name: "nested observation", mutate: func(current *EffectProjection) {
			current.purpose = AttemptPurposeObservation
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			budget, err := NewObservationBudget(effect, 1, fixtureTime.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			_, permit, err := ReserveObservation(budget, fixtureTime)
			if err != nil {
				t.Fatal(err)
			}
			current := EffectProjection{
				initialized:     true,
				key:             effect,
				planDigest:      fixture.plan.digest,
				sourceAttemptID: indexedID("att", 25_403),
				purpose:         AttemptPurposeForward,
				state:           AttemptStateIndeterminate,
				updatedAt:       fixtureTime.Add(-time.Millisecond),
			}
			test.mutate(&current)
			if _, err := NewAttemptAdmission(AttemptAdmissionInput{
				DatabaseTime:       fixtureTime,
				Plan:               fixture.plan,
				Effect:             effect,
				Purpose:            AttemptPurposeObservation,
				RequestFingerprint: mustRequestFingerprint(t, "invalid-observation-target-"+test.name),
				CurrentEffect:      &current,
				Observation:        &permit,
			}); !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestOlderUncertainEffectGatesConflictingNewGeneration(t *testing.T) {
	t.Parallel()
	priorFixture := newPlanFixture(t, 1, 53, false)
	priorEffect := mustEffect(t, priorFixture.plan, "replace-external-object")
	nextFixture := nextGenerationFixture(t, priorFixture, 2, 54)
	nextEffect := mustEffect(t, nextFixture.plan, "replace-external-object")

	for _, state := range []AttemptState{
		AttemptStatePrepared,
		AttemptStateDispatched,
		AttemptStateIndeterminate,
	} {
		projection, err := EffectProjectionFromAttempt(mustAttempt(t, priorFixture, priorEffect, state, int(state[0])))
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckGenerationDispatch(nextEffect, []EffectProjection{projection}, nil); !errors.Is(err, ErrGenerationBlocked) {
			t.Fatalf("state %s did not block: %v", state, err)
		}
		proof, err := NewSafeSupersessionProof(
			priorEffect,
			nextEffect,
			"fake-adapter-v1",
			[]byte("provider-proves-safe-supersession"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckGenerationDispatch(nextEffect, []EffectProjection{projection}, []SafeSupersessionProof{proof}); err != nil {
			t.Fatalf("qualified state %s remained blocked: %v", state, err)
		}
	}
	for _, state := range []AttemptState{AttemptStateApplied, AttemptStateNoEffect} {
		projection, _ := EffectProjectionFromAttempt(mustAttempt(t, priorFixture, priorEffect, state, 100+int(state[0])))
		if err := CheckGenerationDispatch(nextEffect, []EffectProjection{projection}, nil); err != nil {
			t.Fatalf("definitive state %s blocked: %v", state, err)
		}
	}
}

func TestDuplicateDeliveryNeverCreatesSecondAuthority(t *testing.T) {
	fixture := newPlanFixture(t, 1, 55, false)
	work, err := NewWorkKey(fixture.plan, []byte("step-one"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, _ := NewDeliveryLedger(1)
	_, token := mustLease(t, fixture, fixtureTime.Add(time.Second))
	start := make(chan struct{})
	var accepted atomic.Int32
	var duplicates atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			disposition, callErr := ledger.Begin(work, indexedID("dlv", index+1), token)
			if callErr != nil {
				t.Errorf("Begin(%d): %v", index, callErr)
				return
			}
			switch disposition {
			case DeliveryAccepted:
				accepted.Add(1)
			case DeliveryDuplicateActive:
				duplicates.Add(1)
			default:
				t.Errorf("Begin(%d) = %s", index, disposition)
			}
		}()
	}
	close(start)
	wait.Wait()
	if accepted.Load() != 1 || duplicates.Load() != 31 {
		t.Fatalf("accepted/duplicates = %d/%d", accepted.Load(), duplicates.Load())
	}
	if err := ledger.Complete(work, token); err != nil {
		t.Fatal(err)
	}
	if got, err := ledger.Begin(work, indexedID("dlv", 99), token); err != nil || got != DeliveryDuplicateCompleted {
		t.Fatalf("completed redelivery = %s, %v", got, err)
	}
}

func TestDeliveryRequiresWorkAndLeaseFromTheSamePlan(t *testing.T) {
	t.Parallel()
	base := newPlanFixture(t, 1, 157, false)
	next := nextGenerationFixture(t, base, 2, 158)
	work, err := NewWorkKey(base.plan, []byte("plan-bound-work"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseWorkKey(work.String())
	if err != nil || !parsed.Equal(work) || !parsed.PlanDigest().Equal(base.plan.Digest()) {
		t.Fatalf("parsed work provenance = %#v, %v", parsed, err)
	}
	_, baseToken := mustLease(t, base, fixtureTime.Add(time.Second))
	_, nextToken := mustLease(t, next, fixtureTime.Add(time.Second))
	ledger, _ := NewDeliveryLedger(1)
	if _, err := ledger.Begin(work, indexedID("dlv", 157), nextToken); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("cross-plan begin error = %v", err)
	}
	if disposition, err := ledger.Begin(
		work,
		indexedID("dlv", 158),
		baseToken,
	); err != nil || disposition != DeliveryAccepted {
		t.Fatalf("exact-plan begin = %s, %v", disposition, err)
	}
	if err := ledger.Complete(work, nextToken); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("cross-plan completion error = %v", err)
	}
	if err := ledger.Complete(work, baseToken); err != nil {
		t.Fatalf("exact-plan completion: %v", err)
	}
}

func TestAbandonedDeliveryRequiresStrictlyNewerFenceToReclaim(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 155, false)
	work, _ := NewWorkKey(fixture.plan, []byte("reclaim-step"))
	binding, _ := LeaseBindingFromPlan(fixture.plan)
	table, _ := NewLeaseTable(1)
	first, err := table.Acquire(fixtureTime, binding, indexedID("wrk", 1))
	if err != nil {
		t.Fatal(err)
	}
	ledger, _ := NewDeliveryLedger(1)
	if disposition, err := ledger.Begin(work, indexedID("dlv", 1), first); err != nil || disposition != DeliveryAccepted {
		t.Fatalf("first delivery = %s, %v", disposition, err)
	}
	if disposition, err := ledger.Begin(work, indexedID("dlv", 2), first); err != nil || disposition != DeliveryDuplicateActive {
		t.Fatalf("same-fence duplicate = %s, %v", disposition, err)
	}
	second, err := table.Acquire(first.expiresAt, binding, indexedID("wrk", 2))
	if err != nil {
		t.Fatal(err)
	}
	if disposition, err := ledger.Begin(work, indexedID("dlv", 3), second); err != nil || disposition != DeliveryAccepted {
		t.Fatalf("new-fence reclaim = %s, %v", disposition, err)
	}
	if err := ledger.Complete(work, first); !errors.Is(err, ErrReservationLost) {
		t.Fatalf("stale owner completion error = %v", err)
	}
	if err := ledger.Complete(work, second); err != nil {
		t.Fatalf("new owner completion: %v", err)
	}
	if disposition, err := ledger.Begin(work, indexedID("dlv", 4), first); err != nil || disposition != DeliveryDuplicateCompleted {
		t.Fatalf("terminal stale redelivery = %s, %v", disposition, err)
	}
}

func TestCancellationUsesExistingOperationPhasesAndStopsForwardWork(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 56, false)
	effect := mustEffect(t, fixture.plan, "apply")
	prepared := mustAttempt(t, fixture, effect, AttemptStatePrepared, 1)
	phase, reason, err := CancellationPublicState(fixture.op, true, []Attempt{prepared}, false, false)
	if err != nil || phase != operation.PhaseRunning || reason != WorkReasonCancelPending {
		t.Fatalf("active cancellation = %s/%s, %v", phase, reason, err)
	}
	phase, reason, err = CancellationPublicState(fixture.op, false, []Attempt{prepared}, false, false)
	if err != nil || phase != operation.PhaseWaiting || reason != WorkReasonCancelPending {
		t.Fatalf("released cancellation = %s/%s, %v", phase, reason, err)
	}
	unknown := mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 2)
	phase, reason, err = CancellationPublicState(fixture.op, false, []Attempt{unknown}, true, false)
	if err != nil || phase != operation.PhaseWaiting || reason != WorkReasonCancelPending {
		t.Fatalf("unknown cancellation = %s/%s, %v", phase, reason, err)
	}
	phase, reason, err = CancellationPublicState(fixture.op, false, []Attempt{unknown}, true, true)
	if err != nil || phase != operation.PhaseCanceled || reason != WorkReasonNone {
		t.Fatalf("quarantined cancellation = %s/%s, %v", phase, reason, err)
	}
	other := newPlanFixture(t, 1, 156, false)
	otherEffect := mustEffect(t, other.plan, "other")
	otherAttempt := mustAttempt(t, other, otherEffect, AttemptStatePrepared, 3)
	if _, _, err := CancellationPublicState(
		fixture.op,
		false,
		[]Attempt{otherAttempt},
		false,
		false,
	); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("cross-operation cancellation error = %v", err)
	}
	duplicateOrdinal := prepared
	duplicateOrdinal.id = indexedID("att", 9_999)
	if _, _, err := CancellationPublicState(
		fixture.op,
		false,
		[]Attempt{prepared, duplicateOrdinal},
		false,
		false,
	); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("duplicate attempt ordinal error = %v", err)
	}
	resolved := mustAttempt(t, fixture, effect, AttemptStateNoEffect, 4)
	history := make([]Attempt, MaxEffectsPerOperation+1)
	for index := range history {
		history[index] = resolved
		history[index].id = indexedID("att", 10_000+index)
		history[index].ordinal = uint32(index + 1)
	}
	phase, reason, err = CancellationPublicState(fixture.op, false, history, true, false)
	if err != nil || phase != operation.PhaseCanceled || reason != WorkReasonNone {
		t.Fatalf("long physical-attempt history = %s/%s, %v", phase, reason, err)
	}
	current, err := EffectProjectionFromAttempt(unknown)
	if err != nil {
		t.Fatal(err)
	}
	for index, purpose := range []AttemptPurpose{AttemptPurposeObservation, AttemptPurposeProviderCancel} {
		admissionInput := AttemptAdmissionInput{
			DatabaseTime:          fixtureTime.Add(3 * time.Second),
			Plan:                  fixture.plan,
			Effect:                effect,
			Purpose:               purpose,
			RequestFingerprint:    mustRequestFingerprint(t, purpose.String()),
			CancellationRequested: true,
			CurrentEffect:         &current,
		}
		if purpose == AttemptPurposeObservation {
			budget, budgetErr := NewObservationBudget(effect, 1, fixtureTime.Add(time.Hour))
			if budgetErr != nil {
				t.Fatal(budgetErr)
			}
			_, permit, budgetErr := ReserveObservation(budget, admissionInput.DatabaseTime)
			if budgetErr != nil {
				t.Fatal(budgetErr)
			}
			admissionInput.Observation = &permit
		} else {
			admissionInput.Effect = mustEffect(t, fixture.plan, "cancel-indeterminate-effect")
			admissionInput.CurrentEffect = nil
			admissionInput.CancellationTarget = &current
		}
		admission, admissionErr := NewAttemptAdmission(admissionInput)
		if admissionErr != nil {
			t.Fatalf("purpose %s admission: %v", purpose, admissionErr)
		}
		preparedCancellation, preparationErr := NewPreparedAttempt(AttemptInput{
			ID: indexedID("att", 30_000+index), Ordinal: uint32(30_000 + index),
			Admission: admission, OwnerID: indexedID("wrk", 56), Fence: 1,
		})
		if preparationErr != nil {
			t.Fatalf("purpose %s preparation: %v", purpose, preparationErr)
		}
		if purpose == AttemptPurposeProviderCancel {
			target, ok := preparedCancellation.CancellationTarget()
			if !ok || !target.Equal(effect) || preparedCancellation.Effect().Equal(effect) {
				t.Fatalf("provider cancellation identity = %#v, %#v", preparedCancellation.Effect(), target)
			}
		}
	}
	if _, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:          fixtureTime.Add(3 * time.Second),
		Plan:                  fixture.plan,
		Effect:                effect,
		Purpose:               AttemptPurposeForward,
		RequestFingerprint:    mustRequestFingerprint(t, "canceled-forward"),
		CancellationRequested: true,
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("canceled forward admission error = %v", err)
	}
	phase, reason = IndeterminatePublicState()
	if phase != operation.PhaseWaiting || reason != WorkReasonProviderOutcomeIndeterminate {
		t.Fatalf("indeterminate public state = %s/%s", phase, reason)
	}
	for _, terminal := range []operation.Phase{
		operation.PhaseSucceeded,
		operation.PhaseFailed,
		operation.PhaseCanceled,
	} {
		completed := fixture.op
		completed.Phase = terminal
		phase, reason, err = CancellationPublicState(completed, true, []Attempt{prepared}, false, false)
		if err != nil || phase != terminal || reason != WorkReasonNone {
			t.Fatalf("terminal %s cancellation = %s/%s, %v", terminal, phase, reason, err)
		}
	}
}

func TestObservationReservationReleaseUnblocksBudgetAfterPreparationFailure(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 31_100, false)
	effect := mustEffect(t, fixture.plan, "release-observation")
	deadline := fixtureTime.Add(time.Hour)
	budget, err := NewObservationBudget(effect, 2, deadline)
	if err != nil {
		t.Fatal(err)
	}
	reserved, permit, err := ReserveObservation(budget, fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	current := EffectProjection{
		initialized:     true,
		key:             effect,
		planDigest:      fixture.plan.digest,
		sourceAttemptID: indexedID("att", 31_099),
		purpose:         AttemptPurposeForward,
		state:           AttemptStateIndeterminate,
		updatedAt:       fixtureTime.Add(-time.Millisecond),
	}
	admission, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       fixtureTime,
		Plan:               fixture.plan,
		Effect:             effect,
		Purpose:            AttemptPurposeObservation,
		RequestFingerprint: mustRequestFingerprint(t, "release-observation"),
		CurrentEffect:      &current,
		Observation:        &permit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPreparedAttempt(AttemptInput{
		Ordinal: 1, Admission: admission, OwnerID: indexedID("wrk", 31_100), Fence: 1,
	}); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("invalid preparation error = %v", err)
	}

	releasedAt := fixtureTime.Add(time.Millisecond)
	released, err := ReleaseObservation(reserved, permit, releasedAt)
	if err != nil || released.inFlight || released.binding.initialized || released.used != 1 ||
		!released.lastAt.Equal(releasedAt) {
		t.Fatalf("released observation budget = %#v, %v", released, err)
	}
	if _, err := NewPreparedAttempt(AttemptInput{
		ID: indexedID("att", 31_100), Ordinal: 1, Admission: admission,
		OwnerID: indexedID("wrk", 31_100), Fence: 1,
	}); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("preparation after release error = %v", err)
	}
	if _, err := ReleaseObservation(reserved, permit, releasedAt); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("repeated release error = %v", err)
	}

	reserved, permit, err = ReserveObservation(released, releasedAt.Add(time.Millisecond))
	if err != nil || reserved.used != 2 {
		t.Fatalf("reservation after release = %#v, %v", reserved, err)
	}
	released, err = ReleaseObservation(reserved, permit, deadline)
	if err != nil {
		t.Fatal(err)
	}
	expired, decision, err := ExpireObservationBudget(released, deadline)
	if err != nil || decision != ObservationQuarantine || !expired.quarantined {
		t.Fatalf("released exact-deadline budget = %s, %#v, %v", decision, expired, err)
	}
}

func TestObservationReleaseAndPreparationHaveExactlyOneWinner(t *testing.T) {
	t.Parallel()
	for iteration := range 64 {
		fixture := newPlanFixture(t, 1, 31_200+iteration, false)
		effect := mustEffect(t, fixture.plan, fmt.Sprintf("release-race-%d", iteration))
		budget, err := NewObservationBudget(effect, 2, fixtureTime.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		reserved, permit, err := ReserveObservation(budget, fixtureTime)
		if err != nil {
			t.Fatal(err)
		}
		current := EffectProjection{
			initialized:     true,
			key:             effect,
			planDigest:      fixture.plan.digest,
			sourceAttemptID: indexedID("att", 41_200+iteration),
			purpose:         AttemptPurposeForward,
			state:           AttemptStateIndeterminate,
			updatedAt:       fixtureTime.Add(-time.Millisecond),
		}
		admission, err := NewAttemptAdmission(AttemptAdmissionInput{
			DatabaseTime:       fixtureTime,
			Plan:               fixture.plan,
			Effect:             effect,
			Purpose:            AttemptPurposeObservation,
			RequestFingerprint: mustRequestFingerprint(t, fmt.Sprintf("release-race-%d", iteration)),
			CurrentEffect:      &current,
			Observation:        &permit,
		})
		if err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		results := make(chan error, 2)
		go func() {
			<-start
			_, releaseErr := ReleaseObservation(reserved, permit, fixtureTime.Add(time.Millisecond))
			results <- releaseErr
		}()
		go func() {
			<-start
			_, preparationErr := NewPreparedAttempt(AttemptInput{
				ID: indexedID("att", 31_200+iteration), Ordinal: 1, Admission: admission,
				OwnerID: indexedID("wrk", 31_200+iteration), Fence: 1,
			})
			results <- preparationErr
		}()
		close(start)
		first, second := <-results, <-results
		if (first == nil) == (second == nil) {
			t.Fatalf("iteration %d release/preparation errors = %v/%v", iteration, first, second)
		}
	}
}

func TestObservationBudgetQuarantinesExactlyOnceAtCountAndTimeBoundaries(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 57, false)
	effect := mustEffect(t, fixture.plan, "apply")
	budget, err := NewObservationBudget(effect, 2, fixtureTime.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	table, token := mustLease(t, fixture, fixtureTime)
	current := EffectProjection{
		initialized:     true,
		key:             effect,
		planDigest:      fixture.plan.digest,
		sourceAttemptID: indexedID("att", 30_999),
		purpose:         AttemptPurposeForward,
		state:           AttemptStateIndeterminate,
		updatedAt:       fixtureTime.Add(-time.Millisecond),
	}
	observe := func(before ObservationBudget, at time.Time, index int) (ObservationBudget, Attempt) {
		t.Helper()
		reserved, observation, reserveErr := ReserveObservation(before, at)
		if reserveErr != nil {
			t.Fatal(reserveErr)
		}
		admission, admissionErr := NewAttemptAdmission(AttemptAdmissionInput{
			DatabaseTime:       at,
			Plan:               fixture.plan,
			Effect:             effect,
			Purpose:            AttemptPurposeObservation,
			RequestFingerprint: mustRequestFingerprint(t, fmt.Sprintf("observation-%d", index)),
			CurrentEffect:      &current,
			Observation:        &observation,
		})
		if admissionErr != nil {
			t.Fatal(admissionErr)
		}
		attempt, preparationErr := NewPreparedAttempt(AttemptInput{
			ID: indexedID("att", index), Ordinal: uint32(index), Admission: admission,
			OwnerID: token.ownerID, Fence: token.fence,
		})
		if preparationErr != nil {
			t.Fatal(preparationErr)
		}
		_, dispatchPermit := mustPermit(t, fixture, fixture.op, at, table, token, attempt, 5*time.Second)
		attempt, preparationErr = table.MarkAttemptDispatched(attempt, dispatchPermit, at)
		if preparationErr != nil {
			t.Fatal(preparationErr)
		}
		attempt, preparationErr = ResolveAttempt(attempt, EffectStateIndeterminate, at.Add(time.Millisecond))
		if preparationErr != nil {
			t.Fatal(preparationErr)
		}
		return reserved, attempt
	}

	stale := budget
	reserved, first := observe(budget, fixtureTime, 31_000)
	if _, _, err := ReserveObservation(stale, fixtureTime); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("stale budget copy error = %v", err)
	}
	budget, current, decision, err := CompleteObservation(reserved, current, first)
	if err != nil || decision != ObservationContinue || budget.used != 1 {
		t.Fatalf("first observation = %s, %#v, %v", decision, budget, err)
	}
	reserved, second := observe(budget, fixtureTime.Add(2*time.Millisecond), 31_001)
	budget, current, decision, err = CompleteObservation(reserved, current, second)
	if err != nil || decision != ObservationQuarantine || !budget.quarantined {
		t.Fatalf("count exhaustion = %s, %#v, %v", decision, budget, err)
	}
	unchangedBudget, unchangedEffect, _, err := CompleteObservation(reserved, current, second)
	if !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("repeated observation completion error = %v", err)
	}
	if unchangedBudget.version != reserved.version || !effectProjectionsEqual(unchangedEffect, current) {
		t.Fatalf("repeated observation completion changed inputs: %#v/%#v", unchangedBudget, unchangedEffect)
	}
	unchanged, decision, err := ExpireObservationBudget(budget, fixtureTime.Add(2*time.Hour))
	if err != nil || decision != ObservationAlreadyDone || unchanged.used != budget.used {
		t.Fatalf("repeat exhaustion = %s, %#v, %v", decision, unchanged, err)
	}
	timed, _ := NewObservationBudget(effect, 10, fixtureTime.Add(time.Hour))
	_, decision, err = ExpireObservationBudget(timed, fixtureTime.Add(time.Hour))
	if err != nil || decision != ObservationQuarantine {
		t.Fatalf("exact deadline = %s, %v", decision, err)
	}
}

func TestObservationCompletionCompareAndSwapsExactCurrentEffect(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 31_300, false)
	effect := mustEffect(t, fixture.plan, "observe-stale-effect")
	original := mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 31_301)
	current, err := EffectProjectionFromAttempt(original)
	if err != nil {
		t.Fatal(err)
	}
	observationAt := current.updatedAt.Add(time.Millisecond)
	reserved, observation := mustResolvedObservationAttempt(
		t,
		fixture,
		current,
		2,
		observationAt,
		observationAt.Add(time.Hour),
		EffectStateNoEffect,
		true,
		31_302,
	)
	if _, err := EffectProjectionFromAttempt(observation); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("direct observation projection error = %v", err)
	}

	advanced := cloneEffectProjection(current)
	advanced.state = AttemptStateApplied
	advanced.updatedAt = observationAt
	after, preserved, decision, err := CompleteObservation(reserved, advanced, observation)
	if err != nil || decision != ObservationResolved || !after.done || after.quarantined {
		t.Fatalf("stale observation completion = %s, %#v, %v", decision, after, err)
	}
	if !effectProjectionsEqual(preserved, advanced) {
		t.Fatalf("stale observation overwrote current effect: got %#v want %#v", preserved, advanced)
	}
}

func TestObservationCompletionDistinguishesAttemptsResolvedInSameMillisecond(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 31_350, false)
	effect := mustEffect(t, fixture.plan, "observe-same-millisecond-retry")
	original := mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 31_351)
	target, err := EffectProjectionFromAttempt(original)
	if err != nil {
		t.Fatal(err)
	}
	observationAt := target.updatedAt.Add(time.Millisecond)
	reserved, observation := mustResolvedObservationAttempt(
		t,
		fixture,
		target,
		2,
		observationAt,
		observationAt.Add(time.Hour),
		EffectStateNoEffect,
		true,
		31_352,
	)

	retry := mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 31_353)
	advanced, err := EffectProjectionFromAttempt(retry)
	if err != nil {
		t.Fatal(err)
	}
	if !advanced.updatedAt.Equal(target.updatedAt) || original.id == retry.id ||
		target.SourceAttemptID() != original.ID() || advanced.SourceAttemptID() != retry.ID() {
		t.Fatalf("fixture did not create distinct same-millisecond attempts: %#v/%#v", original, retry)
	}

	after, preserved, decision, err := CompleteObservation(reserved, advanced, observation)
	if err != nil || decision != ObservationContinue || after.done || after.quarantined {
		t.Fatalf("same-millisecond stale observation = %s, %#v, %v", decision, after, err)
	}
	if !effectProjectionsEqual(preserved, advanced) || preserved.state != AttemptStateIndeterminate {
		t.Fatalf("stale observation overwrote newer same-millisecond attempt: got %#v want %#v", preserved, advanced)
	}
}

func TestUndispatchedObservationRecoveryPreservesTargetTimestamp(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 31_400, false)
	effect := mustEffect(t, fixture.plan, "observe-never-dispatched")
	original := mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 31_401)
	current, err := EffectProjectionFromAttempt(original)
	if err != nil {
		t.Fatal(err)
	}
	observationAt := current.updatedAt.Add(time.Millisecond)
	reserved, recovered := mustResolvedObservationAttempt(
		t,
		fixture,
		current,
		2,
		observationAt,
		observationAt.Add(time.Hour),
		EffectStateNoEffect,
		false,
		31_402,
	)
	after, preserved, decision, err := CompleteObservation(reserved, current, recovered)
	if err != nil || decision != ObservationContinue || after.done || after.quarantined {
		t.Fatalf("undispatched observation completion = %s, %#v, %v", decision, after, err)
	}
	if !effectProjectionsEqual(preserved, current) ||
		!preserved.updatedAt.Equal(current.updatedAt) ||
		preserved.updatedAt.Equal(recovered.resolvedAt) {
		t.Fatalf("undispatched observation changed target evidence: got %#v want %#v", preserved, current)
	}
	if after.lastAt.Before(recovered.resolvedAt) {
		t.Fatalf("budget clock = %s, want at least %s", after.lastAt, recovered.resolvedAt)
	}
}

func TestEffectEvidenceGCRequiresAgeAndNoResidualAuthority(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 58, false)
	effect := mustEffect(t, fixture.plan, "delete")
	projection, _ := EffectProjectionFromAttempt(mustAttempt(t, fixture, effect, AttemptStateNoEffect, 1))
	deletedAt := fixtureTime
	base := EffectRetentionInput{
		Projection:  projection,
		DeletedAt:   &deletedAt,
		EvaluatedAt: deletedAt.Add(MinimumEffectTombstoneRetention - time.Millisecond),
	}
	regressed := base
	regressed.EvaluatedAt = deletedAt.Add(time.Millisecond)
	if _, err := EvaluateEffectRetention(regressed); !errors.Is(err, ErrInvalidRetention) {
		t.Fatalf("pre-evidence retention time error = %v", err)
	}
	if got, err := EvaluateEffectRetention(base); err != nil || got != RetentionKeep {
		t.Fatalf("pre-boundary retention = %s, %v", got, err)
	}
	base.EvaluatedAt = deletedAt.Add(MinimumEffectTombstoneRetention)
	if got, err := EvaluateEffectRetention(base); err != nil || got != RetentionEligible {
		t.Fatalf("exact-boundary retention = %s, %v", got, err)
	}
	for _, setReference := range []func(*EffectRetentionInput){
		func(input *EffectRetentionInput) { input.OperationReferences = true },
		func(input *EffectRetentionInput) { input.OutboxReferences = true },
		func(input *EffectRetentionInput) { input.DeliveryReferences = true },
		func(input *EffectRetentionInput) { input.RedriveAuthority = true },
	} {
		input := base
		input.EvaluatedAt = deletedAt.Add(10 * MinimumEffectTombstoneRetention)
		setReference(&input)
		if got, err := EvaluateEffectRetention(input); err != nil || got != RetentionKeep {
			t.Fatalf("referenced retention = %s, %v", got, err)
		}
	}
	unknown, _ := EffectProjectionFromAttempt(mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 2))
	base.Projection = unknown
	base.EvaluatedAt = deletedAt.Add(10 * MinimumEffectTombstoneRetention)
	if got, err := EvaluateEffectRetention(base); err != nil || got != RetentionKeep {
		t.Fatalf("unknown-effect retention = %s, %v", got, err)
	}
}

func TestAtomicTransitionBundleRequiresExactAuditAndSuccessorCardinality(t *testing.T) {
	t.Parallel()
	prepared, err := NewTransitionBundle(TransitionBundleInput{AttemptWrite: true})
	if err != nil || prepared.providerAttemptAuditEvents != 0 || prepared.successorOutboxRecords != 0 {
		t.Fatalf("prepared bundle = %#v, %v", prepared, err)
	}
	result, err := NewTransitionBundle(TransitionBundleInput{
		OperationWrite: true, AttemptWrite: true, ObservationWrite: true,
		ProviderPossiblyDispatched: true, ProviderAttemptAuditEvents: 1, SuccessorOutboxRecords: 1,
	})
	if err != nil || result.providerAttemptAuditEvents != 1 || result.successorOutboxRecords != 1 {
		t.Fatalf("result bundle = %#v, %v", result, err)
	}
	for _, input := range []TransitionBundleInput{
		{},
		{AttemptWrite: true, ProviderAttemptAuditEvents: 1},
		{AttemptWrite: true, ProviderPossiblyDispatched: true},
		{AttemptWrite: true, SuccessorOutboxRecords: 2},
	} {
		if _, err := NewTransitionBundle(input); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("invalid bundle %#v error = %v", input, err)
		}
	}
}
