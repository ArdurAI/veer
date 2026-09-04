package reconciliation

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/operation"
)

func TestLeaseFenceAdvancesOnlyOnAcquireOrTakeover(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 40, false)
	binding, _ := LeaseBindingFromPlan(fixture.plan)
	table, _ := NewLeaseTable(1)
	ownerOne := indexedID("wrk", 1)
	ownerTwo := indexedID("wrk", 2)
	token, err := table.Acquire(fixtureTime, binding, ownerOne)
	if err != nil || token.fence != 1 || !token.expiresAt.Equal(fixtureTime.Add(StoreLeaseDuration)) {
		t.Fatalf("Acquire() = %#v, %v", token, err)
	}
	if _, err := table.Acquire(fixtureTime.Add(time.Second), binding, ownerTwo); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("live takeover error = %v", err)
	}
	renewed, err := table.Renew(fixtureTime.Add(RenewalDeadline), token)
	if err != nil || renewed.fence != token.fence ||
		!renewed.expiresAt.Equal(fixtureTime.Add(RenewalDeadline+StoreLeaseDuration)) {
		t.Fatalf("Renew() = %#v, %v", renewed, err)
	}
	takeoverAt := renewed.expiresAt
	taken, err := table.Acquire(takeoverAt, binding, ownerTwo)
	if err != nil || taken.fence != 2 || taken.ownerID != ownerTwo {
		t.Fatalf("exact-expiry takeover = %#v, %v", taken, err)
	}
	bundle, err := NewTransitionBundle(TransitionBundleInput{AttemptWrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := table.AuthorizeCommit(takeoverAt, token, bundle); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale owner commit error = %v", err)
	}
	if err := table.AuthorizeCommit(takeoverAt, taken, bundle); err != nil {
		t.Fatalf("current owner commit: %v", err)
	}
}

func TestLeaseBindingReplacementRequiresExactForwardCompareAndSwap(t *testing.T) {
	t.Parallel()
	base := newPlanFixture(t, 1, 140, false)
	next := nextGenerationFixture(t, base, 2, 141)
	baseBinding, _ := LeaseBindingFromPlan(base.plan)
	nextBinding, _ := LeaseBindingFromPlan(next.plan)
	table, _ := NewLeaseTable(1)
	baseToken, err := table.Acquire(fixtureTime, baseBinding, indexedID("wrk", 140))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Acquire(baseToken.expiresAt, nextBinding, indexedID("wrk", 141)); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("implicit binding replacement error = %v", err)
	}
	generationInput := generationReplacementInput(t, next.plan, 140)
	generationReplacement, _, err := AuthorizeGenerationReplacement(base.plan, next.plan, generationInput)
	if err != nil {
		t.Fatal(err)
	}
	nextToken, err := table.AcquireReplacement(
		baseToken.expiresAt,
		generationReplacement,
		indexedID("wrk", 141),
	)
	if err != nil || nextToken.fence != 2 || !nextToken.binding.Equal(nextBinding) {
		t.Fatalf("forward replacement = %#v, %v", nextToken, err)
	}
	if _, err := table.Acquire(
		baseToken.expiresAt,
		baseBinding,
		indexedID("wrk", 142),
	); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale binding takeover error = %v", err)
	}
	staleGenerationReplacement, _, err := AuthorizeGenerationReplacement(base.plan, next.plan, generationInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.AcquireReplacement(
		nextToken.expiresAt,
		staleGenerationReplacement,
		indexedID("wrk", 142),
	); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale expected binding error = %v", err)
	}
	if _, _, err := AuthorizeGenerationReplacement(next.plan, base.plan, generationInput); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("generation rollback error = %v", err)
	}

	observed := mustEvidence(t, EvidenceObservedSnapshot, "observation-replan", []byte("changed"))
	replanned := next.candidate(t, 2, PlanKindForward, observed, nil, nil)
	replannedBinding, _ := LeaseBindingFromPlan(replanned)
	_, selection, replanReplacement, err := SelectPlan(next.plan, replanned, nil, nil, true, nil)
	if err != nil || selection != PlanSelectionSupersede {
		t.Fatalf("replan selection = %s, %v", selection, err)
	}
	replannedToken, err := table.AcquireReplacement(
		nextToken.expiresAt,
		replanReplacement,
		indexedID("wrk", 142),
	)
	if err != nil || replannedToken.fence != 3 || !replannedToken.binding.Equal(replannedBinding) {
		t.Fatalf("same-generation replan replacement = %#v, %v", replannedToken, err)
	}
	if _, _, _, err := SelectPlan(replanned, next.plan, nil, nil, true, nil); !errors.Is(err, ErrReplanBlocked) {
		t.Fatalf("plan revision rollback error = %v", err)
	}
	skippedRevision := next.candidate(
		t,
		4,
		PlanKindForward,
		mustEvidence(t, EvidenceObservedSnapshot, "observation-skip", []byte("skip")),
		nil,
		nil,
	)
	if _, _, _, err := SelectPlan(replanned, skippedRevision, nil, nil, true, nil); !errors.Is(err, ErrReplanBlocked) {
		t.Fatalf("skipped plan revision error = %v", err)
	}
	nextReplan := next.candidate(
		t,
		2,
		PlanKindForward,
		mustEvidence(t, EvidenceObservedSnapshot, "next-observation-2", []byte("changed-again")),
		nil,
		nil,
	)
	if _, _, err := AuthorizeGenerationReplacement(base.plan, nextReplan, generationInput); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("new-generation noninitial revision error = %v", err)
	}
	if table.Len() != 1 {
		t.Fatalf("stable lineage rows = %d", table.Len())
	}
}

func TestGenerationReplacementRequiresQualifiedNextMutationAdmission(t *testing.T) {
	t.Parallel()
	base := newPlanFixture(t, 1, 24_100, false)
	next := nextGenerationFixture(t, base, 2, 24_101)
	priorEffect := mustEffect(t, base.plan, "unresolved-prior-effect")
	priorAttempt := mustAttempt(t, base, priorEffect, AttemptStateIndeterminate, 24_102)
	prior, err := EffectProjectionFromAttempt(priorAttempt)
	if err != nil {
		t.Fatal(err)
	}
	nextEffect := mustEffect(t, next.plan, "non-conflicting-next-effect")
	input := AttemptAdmissionInput{
		DatabaseTime:           fixtureTime.Add(2 * time.Second),
		Plan:                   next.plan,
		Effect:                 nextEffect,
		Purpose:                AttemptPurposeForward,
		RequestFingerprint:     mustRequestFingerprint(t, "next-generation-replacement"),
		PriorGenerationEffects: []EffectProjection{prior},
	}
	if _, err := NewAttemptAdmission(input); !errors.Is(err, ErrGenerationBlocked) {
		t.Fatalf("unqualified next mutation error = %v", err)
	}
	if _, _, err := AuthorizeGenerationReplacement(
		base.plan,
		next.plan,
		AttemptAdmissionInput{},
	); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("replacement without admission error = %v", err)
	}

	proof, err := NewSafeSupersessionProof(
		priorEffect,
		nextEffect,
		"fake-adapter-v1",
		[]byte("provider-proves-independent-effects"),
	)
	if err != nil {
		t.Fatal(err)
	}
	input.SafeSupersessionProofs = []SafeSupersessionProof{proof}
	replacement, replacementAdmission, err := AuthorizeGenerationReplacement(base.plan, next.plan, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPreparedAttempt(AttemptInput{
		ID:        indexedID("att", 24_103),
		Ordinal:   1,
		Admission: replacementAdmission,
		OwnerID:   indexedID("wrk", 24_101),
		Fence:     2,
	}); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("generation admission before replacement error = %v", err)
	}
	table, token := mustLease(t, base, fixtureTime)
	if err := table.Surrender(fixtureTime.Add(time.Second), token); err != nil {
		t.Fatal(err)
	}
	replaced, err := table.AcquireReplacement(
		fixtureTime.Add(2*time.Second),
		replacement,
		indexedID("wrk", 24_101),
	)
	if err != nil || !replaced.binding.planDigest.Equal(next.plan.digest) {
		t.Fatalf("qualified replacement = %#v, %v", replaced, err)
	}
	if _, err := NewPreparedAttempt(AttemptInput{
		ID:        indexedID("att", 24_104),
		Ordinal:   1,
		Admission: replacementAdmission,
		OwnerID:   replaced.ownerID,
		Fence:     replaced.fence,
	}); err != nil {
		t.Fatalf("paired generation admission after replacement: %v", err)
	}
	if _, err := NewPreparedAttempt(AttemptInput{
		ID:        indexedID("att", 24_105),
		Ordinal:   2,
		Admission: replacementAdmission,
		OwnerID:   replaced.ownerID,
		Fence:     replaced.fence,
	}); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("reused paired generation admission error = %v", err)
	}
}

func TestLeaseReplacementConsumesOnlyQualifiedPlanLineage(t *testing.T) {
	t.Parallel()
	base := newPlanFixture(t, 1, 240, false)
	next := nextGenerationFixture(t, base, 2, 241)
	baseBinding, _ := LeaseBindingFromPlan(base.plan)
	table, _ := NewLeaseTable(1)
	baseToken, err := table.Acquire(fixtureTime, baseBinding, indexedID("wrk", 240))
	if err != nil {
		t.Fatal(err)
	}
	if err := table.Surrender(fixtureTime.Add(time.Millisecond), baseToken); err != nil {
		t.Fatal(err)
	}
	if _, err := table.AcquireReplacement(
		fixtureTime.Add(2*time.Millisecond),
		LeaseReplacementAuthority{},
		indexedID("wrk", 241),
	); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("zero replacement authority error = %v", err)
	}

	qualified, _, err := AuthorizeGenerationReplacement(
		base.plan,
		next.plan,
		generationReplacementInput(t, next.plan, 240),
	)
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := table.AcquireReplacement(
		fixtureTime.Add(2*time.Millisecond),
		qualified,
		indexedID("wrk", 241),
	)
	if err != nil || replaced.fence != baseToken.fence+1 {
		t.Fatalf("qualified replacement = %#v, %v", replaced, err)
	}

	secondTable, _ := NewLeaseTable(1)
	secondBase, err := secondTable.Acquire(fixtureTime, baseBinding, indexedID("wrk", 242))
	if err != nil {
		t.Fatal(err)
	}
	if err := secondTable.Surrender(fixtureTime.Add(time.Millisecond), secondBase); err != nil {
		t.Fatal(err)
	}
	if _, err := secondTable.AcquireReplacement(
		fixtureTime.Add(2*time.Millisecond),
		qualified,
		indexedID("wrk", 243),
	); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("reused replacement authority error = %v", err)
	}

	unrelated := newPlanFixture(t, 1, 242, false)
	observed := mustEvidence(t, EvidenceObservedSnapshot, "unrelated-predecessor", []byte("changed"))
	unrelatedCandidate, err := NewPlan(PlanInput{
		ID:               indexedID("pln", 242),
		Revision:         2,
		Kind:             PlanKindForward,
		Operation:        base.op,
		PlannerVersion:   base.plan.plannerVersion,
		DesiredIntent:    base.desired,
		ObservedSnapshot: observed,
		Actor:            base.actor,
		Authorization:    base.decision,
		ProviderBinding:  base.provider,
		Capability:       base.capability,
		Quota:            base.quota,
		Cost:             base.cost,
		Supersedes:       digestPointer(unrelated.plan.digest),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := SelectPlan(base.plan, unrelatedCandidate, nil, nil, true, nil); !errors.Is(err, ErrReplanBlocked) {
		t.Fatalf("unrelated predecessor error = %v", err)
	}
}

func TestDispatchPermitLosesToLeaseSurrenderAndReplacement(t *testing.T) {
	t.Parallel()
	makePermit := func(t *testing.T, fixture planFixture) (*LeaseTable, LeaseToken, Attempt, DispatchPermit) {
		t.Helper()
		table, token := mustLease(t, fixture, fixtureTime)
		effect := mustEffect(t, fixture.plan, "stale-permit")
		attempt := mustPreparedAttempt(t, fixture, effect, AttemptPurposeForward, 24_000, token, fixtureTime)
		_, permit := mustPermit(t, fixture, fixture.op, fixtureTime, table, token, attempt, 5*time.Second)
		return table, token, attempt, permit
	}

	base := newPlanFixture(t, 1, 243, false)
	table, token, attempt, permit := makePermit(t, base)
	otherTable, _ := NewLeaseTable(1)
	otherToken, err := otherTable.Acquire(
		fixtureTime,
		token.binding,
		token.ownerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherTable.MarkAttemptDispatched(
		attempt,
		permit,
		fixtureTime.Add(10*time.Second),
	); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("cross-table dispatch error = %v", err)
	}
	if permit.use.Load() {
		t.Fatal("cross-table dispatch consumed the permit")
	}
	if _, err := otherTable.Renew(fixtureTime.Add(time.Millisecond), otherToken); err != nil {
		t.Fatalf("cross-table dispatch poisoned unrelated table time: %v", err)
	}
	if err := table.Surrender(fixtureTime.Add(time.Millisecond), token); err != nil {
		t.Fatal(err)
	}
	if _, err := table.MarkAttemptDispatched(
		attempt,
		permit,
		fixtureTime.Add(2*time.Millisecond),
	); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("dispatch after surrender error = %v", err)
	}
	if permit.use.Load() {
		t.Fatal("lost permit was consumed despite no dispatch")
	}

	table, token, attempt, permit = makePermit(t, base)
	if err := table.Surrender(fixtureTime.Add(time.Millisecond), token); err != nil {
		t.Fatal(err)
	}
	next := nextGenerationFixture(t, base, 2, 244)
	replacement, _, err := AuthorizeGenerationReplacement(
		base.plan,
		next.plan,
		generationReplacementInput(t, next.plan, 244),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.AcquireReplacement(
		fixtureTime.Add(2*time.Millisecond),
		replacement,
		indexedID("wrk", 244),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := table.MarkAttemptDispatched(
		attempt,
		permit,
		fixtureTime.Add(3*time.Millisecond),
	); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("dispatch after replacement error = %v", err)
	}
}

func TestDispatchRequiresStrictDeadlineMarginAndExactAuthority(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 41, true)
	binding, _ := LeaseBindingFromPlan(fixture.plan)
	table, _ := NewLeaseTable(1)
	token, err := table.Acquire(fixtureTime, binding, indexedID("wrk", 1))
	if err != nil {
		t.Fatal(err)
	}
	effect := mustEffect(t, fixture.plan, "dispatch")
	prepared := func(index int, purpose AttemptPurpose) Attempt {
		return mustPreparedAttempt(t, fixture, effect, purpose, index, token, fixtureTime)
	}
	first := prepared(1, AttemptPurposeForward)
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
	if _, err := table.AuthorizeDispatch(fixtureTime, token, 50*time.Second, authority); !errors.Is(err, ErrDispatchWindow) {
		t.Fatalf("equal margin error = %v", err)
	}
	permit, err := table.AuthorizeDispatch(fixtureTime, token, 50*time.Second-time.Millisecond, authority)
	if err != nil || !permit.authorizedAt.Equal(fixtureTime) ||
		!permit.deadline.Equal(fixtureTime.Add(50*time.Second-time.Millisecond)) {
		t.Fatalf("strictly safe dispatch = %#v, %v", permit, err)
	}
	if _, err := table.AuthorizeDispatch(fixtureTime, token, 5*time.Second, authority); !errors.Is(err, ErrDispatchAuthority) {
		t.Fatalf("reused authority error = %v", err)
	}
	second := prepared(2, AttemptPurposeForward)
	secondAuthority, err := NewDispatchAuthority(
		fixtureTime,
		fixture.plan,
		second,
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
	shortPermit, err := table.AuthorizeDispatch(fixtureTime, token, 5*time.Second, secondAuthority)
	if err != nil || !shortPermit.deadline.Equal(fixtureTime.Add(5*time.Second)) {
		t.Fatalf("bounded RPC deadline = %#v, %v", shortPermit, err)
	}
	third := prepared(3, AttemptPurposeForward)
	staleAuthority, err := NewDispatchAuthority(
		fixtureTime,
		fixture.plan,
		third,
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
	if _, err := table.AuthorizeDispatch(
		fixtureTime.Add(time.Millisecond),
		token,
		5*time.Second,
		staleAuthority,
	); !errors.Is(err, ErrDispatchAuthority) {
		t.Fatalf("stale execution-time authority error = %v", err)
	}
	fourth := prepared(4, AttemptPurposeForward)
	freshAuthority, err := NewDispatchAuthority(
		fixtureTime.Add(time.Millisecond),
		fixture.plan,
		fourth,
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
	if _, err := table.AuthorizeDispatch(
		fixtureTime.Add(time.Millisecond),
		token,
		50*time.Second-time.Millisecond,
		freshAuthority,
	); !errors.Is(err, ErrDispatchWindow) {
		t.Fatalf("delayed equality error = %v", err)
	}

	changedQuota := mustEvidence(t, EvidenceQuota, "quota-2", []byte("changed"))
	if _, err := NewDispatchAuthority(
		fixtureTime.Add(time.Millisecond),
		fixture.plan,
		prepared(5, AttemptPurposeForward),
		fixture.op,
		fixture.decision,
		fixture.provider,
		fixture.capability,
		changedQuota,
		fixture.cost,
	); !errors.Is(err, ErrDispatchAuthority) {
		t.Fatalf("stale authority error = %v", err)
	}
	futurePrepared := mustPreparedAttempt(
		t,
		fixture,
		effect,
		AttemptPurposeForward,
		7,
		token,
		fixtureTime.Add(2*time.Millisecond),
	)
	if _, err := NewDispatchAuthority(
		fixtureTime.Add(time.Millisecond),
		fixture.plan,
		futurePrepared,
		fixture.op,
		fixture.decision,
		fixture.provider,
		fixture.capability,
		fixture.quota,
		fixture.cost,
	); !errors.Is(err, ErrDispatchAuthority) {
		t.Fatalf("pre-preparation authority error = %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*operation.Operation)
	}{
		{name: "environment", mutate: func(current *operation.Operation) {
			environment := indexedID("env", 410)
			current.EnvironmentID = &environment
		}},
		{name: "provider connection", mutate: func(current *operation.Operation) {
			connection := indexedID("prv", 410)
			current.ProviderConnectionID = &connection
		}},
		{name: "missing binding", mutate: func(current *operation.Operation) {
			current.EnvironmentID = nil
			current.ProviderConnectionID = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := fixture.op
			test.mutate(&current)
			if _, err := NewDispatchAuthority(
				fixtureTime.Add(time.Millisecond),
				fixture.plan,
				prepared(6, AttemptPurposeForward),
				current,
				fixture.decision,
				fixture.provider,
				fixture.capability,
				fixture.quota,
				fixture.cost,
			); !errors.Is(err, ErrDispatchAuthority) {
				t.Fatalf("immutable Operation binding error = %v", err)
			}
		})
	}
}

func TestObservationDeadlineIsClosedAtEveryDispatchBoundary(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 24_600, false)
	effect := mustEffect(t, fixture.plan, "deadline-bound-observation")
	current := EffectProjection{
		initialized:     true,
		key:             effect,
		planDigest:      fixture.plan.digest,
		sourceAttemptID: indexedID("att", 24_599),
		purpose:         AttemptPurposeForward,
		state:           AttemptStateIndeterminate,
		updatedAt:       fixtureTime.Add(-time.Millisecond),
	}
	deadline := fixtureTime.Add(10 * time.Second)
	budget, err := NewObservationBudget(effect, 1, deadline)
	if err != nil {
		t.Fatal(err)
	}
	_, observation, err := ReserveObservation(budget, fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       fixtureTime,
		Plan:               fixture.plan,
		Effect:             effect,
		Purpose:            AttemptPurposeObservation,
		RequestFingerprint: mustRequestFingerprint(t, "deadline-bound-observation"),
		CurrentEffect:      &current,
		Observation:        &observation,
	})
	if err != nil {
		t.Fatal(err)
	}
	table, token := mustLease(t, fixture, fixtureTime)
	attempt, err := NewPreparedAttempt(AttemptInput{
		ID: indexedID("att", 24_600), Ordinal: 1, Admission: admission,
		OwnerID: token.ownerID, Fence: token.fence,
	})
	if err != nil || !attempt.observationDeadline.Equal(deadline) || !observation.Deadline().Equal(deadline) {
		t.Fatalf("observation deadline propagation = %s/%s, %v", attempt.observationDeadline, observation.Deadline(), err)
	}
	if _, err := NewDispatchAuthority(
		deadline,
		fixture.plan,
		attempt,
		fixture.op,
		fixture.decision,
		fixture.provider,
		fixture.capability,
		fixture.quota,
		fixture.cost,
	); !errors.Is(err, ErrDispatchAuthority) {
		t.Fatalf("exact-deadline authority error = %v", err)
	}
	authority, permit := mustPermit(
		t,
		fixture,
		fixture.op,
		fixtureTime,
		table,
		token,
		attempt,
		20*time.Second,
	)
	if !authority.ObservedAt().Equal(fixtureTime) || !permit.Deadline().After(deadline) {
		t.Fatalf("pre-deadline dispatch authority = %#v/%#v", authority, permit)
	}
	if _, err := table.MarkAttemptDispatched(attempt, permit, deadline); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("exact observation deadline dispatch error = %v", err)
	}
	if permit.use.Load() {
		t.Fatal("deadline rejection consumed dispatch permit")
	}
	if _, err := table.MarkAttemptDispatched(attempt, permit, deadline.Add(-time.Millisecond)); err != nil {
		t.Fatalf("pre-deadline dispatch: %v", err)
	}
}

func TestWaitingOperationAllowsOnlyRecoveryDispatchPurposes(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 141, false)
	waiting := fixture.op
	waiting.Phase = operation.PhaseWaiting
	table, token := mustLease(t, fixture, fixtureTime)
	effect := mustEffect(t, fixture.plan, "recover")
	for index, purpose := range []AttemptPurpose{AttemptPurposeObservation, AttemptPurposeProviderCancel} {
		attempt := mustPreparedAttempt(t, fixture, effect, purpose, 20+index, token, fixtureTime)
		authority, err := NewDispatchAuthority(
			fixtureTime,
			fixture.plan,
			attempt,
			waiting,
			fixture.decision,
			fixture.provider,
			fixture.capability,
			fixture.quota,
			fixture.cost,
		)
		if err != nil {
			t.Fatalf("%s authority: %v", purpose, err)
		}
		permit, err := table.AuthorizeDispatch(fixtureTime, token, 5*time.Second, authority)
		if err != nil {
			t.Fatalf("%s permit: %v", purpose, err)
		}
		if _, err := table.MarkAttemptDispatched(attempt, permit, fixtureTime); err != nil {
			t.Fatalf("%s dispatch: %v", purpose, err)
		}
	}
	forward := mustPreparedAttempt(t, fixture, effect, AttemptPurposeForward, 22, token, fixtureTime)
	if _, err := NewDispatchAuthority(
		fixtureTime,
		fixture.plan,
		forward,
		waiting,
		fixture.decision,
		fixture.provider,
		fixture.capability,
		fixture.quota,
		fixture.cost,
	); !errors.Is(err, ErrDispatchAuthority) {
		t.Fatalf("waiting forward authority error = %v", err)
	}
}

func TestVisibilityResetAndStableRenewalJitter(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 42, false)
	work, err := NewWorkKey(fixture.plan, []byte("step-one"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := StableRenewalInterval(work)
	if err != nil || first < RenewalJitterMinimum || first > RenewalDeadline {
		t.Fatalf("StableRenewalInterval() = %s, %v", first, err)
	}
	second, _ := StableRenewalInterval(work)
	if second != first {
		t.Fatalf("renewal interval changed from %s to %s", first, second)
	}
	changedAt := fixtureTime.Add(17 * time.Second)
	deadline, err := VisibilityDeadline(changedAt)
	if err != nil || !deadline.Equal(changedAt.Add(QueueVisibilityDuration)) {
		t.Fatalf("VisibilityDeadline() = %s, %v", deadline, err)
	}
	if deadline.Equal(fixtureTime.Add(QueueVisibilityDuration + 17*time.Second + QueueVisibilityDuration)) {
		t.Fatal("visibility interval was added to a prior deadline")
	}
}

func TestLeaseClockOrderingIsScopedPerLineage(t *testing.T) {
	t.Parallel()
	one := newPlanFixture(t, 1, 142, false)
	two := newPlanFixture(t, 1, 143, false)
	oneBinding, _ := LeaseBindingFromPlan(one.plan)
	twoBinding, _ := LeaseBindingFromPlan(two.plan)
	table, _ := NewLeaseTable(2)
	oneToken, err := table.Acquire(fixtureTime.Add(time.Second), oneBinding, indexedID("wrk", 142))
	if err != nil {
		t.Fatal(err)
	}
	twoToken, err := table.Acquire(fixtureTime, twoBinding, indexedID("wrk", 143))
	if err != nil {
		t.Fatalf("independent lineage inherited another lineage's clock: %v", err)
	}
	if _, err := table.Renew(fixtureTime.Add(-time.Millisecond), twoToken); !errors.Is(err, ErrClockRegressed) {
		t.Fatalf("same-lineage clock regression error = %v", err)
	}
	if _, err := table.Renew(fixtureTime.Add(2*time.Second), oneToken); err != nil {
		t.Fatalf("first lineage renewal: %v", err)
	}
}

func TestSignedFenceFailsClosedAtPostgreSQLBigintBoundary(t *testing.T) {
	t.Parallel()
	if got, err := NextFence(0); err != nil || got != 1 {
		t.Fatalf("NextFence(0) = %d, %v", got, err)
	}
	if got, err := NextFence(MaxFence - 1); err != nil || got != MaxFence {
		t.Fatalf("NextFence(MaxFence-1) = %d, %v", got, err)
	}
	for _, value := range []int64{-1, MaxFence} {
		if _, err := NextFence(value); !errors.Is(err, ErrFenceExhausted) {
			t.Fatalf("NextFence(%d) error = %v", value, err)
		}
	}
}

func TestTargetScaleSynchronizedLeaseRenewalAndFailover(t *testing.T) {
	table, err := NewLeaseTable(TargetActiveLeaseLimit)
	if err != nil {
		t.Fatal(err)
	}
	tokens := make([]LeaseToken, 0, TargetActiveLeaseLimit)
	bindings := make([]LeaseBinding, 0, TargetActiveLeaseLimit)
	for index := 1; index <= TargetActiveLeaseLimit; index++ {
		fixture := newPlanFixture(t, 1, 1000+index, false)
		binding, err := LeaseBindingFromPlan(fixture.plan)
		if err != nil {
			t.Fatal(err)
		}
		token, err := table.Acquire(fixtureTime, binding, indexedID("wrk", index))
		if err != nil {
			t.Fatalf("Acquire(%d): %v", index, err)
		}
		tokens = append(tokens, token)
		bindings = append(bindings, binding)
	}
	if table.Len() != TargetActiveLeaseLimit {
		t.Fatalf("tracked leases = %d", table.Len())
	}
	for index, token := range tokens {
		renewed, err := table.Renew(fixtureTime.Add(RenewalDeadline), token)
		if err != nil || renewed.fence != 1 {
			t.Fatalf("Renew(%d) = fence %d, %v", index, renewed.fence, err)
		}
		tokens[index] = renewed
	}
	failoverAt := fixtureTime.Add(RenewalDeadline + StoreLeaseDuration)
	for index, binding := range bindings {
		taken, err := table.Acquire(failoverAt, binding, indexedID("new", index+1))
		if err != nil || taken.fence != 2 {
			t.Fatalf("takeover(%d) = fence %d, %v", index, taken.fence, err)
		}
	}
}

func TestRenewalAndQueueCostConstantsMatchApprovedEnvelope(t *testing.T) {
	t.Parallel()
	secondsPerMonth := MonthlyHours * int(time.Hour/time.Second)
	if got := SmallActiveLeaseLimit * secondsPerMonth / int(RenewalJitterMinimum/time.Second); got != SmallMonthlyLeaseRenewals {
		t.Fatalf("small monthly renewals = %d", got)
	}
	if got := TargetActiveLeaseLimit * secondsPerMonth / int(RenewalJitterMinimum/time.Second); got != TargetMonthlyLeaseRenewals {
		t.Fatalf("target monthly renewals = %d", got)
	}
	if SmallMonthlyQueueRequestCap != 20_000_000+SmallMonthlyVisibilityRequests {
		t.Fatal("small queue cap does not reserve visibility requests")
	}
	if TargetMonthlyQueueRequestCap != 100_000_000+TargetMonthlyVisibilityRequests {
		t.Fatal("target queue cap does not reserve visibility requests")
	}
	targetWorkItems := 17_608_245
	targetHeartbeatsPerItem := int((60*time.Second - time.Nanosecond) / RenewalJitterMinimum)
	if targetHeartbeatsPerItem != 3 ||
		TargetMonthlyVisibilityRequests != targetWorkItems*targetHeartbeatsPerItem {
		t.Fatal("target queue cap does not reserve three healthy visibility heartbeats per work item")
	}
}

func TestLeaseDerivedTimeAndDurationOverflowFailClosed(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 45, false)
	binding, err := LeaseBindingFromPlan(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	table, err := NewLeaseTable(1)
	if err != nil {
		t.Fatal(err)
	}
	nearUpperBound := time.Date(9999, time.December, 31, 23, 59, 59, 999_000_000, time.UTC)
	if _, err := table.Acquire(nearUpperBound, binding, indexedID("own", 46)); !errors.Is(err, ErrInvalidTime) || !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("Acquire() error = %v", err)
	}
	if table.Len() != 0 {
		t.Fatalf("failed acquire retained %d rows", table.Len())
	}
	if _, err := VisibilityDeadline(nearUpperBound); !errors.Is(err, ErrInvalidTime) {
		t.Fatalf("VisibilityDeadline() error = %v", err)
	}

	table, token := mustLease(t, fixture, fixtureTime.Add(time.Second))
	effect := mustEffect(t, fixture.plan, "overflow-dispatch")
	attempt := mustPreparedAttempt(
		t,
		fixture,
		effect,
		AttemptPurposeForward,
		46,
		token,
		fixtureTime.Add(time.Second),
	)
	authority, err := NewDispatchAuthority(
		fixtureTime.Add(time.Second+time.Millisecond),
		fixture.plan,
		attempt,
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
	if _, err := table.AuthorizeDispatch(fixtureTime.Add(time.Second+time.Millisecond), token, time.Duration(math.MaxInt64), authority); !errors.Is(err, ErrDispatchWindow) {
		t.Fatalf("AuthorizeDispatch() error = %v", err)
	}
}
