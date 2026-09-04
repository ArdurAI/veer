package reconciliation

import (
	"errors"
	"testing"
	"time"
)

func TestPlanDigestUsesSemanticInputsNotRecordIdentity(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 1, true)
	copyPlan, err := NewPlan(PlanInput{
		ID:               indexedID("pln", 2),
		Revision:         1,
		Kind:             PlanKindForward,
		Operation:        fixture.op,
		PlannerVersion:   fixture.plan.plannerVersion,
		DesiredIntent:    fixture.desired,
		ObservedSnapshot: fixture.observed,
		Actor:            fixture.actor,
		Authorization:    fixture.decision,
		ProviderBinding:  fixture.provider,
		Capability:       fixture.capability,
		Quota:            fixture.quota,
		Cost:             fixture.cost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !copyPlan.digest.Equal(fixture.plan.digest) {
		t.Fatal("record ID changed semantic plan digest")
	}
	selected, disposition, replacement, err := SelectPlan(fixture.plan, copyPlan, nil, nil, false, nil)
	if err != nil || disposition != PlanSelectionReuse || selected.id != fixture.plan.id {
		t.Fatalf("SelectPlan() = %#v, %q, %v", selected, disposition, err)
	}
	if replacement.initialized {
		t.Fatal("semantic reuse minted replacement authority")
	}

	changedObserved := mustEvidence(t, EvidenceObservedSnapshot, "observation-2", []byte(`{"observed":true}`))
	changed := fixture.candidate(t, 2, PlanKindForward, changedObserved, nil, nil)
	if changed.digest.Equal(fixture.plan.digest) {
		t.Fatal("changed authoritative observation did not change digest")
	}
	selfCertified := fixture.plan
	selfCertified.completedEffects = []EffectKey{mustEffect(t, fixture.plan, "fabricated-completion")}
	selfCertified.digest = derivePlanDigest(selfCertified)
	if err := ValidatePlan(selfCertified); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("initial plan self-certified completion error = %v", err)
	}
}

func TestSameGenerationReplanRequiresDefinitiveAttemptsAndExactCarryForward(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 3, false)
	effect := mustEffect(t, fixture.plan, `{"apply":"component"}`)
	applied := mustAttempt(t, fixture, effect, AttemptStateApplied, 1)
	appliedProjection, err := EffectProjectionFromAttempt(applied)
	if err != nil {
		t.Fatal(err)
	}
	observed := mustEvidence(t, EvidenceObservedSnapshot, "observation-2", []byte(`{"ready":true}`))
	candidate := fixture.candidate(t, 2, PlanKindForward, observed, []EffectKey{effect}, nil)

	selected, disposition, replacement, err := SelectPlan(
		fixture.plan,
		candidate,
		[]Attempt{applied},
		[]EffectProjection{appliedProjection},
		true,
		nil,
	)
	if err != nil || disposition != PlanSelectionSupersede || !selected.digest.Equal(candidate.digest) {
		t.Fatalf("valid supersession = %q, %v", disposition, err)
	}
	if validateLeaseReplacementAuthority(replacement) != nil {
		t.Fatal("valid supersession omitted replacement authority")
	}

	indeterminate := mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 2)
	indeterminateProjection, err := EffectProjectionFromAttempt(indeterminate)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := SelectPlan(
		fixture.plan,
		candidate,
		[]Attempt{indeterminate},
		[]EffectProjection{indeterminateProjection},
		true,
		nil,
	); !errors.Is(err, ErrAttemptNotDefinitive) {
		t.Fatalf("indeterminate supersession error = %v", err)
	}
	invalid := applied
	invalid.preparedAt = time.Time{}
	if _, _, _, err := SelectPlan(fixture.plan, candidate, []Attempt{invalid}, nil, true, nil); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("invalid prior attempt error = %v", err)
	}
	other := newPlanFixture(t, 1, 103, false)
	otherEffect := mustEffect(t, other.plan, "other-plan-effect")
	otherAttempt := mustAttempt(t, other, otherEffect, AttemptStateNoEffect, 3)
	if _, _, _, err := SelectPlan(fixture.plan, candidate, []Attempt{otherAttempt}, nil, true, nil); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("mismatched prior plan error = %v", err)
	}
	missing := fixture.candidate(t, 2, PlanKindForward, observed, nil, nil)
	if _, _, _, err := SelectPlan(
		fixture.plan,
		missing,
		[]Attempt{applied},
		[]EffectProjection{appliedProjection},
		true,
		nil,
	); !errors.Is(err, ErrCompletedEffectMissing) {
		t.Fatalf("missing carried effect error = %v", err)
	}
	if _, _, _, err := SelectPlan(
		fixture.plan,
		candidate,
		[]Attempt{applied},
		[]EffectProjection{appliedProjection},
		false,
		nil,
	); !errors.Is(err, ErrReplanBlocked) {
		t.Fatalf("stale observation error = %v", err)
	}
	duplicateOrdinal := applied
	duplicateOrdinal.id = indexedID("att", 19_999)
	if _, _, _, err := SelectPlan(
		fixture.plan,
		candidate,
		[]Attempt{applied, duplicateOrdinal},
		[]EffectProjection{appliedProjection},
		true,
		nil,
	); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("duplicate attempt ordinal error = %v", err)
	}
	longHistory := make([]Attempt, MaxEffectsPerOperation+1)
	for index := range longHistory {
		longHistory[index] = applied
		longHistory[index].id = indexedID("att", 20_000+index)
		longHistory[index].ordinal = uint32(index + 1)
	}
	selected, disposition, replacement, err = SelectPlan(
		fixture.plan,
		candidate,
		longHistory,
		[]EffectProjection{appliedProjection},
		true,
		nil,
	)
	if err != nil || disposition != PlanSelectionSupersede || !selected.digest.Equal(candidate.digest) {
		t.Fatalf("long physical-attempt replan = %s, %v", disposition, err)
	}
	if validateLeaseReplacementAuthority(replacement) != nil {
		t.Fatal("long-history replan omitted replacement authority")
	}
}

func TestSameGenerationReplanUsesReconciledLogicalEffects(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 3_100, false)
	effect := mustEffect(t, fixture.plan, "observed-application")
	original := mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 3_101)
	indeterminate, err := EffectProjectionFromAttempt(original)
	if err != nil {
		t.Fatal(err)
	}
	observationAt := indeterminate.updatedAt.Add(time.Millisecond)
	reserved, observation := mustResolvedObservationAttempt(
		t,
		fixture,
		indeterminate,
		1,
		observationAt,
		observationAt.Add(time.Hour),
		EffectStateApplied,
		true,
		3_102,
	)
	_, applied, decision, err := CompleteObservation(reserved, indeterminate, observation)
	if err != nil || decision != ObservationResolved || applied.state != AttemptStateApplied ||
		applied.SourceAttemptID() != observation.ID() {
		t.Fatalf("definitive observation = %s, %#v, %v", decision, applied, err)
	}
	observed := mustEvidence(t, EvidenceObservedSnapshot, "observation-2", []byte("observed-applied"))
	candidate := fixture.candidate(t, 2, PlanKindForward, observed, []EffectKey{effect}, nil)
	selected, disposition, replacement, err := SelectPlan(
		fixture.plan,
		candidate,
		[]Attempt{original, observation},
		[]EffectProjection{applied},
		true,
		nil,
	)
	if err != nil || disposition != PlanSelectionSupersede ||
		!selected.digest.Equal(candidate.digest) || validateLeaseReplacementAuthority(replacement) != nil {
		t.Fatalf("observed-effect replan = %s, %#v, %v", disposition, replacement, err)
	}
	if _, _, _, err := SelectPlan(
		fixture.plan,
		candidate,
		[]Attempt{original, observation},
		[]EffectProjection{indeterminate},
		true,
		nil,
	); !errors.Is(err, ErrAttemptNotDefinitive) {
		t.Fatalf("unreconciled logical effect error = %v", err)
	}
	if _, _, _, err := SelectPlan(
		fixture.plan,
		candidate,
		[]Attempt{original, observation},
		nil,
		true,
		nil,
	); !errors.Is(err, ErrAttemptNotDefinitive) {
		t.Fatalf("missing current logical effect error = %v", err)
	}
	staleApplied := cloneEffectProjection(applied)
	staleApplied.updatedAt = original.preparedAt
	if _, _, _, err := SelectPlan(
		fixture.plan,
		candidate,
		[]Attempt{original, observation},
		[]EffectProjection{staleApplied},
		true,
		nil,
	); !errors.Is(err, ErrAttemptNotDefinitive) {
		t.Fatalf("stale current logical effect error = %v", err)
	}

	undispatchedAt := observationAt.Add(2 * time.Millisecond)
	undispatchedBudget, undispatched := mustResolvedObservationAttempt(
		t,
		fixture,
		indeterminate,
		2,
		undispatchedAt,
		undispatchedAt.Add(time.Hour),
		EffectStateNoEffect,
		false,
		3_103,
	)
	_, preserved, decision, err := CompleteObservation(undispatchedBudget, indeterminate, undispatched)
	if err != nil || decision != ObservationContinue || !effectProjectionsEqual(preserved, indeterminate) {
		t.Fatalf("undispatched observation projection = %s, %#v, %v", decision, preserved, err)
	}
	if _, _, _, err := SelectPlan(
		fixture.plan,
		candidate,
		[]Attempt{original, undispatched},
		[]EffectProjection{preserved},
		true,
		nil,
	); !errors.Is(err, ErrAttemptNotDefinitive) {
		t.Fatalf("undispatched observation replan error = %v", err)
	}
}

func TestCompensationRequiresAppliedEffectsAndReverseQualifiedOrder(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 4, false)
	first := mustEffect(t, fixture.plan, `{"create":"network"}`)
	second := mustEffect(t, fixture.plan, `{"create":"service"}`)
	observed := mustEvidence(t, EvidenceObservedSnapshot, "observation-2", []byte(`{"compensate":true}`))
	compensation := fixture.candidate(
		t,
		2,
		PlanKindCompensation,
		observed,
		[]EffectKey{first, second},
		[]EffectKey{first, second},
	)
	firstProjection, err := EffectProjectionFromAttempt(mustAttempt(t, fixture, first, AttemptStateApplied, 1))
	if err != nil {
		t.Fatal(err)
	}
	secondProjection, err := EffectProjectionFromAttempt(mustAttempt(t, fixture, second, AttemptStateApplied, 2))
	if err != nil {
		t.Fatal(err)
	}
	undoFirst := mustEffect(t, compensation, `{"delete":"network"}`)
	undoSecond := mustEffect(t, compensation, `{"delete":"service"}`)
	proofSecond, err := NewCompensationProof(secondProjection, undoSecond, 2, "fake-adapter-v1", []byte("owned-and-invertible"))
	if err != nil {
		t.Fatal(err)
	}
	proofFirst, err := NewCompensationProof(firstProjection, undoFirst, 1, "fake-adapter-v1", []byte("owned-and-invertible"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCompensationPlan(compensation, []CompensationProof{proofSecond, proofFirst}); err != nil {
		t.Fatalf("valid compensation: %v", err)
	}
	proofs := []CompensationProof{proofSecond, proofFirst}
	priorAttempts := []Attempt{
		mustAttempt(t, fixture, first, AttemptStateApplied, 4),
		mustAttempt(t, fixture, second, AttemptStateApplied, 5),
	}
	if _, _, authority, err := SelectPlan(
		fixture.plan,
		compensation,
		priorAttempts,
		[]EffectProjection{firstProjection, secondProjection},
		true,
		nil,
	); !errors.Is(err, ErrInvalidPlan) || authority.initialized {
		t.Fatalf("unqualified forward-to-compensation selection = %#v, %v", authority, err)
	}
	if _, _, authority, err := SelectPlan(
		fixture.plan,
		compensation,
		priorAttempts,
		[]EffectProjection{firstProjection, secondProjection},
		true,
		[]CompensationProof{proofFirst, proofSecond},
	); !errors.Is(err, ErrInvalidPlan) || authority.initialized {
		t.Fatalf("misordered forward-to-compensation selection = %#v, %v", authority, err)
	}
	firstStep, err := NextCompensationStep(compensation, proofs, nil)
	if err != nil || !firstStep.Inverse().Equal(undoSecond) || firstStep.Position() != 1 || firstStep.Total() != 2 {
		t.Fatalf("first compensation step = %#v, %v", firstStep, err)
	}
	compensationFixture := fixture
	compensationFixture.plan = compensation
	table, token := mustLease(t, compensationFixture, fixtureTime.Add(10*time.Second))
	firstAdmission, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       fixtureTime.Add(10 * time.Second),
		Plan:               compensation,
		Effect:             undoSecond,
		Purpose:            AttemptPurposeCompensation,
		RequestFingerprint: mustRequestFingerprint(t, "undo-service"),
		Compensation:       &firstStep,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		id     int
		mutate func(*CompensationStep)
	}{
		{name: "plan digest", id: 25_901, mutate: func(step *CompensationStep) {
			step.planDigest = fixture.plan.digest
		}},
		{name: "inverse effect", id: 25_902, mutate: func(step *CompensationStep) {
			step.inverse = undoFirst
		}},
	} {
		name, id, mutate := test.name, test.id, test.mutate
		t.Run("tampered admission "+name, func(t *testing.T) {
			admission, admissionErr := NewAttemptAdmission(AttemptAdmissionInput{
				DatabaseTime:       fixtureTime.Add(10 * time.Second),
				Plan:               compensation,
				Effect:             undoSecond,
				Purpose:            AttemptPurposeCompensation,
				RequestFingerprint: mustRequestFingerprint(t, "tampered-compensation-"+name),
				Compensation:       &firstStep,
			})
			if admissionErr != nil {
				t.Fatal(admissionErr)
			}
			mutate(admission.compensation)
			if _, preparationErr := NewPreparedAttempt(AttemptInput{
				ID:        indexedID("att", id),
				Ordinal:   uint32(id),
				Admission: admission,
				OwnerID:   indexedID("wrk", 25_900),
				Fence:     1,
			}); !errors.Is(preparationErr, ErrInvalidAttempt) {
				t.Fatalf("tampered compensation admission error = %v", preparationErr)
			}
		})
	}
	firstAttempt, err := NewPreparedAttempt(AttemptInput{
		ID:        indexedID("att", 406),
		Ordinal:   6,
		Admission: firstAdmission,
		OwnerID:   token.ownerID,
		Fence:     token.fence,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, permit := mustPermit(
		t,
		compensationFixture,
		fixture.op,
		fixtureTime.Add(10*time.Second),
		table,
		token,
		firstAttempt,
		5*time.Second,
	)
	firstAttempt, err = table.MarkAttemptDispatched(
		firstAttempt,
		permit,
		fixtureTime.Add(10*time.Second+time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstAttempt, err = ResolveAttempt(
		firstAttempt,
		EffectStateApplied,
		fixtureTime.Add(10*time.Second+2*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	completedFirst, err := EffectProjectionFromAttempt(firstAttempt)
	if err != nil {
		t.Fatal(err)
	}
	observationBase := fixtureTime.Add(20 * time.Second)
	indeterminateAdmission, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       observationBase,
		Plan:               compensation,
		Effect:             undoSecond,
		Purpose:            AttemptPurposeCompensation,
		RequestFingerprint: mustRequestFingerprint(t, "indeterminate-undo-service"),
		Compensation:       &firstStep,
	})
	if err != nil {
		t.Fatal(err)
	}
	indeterminateAttempt, err := NewPreparedAttempt(AttemptInput{
		ID:        indexedID("att", 409),
		Ordinal:   7,
		Admission: indeterminateAdmission,
		OwnerID:   token.ownerID,
		Fence:     token.fence,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, indeterminatePermit := mustPermit(
		t,
		compensationFixture,
		fixture.op,
		observationBase,
		table,
		token,
		indeterminateAttempt,
		5*time.Second,
	)
	indeterminateAttempt, err = table.MarkAttemptDispatched(
		indeterminateAttempt,
		indeterminatePermit,
		observationBase.Add(time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	indeterminateAttempt, err = ResolveAttempt(
		indeterminateAttempt,
		EffectStateIndeterminate,
		observationBase.Add(2*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	indeterminateProjection, err := EffectProjectionFromAttempt(indeterminateAttempt)
	if err != nil {
		t.Fatal(err)
	}
	observationAt := observationBase.Add(3 * time.Millisecond)
	observationBudget, err := NewObservationBudget(undoSecond, 1, observationAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	reservedBudget, observationPermit, err := ReserveObservation(observationBudget, observationAt)
	if err != nil {
		t.Fatal(err)
	}
	observationAdmission, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       observationAt,
		Plan:               compensation,
		Effect:             undoSecond,
		Purpose:            AttemptPurposeObservation,
		RequestFingerprint: mustRequestFingerprint(t, "observe-indeterminate-undo-service"),
		CurrentEffect:      &indeterminateProjection,
		Observation:        &observationPermit,
	})
	if err != nil {
		t.Fatal(err)
	}
	observationAttempt, err := NewPreparedAttempt(AttemptInput{
		ID:        indexedID("att", 410),
		Ordinal:   8,
		Admission: observationAdmission,
		OwnerID:   token.ownerID,
		Fence:     token.fence,
	})
	if err != nil {
		t.Fatal(err)
	}
	undispatchedObservation, err := RecoverAttempt(
		observationAttempt,
		DispatchProofNeverBegan,
		observationAt.Add(time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EffectProjectionFromAttempt(undispatchedObservation); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("undispatched observation projection error = %v", err)
	}
	_, observationDispatch := mustPermit(
		t,
		compensationFixture,
		fixture.op,
		observationAt,
		table,
		token,
		observationAttempt,
		5*time.Second,
	)
	observationAttempt, err = table.MarkAttemptDispatched(
		observationAttempt,
		observationDispatch,
		observationAt.Add(time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	observationAttempt, err = ResolveAttempt(
		observationAttempt,
		EffectStateApplied,
		observationAt.Add(2*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, completedFromObservation, decision, completionErr := CompleteObservation(
		reservedBudget,
		indeterminateProjection,
		observationAttempt,
	)
	if completionErr != nil || decision != ObservationResolved {
		t.Fatalf("completed compensation observation = %s, %v", decision, completionErr)
	}
	if completedFromObservation.purpose != AttemptPurposeCompensation ||
		completedFromObservation.compensation == nil ||
		completedFromObservation.state != AttemptStateApplied ||
		!completedFromObservation.compensation.inverse.Equal(undoSecond) {
		t.Fatalf("observed compensation projection = %#v", completedFromObservation)
	}
	observedSecondStep, err := NextCompensationStep(
		compensation,
		proofs,
		[]EffectProjection{completedFromObservation},
	)
	if err != nil || !observedSecondStep.Inverse().Equal(undoFirst) || observedSecondStep.Position() != 2 {
		t.Fatalf("second step after observation = %#v, %v", observedSecondStep, err)
	}
	unqualifiedFirst := mustEffect(t, fixture.plan, "undo-second")
	unqualifiedProjection, err := EffectProjectionFromAttempt(
		mustAttempt(t, fixture, unqualifiedFirst, AttemptStateApplied, 408),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NextCompensationStep(
		compensation,
		proofs,
		[]EffectProjection{unqualifiedProjection},
	); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("unqualified completed inverse error = %v", err)
	}
	secondStep, err := NextCompensationStep(compensation, proofs, []EffectProjection{completedFirst})
	if err != nil || !secondStep.Inverse().Equal(undoFirst) || secondStep.Position() != 2 {
		t.Fatalf("second compensation step = %#v, %v", secondStep, err)
	}
	if _, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       fixtureTime.Add(10 * time.Second),
		Plan:               compensation,
		Effect:             undoFirst,
		Purpose:            AttemptPurposeCompensation,
		RequestFingerprint: mustRequestFingerprint(t, "out-of-order-undo"),
		Compensation:       &firstStep,
	}); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("out-of-order compensation attempt error = %v", err)
	}
	if _, err := NextCompensationStep(
		compensation,
		proofs,
		[]EffectProjection{firstProjection},
	); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("wrong completed compensation prefix error = %v", err)
	}
	selected, disposition, _, err := SelectPlan(
		fixture.plan,
		compensation,
		priorAttempts,
		[]EffectProjection{firstProjection, secondProjection},
		true,
		proofs,
	)
	if err != nil || disposition != PlanSelectionSupersede || !selected.digest.Equal(compensation.digest) {
		t.Fatalf("forward-to-compensation selection = %s, %v", disposition, err)
	}
	missingCompleted := compensation
	missingCompleted.completedEffects = missingCompleted.completedEffects[1:]
	missingCompleted.digest = derivePlanDigest(missingCompleted)
	if err := ValidatePlan(missingCompleted); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("compensation missing completed original error = %v", err)
	}
	if err := ValidateCompensationPlan(compensation, []CompensationProof{proofFirst, proofSecond}); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("forward compensation order error = %v", err)
	}
	if _, err := NewCompensationProof(
		firstProjection,
		first,
		1,
		"fake-adapter-v1",
		[]byte("not-an-inverse"),
	); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("self-inverse compensation error = %v", err)
	}
	aliasSecond, err := NewCompensationProof(
		secondProjection,
		first,
		2,
		"fake-adapter-v1",
		[]byte("aliases-an-original"),
	)
	if err != nil {
		t.Fatal(err)
	}
	aliasFirst, err := NewCompensationProof(
		firstProjection,
		second,
		1,
		"fake-adapter-v1",
		[]byte("aliases-an-original"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCompensationPlan(
		compensation,
		[]CompensationProof{aliasSecond, aliasFirst},
	); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("cross-original inverse error = %v", err)
	}

	unknownProjection, err := EffectProjectionFromAttempt(mustAttempt(t, fixture, first, AttemptStateIndeterminate, 3))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCompensationProof(unknownProjection, undoFirst, 1, "fake-adapter-v1", []byte("unsafe")); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("indeterminate compensation error = %v", err)
	}
}

func TestPlanDigestChangesAcrossEveryApprovedEvidenceDimension(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 5, true)
	base := fixture.plan.digest
	cases := []struct {
		name   string
		mutate func(*PlanInput)
	}{
		{name: "planner", mutate: func(input *PlanInput) { input.PlannerVersion = "planner-v2" }},
		{name: "desired", mutate: func(input *PlanInput) {
			input.DesiredIntent = mustEvidence(t, EvidenceDesiredIntent, "resource-rv-2", []byte("changed"))
		}},
		{name: "observed", mutate: func(input *PlanInput) {
			input.ObservedSnapshot = mustEvidence(t, EvidenceObservedSnapshot, "observation-2", []byte("changed"))
		}},
		{name: "capability", mutate: func(input *PlanInput) {
			input.Capability = mustEvidence(t, EvidenceCapability, "capability-2", []byte("changed"))
		}},
		{name: "quota", mutate: func(input *PlanInput) { input.Quota = mustEvidence(t, EvidenceQuota, "quota-2", []byte("changed")) }},
		{name: "cost", mutate: func(input *PlanInput) { input.Cost = mustEvidence(t, EvidenceCost, "cost-2", []byte("changed")) }},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := PlanInput{
				ID: indexedID("pln", 20+index), Revision: 1, Kind: PlanKindForward,
				Operation: fixture.op, PlannerVersion: fixture.plan.plannerVersion,
				DesiredIntent: fixture.desired, ObservedSnapshot: fixture.observed,
				Actor: fixture.actor, Authorization: fixture.decision, ProviderBinding: fixture.provider,
				Capability: fixture.capability, Quota: fixture.quota, Cost: fixture.cost,
			}
			test.mutate(&input)
			plan, err := NewPlan(input)
			if err != nil {
				t.Fatal(err)
			}
			if plan.digest.Equal(base) {
				t.Fatal("changed evidence dimension retained the old digest")
			}
		})
	}
}

func TestPlanTimestampFreeIdentitySurvivesOperationStatusRevision(t *testing.T) {
	fixture := newPlanFixture(t, 1, 6, false)
	updated := fixture.op
	updated.ResourceVersion = "oprv_status_only"
	updated.UpdatedAt = fixtureTime.Add(2 * time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	copyPlan, err := NewPlan(PlanInput{
		ID: indexedID("pln", 7), Revision: 1, Kind: PlanKindForward, Operation: updated,
		PlannerVersion: fixture.plan.plannerVersion, DesiredIntent: fixture.desired,
		ObservedSnapshot: fixture.observed, Actor: fixture.actor, Authorization: fixture.decision,
		Capability: fixture.capability, Quota: fixture.quota, Cost: fixture.cost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !copyPlan.digest.Equal(fixture.plan.digest) {
		t.Fatal("Operation status-only resource version perturbed plan identity")
	}
}
