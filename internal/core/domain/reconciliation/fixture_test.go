package reconciliation

import (
	"fmt"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const allowedDecisionJSON = `{"contractVersion":"veer.authorization.v1alpha1","policyVersion":"azv1_bWmTGhAhKgCLxKUvUAnDTpvuq0qXu3-GpU3-lAQtKQk","inputDigest":"azi1_uCRuS5pfpHN3eE_EboEGGjWQj0pBp5NL0kkRHfpWuHY","effect":"Allow","reason":"RoleGranted"}`

var fixtureTime = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

type planFixture struct {
	op         operation.Operation
	plan       Plan
	actor      identity.Principal
	decision   authorization.Decision
	desired    Evidence
	observed   Evidence
	provider   *ProviderBinding
	capability Evidence
	quota      Evidence
	cost       Evidence
}

func newPlanFixture(t testing.TB, generation int64, index int, bound bool) planFixture {
	t.Helper()
	workspaceID := indexedID("wsp", index)
	resourceID := indexedID("cmp", index)
	operationID := indexedID("opx", index)
	planID := indexedID("pln", index)
	var environmentID, connectionID *resource.ID
	if bound {
		environment := indexedID("env", index)
		connection := indexedID("prv", index)
		environmentID = &environment
		connectionID = &connection
	}
	op, err := operation.New(operation.Input{
		ID:                   operationID,
		WorkspaceID:          workspaceID,
		ResourceID:           resourceID,
		EnvironmentID:        environmentID,
		ProviderConnectionID: connectionID,
		Generation:           generation,
		ResourceVersion:      "oprv_initial",
		CreatedAt:            fixtureTime,
	})
	if err != nil {
		t.Fatalf("operation.New(): %v", err)
	}
	op, err = operation.Transition(op, operation.TransitionInput{
		Phase:           operation.PhaseRunning,
		ResourceVersion: "oprv_running",
		UpdatedAt:       fixtureTime.Add(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("operation.Transition(): %v", err)
	}
	actor, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind:      identity.KindHuman,
		Issuer:    "https://issuer.example",
		Subject:   fmt.Sprintf("subject-%d", index),
		Audiences: []string{"veer-api"},
		Groups:    []string{},
	})
	if err != nil {
		t.Fatalf("identity.NewPrincipal(): %v", err)
	}
	decision, err := authorization.UnmarshalCanonical([]byte(allowedDecisionJSON))
	if err != nil {
		t.Fatalf("authorization.UnmarshalCanonical(): %v", err)
	}
	desired := mustEvidence(t, EvidenceDesiredIntent, fmt.Sprintf("resource-rv-%d", generation), []byte(`{"desired":true}`))
	observed := mustEvidence(t, EvidenceObservedSnapshot, "observation-1", []byte(`{"observed":false}`))
	capability := mustEvidence(t, EvidenceCapability, "capability-1", []byte(`{"supported":true}`))
	quota := mustEvidence(t, EvidenceQuota, "quota-1", []byte(`{"admitted":true}`))
	cost := mustEvidence(t, EvidenceCost, "cost-1", []byte(`{"withinBudget":true}`))
	var provider *ProviderBinding
	if bound {
		connectionEvidence := mustEvidence(t, EvidenceProviderConnection, "connection-rv-1", []byte(`{"provider":"fake"}`))
		credentialEvidence := mustEvidence(t, EvidenceCredentialReference, "credential-rv-1", []byte(`{"version":"1"}`))
		value, err := NewProviderBinding(ProviderBindingInput{
			ConnectionID:              *connectionID,
			ConnectionGeneration:      1,
			ConnectionResourceVersion: "connection-rv-1",
			ConnectionEvidence:        connectionEvidence,
			CredentialReferenceID:     indexedID("crf", index),
			CredentialGeneration:      1,
			CredentialResourceVersion: "credential-rv-1",
			CredentialEvidence:        credentialEvidence,
		})
		if err != nil {
			t.Fatalf("NewProviderBinding(): %v", err)
		}
		provider = &value
	}
	plan, err := NewPlan(PlanInput{
		ID:               planID,
		Revision:         1,
		Kind:             PlanKindForward,
		Operation:        op,
		PlannerVersion:   "planner-v1",
		DesiredIntent:    desired,
		ObservedSnapshot: observed,
		Actor:            actor,
		Authorization:    decision,
		ProviderBinding:  provider,
		Capability:       capability,
		Quota:            quota,
		Cost:             cost,
	})
	if err != nil {
		t.Fatalf("NewPlan(): %v", err)
	}
	return planFixture{
		op: op, plan: plan, actor: actor, decision: decision, desired: desired,
		observed: observed, provider: provider, capability: capability, quota: quota, cost: cost,
	}
}

func (fixture planFixture) candidate(
	t testing.TB,
	revision uint32,
	kind PlanKind,
	observed Evidence,
	completed []EffectKey,
	compensates []EffectKey,
) Plan {
	t.Helper()
	plan, err := NewPlan(PlanInput{
		ID:               indexedID("pln", 1000+int(revision)),
		Revision:         revision,
		Kind:             kind,
		Operation:        fixture.op,
		PlannerVersion:   fixture.plan.plannerVersion,
		DesiredIntent:    fixture.desired,
		ObservedSnapshot: observed,
		Actor:            fixture.actor,
		Authorization:    fixture.decision,
		ProviderBinding:  fixture.provider,
		Capability:       fixture.capability,
		Quota:            fixture.quota,
		Cost:             fixture.cost,
		Supersedes:       digestPointer(fixture.plan.digest),
		CompletedEffects: completed,
		Compensates:      compensates,
	})
	if err != nil {
		t.Fatalf("NewPlan(candidate): %v", err)
	}
	return plan
}

func nextGenerationFixture(t testing.TB, previous planFixture, generation int64, index int) planFixture {
	t.Helper()
	op, err := operation.New(operation.Input{
		ID:                   indexedID("opx", index),
		WorkspaceID:          previous.op.WorkspaceID,
		ResourceID:           previous.op.ResourceID,
		EnvironmentID:        previous.op.EnvironmentID,
		ProviderConnectionID: previous.op.ProviderConnectionID,
		Generation:           generation,
		ResourceVersion:      "oprv_next_initial",
		CreatedAt:            fixtureTime.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("operation.New(next): %v", err)
	}
	op, err = operation.Transition(op, operation.TransitionInput{
		Phase: operation.PhaseRunning, ResourceVersion: "oprv_next_running",
		UpdatedAt: fixtureTime.Add(time.Second + time.Millisecond),
	})
	if err != nil {
		t.Fatalf("operation.Transition(next): %v", err)
	}
	desired := mustEvidence(t, EvidenceDesiredIntent, fmt.Sprintf("resource-rv-%d", generation), []byte(`{"next":true}`))
	observed := mustEvidence(t, EvidenceObservedSnapshot, "observation-next", []byte(`{"oldGenerationSettled":false}`))
	plan, err := NewPlan(PlanInput{
		ID: indexedID("pln", index), Revision: 1, Kind: PlanKindForward, Operation: op,
		PlannerVersion: previous.plan.plannerVersion, DesiredIntent: desired, ObservedSnapshot: observed,
		Actor: previous.actor, Authorization: previous.decision, ProviderBinding: previous.provider,
		Capability: previous.capability, Quota: previous.quota, Cost: previous.cost,
	})
	if err != nil {
		t.Fatalf("NewPlan(next): %v", err)
	}
	return planFixture{
		op: op, plan: plan, actor: previous.actor, decision: previous.decision, desired: desired,
		observed: observed, provider: previous.provider, capability: previous.capability,
		quota: previous.quota, cost: previous.cost,
	}
}

func mustEvidence(t testing.TB, kind EvidenceKind, version string, canonical []byte) Evidence {
	t.Helper()
	value, err := NewEvidence(kind, version, canonical)
	if err != nil {
		t.Fatalf("NewEvidence(%s): %v", kind, err)
	}
	return value
}

func mustRequestFingerprint(t testing.TB, value string) RequestFingerprint {
	t.Helper()
	fingerprint, err := NewRequestFingerprint([]byte(value))
	if err != nil {
		t.Fatalf("NewRequestFingerprint(): %v", err)
	}
	return fingerprint
}

func mustResultDigest(t testing.TB, value string) ResultDigest {
	t.Helper()
	digest, err := NewResultDigest([]byte(value))
	if err != nil {
		t.Fatalf("NewResultDigest(): %v", err)
	}
	return digest
}

func mustEffect(t testing.TB, plan Plan, semantic string) EffectKey {
	t.Helper()
	effect, err := NewEffectKey(plan, []byte(semantic))
	if err != nil {
		t.Fatalf("NewEffectKey(): %v", err)
	}
	return effect
}

func mustLease(
	t testing.TB,
	fixture planFixture,
	now time.Time,
) (*LeaseTable, LeaseToken) {
	t.Helper()
	table, err := NewLeaseTable(4)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := LeaseBindingFromPlan(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	token, err := table.Acquire(now, binding, indexedID("wrk", 1))
	if err != nil {
		t.Fatal(err)
	}
	return table, token
}

func generationReplacementInput(
	t testing.TB,
	plan Plan,
	index int,
) AttemptAdmissionInput {
	t.Helper()
	effect, err := NewEffectKey(plan, []byte(fmt.Sprintf("generation-replacement-%d", index)))
	if err != nil {
		t.Fatal(err)
	}
	return AttemptAdmissionInput{
		DatabaseTime:       fixtureTime,
		Plan:               plan,
		Effect:             effect,
		Purpose:            AttemptPurposeForward,
		RequestFingerprint: mustRequestFingerprint(t, fmt.Sprintf("generation-replacement-%d", index)),
	}
}

func mustPreparedAttempt(
	t testing.TB,
	fixture planFixture,
	effect EffectKey,
	purpose AttemptPurpose,
	index int,
	token LeaseToken,
	preparedAt time.Time,
) Attempt {
	t.Helper()
	fingerprint := mustRequestFingerprint(t, fmt.Sprintf("request-%d", index))
	admissionInput := AttemptAdmissionInput{
		DatabaseTime:       preparedAt,
		Plan:               fixture.plan,
		Effect:             effect,
		Purpose:            purpose,
		RequestFingerprint: fingerprint,
	}
	if purpose == AttemptPurposeObservation || purpose == AttemptPurposeProviderCancel {
		current := EffectProjection{
			initialized:     true,
			key:             effect,
			planDigest:      fixture.plan.digest,
			sourceAttemptID: indexedID("att", 900_000+index),
			purpose:         AttemptPurposeForward,
			state:           AttemptStateIndeterminate,
			updatedAt:       preparedAt.Add(-time.Millisecond),
		}
		admissionInput.CurrentEffect = &current
		if purpose == AttemptPurposeProviderCancel {
			admissionInput.CancellationRequested = true
			cancelEffect, err := NewEffectKey(
				fixture.plan,
				[]byte(fmt.Sprintf("provider-cancel-%d", index)),
			)
			if err != nil {
				t.Fatal(err)
			}
			admissionInput.Effect = cancelEffect
			admissionInput.CurrentEffect = nil
			admissionInput.CancellationTarget = &current
		}
	}
	if purpose == AttemptPurposeObservation {
		budget, err := NewObservationBudget(effect, 2, preparedAt.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		_, permit, err := ReserveObservation(budget, preparedAt)
		if err != nil {
			t.Fatal(err)
		}
		admissionInput.Observation = &permit
	}
	admission, err := NewAttemptAdmission(admissionInput)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewPreparedAttempt(AttemptInput{
		ID:        indexedID("att", index),
		Ordinal:   uint32(index),
		Admission: admission,
		OwnerID:   token.ownerID,
		Fence:     token.fence,
	})
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}

func mustPermit(
	t testing.TB,
	fixture planFixture,
	current operation.Operation,
	now time.Time,
	table *LeaseTable,
	token LeaseToken,
	attempt Attempt,
	rpcTimeout time.Duration,
) (DispatchAuthority, DispatchPermit) {
	t.Helper()
	authority, err := NewDispatchAuthority(
		now,
		fixture.plan,
		attempt,
		current,
		fixture.decision,
		fixture.provider,
		fixture.capability,
		fixture.quota,
		fixture.cost,
	)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := table.AuthorizeDispatch(now, token, rpcTimeout, authority)
	if err != nil {
		t.Fatal(err)
	}
	return authority, permit
}

func mustAttempt(
	t testing.TB,
	fixture planFixture,
	effect EffectKey,
	state AttemptState,
	index int,
) Attempt {
	t.Helper()
	if fixture.plan.kind != PlanKindForward {
		t.Fatal("mustAttempt requires a forward plan; construct compensation attempts with an exact CompensationStep")
	}
	table, token := mustLease(t, fixture, fixtureTime.Add(time.Second))
	attempt := mustPreparedAttempt(t, fixture, effect, AttemptPurposeForward, index, token, fixtureTime.Add(time.Second))
	if state == AttemptStatePrepared {
		return attempt
	}
	_, permit := mustPermit(
		t,
		fixture,
		fixture.op,
		fixtureTime.Add(time.Second),
		table,
		token,
		attempt,
		5*time.Second,
	)
	var err error
	attempt, err = table.MarkAttemptDispatched(attempt, permit, fixtureTime.Add(time.Second+time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if state == AttemptStateDispatched {
		return attempt
	}
	attempt, err = ResolveAttempt(attempt, EffectState(state), fixtureTime.Add(time.Second+2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}

func mustResolvedObservationAttempt(
	t testing.TB,
	fixture planFixture,
	current EffectProjection,
	maximum uint32,
	reservedAt time.Time,
	deadline time.Time,
	outcome EffectState,
	dispatched bool,
	index int,
) (ObservationBudget, Attempt) {
	t.Helper()
	budget, err := NewObservationBudget(current.key, maximum, deadline)
	if err != nil {
		t.Fatal(err)
	}
	reserved, observation, err := ReserveObservation(budget, reservedAt)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime:       reservedAt,
		Plan:               fixture.plan,
		Effect:             current.key,
		Purpose:            AttemptPurposeObservation,
		RequestFingerprint: mustRequestFingerprint(t, fmt.Sprintf("observation-%d", index)),
		CurrentEffect:      &current,
		Observation:        &observation,
	})
	if err != nil {
		t.Fatal(err)
	}
	table, token := mustLease(t, fixture, reservedAt)
	attempt, err := NewPreparedAttempt(AttemptInput{
		ID:        indexedID("att", index),
		Ordinal:   uint32(index),
		Admission: admission,
		OwnerID:   token.ownerID,
		Fence:     token.fence,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !dispatched {
		attempt, err = RecoverAttempt(attempt, DispatchProofNeverBegan, reservedAt.Add(time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		return reserved, attempt
	}
	_, permit := mustPermit(t, fixture, fixture.op, reservedAt, table, token, attempt, 5*time.Second)
	attempt, err = table.MarkAttemptDispatched(attempt, permit, reservedAt)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err = ResolveAttempt(attempt, outcome, reservedAt.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	return reserved, attempt
}

func indexedID(prefix string, index int) resource.ID {
	return resource.ID(fmt.Sprintf("%s_%024d", prefix, index))
}

func digestPointer(value PlanDigest) *PlanDigest { return &value }
