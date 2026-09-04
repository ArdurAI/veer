package audit

import (
	"fmt"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/administration"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	testWorkspaceID     resource.ID = "wsp_01JAUDIT00000000000000000"
	testResourceID      resource.ID = "cmp_01JAUDIT00000000000000000"
	testEnvironmentID   resource.ID = "env_01JAUDIT00000000000000000"
	testApplicationID   resource.ID = "app_01JAUDIT00000000000000000"
	testConnectionID    resource.ID = "pvc_01JAUDIT00000000000000000"
	testOperationID     resource.ID = "op_01JAUDIT000000000000000000"
	testAttemptID       resource.ID = "att_01JAUDIT00000000000000000"
	testRequestID       resource.ID = "req_01JAUDIT00000000000000000"
	testAdministratorID resource.ID = "adm_01JAUDIT00000000000000000"
	testGrantID         resource.ID = "grt_01JAUDIT00000000000000000"
	testProofID         resource.ID = "prf_01JAUDIT00000000000000000"
	testHoldID          resource.ID = "hld_01JAUDIT00000000000000000"

	testIssuerCanary  = "https://identity-canary.example.test/tenant"
	testSubjectCanary = "personal-subject-canary"
	testGroupCanary   = "personal-group-canary"
)

var testTime = time.Date(2026, time.September, 3, 12, 34, 56, 789_000_000, time.UTC)

type auditFixtureStatus struct{}

func (auditFixtureStatus) ObservedGenerations() []int64 { return nil }

func mustWorkspaceStream(t testing.TB) Stream {
	t.Helper()
	stream, err := NewWorkspaceStream(testWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func mustHierarchySnapshot(t testing.TB) hierarchy.Snapshot {
	t.Helper()
	resources := []struct {
		kind   hierarchy.Kind
		id     resource.ID
		parent *resource.ID
	}{
		{kind: hierarchy.KindWorkspace, id: testWorkspaceID},
		{kind: hierarchy.KindEnvironment, id: testEnvironmentID, parent: idPointer(testWorkspaceID)},
		{kind: hierarchy.KindApplication, id: testApplicationID, parent: idPointer(testEnvironmentID)},
		{kind: hierarchy.KindComponent, id: testResourceID, parent: idPointer(testApplicationID)},
		{kind: hierarchy.KindProviderConnection, id: testConnectionID, parent: idPointer(testEnvironmentID)},
	}
	records := make([]hierarchy.Record, 0, len(resources))
	for _, item := range resources {
		value, err := resource.New(resource.CreateInput[struct{}, auditFixtureStatus]{
			APIVersion:      hierarchy.APIVersion,
			Kind:            item.kind.String(),
			ID:              item.id.String(),
			WorkspaceID:     testWorkspaceID.String(),
			DisplayName:     "audit hierarchy fixture",
			Parent:          item.parent,
			Labels:          map[string]string{},
			ResourceVersion: "rv_audit_hierarchy_1",
			CreatedAt:       testTime,
			Spec:            struct{}{},
			Status:          auditFixtureStatus{},
		})
		if err != nil {
			t.Fatalf("resource.New(%s): %v", item.kind, err)
		}
		record, err := hierarchy.RecordFrom(value.APIVersion(), value.Kind(), value.Metadata())
		if err != nil {
			t.Fatalf("hierarchy.RecordFrom(%s): %v", item.kind, err)
		}
		records = append(records, record)
	}
	snapshot, err := hierarchy.NewSnapshot(testWorkspaceID, records)
	if err != nil {
		t.Fatalf("hierarchy.NewSnapshot(): %v", err)
	}
	return snapshot
}

func mustHumanPrincipal(t testing.TB) identity.Principal {
	t.Helper()
	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind:      identity.KindHuman,
		Issuer:    testIssuerCanary,
		Subject:   testSubjectCanary,
		Audiences: []string{"veer-api"},
		Groups:    []string{testGroupCanary},
	})
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func mustWorkloadPrincipal(t testing.TB) identity.Principal {
	t.Helper()
	workload, err := identity.NewWorkloadIdentity("spiffe://workload-canary.example.test/audit-worker")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind:             identity.KindWorkload,
		Issuer:           "https://workload-issuer.example.test",
		Subject:          "audit-worker",
		Audiences:        []string{"veer-api"},
		Groups:           []string{},
		WorkloadIdentity: &workload,
	})
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func mustRequestEvent(t testing.TB, sequence uint64) Event {
	t.Helper()
	actor, err := ActorFromPrincipal(mustHumanPrincipal(t))
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequestRef(testRequestID)
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewEvent(EventInput{
		ID:                   eventID(sequence),
		Stream:               mustWorkspaceStream(t),
		Sequence:             sequence,
		RecordedAt:           testTime.Add(time.Duration(sequence-1) * time.Millisecond),
		ClockState:           ClockStateSynchronized,
		Kind:                 EventKindRequest,
		Source:               SourceAPI,
		Actor:                actor,
		AuthenticationMethod: AuthenticationMethodOIDC,
		Action:               authorization.ActionResourceGet,
		Request:              &request,
		Outcome:              OutcomeAccepted,
	})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func mustProviderAttemptEvent(t testing.TB, sequence uint64) Event {
	t.Helper()
	environmentID := testEnvironmentID
	connectionID := testConnectionID
	value, err := operation.New(operation.Input{
		ID:                   testOperationID,
		WorkspaceID:          testWorkspaceID,
		ResourceID:           testResourceID,
		EnvironmentID:        &environmentID,
		ProviderConnectionID: &connectionID,
		Generation:           7,
		ResourceVersion:      "rv_audit_operation_1",
		Reason:               "ProviderExecution",
		Message:              "excluded-message-canary",
		CreatedAt:            testTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	operationRef, err := OperationRefFromOperation(value)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewAttemptRef(testAttemptID, 3)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ActorFromPrincipal(mustWorkloadPrincipal(t))
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewEvent(EventInput{
		ID:                   eventID(sequence),
		Stream:               mustWorkspaceStream(t),
		Sequence:             sequence,
		RecordedAt:           testTime.Add(time.Duration(sequence-1) * time.Millisecond),
		ClockState:           ClockStateSynchronized,
		Kind:                 EventKindProviderAttempt,
		Source:               SourceProviderAdapter,
		Actor:                actor,
		AuthenticationMethod: AuthenticationMethodWorkloadOIDC,
		Action:               authorization.ActionProviderApply,
		Operation:            &operationRef,
		Attempt:              &attempt,
		Outcome:              OutcomeIndeterminate,
	})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func mustOperationEvent(t testing.TB, sequence uint64) Event {
	t.Helper()
	providerAttempt := mustProviderAttemptEvent(t, sequence)
	operationReference, present := providerAttempt.Operation()
	if !present {
		t.Fatal("provider-attempt fixture omitted operation reference")
	}
	event, err := NewEvent(EventInput{
		ID:                   eventID(sequence),
		Stream:               mustWorkspaceStream(t),
		Sequence:             sequence,
		RecordedAt:           providerAttempt.RecordedAt(),
		ClockState:           providerAttempt.ClockState(),
		Kind:                 EventKindOperation,
		Source:               SourceController,
		Actor:                providerAttempt.Actor(),
		AuthenticationMethod: providerAttempt.AuthenticationMethod(),
		Action:               authorization.ActionOperationGet,
		Operation:            &operationReference,
		Outcome:              OutcomeSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func eventInputFromEvent(event Event) EventInput {
	return EventInput{
		ID:                   event.id,
		Stream:               event.stream,
		Sequence:             event.sequence,
		RecordedAt:           event.RecordedAt(),
		ClockState:           event.clockState,
		Kind:                 event.kind,
		Source:               event.source,
		Actor:                event.actor,
		AuthenticationMethod: event.authenticationMethod,
		Action:               event.action,
		Request:              cloneRequestRef(event.request),
		Target:               cloneTargetRef(event.target),
		Decision:             cloneDecisionRef(event.decision),
		Operation:            cloneOperationRef(event.operation),
		Attempt:              cloneAttemptRef(event.attempt),
		Elevation:            cloneElevationRef(event.elevation),
		Outcome:              event.outcome,
	}
}

func eventID(sequence uint64) resource.ID {
	return resource.ID(fmt.Sprintf("evt_01JAUDIT%016d", sequence))
}

func mustAdministrationGrant(t testing.TB, reason, caseReference string) (administration.Grant, administration.Ledger) {
	t.Helper()
	principal := mustHumanPrincipal(t)
	administrator, err := administration.NewAdministrator(testAdministratorID, principal)
	if err != nil {
		t.Fatal(err)
	}
	target := administration.ResolvePlatformAuditExportTarget()
	request, err := administration.NewElevationRequest(
		testGrantID,
		administrator,
		principal,
		authorization.ActionAuditExport,
		target,
		reason,
		caseReference,
		testTime,
		5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	strongAuth, err := administration.NewStrongAuthReceipt(
		testProofID,
		request,
		testTime,
		testTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := administration.NewLedger([]administration.Administrator{administrator})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ledger.Issue(testTime, strongAuth)
	if err != nil {
		t.Fatal(err)
	}
	return grant, ledger
}

func mustPlatformAuditElevationEvent(t testing.TB) Event {
	t.Helper()
	grant, _ := mustAdministrationGrant(t, "Emergency platform audit export", "CASE-PLATFORM-417")
	elevation, err := ElevationRefFromGrant(grant, ElevationStateIssued)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := AdministratorActor(elevation.AdministratorID())
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewEvent(EventInput{
		ID:                   eventID(1),
		Stream:               NewPlatformStream(),
		Sequence:             1,
		RecordedAt:           elevation.RecordedAt(),
		ClockState:           ClockStateSynchronized,
		Kind:                 EventKindElevation,
		Source:               SourceAdministration,
		Actor:                actor,
		AuthenticationMethod: AuthenticationMethodStrongOIDC,
		Action:               elevation.Action(),
		Elevation:            &elevation,
		Outcome:              OutcomeSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func mustOperationElevationEvent(t testing.TB) Event {
	t.Helper()
	operationEvent := mustProviderAttemptEvent(t, 1)
	operationReference, present := operationEvent.Operation()
	if !present {
		t.Fatal("operation fixture omitted reference")
	}
	environmentID := testEnvironmentID
	providerID := testConnectionID
	elevation := ElevationRef{
		initialized:          true,
		grantID:              testGrantID,
		administratorID:      testAdministratorID,
		action:               authorization.ActionOperationQuarantine,
		targetKind:           administration.TargetKindOperation.String(),
		workspaceID:          idPointer(testWorkspaceID),
		objectID:             idPointer(testOperationID),
		resourceID:           idPointer(testResourceID),
		environmentID:        &environmentID,
		providerConnectionID: &providerID,
		reason:               "Emergency operation quarantine",
		caseReference:        "CASE-OPERATION-417",
		issuedAt:             testTime.Format(timestampLayout),
		expiresAt:            testTime.Add(5 * time.Minute).Format(timestampLayout),
		state:                ElevationStateIssued,
		recordedAt:           testTime.Format(timestampLayout),
	}
	if err := validateElevationRef(elevation); err != nil {
		t.Fatal(err)
	}
	target := TargetRef{
		initialized:          true,
		objectKind:           authorization.ObjectKindOperation,
		objectID:             testOperationID,
		resourceKind:         "Component",
		resourceID:           testResourceID,
		workspaceID:          testWorkspaceID,
		environmentID:        idPointer(testEnvironmentID),
		providerConnectionID: idPointer(testConnectionID),
	}
	actor, err := AdministratorActor(testAdministratorID)
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewEvent(EventInput{
		ID:                   eventID(1),
		Stream:               mustWorkspaceStream(t),
		Sequence:             1,
		RecordedAt:           testTime,
		ClockState:           ClockStateSynchronized,
		Kind:                 EventKindElevation,
		Source:               SourceAdministration,
		Actor:                actor,
		AuthenticationMethod: AuthenticationMethodStrongOIDC,
		Action:               authorization.ActionOperationQuarantine,
		Target:               &target,
		Operation:            &operationReference,
		Elevation:            &elevation,
		Outcome:              OutcomeSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	return event
}
