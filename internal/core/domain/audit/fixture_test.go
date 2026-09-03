package audit

import (
	"fmt"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/administration"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	testWorkspaceID     resource.ID = "wsp_01JAUDIT00000000000000000"
	testResourceID      resource.ID = "cmp_01JAUDIT00000000000000000"
	testEnvironmentID   resource.ID = "env_01JAUDIT00000000000000000"
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

func mustWorkspaceStream(t testing.TB) Stream {
	t.Helper()
	stream, err := NewWorkspaceStream(testWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	return stream
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
		Stream:               NewPlatformStream(),
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
