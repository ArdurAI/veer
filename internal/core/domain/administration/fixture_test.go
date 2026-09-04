package administration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authentication"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	testWorkspaceID          resource.ID = "wrk_01JADMIN00000000000000001"
	testEnvironmentID        resource.ID = "env_01JADMIN00000000000000001"
	testApplicationID        resource.ID = "app_01JADMIN00000000000000001"
	testComponentID          resource.ID = "cmp_01JADMIN00000000000000001"
	testConnectionID         resource.ID = "con_01JADMIN00000000000000001"
	testOperationID          resource.ID = "op_01JADMIN000000000000000001"
	testAdministratorID      resource.ID = "adm_01JADMIN00000000000000001"
	testOtherAdministratorID resource.ID = "adm_01JADMIN00000000000000002"
	testGrantID              resource.ID = "elv_01JADMIN00000000000000001"
	testProofID              resource.ID = "prf_01JADMIN00000000000000001"
	testIssuer                           = "https://identity-canary.example/tenant"
	testSubject                          = "subject-canary-sensitive"
	testReason                           = "Restore delivery after verified queue isolation"
	testCaseReference                    = "INC-canary-1042"
	testBearerToken                      = "strong-authentication-canary.signature"
)

var testNow = time.Date(2026, time.September, 3, 12, 0, 0, 123_000_000, time.UTC)

type testSpec struct {
	Value string `json:"value"`
}

type testStatus struct{}

func (testStatus) ObservedGenerations() []int64 { return nil }

type hierarchyFixture struct {
	snapshot           hierarchy.Snapshot
	workspace          resource.ID
	environment        resource.ID
	application        resource.ID
	component          resource.ID
	connection         resource.ID
	operation          operation.Operation
	workspaceOperation operation.Operation
}

type testStrongAuthenticationVerifier struct {
	mu              sync.Mutex
	proofID         resource.ID
	authenticatedAt time.Time
	err             error
	calls           int
	credential      authentication.BearerCredential
	request         ElevationRequest
}

func (verifier *testStrongAuthenticationVerifier) VerifyStrongAuthentication(
	ctx context.Context,
	credential authentication.BearerCredential,
	request ElevationRequest,
) (resource.ID, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return "", time.Time{}, err
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.calls++
	verifier.credential = credential
	verifier.request = cloneElevationRequest(request)
	return verifier.proofID, verifier.authenticatedAt, verifier.err
}

func (verifier *testStrongAuthenticationVerifier) configure(
	proofID resource.ID,
	authenticatedAt time.Time,
	err error,
) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.proofID = proofID
	verifier.authenticatedAt = authenticatedAt
	verifier.err = err
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) set(now time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = now
}

func newHierarchyFixture(t testing.TB) hierarchyFixture {
	t.Helper()
	workspacePlacement, err := hierarchy.DeriveWorkspace(testWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	workspaceRecord := recordFromPlacement(t, workspacePlacement, "workspace")
	snapshot, err := hierarchy.NewSnapshot(testWorkspaceID, []hierarchy.Record{workspaceRecord})
	if err != nil {
		t.Fatal(err)
	}
	environmentPlacement, err := snapshot.DeriveChild(
		hierarchy.KindEnvironment,
		testEnvironmentID,
		testWorkspaceID,
	)
	if err != nil {
		t.Fatal(err)
	}
	environmentRecord := recordFromPlacement(t, environmentPlacement, "environment")
	snapshot, err = hierarchy.NewSnapshot(
		testWorkspaceID,
		[]hierarchy.Record{workspaceRecord, environmentRecord},
	)
	if err != nil {
		t.Fatal(err)
	}
	applicationPlacement, err := snapshot.DeriveChild(
		hierarchy.KindApplication,
		testApplicationID,
		testEnvironmentID,
	)
	if err != nil {
		t.Fatal(err)
	}
	applicationRecord := recordFromPlacement(t, applicationPlacement, "application")
	snapshot, err = hierarchy.NewSnapshot(
		testWorkspaceID,
		[]hierarchy.Record{workspaceRecord, environmentRecord, applicationRecord},
	)
	if err != nil {
		t.Fatal(err)
	}
	componentPlacement, err := snapshot.DeriveChild(
		hierarchy.KindComponent,
		testComponentID,
		testApplicationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	componentRecord := recordFromPlacement(t, componentPlacement, "component")
	snapshot, err = hierarchy.NewSnapshot(
		testWorkspaceID,
		[]hierarchy.Record{workspaceRecord, environmentRecord, applicationRecord, componentRecord},
	)
	if err != nil {
		t.Fatal(err)
	}
	connectionPlacement, err := snapshot.DeriveChild(
		hierarchy.KindProviderConnection,
		testConnectionID,
		testEnvironmentID,
	)
	if err != nil {
		t.Fatal(err)
	}
	connectionRecord := recordFromPlacement(t, connectionPlacement, "connection")
	snapshot, err = hierarchy.NewSnapshot(
		testWorkspaceID,
		[]hierarchy.Record{
			workspaceRecord,
			environmentRecord,
			applicationRecord,
			componentRecord,
			connectionRecord,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	environmentID := testEnvironmentID
	connectionID := testConnectionID
	op, err := operation.New(operation.Input{
		ID:                   testOperationID,
		WorkspaceID:          testWorkspaceID,
		ResourceID:           testEnvironmentID,
		EnvironmentID:        &environmentID,
		ProviderConnectionID: &connectionID,
		Generation:           1,
		ResourceVersion:      "rv_admin_1",
		CreatedAt:            testNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	workspaceOperation, err := operation.New(operation.Input{
		ID:              "op_01JADMIN000000000000000002",
		WorkspaceID:     testWorkspaceID,
		ResourceID:      testWorkspaceID,
		Generation:      1,
		ResourceVersion: "rv_admin_2",
		CreatedAt:       testNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return hierarchyFixture{
		snapshot:           snapshot,
		workspace:          testWorkspaceID,
		environment:        testEnvironmentID,
		application:        testApplicationID,
		component:          testComponentID,
		connection:         testConnectionID,
		operation:          op,
		workspaceOperation: workspaceOperation,
	}
}

func recordFromPlacement(t testing.TB, placement hierarchy.Placement, name string) hierarchy.Record {
	t.Helper()
	value, err := hierarchy.NewResource[testSpec, testStatus](placement, hierarchy.CreateInput[testSpec, testStatus]{
		DisplayName:     name,
		ResourceVersion: "rv_" + name,
		CreatedAt:       testNow,
		Spec:            testSpec{Value: name},
		Status:          testStatus{},
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := hierarchy.RecordFrom(value.APIVersion(), value.Kind(), value.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func mustPrincipal(t testing.TB, issuer, subject string) identity.Principal {
	t.Helper()
	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind:      identity.KindHuman,
		Issuer:    issuer,
		Subject:   subject,
		Audiences: []string{"veer-api"},
		Groups:    []string{"platform-operators"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func mustAdministrator(t testing.TB, id resource.ID, principal identity.Principal) Administrator {
	t.Helper()
	administrator, err := NewAdministrator(id, principal)
	if err != nil {
		t.Fatal(err)
	}
	return administrator
}

func mustLedger(t testing.TB, administrators ...Administrator) Ledger {
	t.Helper()
	verifier := &testStrongAuthenticationVerifier{
		proofID:         testProofID,
		authenticatedAt: testNow,
	}
	clock := &testClock{now: testNow}
	ledger, err := NewLedger(administrators, verifier, clock)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func mustRequest(
	t testing.TB,
	grantID resource.ID,
	administrator Administrator,
	principal identity.Principal,
	action authorization.Action,
	target Target,
	duration time.Duration,
) ElevationRequest {
	t.Helper()
	request, err := NewElevationRequest(
		grantID,
		administrator,
		principal,
		action,
		target,
		testReason,
		testCaseReference,
		testNow,
		duration,
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func mustIssue(
	t testing.TB,
	ledger Ledger,
	proofID resource.ID,
	request ElevationRequest,
	authenticatedAt, issuedAt time.Time,
) (Grant, error) {
	t.Helper()
	verifier, ok := ledger.state.verifier.(*testStrongAuthenticationVerifier)
	if !ok {
		t.Fatal("mustIssue requires the test strong-authentication verifier")
	}
	clock, ok := ledger.state.clock.(*testClock)
	if !ok {
		t.Fatal("mustIssue requires the test clock")
	}
	verifier.configure(proofID, authenticatedAt, nil)
	clock.set(issuedAt)
	credential, err := authentication.NewBearerCredential(testBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	return ledger.Issue(context.Background(), credential, request)
}

func generatedID(prefix string, index int) resource.ID {
	return resource.ID(fmt.Sprintf("%s_%024d", prefix, index))
}
