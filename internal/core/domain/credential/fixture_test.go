package credential

import (
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	testWorkspaceID  resource.ID = "wsp_01J00000000000000000000000"
	testEnvironmentA resource.ID = "env_01J00000000000000000000000"
	testEnvironmentB resource.ID = "env_01J11111111111111111111111"
	testApplicationA resource.ID = "app_01J00000000000000000000000"
	testComponentA   resource.ID = "cmp_01J00000000000000000000000"
	testConnectionA  resource.ID = "pvc_01J00000000000000000000000"
	testConnectionB  resource.ID = "pvc_01J11111111111111111111111"
	testReferenceA   resource.ID = "sec_01J00000000000000000000000"
	testOperationA   resource.ID = "opn_01J00000000000000000000000"
)

var testNow = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

type fixtureSpec struct {
	Enabled bool `json:"enabled"`
}

type fixtureStatus struct {
	ObservedGeneration int64 `json:"observedGeneration"`
}

func (status fixtureStatus) ObservedGenerations() []int64 {
	return []int64{status.ObservedGeneration}
}

type credentialFixture struct {
	snapshot    hierarchy.Snapshot
	workspace   resource.Resource[fixtureSpec, fixtureStatus]
	environment resource.Resource[fixtureSpec, fixtureStatus]
	application resource.Resource[fixtureSpec, fixtureStatus]
	component   resource.Resource[fixtureSpec, fixtureStatus]
	connection  resource.Resource[control.ProviderConnectionSpec, control.ProviderConnectionStatus]
	target      ResourceView
	operation   operation.Operation
	recipient   Recipient
	request     Request
}

func newCredentialFixture(t testing.TB) credentialFixture {
	t.Helper()
	workspace := mustFixtureResource(
		t,
		hierarchy.KindWorkspace,
		testWorkspaceID,
		nil,
		fixtureSpec{Enabled: true},
		fixtureStatus{},
	)
	environment := mustFixtureResource(
		t,
		hierarchy.KindEnvironment,
		testEnvironmentA,
		idPointer(testWorkspaceID),
		fixtureSpec{Enabled: true},
		fixtureStatus{},
	)
	application := mustFixtureResource(
		t,
		hierarchy.KindApplication,
		testApplicationA,
		idPointer(testEnvironmentA),
		fixtureSpec{Enabled: true},
		fixtureStatus{},
	)
	component := mustFixtureResource(
		t,
		hierarchy.KindComponent,
		testComponentA,
		idPointer(testApplicationA),
		fixtureSpec{Enabled: true},
		fixtureStatus{},
	)
	connection := mustFixtureResource(
		t,
		hierarchy.KindProviderConnection,
		testConnectionA,
		idPointer(testEnvironmentA),
		control.ProviderConnectionSpec{
			Provider: "aws",
			CredentialRef: control.CredentialReference{
				ReferenceID: testReferenceA.String(),
				Version:     "version_1",
			},
		},
		control.ProviderConnectionStatus{
			Conditions:   []condition.Condition{},
			Capabilities: []control.ProviderCapability{},
			QuotaChecks:  []control.QuotaCheck{},
		},
	)
	records := []hierarchy.Record{
		mustFixtureRecord(t, workspace),
		mustFixtureRecord(t, environment),
		mustFixtureRecord(t, application),
		mustFixtureRecord(t, component),
		mustFixtureRecord(t, connection),
	}
	snapshot, err := hierarchy.NewSnapshot(testWorkspaceID, records)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	target, err := NewResourceView(component)
	if err != nil {
		t.Fatalf("NewResourceView() error = %v", err)
	}
	op := mustRunningOperation(t, testComponentA, component.Metadata().Generation().Int64())
	recipient, err := NewRecipient("aws", "provider-adapter")
	if err != nil {
		t.Fatalf("NewRecipient() error = %v", err)
	}
	request, err := NewRequest(
		snapshot,
		connection,
		target,
		op,
		authorization.ActionProviderApply,
		recipient,
	)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	return credentialFixture{
		snapshot:    snapshot,
		workspace:   workspace,
		environment: environment,
		application: application,
		component:   component,
		connection:  connection,
		target:      target,
		operation:   op,
		recipient:   recipient,
		request:     request,
	}
}

func mustFixtureResource[Spec any, Status resource.GenerationObservations](
	t testing.TB,
	kind hierarchy.Kind,
	id resource.ID,
	parent *resource.ID,
	spec Spec,
	status Status,
) resource.Resource[Spec, Status] {
	t.Helper()
	value, err := resource.New(resource.CreateInput[Spec, Status]{
		APIVersion:      hierarchy.APIVersion,
		Kind:            kind.String(),
		ID:              id.String(),
		WorkspaceID:     testWorkspaceID.String(),
		DisplayName:     "fixture",
		Parent:          parent,
		ResourceVersion: "resource_1",
		CreatedAt:       testNow,
		Spec:            spec,
		Status:          status,
	})
	if err != nil {
		t.Fatalf("resource.New(%s) error = %v", kind, err)
	}
	return value
}

func mustFixtureRecord[Spec any, Status resource.GenerationObservations](
	t testing.TB,
	value resource.Resource[Spec, Status],
) hierarchy.Record {
	t.Helper()
	record, err := hierarchy.RecordFrom(value.APIVersion(), value.Kind(), value.Metadata())
	if err != nil {
		t.Fatalf("RecordFrom(%s) error = %v", value.Kind(), err)
	}
	return record
}

func mustRunningOperation(t testing.TB, targetID resource.ID, generation int64) operation.Operation {
	t.Helper()
	environmentID := testEnvironmentA
	connectionID := testConnectionA
	op, err := operation.New(operation.Input{
		ID:                   testOperationA,
		WorkspaceID:          testWorkspaceID,
		ResourceID:           targetID,
		EnvironmentID:        &environmentID,
		ProviderConnectionID: &connectionID,
		Generation:           generation,
		ResourceVersion:      "operation_1",
		CreatedAt:            testNow,
	})
	if err != nil {
		t.Fatalf("operation.New() error = %v", err)
	}
	op, err = operation.Transition(op, operation.TransitionInput{
		Phase:           operation.PhaseRunning,
		ResourceVersion: "operation_2",
		UpdatedAt:       testNow.Add(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("operation.Transition() error = %v", err)
	}
	return op
}

func idPointer(id resource.ID) *resource.ID {
	copy := id
	return &copy
}

func credentialBytes(length int) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = byte(33 + index%89)
	}
	return value
}
