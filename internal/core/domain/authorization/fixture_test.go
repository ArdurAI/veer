package authorization

import (
	"sort"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	testIssuer = "https://issuer.example"

	testWorkspaceAID = resource.ID("wsp_01J00000000000000000000000")
	testWorkspaceBID = resource.ID("wsp_01J11111111111111111111111")
	testPolicyAID    = resource.ID("pol_01J00000000000000000000000")
	testPolicyBID    = resource.ID("pol_01J11111111111111111111111")
	testPolicySecond = resource.ID("pol_01J22222222222222222222222")
	testEnvironmentA = resource.ID("env_01J00000000000000000000000")
	testEnvironmentB = resource.ID("env_01J11111111111111111111111")
	testApplicationA = resource.ID("app_01J00000000000000000000000")
	testApplicationB = resource.ID("app_01J11111111111111111111111")
	testComponentA   = resource.ID("cmp_01J00000000000000000000000")
	testProviderA    = resource.ID("prv_01J00000000000000000000000")
	testOperationA   = resource.ID("opx_01J00000000000000000000000")
	testPlanA        = resource.ID("pln_01J00000000000000000000000")
	testAuditA       = resource.ID("aud_01J00000000000000000000000")

	testViewerID    = resource.ID("mem_01J00000000000000000000001")
	testDeveloperID = resource.ID("mem_01J00000000000000000000002")
	testOperatorID  = resource.ID("mem_01J00000000000000000000003")
	testAdminID     = resource.ID("mem_01J00000000000000000000004")
	testUnboundID   = resource.ID("mem_01J00000000000000000000005")
)

type fixtureStatus struct{}

func (fixtureStatus) ObservedGenerations() []int64 { return nil }

type hierarchyFixture struct {
	snapshot hierarchy.Snapshot
	records  map[resource.ID]hierarchy.Record
}

func newHierarchyFixture(t testing.TB, workspaceID resource.ID) hierarchyFixture {
	t.Helper()
	ids := []struct {
		kind   hierarchy.Kind
		id     resource.ID
		parent *resource.ID
	}{
		{kind: hierarchy.KindWorkspace, id: workspaceID},
		{kind: hierarchy.KindPolicy, id: chooseID(workspaceID, testPolicyAID, testPolicyBID), parent: idPointer(workspaceID)},
		{kind: hierarchy.KindPolicy, id: testPolicySecond, parent: idPointer(workspaceID)},
		{kind: hierarchy.KindEnvironment, id: testEnvironmentA, parent: idPointer(workspaceID)},
		{kind: hierarchy.KindEnvironment, id: testEnvironmentB, parent: idPointer(workspaceID)},
		{kind: hierarchy.KindApplication, id: testApplicationA, parent: idPointer(testEnvironmentA)},
		{kind: hierarchy.KindApplication, id: testApplicationB, parent: idPointer(testEnvironmentB)},
		{kind: hierarchy.KindComponent, id: testComponentA, parent: idPointer(testApplicationA)},
		{kind: hierarchy.KindProviderConnection, id: testProviderA, parent: idPointer(testEnvironmentA)},
	}
	records := make(map[resource.ID]hierarchy.Record, len(ids))
	ordered := make([]hierarchy.Record, 0, len(ids))
	for _, item := range ids {
		value, err := resource.New(resource.CreateInput[struct{}, fixtureStatus]{
			APIVersion:      hierarchy.APIVersion,
			Kind:            item.kind.String(),
			ID:              item.id.String(),
			WorkspaceID:     workspaceID.String(),
			DisplayName:     "fixture",
			Parent:          cloneIDPointer(item.parent),
			Labels:          map[string]string{},
			ResourceVersion: "rv_01J00000000000000000000000",
			CreatedAt:       time.Date(2026, 9, 3, 1, 2, 3, 0, time.UTC),
			Spec:            struct{}{},
			Status:          fixtureStatus{},
		})
		if err != nil {
			t.Fatalf("resource.New(%s): %v", item.kind, err)
		}
		record, err := hierarchy.RecordFrom(value.APIVersion(), value.Kind(), value.Metadata())
		if err != nil {
			t.Fatalf("hierarchy.RecordFrom(%s): %v", item.kind, err)
		}
		records[item.id] = record
		ordered = append(ordered, record)
	}
	snapshot, err := hierarchy.NewSnapshot(workspaceID, ordered)
	if err != nil {
		t.Fatalf("hierarchy.NewSnapshot(): %v", err)
	}
	return hierarchyFixture{snapshot: snapshot, records: records}
}

func chooseID(workspaceID, workspaceAValue, workspaceBValue resource.ID) resource.ID {
	if workspaceID == testWorkspaceAID {
		return workspaceAValue
	}
	return workspaceBValue
}

func mustLogical(t testing.TB, subject string) identity.LogicalIdentity {
	t.Helper()
	logical, err := identity.NewLogicalIdentity(testIssuer, subject)
	if err != nil {
		t.Fatalf("identity.NewLogicalIdentity(): %v", err)
	}
	return logical
}

func mustPrincipal(t testing.TB, kind identity.Kind, subject string) identity.Principal {
	t.Helper()
	input := identity.PrincipalInput{
		Kind:      kind,
		Issuer:    testIssuer,
		Subject:   subject,
		Audiences: []string{"veer-api"},
		Groups:    []string{},
	}
	if kind == identity.KindWorkload {
		workload, err := identity.NewWorkloadIdentity("workload:" + subject)
		if err != nil {
			t.Fatalf("identity.NewWorkloadIdentity(): %v", err)
		}
		input.WorkloadIdentity = &workload
	}
	principal, err := identity.NewPrincipal(input)
	if err != nil {
		t.Fatalf("identity.NewPrincipal(): %v", err)
	}
	return principal
}

func mustMember(
	t testing.TB,
	id resource.ID,
	workspaceID resource.ID,
	kind identity.Kind,
	subject string,
) MemberRecord {
	t.Helper()
	member, err := NewMemberRecord(MemberInput{
		ID:              id,
		WorkspaceID:     workspaceID,
		Kind:            kind,
		LogicalIdentity: mustLogical(t, subject),
	})
	if err != nil {
		t.Fatalf("NewMemberRecord(): %v", err)
	}
	return member
}

func mustDirectory(t testing.TB, workspaceID resource.ID, members ...MemberRecord) MemberDirectory {
	t.Helper()
	directory, err := NewMemberDirectory(workspaceID, members)
	if err != nil {
		t.Fatalf("NewMemberDirectory(): %v", err)
	}
	return directory
}

func canonicalSpec(bindings ...RoleBinding) PolicySpec {
	result := PolicySpec{Bindings: make([]RoleBinding, len(bindings))}
	for index, binding := range bindings {
		result.Bindings[index] = cloneRoleBinding(binding)
	}
	sort.Slice(result.Bindings, func(left, right int) bool {
		return CompareRoleBindings(result.Bindings[left], result.Bindings[right]) < 0
	})
	return result
}

func workspaceBinding(memberID resource.ID, role Role) RoleBinding {
	return RoleBinding{MemberID: memberID, Role: role, Scope: Scope{Kind: ScopeKindWorkspace}}
}

func environmentBinding(memberID resource.ID, role Role, environmentID resource.ID) RoleBinding {
	return RoleBinding{
		MemberID: memberID,
		Role:     role,
		Scope: Scope{
			Kind:          ScopeKindEnvironment,
			EnvironmentID: idPointer(environmentID),
		},
	}
}

func policyRevision(record hierarchy.Record, generation int64, spec PolicySpec) PolicyRevision {
	return PolicyRevision{Record: record, Generation: resource.Generation(generation), Spec: spec}
}

// syntheticBoundTarget is a package-test-only matrix fixture. Production
// retained-object target construction remains unavailable until issue #24
// supplies an authoritative object-ID lookup.
func syntheticBoundTarget(
	t testing.TB,
	snapshot hierarchy.Snapshot,
	kind ObjectKind,
	objectID resource.ID,
	resourceID resource.ID,
) Target {
	t.Helper()
	record, err := snapshot.Lookup(resourceID)
	if err != nil {
		t.Fatalf("snapshot.Lookup(%s): %v", resourceID, err)
	}
	environmentID, err := resolveRecordEnvironment(snapshot, record)
	if err != nil {
		t.Fatalf("resolveRecordEnvironment(%s): %v", resourceID, err)
	}
	target, err := newTarget(
		kind,
		objectID,
		record.Kind(),
		record.ID(),
		record.WorkspaceID(),
		environmentID,
		nil,
	)
	if err != nil {
		t.Fatalf("newTarget(%s, %s): %v", kind, objectID, err)
	}
	return target
}
