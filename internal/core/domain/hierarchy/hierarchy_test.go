package hierarchy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	workspaceAID   resource.ID = "wsp_01J00000000000000000000000"
	workspaceBID   resource.ID = "wsp_01J11111111111111111111111"
	environmentAID resource.ID = "env_01J00000000000000000000000"
	environmentBID resource.ID = "env_01J11111111111111111111111"
	applicationAID resource.ID = "app_01J00000000000000000000000"
	applicationBID resource.ID = "app_01J11111111111111111111111"
	componentAID   resource.ID = "cmp_01J00000000000000000000000"
	componentBID   resource.ID = "cmp_01J11111111111111111111111"
	policyAID      resource.ID = "pol_01J00000000000000000000000"
	policyBID      resource.ID = "pol_01J11111111111111111111111"
	connectionAID  resource.ID = "pvc_01J00000000000000000000000"
	connectionBID  resource.ID = "pvc_01J11111111111111111111111"
)

var fixtureTime = time.Date(2026, 9, 2, 17, 30, 0, 0, time.UTC)

type fixtureWorkspaceSpec struct {
	SuspendReconciliation bool `json:"suspendReconciliation"`
}

type fixtureEnvironmentSpec struct{}

type fixtureApplicationSpec struct{}

type fixtureComponentSpec struct{}

type fixtureCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	ObservedGeneration int64  `json:"observedGeneration"`
	LastTransitionAt   string `json:"lastTransitionAt"`
}

type fixtureStatus struct {
	Conditions         []fixtureCondition `json:"conditions"`
	ObservedGeneration int64              `json:"observedGeneration"`
}

func (status fixtureStatus) ObservedGenerations() []int64 {
	result := make([]int64, 1, len(status.Conditions)+1)
	result[0] = status.ObservedGeneration
	for _, condition := range status.Conditions {
		result = append(result, condition.ObservedGeneration)
	}
	return result
}

type hierarchyFixture struct {
	workspace   resource.Resource[fixtureWorkspaceSpec, fixtureStatus]
	environment resource.Resource[fixtureEnvironmentSpec, fixtureStatus]
	application resource.Resource[fixtureApplicationSpec, fixtureStatus]
	component   resource.Resource[fixtureComponentSpec, fixtureStatus]
	records     []Record
}

func TestParseKind(t *testing.T) {
	t.Parallel()

	for _, want := range []Kind{
		KindWorkspace,
		KindEnvironment,
		KindApplication,
		KindComponent,
		KindPolicy,
		KindProviderConnection,
	} {
		got, err := ParseKind(want.String())
		if err != nil || got != want {
			t.Fatalf("ParseKind(%q) = %q, %v", want, got, err)
		}
	}
	for _, value := range []string{"", "workspace", "Database", "Component "} {
		if _, err := ParseKind(value); !errors.Is(err, ErrUnsupportedKind) {
			t.Fatalf("ParseKind(%q) error = %v, want ErrUnsupportedKind", value, err)
		}
	}
}

func TestControlResourceEdges(t *testing.T) {
	t.Parallel()

	root := rawRecord(workspaceAID, KindWorkspace, workspaceAID, "")
	environment := rawRecord(environmentAID, KindEnvironment, workspaceAID, workspaceAID)
	policy := rawRecord(policyAID, KindPolicy, workspaceAID, workspaceAID)
	connection := rawRecord(connectionAID, KindProviderConnection, workspaceAID, environmentAID)
	records := []Record{root, environment, policy, connection}

	snapshot, err := NewSnapshot(workspaceAID, records)
	if err != nil {
		t.Fatalf("NewSnapshot(control resources) error = %v", err)
	}
	if snapshot.Len() != len(records) {
		t.Fatalf("snapshot len = %d, want %d", snapshot.Len(), len(records))
	}

	policyPlacement, err := snapshot.DeriveChild(KindPolicy, policyBID, workspaceAID)
	if err != nil {
		t.Fatalf("DeriveChild(Policy) error = %v", err)
	}
	if parent, present := policyPlacement.Parent(); !present || parent != workspaceAID {
		t.Fatalf("Policy parent = %q, %t", parent, present)
	}
	connectionPlacement, err := snapshot.DeriveChild(KindProviderConnection, connectionBID, environmentAID)
	if err != nil {
		t.Fatalf("DeriveChild(ProviderConnection) error = %v", err)
	}
	if parent, present := connectionPlacement.Parent(); !present || parent != environmentAID {
		t.Fatalf("ProviderConnection parent = %q, %t", parent, present)
	}

	if _, err := snapshot.DeriveChild(KindPolicy, policyBID, environmentAID); !errors.Is(err, ErrParentKindMismatch) {
		t.Fatalf("DeriveChild(Policy under Environment) error = %v", err)
	}
	if _, err := snapshot.DeriveChild(KindProviderConnection, connectionBID, workspaceAID); !errors.Is(err, ErrParentKindMismatch) {
		t.Fatalf("DeriveChild(ProviderConnection under Workspace) error = %v", err)
	}

	for _, id := range []resource.ID{workspaceAID, environmentAID} {
		if err := snapshot.CheckDelete(id); !errors.Is(err, ErrDeleteRestricted) {
			t.Fatalf("CheckDelete(%q) error = %v, want ErrDeleteRestricted", id, err)
		}
	}
	for _, id := range []resource.ID{policyAID, connectionAID} {
		if err := snapshot.CheckDelete(id); err != nil {
			t.Fatalf("CheckDelete(%q) error = %v", id, err)
		}
	}
}

func TestControlResourceWrongParentKinds(t *testing.T) {
	t.Parallel()

	root := rawRecord(workspaceAID, KindWorkspace, workspaceAID, "")
	environment := rawRecord(environmentAID, KindEnvironment, workspaceAID, workspaceAID)
	tests := []struct {
		name   string
		record Record
	}{
		{name: "Policy under Environment", record: rawRecord(policyAID, KindPolicy, workspaceAID, environmentAID)},
		{name: "ProviderConnection under Workspace", record: rawRecord(connectionAID, KindProviderConnection, workspaceAID, workspaceAID)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewSnapshot(workspaceAID, []Record{root, environment, test.record})
			if !errors.Is(err, ErrParentKindMismatch) {
				t.Fatalf("NewSnapshot() error = %v, want ErrParentKindMismatch", err)
			}
		})
	}
}

func TestValidHierarchyMatrix(t *testing.T) {
	t.Parallel()

	primary := newHierarchyFixture(t, workspaceAID, "shared", "shared", "shared", "shared")
	if snapshot, err := NewSnapshot(workspaceAID, primary.records); err != nil {
		t.Fatalf("NewSnapshot(full chain) error = %v", err)
	} else if snapshot.Len() != 4 || snapshot.WorkspaceID() != workspaceAID {
		t.Fatalf("snapshot = len %d, workspace %q", snapshot.Len(), snapshot.WorkspaceID())
	}

	rootOnly := primary.records[:1]
	if _, err := NewSnapshot(workspaceAID, rootOnly); err != nil {
		t.Fatalf("NewSnapshot(root only) error = %v", err)
	}

	snapshot, err := NewSnapshot(workspaceAID, primary.records)
	if err != nil {
		t.Fatalf("NewSnapshot(parent chain) error = %v", err)
	}
	environmentPlacement, err := snapshot.DeriveChild(KindEnvironment, environmentBID, workspaceAID)
	if err != nil {
		t.Fatalf("DeriveChild(Environment sibling) error = %v", err)
	}
	applicationPlacement, err := snapshot.DeriveChild(KindApplication, applicationBID, environmentAID)
	if err != nil {
		t.Fatalf("DeriveChild(Application sibling) error = %v", err)
	}
	componentPlacement, err := snapshot.DeriveChild(KindComponent, componentBID, applicationAID)
	if err != nil {
		t.Fatalf("DeriveChild(Component sibling) error = %v", err)
	}
	environment := mustNewResource(t, environmentPlacement, "shared", "rv_environment_sibling", fixtureEnvironmentSpec{})
	application := mustNewResource(t, applicationPlacement, "shared", "rv_application_sibling", fixtureApplicationSpec{})
	component := mustNewResource(t, componentPlacement, "shared", "rv_component_sibling", fixtureComponentSpec{})
	withSiblings := append(
		cloneRecords(primary.records),
		mustRecordFromResource(t, environment),
		mustRecordFromResource(t, application),
		mustRecordFromResource(t, component),
	)
	if _, err := NewSnapshot(workspaceAID, withSiblings); err != nil {
		t.Fatalf("NewSnapshot(siblings) error = %v", err)
	}

	secondary := newHierarchyFixture(t, workspaceBID, "shared", "shared", "shared", "shared")
	if _, err := NewSnapshot(workspaceBID, secondary.records); err != nil {
		t.Fatalf("NewSnapshot(second workspace) error = %v", err)
	}
	if _, err := NewSnapshot(workspaceAID, append(cloneRecords(primary.records), secondary.records...)); !errors.Is(err, ErrWorkspaceMismatch) {
		t.Fatalf("two-workspace snapshot error = %v, want ErrWorkspaceMismatch", err)
	}
}

func TestParentKindMatrix(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, workspaceAID, "workspace", "environment", "application", "component")
	baseline := append(
		cloneRecords(fixture.records),
		rawRecord(policyAID, KindPolicy, workspaceAID, workspaceAID),
		rawRecord(connectionAID, KindProviderConnection, workspaceAID, environmentAID),
	)
	byKind := make(map[Kind]Record, len(baseline))
	for _, record := range baseline {
		byKind[record.kind] = record
	}

	kinds := []Kind{
		KindWorkspace,
		KindEnvironment,
		KindApplication,
		KindComponent,
		KindPolicy,
		KindProviderConnection,
	}
	for _, childKind := range kinds {
		childKind := childKind
		for _, parentKind := range kinds {
			parentKind := parentKind
			t.Run(childKind.String()+"_under_"+parentKind.String(), func(t *testing.T) {
				t.Parallel()
				records := cloneRecords(baseline)
				parent := byKind[parentKind]

				if childKind == KindWorkspace {
					records[0].parent = cloneID(parent.id)
					_, err := NewSnapshot(workspaceAID, records)
					if !errors.Is(err, ErrRootHasParent) {
						t.Fatalf("NewSnapshot() error = %v, want ErrRootHasParent", err)
					}
					return
				}

				subject := rawRecord(subjectID(childKind), childKind, workspaceAID, parent.id)
				records = append(records, subject)
				_, err := NewSnapshot(workspaceAID, records)
				if expectedParentKind(childKind) == parentKind {
					if err != nil {
						t.Fatalf("NewSnapshot(allowed edge) error = %v", err)
					}
					return
				}
				if !errors.Is(err, ErrParentKindMismatch) {
					t.Fatalf("NewSnapshot() error = %v, want ErrParentKindMismatch", err)
				}
			})
		}
	}
}

func TestInvalidSnapshotMatrix(t *testing.T) {
	t.Parallel()

	root := rawRecord(workspaceAID, KindWorkspace, workspaceAID, "")
	tests := []struct {
		name      string
		workspace resource.ID
		records   []Record
		want      error
	}{
		{
			name:      "invalid scope",
			workspace: "short",
			records:   []Record{root},
			want:      ErrInvalidSnapshot,
		},
		{
			name:      "duplicate identity",
			workspace: workspaceAID,
			records:   []Record{root, root},
			want:      ErrDuplicateID,
		},
		{
			name:      "empty scope",
			workspace: workspaceAID,
			want:      ErrWorkspaceRootMissing,
		},
		{
			name:      "workspace root missing",
			workspace: workspaceAID,
			records: []Record{
				rawRecord(environmentAID, KindEnvironment, workspaceAID, workspaceAID),
			},
			want: ErrWorkspaceRootMissing,
		},
		{
			name:      "root slot has child kind",
			workspace: workspaceAID,
			records: []Record{
				rawRecord(workspaceAID, KindEnvironment, workspaceAID, applicationAID),
			},
			want: ErrWorkspaceRootMissing,
		},
		{
			name:      "foreign ownership",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord(environmentAID, KindEnvironment, workspaceBID, workspaceAID),
			},
			want: ErrWorkspaceMismatch,
		},
		{
			name:      "foreign workspace root",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord(workspaceBID, KindWorkspace, workspaceBID, ""),
			},
			want: ErrWorkspaceMismatch,
		},
		{
			name:      "second local root",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord(workspaceBID, KindWorkspace, workspaceAID, ""),
			},
			want: ErrWorkspaceMismatch,
		},
		{
			name:      "root parent",
			workspace: workspaceAID,
			records: []Record{
				rawRecord(workspaceAID, KindWorkspace, workspaceAID, workspaceAID),
			},
			want: ErrRootHasParent,
		},
		{
			name:      "environment parent required",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord(environmentAID, KindEnvironment, workspaceAID, ""),
			},
			want: ErrParentRequired,
		},
		{
			name:      "application parent required",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord(applicationAID, KindApplication, workspaceAID, ""),
			},
			want: ErrParentRequired,
		},
		{
			name:      "component parent required",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord(componentAID, KindComponent, workspaceAID, ""),
			},
			want: ErrParentRequired,
		},
		{
			name:      "environment orphan",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord(environmentAID, KindEnvironment, workspaceAID, workspaceBID),
			},
			want: ErrParentNotFound,
		},
		{
			name:      "application orphan",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord(applicationAID, KindApplication, workspaceAID, environmentBID),
			},
			want: ErrParentNotFound,
		},
		{
			name:      "component orphan",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord(componentAID, KindComponent, workspaceAID, applicationBID),
			},
			want: ErrParentNotFound,
		},
		{
			name:      "unsupported record kind",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord(environmentAID, Kind("Database"), workspaceAID, workspaceAID),
			},
			want: ErrUnsupportedKind,
		},
		{
			name:      "invalid record ID",
			workspace: workspaceAID,
			records: []Record{
				root,
				rawRecord("short", KindEnvironment, workspaceAID, workspaceAID),
			},
			want: ErrInvalidSnapshot,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewSnapshot(test.workspace, test.records)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewSnapshot() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSnapshotRecordLimitPrecedesAllocation(t *testing.T) {
	t.Parallel()
	if MaxSnapshotRecords != 64_001 {
		t.Fatalf("MaxSnapshotRecords = %d, want 64001", MaxSnapshotRecords)
	}

	records := make([]Record, MaxSnapshotRecords+1)
	if _, err := NewSnapshot(workspaceAID, records[:MaxSnapshotRecords]); !errors.Is(err, ErrUnsupportedAPIVersion) {
		t.Fatalf("NewSnapshot(at limit) error = %v, want record validation", err)
	}
	if _, err := NewSnapshot(workspaceAID, records); !errors.Is(err, ErrInvalidSnapshot) ||
		!errors.Is(err, ErrSnapshotTooLarge) {
		t.Fatalf("NewSnapshot(over limit) error = %v, want size and invalid-snapshot sentinels", err)
	}
}

func TestCycleMatrix(t *testing.T) {
	t.Parallel()

	root := rawRecord(workspaceAID, KindWorkspace, workspaceAID, "")
	long := []Record{root}
	const longCycleLength = 4_096
	for index := 0; index < longCycleLength; index++ {
		id := generatedID(index)
		parent := generatedID((index + 1) % longCycleLength)
		long = append(long, rawRecord(id, KindComponent, workspaceAID, parent))
	}

	tests := []struct {
		name    string
		records []Record
	}{
		{
			name: "self",
			records: []Record{
				root,
				rawRecord(componentAID, KindComponent, workspaceAID, componentAID),
			},
		},
		{
			name: "two nodes",
			records: []Record{
				root,
				rawRecord(applicationAID, KindApplication, workspaceAID, applicationBID),
				rawRecord(applicationBID, KindApplication, workspaceAID, applicationAID),
			},
		},
		{
			name: "three kinds",
			records: []Record{
				root,
				rawRecord(environmentAID, KindEnvironment, workspaceAID, applicationAID),
				rawRecord(applicationAID, KindApplication, workspaceAID, componentAID),
				rawRecord(componentAID, KindComponent, workspaceAID, environmentAID),
			},
		},
		{name: "long iterative cycle", records: long},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewSnapshot(workspaceAID, test.records); !errors.Is(err, ErrCycle) {
				t.Fatalf("NewSnapshot() error = %v, want ErrCycle", err)
			}
		})
	}
}

func TestPlacementAndResourceCreation(t *testing.T) {
	t.Parallel()

	rootPlacement, err := DeriveWorkspace(workspaceAID)
	if err != nil {
		t.Fatalf("DeriveWorkspace() error = %v", err)
	}
	if rootPlacement.ID() != workspaceAID || rootPlacement.Kind() != KindWorkspace ||
		rootPlacement.WorkspaceID() != workspaceAID {
		t.Fatalf("root placement = %#v", rootPlacement)
	}
	if _, present := rootPlacement.Parent(); present {
		t.Fatal("root placement unexpectedly has a parent")
	}

	workspace := mustNewResource(t, rootPlacement, "workspace", "rv_workspace", fixtureWorkspaceSpec{})
	if workspace.Metadata().WorkspaceID() != workspace.Metadata().ID() {
		t.Fatal("workspace resource does not own itself")
	}
	rootRecord := mustRecordFromResource(t, workspace)
	snapshot, err := NewSnapshot(workspaceAID, []Record{rootRecord})
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}

	environmentPlacement, err := snapshot.DeriveChild(KindEnvironment, environmentAID, workspaceAID)
	if err != nil {
		t.Fatalf("DeriveChild() error = %v", err)
	}
	if environmentPlacement.WorkspaceID() != workspaceAID {
		t.Fatalf("child workspace = %q, want %q", environmentPlacement.WorkspaceID(), workspaceAID)
	}
	if parent, present := environmentPlacement.Parent(); !present || parent != workspaceAID {
		t.Fatalf("child parent = %q, %t", parent, present)
	}

	environment := mustNewResource(t, environmentPlacement, "environment", "rv_environment", fixtureEnvironmentSpec{})
	metadata := environment.Metadata()
	if metadata.ID() != environmentAID || metadata.WorkspaceID() != workspaceAID {
		t.Fatalf("environment identity = %q / %q", metadata.ID(), metadata.WorkspaceID())
	}
	if parent, present := metadata.Parent(); !present || parent != workspaceAID {
		t.Fatalf("environment parent = %q, %t", parent, present)
	}
}

func TestInvalidPlacementMatrix(t *testing.T) {
	t.Parallel()

	if _, err := DeriveWorkspace("short"); !errors.Is(err, ErrInvalidPlacement) {
		t.Fatalf("DeriveWorkspace(invalid) error = %v", err)
	}
	fixture := newHierarchyFixture(t, workspaceAID, "w", "e", "a", "c")
	snapshot, err := NewSnapshot(workspaceAID, fixture.records)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}

	tests := []struct {
		name   string
		kind   Kind
		id     resource.ID
		parent resource.ID
		want   error
	}{
		{name: "root through child API", kind: KindWorkspace, id: workspaceBID, parent: workspaceAID, want: ErrInvalidPlacement},
		{name: "unsupported kind", kind: "Database", id: componentBID, parent: applicationAID, want: ErrUnsupportedKind},
		{name: "invalid child ID", kind: KindComponent, id: "short", parent: applicationAID, want: ErrInvalidPlacement},
		{name: "invalid parent ID", kind: KindComponent, id: componentBID, parent: "short", want: ErrInvalidPlacement},
		{name: "duplicate ID", kind: KindComponent, id: componentAID, parent: applicationAID, want: ErrDuplicateID},
		{name: "missing parent", kind: KindComponent, id: componentBID, parent: workspaceBID, want: ErrParentNotFound},
		{name: "wrong parent kind", kind: KindComponent, id: componentBID, parent: environmentAID, want: ErrParentKindMismatch},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := snapshot.DeriveChild(test.kind, test.id, test.parent)
			if !errors.Is(err, test.want) {
				t.Fatalf("DeriveChild() error = %v, want %v", err, test.want)
			}
		})
	}

	if _, err := NewResource(Placement{}, CreateInput[fixtureComponentSpec, fixtureStatus]{
		DisplayName:     "component",
		ResourceVersion: "rv_component",
		CreatedAt:       fixtureTime,
		Spec:            fixtureComponentSpec{},
		Status:          emptyFixtureStatus(),
	}); !errors.Is(err, ErrInvalidPlacement) {
		t.Fatalf("NewResource(zero placement) error = %v", err)
	}
}

func TestZeroSnapshotFailsClosed(t *testing.T) {
	t.Parallel()

	var snapshot Snapshot
	if _, err := snapshot.DeriveChild(KindEnvironment, environmentAID, workspaceAID); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("zero Snapshot.DeriveChild() error = %v, want ErrInvalidSnapshot", err)
	}
	if err := snapshot.CheckDelete(workspaceAID); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("zero Snapshot.CheckDelete() error = %v, want ErrInvalidSnapshot", err)
	}
}

func TestRecordProjectionAndDisplayNames(t *testing.T) {
	t.Parallel()

	placement, err := DeriveWorkspace(workspaceAID)
	if err != nil {
		t.Fatalf("DeriveWorkspace() error = %v", err)
	}
	beforeResource := mustNewResource(t, placement, "first display name", "rv_first", fixtureWorkspaceSpec{})
	afterResource, err := beforeResource.Rename("second display name", "rv_second", fixtureTime.Add(time.Millisecond))
	if err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	before := mustRecordFromResource(t, beforeResource)
	after := mustRecordFromResource(t, afterResource)
	if before.APIVersion() != APIVersion || before.ID() != workspaceAID || before.Kind() != KindWorkspace ||
		before.WorkspaceID() != workspaceAID {
		t.Fatalf("projected record = %#v", before)
	}
	if _, present := before.Parent(); present {
		t.Fatal("projected workspace unexpectedly has a parent")
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("display-only rename changed hierarchy record: %#v / %#v", before, after)
	}
	if err := CheckTransition(before, after); err != nil {
		t.Fatalf("CheckTransition(rename) error = %v", err)
	}

	if _, err := RecordFrom("v1beta1", KindWorkspace.String(), beforeResource.Metadata()); !errors.Is(err, ErrUnsupportedAPIVersion) {
		t.Fatalf("RecordFrom(version) error = %v", err)
	}
	if _, err := RecordFrom(APIVersion, "workspace", beforeResource.Metadata()); !errors.Is(err, ErrUnsupportedKind) {
		t.Fatalf("RecordFrom(kind) error = %v", err)
	}
	if _, err := RecordFrom(APIVersion, KindWorkspace.String(), resource.Metadata{}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("RecordFrom(zero metadata) error = %v", err)
	}
}

func TestLowLevelEnvelopeOwnershipIsRevalidated(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, workspaceAID, "w", "e", "a", "c")
	parent := workspaceAID
	foreign, err := resource.New(resource.CreateInput[fixtureEnvironmentSpec, fixtureStatus]{
		APIVersion:      APIVersion,
		Kind:            KindEnvironment.String(),
		ID:              environmentBID.String(),
		WorkspaceID:     workspaceBID.String(),
		DisplayName:     "restored",
		Parent:          &parent,
		ResourceVersion: "rv_restored",
		CreatedAt:       fixtureTime,
		Spec:            fixtureEnvironmentSpec{},
		Status:          emptyFixtureStatus(),
	})
	if err != nil {
		t.Fatalf("resource.New() error = %v", err)
	}
	foreignRecord := mustRecordFromResource(t, foreign)
	if _, err := NewSnapshot(workspaceAID, []Record{fixture.records[0], foreignRecord}); !errors.Is(err, ErrWorkspaceMismatch) {
		t.Fatalf("NewSnapshot(restored foreign ownership) error = %v, want ErrWorkspaceMismatch", err)
	}
}

func TestImmutableTransitionMatrix(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, workspaceAID, "w", "e", "a", "c")
	before := fixture.records[1]
	tests := []struct {
		name   string
		mutate func(*Record)
		want   error
	}{
		{name: "same record", mutate: func(*Record) {}, want: nil},
		{name: "ID", mutate: func(record *Record) { record.id = environmentBID }, want: ErrImmutableID},
		{name: "kind", mutate: func(record *Record) { record.kind = KindApplication }, want: ErrImmutableKind},
		{name: "parent", mutate: func(record *Record) { record.parent = cloneID(environmentBID) }, want: ErrImmutableParent},
		{name: "parent removed", mutate: func(record *Record) { record.parent = nil }, want: ErrImmutableParent},
		{name: "workspace", mutate: func(record *Record) { record.workspaceID = workspaceBID }, want: ErrImmutableWorkspaceID},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			after := cloneRecord(before)
			test.mutate(&after)
			err := CheckTransition(before, after)
			if test.want == nil {
				if err != nil {
					t.Fatalf("CheckTransition() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("CheckTransition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDeleteRestriction(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, workspaceAID, "w", "e", "a", "c")
	snapshot, err := NewSnapshot(workspaceAID, fixture.records)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}

	for _, id := range []resource.ID{workspaceAID, environmentAID, applicationAID} {
		if err := snapshot.CheckDelete(id); !errors.Is(err, ErrDeleteRestricted) {
			t.Fatalf("CheckDelete(%q) error = %v, want ErrDeleteRestricted", id, err)
		}
	}
	if err := snapshot.CheckDelete(componentAID); err != nil {
		t.Fatalf("CheckDelete(leaf) error = %v", err)
	}
	if err := snapshot.CheckDelete(componentBID); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("CheckDelete(missing) error = %v, want ErrResourceNotFound", err)
	}
	if snapshot.Len() != len(fixture.records) {
		t.Fatal("CheckDelete mutated the snapshot")
	}
}

func TestCanonicalKindFixturesRoundTrip(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, workspaceAID, "payments", "production", "payments-api", "api")
	assertHierarchyGolden(t, "workspace", fixture.workspace)
	assertHierarchyGolden(t, "environment", fixture.environment)
	assertHierarchyGolden(t, "application", fixture.application)
	assertHierarchyGolden(t, "component", fixture.component)

	restored := make([]Record, 0, 4)
	restored = append(restored, recordFromCanonical(t, "workspace", fixture.workspace))
	restored = append(restored, recordFromCanonical(t, "environment", fixture.environment))
	restored = append(restored, recordFromCanonical(t, "application", fixture.application))
	restored = append(restored, recordFromCanonical(t, "component", fixture.component))
	if _, err := NewSnapshot(workspaceAID, restored); err != nil {
		t.Fatalf("NewSnapshot(round-tripped fixtures) error = %v", err)
	}
}

func TestProviderSpecificSpecFieldsAreRejected(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, workspaceAID, "w", "e", "a", "c")
	assertUnknownSpecRejected(t, fixture.workspace, `"spec":{"suspendReconciliation":false}`, `"spec":{"provider":"aws","suspendReconciliation":false}`)
	assertUnknownSpecRejected(t, fixture.environment, `"spec":{}`, `"spec":{"provider":"aws"}`)
	assertUnknownSpecRejected(t, fixture.application, `"spec":{}`, `"spec":{"provider":"aws"}`)
	assertUnknownSpecRejected(t, fixture.component, `"spec":{}`, `"spec":{"provider":"aws"}`)
}

func TestHierarchyErrorsDoNotContainResourceData(t *testing.T) {
	t.Parallel()

	sensitiveID := resource.ID("sensitive_credential_identifier")
	sensitiveName := "private-customer-display-name"
	errorsToCheck := []error{}
	if _, err := DeriveWorkspace("short"); err != nil {
		errorsToCheck = append(errorsToCheck, err)
	}
	root := rawRecord(workspaceAID, KindWorkspace, workspaceAID, "")
	if _, err := NewSnapshot(workspaceAID, []Record{
		root,
		rawRecord(environmentAID, KindEnvironment, workspaceAID, sensitiveID),
	}); err != nil {
		errorsToCheck = append(errorsToCheck, err)
	}
	_, resourceErr := NewResource(Placement{}, CreateInput[fixtureWorkspaceSpec, fixtureStatus]{
		DisplayName:     sensitiveName,
		ResourceVersion: "rv_safe",
		CreatedAt:       fixtureTime,
		Spec:            fixtureWorkspaceSpec{},
		Status:          emptyFixtureStatus(),
	})
	if !errors.Is(resourceErr, ErrInvalidPlacement) {
		t.Fatalf("NewResource(invalid placement) error = %v, want ErrInvalidPlacement", resourceErr)
	}
	errorsToCheck = append(errorsToCheck, resourceErr)

	for _, err := range errorsToCheck {
		if strings.Contains(err.Error(), sensitiveID.String()) || strings.Contains(err.Error(), sensitiveName) {
			t.Fatalf("error contains resource data: %q", err)
		}
	}
}

func newHierarchyFixture(
	t *testing.T,
	workspaceID resource.ID,
	workspaceName, environmentName, applicationName, componentName string,
) hierarchyFixture {
	t.Helper()

	rootPlacement, err := DeriveWorkspace(workspaceID)
	if err != nil {
		t.Fatalf("DeriveWorkspace() error = %v", err)
	}
	workspace := mustNewResourceWithMetadata(
		t,
		rootPlacement,
		workspaceName,
		"rv_01J00000000000000000000000",
		fixtureTime,
		map[string]string{"environment": "production", "team": "platform"},
		fixtureWorkspaceSpec{},
	)
	rootRecord := mustRecordFromResource(t, workspace)

	snapshot, err := NewSnapshot(workspaceID, []Record{rootRecord})
	if err != nil {
		t.Fatalf("NewSnapshot(root) error = %v", err)
	}
	environmentID := environmentAID
	applicationID := applicationAID
	componentID := componentAID
	if workspaceID == workspaceBID {
		environmentID = environmentBID
		applicationID = applicationBID
		componentID = componentBID
	}
	environmentPlacement, err := snapshot.DeriveChild(KindEnvironment, environmentID, workspaceID)
	if err != nil {
		t.Fatalf("DeriveChild(Environment) error = %v", err)
	}
	environment := mustNewResourceWithMetadata(
		t,
		environmentPlacement,
		environmentName,
		"rv_01J00000000000000000000010",
		fixtureTime.Add(time.Minute),
		map[string]string{"team": "platform"},
		fixtureEnvironmentSpec{},
	)
	environmentRecord := mustRecordFromResource(t, environment)

	snapshot, err = NewSnapshot(workspaceID, []Record{rootRecord, environmentRecord})
	if err != nil {
		t.Fatalf("NewSnapshot(environment) error = %v", err)
	}
	applicationPlacement, err := snapshot.DeriveChild(KindApplication, applicationID, environmentID)
	if err != nil {
		t.Fatalf("DeriveChild(Application) error = %v", err)
	}
	application := mustNewResourceWithMetadata(
		t,
		applicationPlacement,
		applicationName,
		"rv_01J00000000000000000000020",
		fixtureTime.Add(2*time.Minute),
		map[string]string{"team": "platform"},
		fixtureApplicationSpec{},
	)
	applicationRecord := mustRecordFromResource(t, application)

	snapshot, err = NewSnapshot(workspaceID, []Record{rootRecord, environmentRecord, applicationRecord})
	if err != nil {
		t.Fatalf("NewSnapshot(application) error = %v", err)
	}
	componentPlacement, err := snapshot.DeriveChild(KindComponent, componentID, applicationID)
	if err != nil {
		t.Fatalf("DeriveChild(Component) error = %v", err)
	}
	component := mustNewResourceWithMetadata(
		t,
		componentPlacement,
		componentName,
		"rv_01J00000000000000000000030",
		fixtureTime.Add(3*time.Minute),
		map[string]string{"team": "platform"},
		fixtureComponentSpec{},
	)
	componentRecord := mustRecordFromResource(t, component)

	return hierarchyFixture{
		workspace:   workspace,
		environment: environment,
		application: application,
		component:   component,
		records:     []Record{rootRecord, environmentRecord, applicationRecord, componentRecord},
	}
}

func mustNewResource[Spec any](
	t *testing.T,
	placement Placement,
	displayName, version string,
	spec Spec,
) resource.Resource[Spec, fixtureStatus] {
	t.Helper()
	return mustNewResourceWithMetadata(
		t,
		placement,
		displayName,
		version,
		fixtureTime,
		map[string]string{"team": "platform"},
		spec,
	)
}

func mustNewResourceWithMetadata[Spec any](
	t *testing.T,
	placement Placement,
	displayName, version string,
	createdAt time.Time,
	labels map[string]string,
	spec Spec,
) resource.Resource[Spec, fixtureStatus] {
	t.Helper()
	result, err := NewResource(placement, CreateInput[Spec, fixtureStatus]{
		DisplayName:     displayName,
		Labels:          labels,
		ResourceVersion: version,
		CreatedAt:       createdAt,
		Spec:            spec,
		Status:          emptyFixtureStatus(),
	})
	if err != nil {
		t.Fatalf("NewResource() error = %v", err)
	}
	return result
}

func mustRecordFromResource[Spec any, Status resource.GenerationObservations](
	t *testing.T,
	value resource.Resource[Spec, Status],
) Record {
	t.Helper()
	record, err := RecordFrom(value.APIVersion(), value.Kind(), value.Metadata())
	if err != nil {
		t.Fatalf("RecordFrom() error = %v", err)
	}
	return record
}

func emptyFixtureStatus() fixtureStatus {
	return fixtureStatus{Conditions: []fixtureCondition{}}
}

func rawRecord(id resource.ID, kind Kind, workspaceID resource.ID, parent resource.ID) Record {
	record := Record{apiVersion: APIVersion, id: id, kind: kind, workspaceID: workspaceID}
	if parent != "" {
		record.parent = cloneID(parent)
	}
	return record
}

func cloneRecords(records []Record) []Record {
	result := make([]Record, len(records))
	for index, record := range records {
		result[index] = cloneRecord(record)
	}
	return result
}

func subjectID(kind Kind) resource.ID {
	switch kind {
	case KindEnvironment:
		return "env_01J22222222222222222222222"
	case KindApplication:
		return "app_01J22222222222222222222222"
	case KindComponent:
		return "cmp_01J22222222222222222222222"
	case KindPolicy:
		return "pol_01J22222222222222222222222"
	case KindProviderConnection:
		return "pvc_01J22222222222222222222222"
	default:
		return "wsp_01J22222222222222222222222"
	}
}

func generatedID(index int) resource.ID {
	return resource.ID(fmt.Sprintf("node_%016x", index))
}

func assertHierarchyGolden[Spec any](
	t *testing.T,
	name string,
	value resource.Resource[Spec, fixtureStatus],
) {
	t.Helper()
	want, err := os.ReadFile("testdata/" + name + ".golden.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))
	got, err := resource.MarshalCanonical(value)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes:\n got %s\nwant %s", got, want)
	}
	decoded, err := resource.UnmarshalCanonical[Spec, fixtureStatus](want)
	if err != nil {
		t.Fatalf("UnmarshalCanonical() error = %v", err)
	}
	roundTrip, err := resource.MarshalCanonical(decoded)
	if err != nil {
		t.Fatalf("round-trip MarshalCanonical() error = %v", err)
	}
	if !bytes.Equal(roundTrip, want) {
		t.Fatalf("round-trip bytes:\n got %s\nwant %s", roundTrip, want)
	}
}

func recordFromCanonical[Spec any](
	t *testing.T,
	name string,
	prototype resource.Resource[Spec, fixtureStatus],
) Record {
	t.Helper()
	_ = prototype
	data, err := os.ReadFile("testdata/" + name + ".golden.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	decoded, err := resource.UnmarshalCanonical[Spec, fixtureStatus](bytes.TrimSpace(data))
	if err != nil {
		t.Fatalf("UnmarshalCanonical() error = %v", err)
	}
	return mustRecordFromResource(t, decoded)
}

func assertUnknownSpecRejected[Spec any](
	t *testing.T,
	value resource.Resource[Spec, fixtureStatus],
	oldSpec, newSpec string,
) {
	t.Helper()
	encoded, err := resource.MarshalCanonical(value)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	malformed := bytes.Replace(encoded, []byte(oldSpec), []byte(newSpec), 1)
	if bytes.Equal(malformed, encoded) {
		t.Fatal("test did not replace the spec payload")
	}
	if _, err := resource.UnmarshalCanonical[Spec, fixtureStatus](malformed); err == nil {
		t.Fatal("UnmarshalCanonical(provider field) unexpectedly succeeded")
	}
}
