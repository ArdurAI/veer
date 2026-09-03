package admission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/model"
	modelv1 "github.com/ArdurAI/veer/internal/core/domain/model/v1alpha1"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	testWorkspaceID   resource.ID = "wsp_01J00000000000000000000000"
	testWorkspaceBID  resource.ID = "wsp_01J11111111111111111111111"
	testPolicyID      resource.ID = "pol_01J00000000000000000000000"
	testEnvironmentID resource.ID = "env_01J00000000000000000000000"
	testProviderID    resource.ID = "pvc_01J00000000000000000000000"
	testApplicationID resource.ID = "app_01J00000000000000000000000"
	testComponentID   resource.ID = "cmp_01J00000000000000000000000"
)

var testKinds = []hierarchy.Kind{
	hierarchy.KindWorkspace,
	hierarchy.KindPolicy,
	hierarchy.KindEnvironment,
	hierarchy.KindProviderConnection,
	hierarchy.KindApplication,
	hierarchy.KindComponent,
}

type fixtureStatus struct{}

func (fixtureStatus) ObservedGenerations() []int64 { return []int64{0} }

func TestAdmissionPositiveMatrix(t *testing.T) {
	t.Parallel()

	snapshot, records := admissionFixture(t, testWorkspaceID)
	for _, kind := range testKinds {
		kind := kind
		t.Run(kind.String()+"Create", func(t *testing.T) {
			t.Parallel()
			context := createContext(kind, snapshot)
			result, err := AdmitCreate(intentJSON(kind, false), context)
			if err != nil {
				t.Fatalf("AdmitCreate() error = %v", err)
			}
			if result.Intent().Kind() != kind || result.Placement().Kind() != kind {
				t.Fatalf("create kinds = %q/%q, want %q", result.Intent().Kind(), result.Placement().Kind(), kind)
			}
			assertIntentRoundTrip(t, result.Intent())
		})
		t.Run(kind.String()+"Replace", func(t *testing.T) {
			t.Parallel()
			intent, err := AdmitReplace(intentJSON(kind, false), records[kind], snapshot)
			if err != nil {
				t.Fatalf("AdmitReplace() error = %v", err)
			}
			if intent.Kind() != kind {
				t.Fatalf("replace kind = %q, want %q", intent.Kind(), kind)
			}
			assertIntentRoundTrip(t, intent)
		})
		t.Run(kind.String()+"Status", func(t *testing.T) {
			t.Parallel()
			status, err := AdmitStatus(statusJSON(kind), records[kind], 1, snapshot)
			if err != nil {
				t.Fatalf("AdmitStatus() error = %v", err)
			}
			if status.Kind() != kind {
				t.Fatalf("status kind = %q, want %q", status.Kind(), kind)
			}
			assertStatusRoundTrip(t, status)
		})
	}
}

func TestWorkspaceOmissionEqualsExplicitFalse(t *testing.T) {
	t.Parallel()

	omitted, err := AdmitCreate(intentJSON(hierarchy.KindWorkspace, false), createContext(hierarchy.KindWorkspace, hierarchy.Snapshot{}))
	if err != nil {
		t.Fatalf("AdmitCreate(omitted) error = %v", err)
	}
	explicitRaw := bytes.Replace(intentJSON(hierarchy.KindWorkspace, false), []byte(`"spec":{}`), []byte(`"spec":{"suspendReconciliation":false}`), 1)
	explicit, err := AdmitCreate(explicitRaw, createContext(hierarchy.KindWorkspace, hierarchy.Snapshot{}))
	if err != nil {
		t.Fatalf("AdmitCreate(explicit) error = %v", err)
	}
	if !model.EqualIntent(omitted.Intent(), explicit.Intent()) {
		t.Fatal("omitted Workspace default is not semantically equal to explicit false")
	}
	workspace := omitted.Intent().(*model.WorkspaceIntent)
	if workspace.Spec().SuspendReconciliation {
		t.Fatal("omitted Workspace default = true, want false")
	}

	explicitTrue, err := AdmitCreate(
		intentJSON(hierarchy.KindWorkspace, true),
		createContext(hierarchy.KindWorkspace, hierarchy.Snapshot{}),
	)
	if err != nil {
		t.Fatalf("AdmitCreate(explicit true) error = %v", err)
	}
	if !explicitTrue.Intent().(*model.WorkspaceIntent).Spec().SuspendReconciliation {
		t.Fatal("explicit Workspace value true was overwritten by defaulting")
	}
}

func TestAdmittedCreateMatrixGolden(t *testing.T) {
	t.Parallel()

	type admitted struct {
		Kind                  string            `json:"kind"`
		ID                    string            `json:"id"`
		WorkspaceID           string            `json:"workspaceId"`
		Parent                *string           `json:"parent"`
		DisplayName           string            `json:"displayName"`
		Labels                map[string]string `json:"labels"`
		SuspendReconciliation *bool             `json:"suspendReconciliation,omitempty"`
	}
	snapshot, _ := admissionFixture(t, testWorkspaceID)
	results := make([]admitted, 0, len(testKinds))
	for _, kind := range testKinds {
		result, err := AdmitCreate(intentJSON(kind, false), createContext(kind, snapshot))
		if err != nil {
			t.Fatalf("AdmitCreate(%s) error = %v", kind, err)
		}
		placement, intent := result.Placement(), result.Intent()
		var parent *string
		if value, present := placement.Parent(); present {
			text := value.String()
			parent = &text
		}
		entry := admitted{
			Kind: kind.String(), ID: placement.ID().String(), WorkspaceID: placement.WorkspaceID().String(),
			Parent: parent, DisplayName: intent.Metadata().DisplayName(), Labels: intent.Metadata().Labels(),
		}
		if workspace, ok := intent.(*model.WorkspaceIntent); ok {
			value := workspace.Spec().SuspendReconciliation
			entry.SuspendReconciliation = &value
		}
		results = append(results, entry)
	}
	got, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("testdata/admitted-create-matrix.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("admitted create matrix drifted\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestAdmissionDoesNotMutateInputsOrRetainedOutputs(t *testing.T) {
	t.Parallel()

	snapshot, records := admissionFixture(t, testWorkspaceID)
	raw := intentJSON(hierarchy.KindEnvironment, false)
	rawBefore := bytes.Clone(raw)
	currentBefore := records[hierarchy.KindEnvironment]
	retainedBefore, err := snapshot.Lookup(testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}

	intent, err := AdmitReplace(raw, records[hierarchy.KindEnvironment], snapshot)
	if err != nil {
		t.Fatalf("AdmitReplace() error = %v", err)
	}
	if !bytes.Equal(raw, rawBefore) {
		t.Fatal("AdmitReplace mutated raw bytes")
	}
	if !reflect.DeepEqual(records[hierarchy.KindEnvironment], currentBefore) {
		t.Fatal("AdmitReplace mutated current record")
	}
	retainedAfter, err := snapshot.Lookup(testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(retainedBefore, retainedAfter) {
		t.Fatal("AdmitReplace mutated snapshot")
	}

	labels := intent.Metadata().Labels()
	labels["team"] = "changed"
	if intent.Metadata().Labels()["team"] != "platform" {
		t.Fatal("returned hub intent retained caller-mutable labels")
	}
	result, err := AdmitCreate(raw, createContext(hierarchy.KindEnvironment, snapshot))
	if err != nil {
		t.Fatal(err)
	}
	firstLabels := result.Intent().Metadata().Labels()
	firstLabels["team"] = "changed"
	if result.Intent().Metadata().Labels()["team"] != "platform" {
		t.Fatal("CreateResult.Intent did not return an independent value")
	}
}

func TestRejectedWritesDoNotMutateInputsCurrentOrSnapshot(t *testing.T) {
	t.Parallel()

	snapshot, records := admissionFixture(t, testWorkspaceID)
	tests := []struct {
		name string
		raw  []byte
		run  func([]byte) error
		want Stage
	}{
		{
			name: "schema",
			raw:  []byte(`{"apiVersion":"v1alpha1","kind":"Environment","metadata":{"displayName":"x","unknown":true},"spec":{}}`),
			run: func(raw []byte) error {
				_, err := AdmitReplace(raw, records[hierarchy.KindEnvironment], snapshot)
				return err
			},
			want: StageSchema,
		},
		{
			name: "semantic",
			raw:  providerStatusWithFaults(true),
			run: func(raw []byte) error {
				_, err := AdmitStatus(raw, records[hierarchy.KindProviderConnection], 1, snapshot)
				return err
			},
			want: StageSemantic,
		},
		{
			name: "immutable",
			raw:  intentJSON(hierarchy.KindWorkspace, false),
			run: func(raw []byte) error {
				_, err := AdmitReplace(raw, records[hierarchy.KindEnvironment], snapshot)
				return err
			},
			want: StageImmutable,
		},
		{
			name: "reference",
			raw:  intentJSON(hierarchy.KindEnvironment, false),
			run: func(raw []byte) error {
				_, err := AdmitReplace(raw, records[hierarchy.KindEnvironment], hierarchy.Snapshot{})
				return err
			},
			want: StageReference,
		},
		{
			name: "default",
			raw:  []byte("default-stage-sentinel"),
			run: func([]byte) error {
				_, failure := checkedDefaultIntent(defaultedIntent{kind: hierarchy.KindWorkspace, value: modelv1.EnvironmentWrite{}})
				return failure
			},
			want: StageDefault,
		},
		{
			name: "conversion",
			raw:  []byte("conversion-stage-sentinel"),
			run: func([]byte) error {
				_, failure := convertIntent(defaultedIntent{kind: hierarchy.KindWorkspace, value: modelv1.EnvironmentWrite{}})
				return failure
			},
			want: StageConversion,
		},
	}
	currentBefore := records[hierarchy.KindEnvironment]
	retainedBefore, err := snapshot.Lookup(testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			rawBefore := bytes.Clone(test.raw)
			rejection := test.run(test.raw)
			if rejection == nil {
				t.Fatal("rejected admission returned nil error")
			}
			var failure *Error
			if !errors.As(rejection, &failure) || failure.Stage() != test.want {
				t.Fatalf("rejection = %v, want stage %q", rejection, test.want)
			}
			if !bytes.Equal(test.raw, rawBefore) {
				t.Fatal("rejected admission mutated raw input")
			}
			if !reflect.DeepEqual(records[hierarchy.KindEnvironment], currentBefore) {
				t.Fatal("rejected admission mutated current record")
			}
			retainedAfter, lookupErr := snapshot.Lookup(testEnvironmentID)
			if lookupErr != nil || !reflect.DeepEqual(retainedBefore, retainedAfter) {
				t.Fatal("rejected admission mutated snapshot")
			}
		})
	}

	labels := map[string]string{"team": "platform"}
	badDefault := defaultedIntent{kind: hierarchy.KindWorkspace, value: modelv1.WorkspaceWrite{
		APIVersion: "v2", Kind: hierarchy.KindWorkspace.String(),
		Metadata: modelv1.WriteMetadata{DisplayName: "x", Labels: labels},
		Spec:     modelv1.WorkspaceWriteSpec{},
	}}
	labelsBefore := cloneLabels(labels)
	if _, failure := checkedDefaultIntent(badDefault); failure == nil || !reflect.DeepEqual(labels, labelsBefore) {
		t.Fatal("default rejection mutated input or failed to reject")
	}
	badConversion := defaultedIntent{kind: hierarchy.KindWorkspace, value: modelv1.WorkspaceWrite{
		APIVersion: modelv1.APIVersion, Kind: hierarchy.KindWorkspace.String(),
		Metadata: modelv1.WriteMetadata{DisplayName: "x", Labels: labels},
		Spec:     modelv1.WorkspaceWriteSpec{},
	}}
	if _, failure := convertIntent(badConversion); failure == nil || !reflect.DeepEqual(labels, labelsBefore) {
		t.Fatal("conversion rejection mutated input or failed to reject")
	}
}

func TestCrossWorkspaceCurrentMismatch(t *testing.T) {
	t.Parallel()

	snapshot, records := admissionFixture(t, testWorkspaceID)
	parent := testWorkspaceID
	foreign, err := resource.New(resource.CreateInput[struct{}, fixtureStatus]{
		APIVersion: hierarchy.APIVersion, Kind: hierarchy.KindEnvironment.String(),
		ID: testEnvironmentID.String(), WorkspaceID: testWorkspaceBID.String(), Parent: &parent,
		DisplayName: "foreign", Labels: map[string]string{}, ResourceVersion: "rv_foreign",
		CreatedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC), Spec: struct{}{}, Status: fixtureStatus{},
	})
	if err != nil {
		t.Fatal(err)
	}
	foreignRecord, err := hierarchy.RecordFrom(foreign.APIVersion(), foreign.Kind(), foreign.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	if records[hierarchy.KindEnvironment].ID() != foreignRecord.ID() {
		t.Fatal("fixture does not exercise same-ID transition")
	}
	_, err = AdmitReplace(intentJSON(hierarchy.KindEnvironment, false), foreignRecord, snapshot)
	assertFailure(t, err, StageReference, CodeWorkspaceMismatch, "")
}

func TestStageAndLexicographicErrorPrecedence(t *testing.T) {
	t.Parallel()

	snapshot, records := admissionFixture(t, testWorkspaceID)
	tests := []struct {
		name      string
		run       func() error
		wantStage Stage
		wantCode  Code
		wantPath  string
	}{
		{
			name: "schema missing beats later unknown and type",
			run: func() error {
				_, err := AdmitCreate([]byte(`{"zzz":1,"kind":7,"metadata":{},"spec":{}}`), CreateContext{})
				return err
			},
			wantStage: StageSchema, wantCode: CodeMissingField, wantPath: "/apiVersion",
		},
		{
			name: "lexically earlier unknown beats version value",
			run: func() error {
				_, err := AdmitCreate([]byte(`{"aaa":1,"apiVersion":"v2","kind":"Workspace","metadata":{"displayName":"x"},"spec":{}}`), CreateContext{})
				return err
			},
			wantStage: StageSchema, wantCode: CodeUnknownField, wantPath: "/aaa",
		},
		{
			name: "semantic beats immutable and reference",
			run: func() error {
				raw := providerStatusWithFaults(true)
				_, err := AdmitStatus(raw, records[hierarchy.KindWorkspace], 1, hierarchy.Snapshot{})
				return err
			},
			wantStage: StageSemantic, wantCode: CodeDuplicateItem, wantPath: "/status/capabilities/1/name",
		},
		{
			name: "immutable beats reference",
			run: func() error {
				_, err := AdmitReplace(intentJSON(hierarchy.KindWorkspace, false), records[hierarchy.KindEnvironment], hierarchy.Snapshot{})
				return err
			},
			wantStage: StageImmutable, wantCode: CodeImmutableField, wantPath: "/kind",
		},
		{
			name: "reference exact snapshot",
			run: func() error {
				_, err := AdmitReplace(intentJSON(hierarchy.KindEnvironment, false), records[hierarchy.KindEnvironment], hierarchy.Snapshot{})
				return err
			},
			wantStage: StageReference, wantCode: CodeInvalidPlacement, wantPath: "",
		},
		{
			name: "create parent missing",
			run: func() error {
				missing := resource.ID("missing_01J000000000000000000")
				_, err := AdmitCreate(intentJSON(hierarchy.KindEnvironment, false), CreateContext{ID: createID(hierarchy.KindEnvironment), ParentID: &missing, Snapshot: snapshot})
				return err
			},
			wantStage: StageReference, wantCode: CodeParentNotFound, wantPath: "",
		},
		{
			name: "create parent kind",
			run: func() error {
				parent := testEnvironmentID
				_, err := AdmitCreate(intentJSON(hierarchy.KindComponent, false), CreateContext{ID: createID(hierarchy.KindComponent), ParentID: &parent, Snapshot: snapshot})
				return err
			},
			wantStage: StageReference, wantCode: CodeParentKindMismatch, wantPath: "",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertFailure(t, test.run(), test.wantStage, test.wantCode, test.wantPath)
		})
	}
}

func TestSchemaOpaqueIDPrecedesSemantic(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"apiVersion":"v1alpha1","kind":"ProviderConnection","metadata":{"displayName":"x"},"spec":{"provider":"aws","credentialRef":{"referenceId":"invalid.secret.value","version":"v1"}}}`)
	_, err := AdmitCreate(raw, CreateContext{})
	assertFailure(t, err, StageSchema, CodeInvalidValue, "/spec/credentialRef/referenceId")
}

func TestInternalDefaultAndConversionFailuresAreSafe(t *testing.T) {
	t.Parallel()

	_, failure := checkedDefaultIntent(defaultedIntent{kind: hierarchy.KindWorkspace, value: modelv1.EnvironmentWrite{}})
	assertFailure(t, failure, StageDefault, CodeDefaultFailed, "")
	_, failure = convertIntent(defaultedIntent{kind: hierarchy.KindWorkspace, value: modelv1.EnvironmentWrite{}})
	assertFailure(t, failure, StageConversion, CodeConversionFailed, "")
	_, failure = checkedDefaultStatus(defaultedStatus{kind: hierarchy.KindWorkspace, value: modelv1.EnvironmentStatusWrite{}})
	assertFailure(t, failure, StageDefault, CodeDefaultFailed, "")
	_, failure = convertStatus(defaultedStatus{kind: hierarchy.KindWorkspace, value: modelv1.EnvironmentStatusWrite{}}, 1)
	assertFailure(t, failure, StageConversion, CodeConversionFailed, "")
}

func TestErrorsNeverEchoSubmittedValues(t *testing.T) {
	t.Parallel()

	secret := "super-secret-credential-material"
	raw := []byte(fmt.Sprintf(`{"apiVersion":"v1alpha1","kind":"ProviderConnection","metadata":{"displayName":"x"},"spec":{"provider":"aws","credentialRef":{"referenceId":"%s","version":"v1"}}}`, secret))
	_, err := AdmitCreate(raw, CreateContext{})
	if err == nil {
		t.Fatal("AdmitCreate() error = nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("safe error echoes submitted value: %q", err)
	}
}

func assertFailure(t *testing.T, err error, stage Stage, code Code, path string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) {
		t.Fatalf("error = %T %v, want *Error", err, err)
	}
	if failure.Stage() != stage || failure.Code() != code || failure.Path() != path {
		t.Fatalf("failure = (%q, %q, %q), want (%q, %q, %q)", failure.Stage(), failure.Code(), failure.Path(), stage, code, path)
	}
}

func intentJSON(kind hierarchy.Kind, explicitTrue bool) []byte {
	spec := `{}`
	if kind == hierarchy.KindWorkspace && explicitTrue {
		spec = `{"suspendReconciliation":true}`
	}
	if kind == hierarchy.KindProviderConnection {
		spec = `{"provider":"aws","credentialRef":{"referenceId":"cred_01J0000000000000000000000","version":"v1"}}`
	}
	return []byte(fmt.Sprintf(`{"apiVersion":"v1alpha1","kind":%q,"metadata":{"displayName":"example","labels":{"team":"platform"}},"spec":%s}`, kind, spec))
}

func statusJSON(kind hierarchy.Kind) []byte {
	status := `{"observedGeneration":1,"conditions":[]}`
	if kind == hierarchy.KindProviderConnection {
		status = `{"observedGeneration":1,"conditions":[],"capabilities":[],"quotaChecks":[]}`
	}
	return []byte(fmt.Sprintf(`{"apiVersion":"v1alpha1","kind":%q,"status":%s}`, kind, status))
}

func providerStatusWithFaults(includeFuture bool) []byte {
	observed := 1
	conditions := `[]`
	if includeFuture {
		observed = 2
		conditions = `[{"type":"Ready","status":"True","reason":"Ready","message":"","observedGeneration":2,"lastTransitionAt":"2026-09-02T01:02:03.000Z"}]`
	}
	status := fmt.Sprintf(`{"observedGeneration":%d,"conditions":%s,"capabilities":[{"name":"compute","state":"Supported","source":"probe","observedAt":"2026-09-02T01:02:03.000Z","reason":"Observed"},{"name":"compute","state":"Supported","source":"probe","observedAt":"2026-09-02T01:02:03.000Z","reason":"Observed"}],"quotaChecks":[]}`, observed, conditions)
	return []byte(fmt.Sprintf(`{"apiVersion":"v1alpha1","kind":"ProviderConnection","status":%s}`, status))
}

func createContext(kind hierarchy.Kind, snapshot hierarchy.Snapshot) CreateContext {
	context := CreateContext{ID: createID(kind), Snapshot: snapshot}
	var parent resource.ID
	switch kind {
	case hierarchy.KindPolicy, hierarchy.KindEnvironment:
		parent = testWorkspaceID
	case hierarchy.KindProviderConnection, hierarchy.KindApplication:
		parent = testEnvironmentID
	case hierarchy.KindComponent:
		parent = testApplicationID
	}
	if parent != "" {
		context.ParentID = &parent
	}
	return context
}

func createID(kind hierarchy.Kind) resource.ID {
	return resource.ID("new_" + strings.ToLower(kind.String()) + "_01J0000000000000000")
}

func admissionFixture(t *testing.T, workspaceID resource.ID) (hierarchy.Snapshot, map[hierarchy.Kind]hierarchy.Record) {
	t.Helper()
	ids := map[hierarchy.Kind]resource.ID{
		hierarchy.KindWorkspace:          workspaceID,
		hierarchy.KindPolicy:             testPolicyID,
		hierarchy.KindEnvironment:        testEnvironmentID,
		hierarchy.KindProviderConnection: testProviderID,
		hierarchy.KindApplication:        testApplicationID,
		hierarchy.KindComponent:          testComponentID,
	}
	parents := map[hierarchy.Kind]resource.ID{
		hierarchy.KindPolicy:             workspaceID,
		hierarchy.KindEnvironment:        workspaceID,
		hierarchy.KindProviderConnection: testEnvironmentID,
		hierarchy.KindApplication:        testEnvironmentID,
		hierarchy.KindComponent:          testApplicationID,
	}
	records := make(map[hierarchy.Kind]hierarchy.Record, len(testKinds))
	list := make([]hierarchy.Record, 0, len(testKinds))
	for _, kind := range testKinds {
		id := ids[kind]
		var parent *resource.ID
		if value := parents[kind]; value != "" {
			copy := value
			parent = &copy
		}
		value, err := resource.New(resource.CreateInput[struct{}, fixtureStatus]{
			APIVersion: hierarchy.APIVersion, Kind: kind.String(), ID: id.String(), WorkspaceID: workspaceID.String(),
			DisplayName: "fixture", Parent: parent, Labels: map[string]string{"team": "platform"},
			ResourceVersion: "rv_01J00000000000000000000000", CreatedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
			Spec: struct{}{}, Status: fixtureStatus{},
		})
		if err != nil {
			t.Fatalf("resource.New(%s) error = %v", kind, err)
		}
		record, err := hierarchy.RecordFrom(value.APIVersion(), value.Kind(), value.Metadata())
		if err != nil {
			t.Fatalf("RecordFrom(%s) error = %v", kind, err)
		}
		records[kind] = record
		list = append(list, record)
	}
	snapshot, err := hierarchy.NewSnapshot(workspaceID, list)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	return snapshot, records
}

func assertIntentRoundTrip(t *testing.T, intent model.Intent) {
	t.Helper()
	var roundTrip model.Intent
	var err error
	switch value := intent.(type) {
	case *model.WorkspaceIntent:
		var source modelv1.WorkspaceWrite
		source, err = modelv1.FromHubWorkspaceIntent(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubWorkspaceIntent(source)
		}
	case *model.PolicyIntent:
		var source modelv1.PolicyWrite
		source, err = modelv1.FromHubPolicyIntent(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubPolicyIntent(source)
		}
	case *model.EnvironmentIntent:
		var source modelv1.EnvironmentWrite
		source, err = modelv1.FromHubEnvironmentIntent(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubEnvironmentIntent(source)
		}
	case *model.ProviderConnectionIntent:
		var source modelv1.ProviderConnectionWrite
		source, err = modelv1.FromHubProviderConnectionIntent(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubProviderConnectionIntent(source)
		}
	case *model.ApplicationIntent:
		var source modelv1.ApplicationWrite
		source, err = modelv1.FromHubApplicationIntent(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubApplicationIntent(source)
		}
	case *model.ComponentIntent:
		var source modelv1.ComponentWrite
		source, err = modelv1.FromHubComponentIntent(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubComponentIntent(source)
		}
	default:
		t.Fatalf("unexpected intent type %T", intent)
	}
	if err != nil || !model.EqualIntent(intent, roundTrip) {
		t.Fatalf("intent round trip = %T, %v", roundTrip, err)
	}
}

func assertStatusRoundTrip(t *testing.T, status model.StatusWrite) {
	t.Helper()
	generation := status.ResourceGeneration()
	var roundTrip model.StatusWrite
	var err error
	switch value := status.(type) {
	case *model.WorkspaceStatusWrite:
		var source modelv1.WorkspaceStatusWrite
		source, err = modelv1.FromHubWorkspaceStatusWrite(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubWorkspaceStatusWrite(source, generation)
		}
	case *model.PolicyStatusWrite:
		var source modelv1.PolicyStatusWrite
		source, err = modelv1.FromHubPolicyStatusWrite(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubPolicyStatusWrite(source, generation)
		}
	case *model.EnvironmentStatusWrite:
		var source modelv1.EnvironmentStatusWrite
		source, err = modelv1.FromHubEnvironmentStatusWrite(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubEnvironmentStatusWrite(source, generation)
		}
	case *model.ProviderConnectionStatusWrite:
		var source modelv1.ProviderConnectionStatusWrite
		source, err = modelv1.FromHubProviderConnectionStatusWrite(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubProviderConnectionStatusWrite(source, generation)
		}
	case *model.ApplicationStatusWrite:
		var source modelv1.ApplicationStatusWrite
		source, err = modelv1.FromHubApplicationStatusWrite(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubApplicationStatusWrite(source, generation)
		}
	case *model.ComponentStatusWrite:
		var source modelv1.ComponentStatusWrite
		source, err = modelv1.FromHubComponentStatusWrite(value)
		if err == nil {
			roundTrip, err = modelv1.ToHubComponentStatusWrite(source, generation)
		}
	default:
		t.Fatalf("unexpected status type %T", status)
	}
	if err != nil || !model.EqualStatusWrite(status, roundTrip) {
		t.Fatalf("status round trip = %T, %v", roundTrip, err)
	}
}
