package resource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type testSpec struct {
	Config                map[string]string `json:"config,omitempty"`
	Region                string            `json:"region"`
	Revision              int64             `json:"revision,omitempty"`
	SuspendReconciliation bool              `json:"suspendReconciliation"`
}

type testCondition struct {
	ObservedGeneration int64  `json:"observedGeneration"`
	Type               string `json:"type"`
}

type testStatus struct {
	Conditions         []testCondition `json:"conditions"`
	ObservedGeneration int64           `json:"observedGeneration"`
}

type boundedObject struct {
	Items []int64 `json:"items"`
}

func (boundedObject) ObservedGenerations() []int64 { return nil }

type workspaceSpec struct {
	SuspendReconciliation bool `json:"suspendReconciliation"`
}

func (status testStatus) ObservedGenerations() []int64 {
	result := make([]int64, 1, len(status.Conditions)+1)
	result[0] = status.ObservedGeneration
	for _, condition := range status.Conditions {
		result = append(result, condition.ObservedGeneration)
	}
	return result
}

func TestNewNormalizesAndDefensivelyCopies(t *testing.T) {
	t.Parallel()

	parent := ID("wsp_01J00000000000000000000000")
	labels := map[string]string{"team": "platform"}
	spec := testSpec{Config: map[string]string{"tier": "critical"}, Region: "us-east-1"}
	status := testStatus{
		Conditions:         []testCondition{{Type: "Ready", ObservedGeneration: 0}},
		ObservedGeneration: 0,
	}
	createdAt := time.Date(2026, 9, 2, 12, 30, 0, 999_999, time.FixedZone("offset", -5*60*60))

	resource, err := New(CreateInput[testSpec, testStatus]{
		APIVersion:      "v1alpha1",
		Kind:            "Environment",
		ID:              "env_01J00000000000000000000000",
		DisplayName:     "production",
		Parent:          &parent,
		Labels:          labels,
		ResourceVersion: "rv_01J00000000000000000000000",
		CreatedAt:       createdAt,
		Spec:            spec,
		Status:          status,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	parent = ID("wsp_01J99999999999999999999999")
	labels["team"] = "mutated"
	spec.Config["tier"] = "mutated"
	status.Conditions[0].Type = "Mutated"

	metadata := resource.Metadata()
	if metadata.Generation() != 1 {
		t.Fatalf("Generation() = %d, want 1", metadata.Generation())
	}
	gotParent, present := metadata.Parent()
	if !present || gotParent != "wsp_01J00000000000000000000000" {
		t.Fatalf("Parent() = %q, %t", gotParent, present)
	}
	if got := metadata.Labels()["team"]; got != "platform" {
		t.Fatalf("Labels()[team] = %q, want platform", got)
	}
	wantTime := time.Date(2026, 9, 2, 17, 30, 0, 0, time.UTC)
	if !metadata.CreatedAt().Equal(wantTime) || !metadata.UpdatedAt().Equal(wantTime) {
		t.Fatalf("timestamps = %s / %s, want %s", metadata.CreatedAt(), metadata.UpdatedAt(), wantTime)
	}

	gotSpec, err := resource.Spec()
	if err != nil {
		t.Fatalf("Spec() error = %v", err)
	}
	if gotSpec.Config["tier"] != "critical" {
		t.Fatalf("Spec().Config[tier] = %q, want critical", gotSpec.Config["tier"])
	}
	gotStatus, err := resource.Status()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if len(gotStatus.Conditions) != 1 || gotStatus.Conditions[0].Type != "Ready" {
		t.Fatalf("Status().Conditions = %#v, want original Ready condition", gotStatus.Conditions)
	}

	returnedLabels := metadata.Labels()
	returnedLabels["team"] = "second mutation"
	if resource.Metadata().Labels()["team"] != "platform" {
		t.Fatal("mutating returned labels changed resource state")
	}
	gotSpec.Config["tier"] = "second mutation"
	again, err := resource.Spec()
	if err != nil || again.Config["tier"] != "critical" {
		t.Fatalf("mutating returned spec changed resource state: %#v, %v", again, err)
	}
	gotStatus.Conditions[0].Type = "SecondMutation"
	statusAgain, err := resource.Status()
	if err != nil || statusAgain.Conditions[0].Type != "Ready" {
		t.Fatalf("mutating returned status changed resource state: %#v, %v", statusAgain, err)
	}
}

func TestRenamePreservesStableState(t *testing.T) {
	t.Parallel()

	before := newTestResource(t, true)
	after, err := before.Rename(
		"renamed-workspace",
		"rv_01J00000000000000000000001",
		time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("Rename() error = %v", err)
	}

	beforeMetadata := before.Metadata()
	afterMetadata := after.Metadata()
	if afterMetadata.DisplayName() != "renamed-workspace" {
		t.Fatalf("DisplayName() = %q", afterMetadata.DisplayName())
	}
	if beforeMetadata.ID() != afterMetadata.ID() {
		t.Fatalf("ID changed from %q to %q", beforeMetadata.ID(), afterMetadata.ID())
	}
	if beforeMetadata.Generation() != afterMetadata.Generation() {
		t.Fatalf("generation changed from %d to %d", beforeMetadata.Generation(), afterMetadata.Generation())
	}
	if afterMetadata.ResourceVersion() != "rv_01J00000000000000000000001" {
		t.Fatalf("ResourceVersion() = %q", afterMetadata.ResourceVersion())
	}
	if !afterMetadata.UpdatedAt().Equal(time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC)) {
		t.Fatalf("UpdatedAt() = %s", afterMetadata.UpdatedAt())
	}
	if !beforeMetadata.CreatedAt().Equal(afterMetadata.CreatedAt()) {
		t.Fatal("creation timestamp changed during rename")
	}
	beforeParent, _ := beforeMetadata.Parent()
	afterParent, _ := afterMetadata.Parent()
	if beforeParent != afterParent {
		t.Fatalf("parent changed from %q to %q", beforeParent, afterParent)
	}
	assertResourceValuesEqual(t, before, after)

	replayed, err := after.Rename("renamed-workspace", "invalid version", time.Time{})
	if err != nil {
		t.Fatalf("no-op Rename() error = %v", err)
	}
	beforeReplay, _ := MarshalCanonical(after)
	afterReplay, _ := MarshalCanonical(replayed)
	if !bytes.Equal(beforeReplay, afterReplay) {
		t.Fatal("no-op rename changed canonical resource")
	}
}

func TestSpecAndStatusGenerationTransitions(t *testing.T) {
	t.Parallel()

	initial := newTestResource(t, false)
	unchanged, err := initial.ReplaceSpec(
		testSpec{Config: map[string]string{"a": "first", "z": "last"}, Region: "us-east-1"},
		"rv_unused",
		time.Time{},
	)
	if err != nil {
		t.Fatalf("no-op ReplaceSpec() error = %v", err)
	}
	if unchanged.Metadata().ResourceVersion() != initial.Metadata().ResourceVersion() {
		t.Fatal("no-op spec replacement consumed a resource version")
	}

	changed, err := initial.ReplaceSpec(
		testSpec{Config: map[string]string{"a": "first", "z": "last"}, Region: "us-west-2"},
		"rv_01J00000000000000000000001",
		time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("ReplaceSpec() error = %v", err)
	}
	if changed.Metadata().Generation() != initial.Metadata().Generation()+1 {
		t.Fatalf("changed generation = %d, want %d", changed.Metadata().Generation(), initial.Metadata().Generation()+1)
	}
	changedSpec, err := changed.Spec()
	if err != nil {
		t.Fatalf("changed Spec() error = %v", err)
	}
	if changedSpec.Region != "us-west-2" {
		t.Fatalf("changed Spec().Region = %q", changedSpec.Region)
	}
	if changed.Metadata().ResourceVersion() != "rv_01J00000000000000000000001" ||
		!changed.Metadata().UpdatedAt().Equal(time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC)) {
		t.Fatalf("spec revision metadata = %q / %s", changed.Metadata().ResourceVersion(), changed.Metadata().UpdatedAt())
	}
	initialStatus, err := initial.Status()
	if err != nil {
		t.Fatalf("initial Status() error = %v", err)
	}
	afterSpecStatus, err := changed.Status()
	if err != nil || !reflect.DeepEqual(initialStatus, afterSpecStatus) {
		t.Fatalf("spec write changed status: %#v / %v", afterSpecStatus, err)
	}

	statusChanged, err := changed.ReplaceStatus(
		testStatus{Conditions: []testCondition{{Type: "Ready", ObservedGeneration: 2}}, ObservedGeneration: 2},
		"rv_01J00000000000000000000002",
		time.Date(2026, 9, 2, 18, 1, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("ReplaceStatus() error = %v", err)
	}
	if statusChanged.Metadata().Generation() != changed.Metadata().Generation() {
		t.Fatalf("status write changed generation from %d to %d", changed.Metadata().Generation(), statusChanged.Metadata().Generation())
	}
	if statusChanged.Metadata().ResourceVersion() == changed.Metadata().ResourceVersion() {
		t.Fatal("changed status did not advance resource version")
	}
	if statusChanged.Metadata().ResourceVersion() != "rv_01J00000000000000000000002" ||
		!statusChanged.Metadata().UpdatedAt().Equal(time.Date(2026, 9, 2, 18, 1, 0, 0, time.UTC)) {
		t.Fatalf("status revision metadata = %q / %s", statusChanged.Metadata().ResourceVersion(), statusChanged.Metadata().UpdatedAt())
	}
	changedStatus, err := statusChanged.Status()
	if err != nil {
		t.Fatalf("changed Status() error = %v", err)
	}
	if changedStatus.ObservedGeneration != 2 || len(changedStatus.Conditions) != 1 ||
		changedStatus.Conditions[0].Type != "Ready" {
		t.Fatalf("changed Status() = %#v", changedStatus)
	}
	afterStatusSpec, err := statusChanged.Spec()
	if err != nil || !reflect.DeepEqual(changedSpec, afterStatusSpec) {
		t.Fatalf("status write changed spec: %#v / %v", afterStatusSpec, err)
	}

	future := testStatus{
		Conditions: []testCondition{
			{Type: "Ready", ObservedGeneration: 2},
			{Type: "Healthy", ObservedGeneration: 3},
		},
		ObservedGeneration: 2,
	}
	if _, err := statusChanged.ReplaceStatus(future, "rv_next", time.Now()); err == nil || !strings.Contains(err.Error(), "index 2") {
		t.Fatalf("future ReplaceStatus() error = %v, want indexed generation error", err)
	}
}

func TestReplaceLabelsDistinguishesMissingAndEmptyValues(t *testing.T) {
	t.Parallel()

	initial := newTestResource(t, false)
	left, err := initial.ReplaceLabels(
		map[string]string{"left": ""},
		"rv_left",
		initial.Metadata().UpdatedAt().Add(time.Millisecond),
	)
	if err != nil {
		t.Fatalf("first ReplaceLabels() error = %v", err)
	}
	right, err := left.ReplaceLabels(
		map[string]string{"right": ""},
		"rv_right",
		left.Metadata().UpdatedAt().Add(time.Millisecond),
	)
	if err != nil {
		t.Fatalf("second ReplaceLabels() error = %v", err)
	}
	if right.Metadata().ResourceVersion() != "rv_right" {
		t.Fatalf("ResourceVersion() = %q, want rv_right", right.Metadata().ResourceVersion())
	}
	if right.Metadata().Generation() != initial.Metadata().Generation() {
		t.Fatalf("label write changed generation from %d to %d", initial.Metadata().Generation(), right.Metadata().Generation())
	}
	if !reflect.DeepEqual(right.Metadata().Labels(), map[string]string{"right": ""}) {
		t.Fatalf("Labels() = %#v", right.Metadata().Labels())
	}
}

func TestTransitionsRejectInvalidRevisionInputs(t *testing.T) {
	t.Parallel()

	initial := newTestResource(t, false)
	changedSpec := testSpec{Region: "us-west-2"}
	tests := []struct {
		name    string
		version string
		at      time.Time
		message string
	}{
		{
			name:    "same resource version",
			version: initial.Metadata().ResourceVersion().String(),
			at:      initial.Metadata().UpdatedAt().Add(time.Millisecond),
			message: "must differ",
		},
		{
			name:    "time regresses",
			version: "rv_next",
			at:      initial.Metadata().UpdatedAt().Add(-time.Millisecond),
			message: "cannot move backwards",
		},
		{
			name:    "invalid resource version",
			version: "invalid version",
			at:      initial.Metadata().UpdatedAt().Add(time.Millisecond),
			message: "opaque version",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := initial.ReplaceSpec(changedSpec, test.version, test.at); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("ReplaceSpec() error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestGenerationOverflowHasNoPartialResult(t *testing.T) {
	t.Parallel()

	initial := newTestResource(t, false)
	initial.metadata.generation = Generation(math.MaxInt64)
	before, err := MarshalCanonical(initial)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	result, err := initial.ReplaceSpec(
		testSpec{Region: "us-west-2"},
		"rv_next",
		initial.Metadata().UpdatedAt().Add(time.Millisecond),
	)
	if !errors.Is(err, ErrGenerationOverflow) {
		t.Fatalf("ReplaceSpec() error = %v, want ErrGenerationOverflow", err)
	}
	after, marshalErr := MarshalCanonical(result)
	if marshalErr != nil {
		t.Fatalf("MarshalCanonical(result) error = %v", marshalErr)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("overflow returned a partially mutated resource")
	}
}

func TestOversizedTransitionHasNoPartialResult(t *testing.T) {
	t.Parallel()

	initial := newTestResource(t, false)
	before, err := MarshalCanonical(initial)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	oversized := testSpec{
		Config: map[string]string{"payload": strings.Repeat("x", MaxCanonicalBytes)},
		Region: "us-east-1",
	}
	result, err := initial.ReplaceSpec(
		oversized,
		"rv_next",
		initial.Metadata().UpdatedAt().Add(time.Millisecond),
	)
	if !errors.Is(err, ErrRepresentationTooLarge) {
		t.Fatalf("ReplaceSpec() error = %v, want ErrRepresentationTooLarge", err)
	}
	after, marshalErr := MarshalCanonical(result)
	if marshalErr != nil {
		t.Fatalf("MarshalCanonical(result) error = %v", marshalErr)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("oversize failure returned a partially mutated resource")
	}
}

func TestStructuralBoundsApplyToWholeEnvelope(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 9, 2, 17, 30, 0, 0, time.UTC)
	common := CreateInput[boundedObject, boundedObject]{
		APIVersion:      "v1alpha1",
		Kind:            "Workspace",
		ID:              "wsp_01J00000000000000000000000",
		DisplayName:     "payments",
		ResourceVersion: "rv_initial",
		CreatedAt:       createdAt,
	}

	combined := common
	combined.Spec.Items = make([]int64, 25_000)
	combined.Status.Items = make([]int64, 25_000)
	if _, err := New(combined); err == nil || !strings.Contains(err.Error(), "maximum node count") {
		t.Fatalf("New(combined nodes) error = %v, want global node bound", err)
	}

	deepValue := map[string]any{}
	for range maxJSONDepth {
		deepValue = map[string]any{"child": deepValue}
	}
	deep, err := New(CreateInput[map[string]any, testStatus]{
		APIVersion:      "v1alpha1",
		Kind:            "Workspace",
		ID:              "wsp_01J00000000000000000000000",
		DisplayName:     "payments",
		ResourceVersion: "rv_initial",
		CreatedAt:       createdAt,
		Spec:            deepValue,
		Status:          testStatus{Conditions: []testCondition{}},
	})
	if err == nil || !strings.Contains(err.Error(), "maximum depth") {
		t.Fatalf("New(envelope depth) error = %v, want global depth bound", err)
	}
	if _, marshalErr := MarshalCanonical(deep); marshalErr == nil {
		t.Fatal("failed deep construction returned a marshalable partial resource")
	}
}

func TestStructuralBoundFailurePreservesOriginalTransitionState(t *testing.T) {
	t.Parallel()

	initial, err := New(CreateInput[boundedObject, boundedObject]{
		APIVersion:      "v1alpha1",
		Kind:            "Workspace",
		ID:              "wsp_01J00000000000000000000000",
		DisplayName:     "payments",
		ResourceVersion: "rv_initial",
		CreatedAt:       time.Date(2026, 9, 2, 17, 30, 0, 0, time.UTC),
		Spec:            boundedObject{Items: []int64{}},
		Status:          boundedObject{Items: []int64{}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	before, err := MarshalCanonical(initial)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	replacement := boundedObject{Items: make([]int64, maxJSONNodes-2)}
	result, err := initial.ReplaceSpec(
		replacement,
		"rv_next",
		initial.Metadata().UpdatedAt().Add(time.Millisecond),
	)
	if err == nil || !strings.Contains(err.Error(), "maximum node count") {
		t.Fatalf("ReplaceSpec(global nodes) error = %v, want global node bound", err)
	}
	after, marshalErr := MarshalCanonical(result)
	if marshalErr != nil {
		t.Fatalf("MarshalCanonical(result) error = %v", marshalErr)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("global-bound failure returned a partially mutated resource")
	}
}

func TestResourceValidationBounds(t *testing.T) {
	t.Parallel()

	valid := CreateInput[testSpec, testStatus]{
		APIVersion:      "v1alpha1",
		Kind:            "Workspace",
		ID:              "wsp_01J00000000000000000000000",
		DisplayName:     "payments",
		ResourceVersion: "rv_initial",
		CreatedAt:       time.Date(2026, 9, 2, 17, 30, 0, 0, time.UTC),
		Spec:            testSpec{Region: "us-east-1"},
		Status:          testStatus{Conditions: []testCondition{}},
	}

	tests := []struct {
		name    string
		mutate  func(*CreateInput[testSpec, testStatus])
		message string
	}{
		{name: "api version", mutate: func(input *CreateInput[testSpec, testStatus]) { input.APIVersion = "latest" }, message: "apiVersion"},
		{name: "kind", mutate: func(input *CreateInput[testSpec, testStatus]) { input.Kind = "workspace" }, message: "kind"},
		{name: "ID", mutate: func(input *CreateInput[testSpec, testStatus]) { input.ID = "short" }, message: "metadata.id"},
		{name: "display name", mutate: func(input *CreateInput[testSpec, testStatus]) { input.DisplayName = "" }, message: "displayName"},
		{name: "resource version", mutate: func(input *CreateInput[testSpec, testStatus]) { input.ResourceVersion = "has spaces" }, message: "resourceVersion"},
		{name: "timestamp", mutate: func(input *CreateInput[testSpec, testStatus]) { input.CreatedAt = time.Time{} }, message: "createdAt"},
		{name: "label key", mutate: func(input *CreateInput[testSpec, testStatus]) { input.Labels = map[string]string{"Invalid": "value"} }, message: "labels key"},
		{name: "future status", mutate: func(input *CreateInput[testSpec, testStatus]) { input.Status = testStatus{ObservedGeneration: 2} }, message: "exceeds"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := valid
			test.mutate(&input)
			if _, err := New(input); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("New() error = %v, want %q", err, test.message)
			}
		})
	}

	oversized := valid
	oversized.Spec.Config = map[string]string{"payload": strings.Repeat("x", MaxCanonicalBytes)}
	if _, err := New(oversized); !errors.Is(err, ErrRepresentationTooLarge) {
		t.Fatalf("New(oversized) error = %v, want ErrRepresentationTooLarge", err)
	}
}

func TestCanonicalGoldenFixtures(t *testing.T) {
	t.Parallel()

	t.Run("Workspace root schema fixture", func(t *testing.T) {
		t.Parallel()
		assertGolden(t, "root", newWorkspaceResource(t))
	})
	t.Run("parented domain fixture", func(t *testing.T) {
		t.Parallel()
		assertGolden(t, "parented", newTestResource(t, true))
	})
}

func TestUnmarshalCanonicalRejectsAmbiguousInput(t *testing.T) {
	t.Parallel()

	baseline, err := MarshalCanonical(newTestResource(t, false))
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(baseline, &root); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	root["spec"] = []any{}
	nonObjectSpec, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	tests := []struct {
		name    string
		data    []byte
		message string
	}{
		{
			name:    "duplicate key",
			data:    bytes.Replace(baseline, []byte(`"kind":"DomainResource"`), []byte(`"kind":"DomainResource","kind":"DomainChild"`), 1),
			message: "duplicate object key",
		},
		{
			name:    "unknown envelope field",
			data:    bytes.Replace(baseline, []byte(`"status":`), []byte(`"unknown":true,"status":`), 1),
			message: "unknown field",
		},
		{
			name:    "non-object spec",
			data:    nonObjectSpec,
			message: "spec must be a JSON object",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := UnmarshalCanonical[testSpec, testStatus](test.data); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("UnmarshalCanonical() error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestCanonicalIntegerSpellingIsUnique(t *testing.T) {
	t.Parallel()

	baseline, err := MarshalCanonical(newTestResource(t, false))
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	withNegativeZero := bytes.Replace(
		baseline,
		[]byte(`"region":"us-east-1"`),
		[]byte(`"region":"us-east-1","revision":-0`),
		1,
	)
	decoded, err := UnmarshalCanonical[testSpec, testStatus](withNegativeZero)
	if err != nil {
		t.Fatalf("UnmarshalCanonical() error = %v", err)
	}
	canonical, err := MarshalCanonical(decoded)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	if bytes.Contains(canonical, []byte(`"revision":-0`)) ||
		!bytes.Contains(canonical, []byte(`"revision":0`)) {
		t.Fatalf("canonical integer spelling = %s", canonical)
	}
}

func TestUnstructuredSpecPreservesFullInt64Precision(t *testing.T) {
	t.Parallel()

	initial, err := New(CreateInput[map[string]any, testStatus]{
		APIVersion:      "v1alpha1",
		Kind:            "Workspace",
		ID:              "wsp_01J00000000000000000000000",
		DisplayName:     "payments",
		ResourceVersion: "rv_initial",
		CreatedAt:       time.Date(2026, 9, 2, 17, 30, 0, 0, time.UTC),
		Spec:            map[string]any{"limit": json.Number("9223372036854775807")},
		Status:          testStatus{Conditions: []testCondition{}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	encoded, err := MarshalCanonical(initial)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	decoded, err := UnmarshalCanonical[map[string]any, testStatus](encoded)
	if err != nil {
		t.Fatalf("UnmarshalCanonical() error = %v", err)
	}
	spec, err := decoded.Spec()
	if err != nil {
		t.Fatalf("Spec() error = %v", err)
	}
	limit, ok := spec["limit"].(json.Number)
	if !ok || limit.String() != "9223372036854775807" {
		t.Fatalf("Spec()[limit] = %#v, want exact json.Number", spec["limit"])
	}
	unchanged, err := decoded.ReplaceSpec(spec, "invalid version", time.Time{})
	if err != nil {
		t.Fatalf("no-op ReplaceSpec() error = %v", err)
	}
	roundTrip, err := MarshalCanonical(unchanged)
	if err != nil {
		t.Fatalf("round-trip MarshalCanonical() error = %v", err)
	}
	if !bytes.Equal(encoded, roundTrip) {
		t.Fatalf("full int64 round trip changed bytes:\n got %s\nwant %s", roundTrip, encoded)
	}
}

func newTestResource(t *testing.T, parented bool) Resource[testSpec, testStatus] {
	t.Helper()
	var parent *ID
	kind := "DomainResource"
	id := "wsp_01J00000000000000000000000"
	displayName := "payments"
	if parented {
		value := ID("wsp_01J00000000000000000000000")
		parent = &value
		kind = "DomainChild"
		id = "env_01J00000000000000000000000"
		displayName = "production"
	}
	result, err := New(CreateInput[testSpec, testStatus]{
		APIVersion:      "v1alpha1",
		Kind:            kind,
		ID:              id,
		DisplayName:     displayName,
		Parent:          parent,
		Labels:          map[string]string{"team": "platform", "environment": "production"},
		ResourceVersion: "rv_01J00000000000000000000000",
		CreatedAt:       time.Date(2026, 9, 2, 17, 30, 0, 0, time.UTC),
		Spec: testSpec{
			Config: map[string]string{"z": "last", "a": "first"},
			Region: "us-east-1",
		},
		Status: testStatus{Conditions: []testCondition{}, ObservedGeneration: 0},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return result
}

func newWorkspaceResource(t *testing.T) Resource[workspaceSpec, testStatus] {
	t.Helper()
	result, err := New(CreateInput[workspaceSpec, testStatus]{
		APIVersion:      "v1alpha1",
		Kind:            "Workspace",
		ID:              "wsp_01J00000000000000000000000",
		DisplayName:     "payments",
		Labels:          map[string]string{"team": "platform", "environment": "production"},
		ResourceVersion: "rv_01J00000000000000000000000",
		CreatedAt:       time.Date(2026, 9, 2, 17, 30, 0, 0, time.UTC),
		Spec:            workspaceSpec{SuspendReconciliation: false},
		Status:          testStatus{Conditions: []testCondition{}, ObservedGeneration: 0},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return result
}

func assertGolden[Spec any, Status GenerationObservations](
	t *testing.T,
	name string,
	resource Resource[Spec, Status],
) {
	t.Helper()
	want, err := os.ReadFile("testdata/" + name + ".golden.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))
	got, err := MarshalCanonical(resource)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes:\n got %s\nwant %s", got, want)
	}

	decoded, err := UnmarshalCanonical[Spec, Status](want)
	if err != nil {
		t.Fatalf("UnmarshalCanonical() error = %v", err)
	}
	roundTrip, err := MarshalCanonical(decoded)
	if err != nil {
		t.Fatalf("round-trip MarshalCanonical() error = %v", err)
	}
	if !bytes.Equal(roundTrip, want) {
		t.Fatalf("round-trip bytes:\n got %s\nwant %s", roundTrip, want)
	}
}

func assertResourceValuesEqual(
	t *testing.T,
	left, right Resource[testSpec, testStatus],
) {
	t.Helper()
	leftSpec, err := left.Spec()
	if err != nil {
		t.Fatalf("left.Spec() error = %v", err)
	}
	rightSpec, err := right.Spec()
	if err != nil {
		t.Fatalf("right.Spec() error = %v", err)
	}
	if !reflect.DeepEqual(leftSpec, rightSpec) {
		t.Fatalf("spec changed: %#v != %#v", leftSpec, rightSpec)
	}
	leftStatus, err := left.Status()
	if err != nil {
		t.Fatalf("left.Status() error = %v", err)
	}
	rightStatus, err := right.Status()
	if err != nil {
		t.Fatalf("right.Status() error = %v", err)
	}
	if !reflect.DeepEqual(leftStatus, rightStatus) {
		t.Fatalf("status changed: %#v != %#v", leftStatus, rightStatus)
	}
}

func resourceVersionFor(index int) string {
	return fmt.Sprintf("rv_%029d", index)
}
