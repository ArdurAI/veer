package model

import (
	"errors"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const validCredentialID = "cred_01J0000000000000000000000"

func TestWriteMetadataValidationCloneAndEquality(t *testing.T) {
	t.Parallel()

	labels := map[string]string{"team": "platform"}
	metadata := mustWriteMetadata(t, "payments", labels)
	labels["team"] = "mutated"
	if metadata.Labels()["team"] != "platform" {
		t.Fatal("NewWriteMetadata retained the input label map")
	}
	returned := metadata.Labels()
	returned["team"] = "mutated-again"
	if metadata.Labels()["team"] != "platform" {
		t.Fatal("WriteMetadata.Labels returned an internal map alias")
	}
	clone := CloneWriteMetadata(metadata)
	if !EqualWriteMetadata(metadata, clone) {
		t.Fatal("CloneWriteMetadata changed the value")
	}
	if err := ValidateWriteMetadata(WriteMetadata{}); !errors.Is(err, ErrInvalidDisplayName) {
		t.Fatalf("ValidateWriteMetadata(zero) error = %v", err)
	}

	left := mustWriteMetadata(t, "same", map[string]string{"left": ""})
	right := mustWriteMetadata(t, "same", map[string]string{"right": ""})
	if EqualWriteMetadata(left, right) {
		t.Fatal("disjoint empty-valued labels compared equal")
	}

	empty, err := NewWriteMetadata("same", map[string]string{})
	if err != nil {
		t.Fatalf("NewWriteMetadata(empty labels) error = %v", err)
	}
	if empty.Labels() != nil {
		t.Fatal("empty labels did not normalize to nil")
	}
}

func FuzzWriteMetadataEqualityUsesLabelKeyPresence(f *testing.F) {
	f.Add("left", "right")
	f.Add("same", "same")
	f.Fuzz(func(t *testing.T, leftKey, rightKey string) {
		left := WriteMetadata{displayName: "same", labels: map[string]string{leftKey: ""}}
		right := WriteMetadata{displayName: "same", labels: map[string]string{rightKey: ""}}
		want := leftKey == rightKey
		if got := EqualWriteMetadata(left, right); got != want {
			t.Fatalf("EqualWriteMetadata(keys %q, %q) = %t, want %t", leftKey, rightKey, got, want)
		}
		if EqualWriteMetadata(left, right) != EqualWriteMetadata(right, left) {
			t.Fatal("EqualWriteMetadata is not symmetric")
		}
		if !EqualWriteMetadata(left, left) {
			t.Fatal("EqualWriteMetadata is not reflexive")
		}
	})
}

func TestProviderConnectionSpecTransitionContractIsAvailableThroughHub(t *testing.T) {
	t.Parallel()

	before := validProviderSpec()
	after := before
	after.CredentialRef.Version = "next"
	if err := CheckProviderConnectionSpecTransition(before, after); err != nil {
		t.Fatalf("CheckProviderConnectionSpecTransition(rotation) error = %v", err)
	}

	after.Provider = "kubernetes"
	if err := CheckProviderConnectionSpecTransition(before, after); !errors.Is(err, control.ErrProviderConnectionRebind) {
		t.Fatalf("CheckProviderConnectionSpecTransition(rebind) error = %v", err)
	}
}

func TestIntentClosedSumAllKinds(t *testing.T) {
	t.Parallel()

	metadata := mustWriteMetadata(t, "payments", map[string]string{"team": "platform"})
	workspace, err := NewWorkspaceIntent(metadata, WorkspaceSpec{SuspendReconciliation: true})
	if err != nil {
		t.Fatalf("NewWorkspaceIntent() error = %v", err)
	}
	environment, err := NewEnvironmentIntent(metadata, EnvironmentSpec{})
	if err != nil {
		t.Fatalf("NewEnvironmentIntent() error = %v", err)
	}
	application, err := NewApplicationIntent(metadata, ApplicationSpec{})
	if err != nil {
		t.Fatalf("NewApplicationIntent() error = %v", err)
	}
	component, err := NewComponentIntent(metadata, ComponentSpec{})
	if err != nil {
		t.Fatalf("NewComponentIntent() error = %v", err)
	}
	policySpec := validModelPolicySpec()
	policy, err := NewPolicyIntent(metadata, policySpec)
	if err != nil {
		t.Fatalf("NewPolicyIntent() error = %v", err)
	}
	connection, err := NewProviderConnectionIntent(metadata, validProviderSpec())
	if err != nil {
		t.Fatalf("NewProviderConnectionIntent() error = %v", err)
	}

	tests := []struct {
		value Intent
		kind  hierarchy.Kind
	}{
		{workspace, hierarchy.KindWorkspace},
		{environment, hierarchy.KindEnvironment},
		{application, hierarchy.KindApplication},
		{component, hierarchy.KindComponent},
		{policy, hierarchy.KindPolicy},
		{connection, hierarchy.KindProviderConnection},
	}
	for _, test := range tests {
		if err := ValidateIntent(test.value); err != nil {
			t.Fatalf("ValidateIntent(%s) error = %v", test.kind, err)
		}
		if test.value.Kind() != test.kind {
			t.Fatalf("Intent.Kind() = %s, want %s", test.value.Kind(), test.kind)
		}
		clone := CloneIntent(test.value)
		if !EqualIntent(test.value, clone) {
			t.Fatalf("CloneIntent(%s) changed semantic value", test.kind)
		}
	}
	if EqualIntent(workspace, environment) {
		t.Fatal("different intent variants compared equal")
	}

	returnedLabels := workspace.Metadata().Labels()
	returnedLabels["team"] = "changed"
	if workspace.Metadata().Labels()["team"] != "platform" {
		t.Fatal("intent metadata accessor retained an alias")
	}

	invalidProvider, err := NewProviderConnectionIntent(metadata, ProviderConnectionSpec{})
	if !errors.Is(err, control.ErrInvalidProviderConnectionSpec) {
		t.Fatalf("NewProviderConnectionIntent(invalid) error = %v", err)
	}
	if invalidProvider != nil {
		t.Fatalf("NewProviderConnectionIntent(invalid) = %#v, want nil", invalidProvider)
	}
	invalidMetadata, err := NewWorkspaceIntent(WriteMetadata{}, WorkspaceSpec{})
	if !errors.Is(err, ErrInvalidWriteMetadata) {
		t.Fatalf("NewWorkspaceIntent(invalid metadata) error = %v", err)
	}
	if invalidMetadata != nil {
		t.Fatalf("NewWorkspaceIntent(invalid metadata) = %#v, want nil", invalidMetadata)
	}

	policySpec.Bindings[0].Role = authorization.RoleOperator
	if policy.Spec().Bindings[0].Role != authorization.RoleViewer {
		t.Fatal("NewPolicyIntent retained the caller's binding slice")
	}
	returnedPolicy := policy.Spec()
	returnedPolicy.Bindings[0].Role = authorization.RoleDeveloper
	if policy.Spec().Bindings[0].Role != authorization.RoleViewer {
		t.Fatal("PolicyIntent.Spec exposed the retained binding slice")
	}
}

func validModelPolicySpec() PolicySpec {
	return PolicySpec{Bindings: []authorization.RoleBinding{{
		MemberID: resource.ID("mem_01J00000000000000000000000"),
		Role:     authorization.RoleViewer,
		Scope:    authorization.Scope{Kind: authorization.ScopeKindWorkspace},
	}}}
}

func TestIntentTypedNilOperationsArePanicFree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		value  Intent
		kind   hierarchy.Kind
		access func()
	}{
		{"Workspace", (*WorkspaceIntent)(nil), hierarchy.KindWorkspace, func() { _ = (*WorkspaceIntent)(nil).Spec() }},
		{"Environment", (*EnvironmentIntent)(nil), hierarchy.KindEnvironment, func() { _ = (*EnvironmentIntent)(nil).Spec() }},
		{"Application", (*ApplicationIntent)(nil), hierarchy.KindApplication, func() { _ = (*ApplicationIntent)(nil).Spec() }},
		{"Component", (*ComponentIntent)(nil), hierarchy.KindComponent, func() { _ = (*ComponentIntent)(nil).Spec() }},
		{"Policy", (*PolicyIntent)(nil), hierarchy.KindPolicy, func() { _ = (*PolicyIntent)(nil).Spec() }},
		{"ProviderConnection", (*ProviderConnectionIntent)(nil), hierarchy.KindProviderConnection, func() {
			_ = (*ProviderConnectionIntent)(nil).Spec()
		}},
	}
	for _, test := range tests {
		if err := ValidateIntent(test.value); !errors.Is(err, ErrInvalidIntent) {
			t.Fatalf("ValidateIntent(%s typed nil) error = %v", test.name, err)
		}
		if clone := CloneIntent(test.value); clone != nil {
			t.Fatalf("CloneIntent(%s typed nil) = %#v, want nil", test.name, clone)
		}
		if EqualIntent(test.value, test.value) {
			t.Fatalf("invalid %s typed-nil intents compared equal", test.name)
		}
		if test.value.Kind() != test.kind {
			t.Fatalf("%s typed-nil Kind() = %s, want %s", test.name, test.value.Kind(), test.kind)
		}
		if got := test.value.Metadata(); got.DisplayName() != "" || got.Labels() != nil {
			t.Fatalf("%s typed-nil Metadata() = %#v, want zero", test.name, got)
		}
		test.access()
	}
	if !EqualIntent(nil, nil) {
		t.Fatal("nil intents did not compare equal")
	}
	zero := &WorkspaceIntent{}
	if CloneIntent(zero) != nil {
		t.Fatal("CloneIntent(public zero) did not reject the invalid value")
	}
	if EqualIntent(zero, zero) {
		t.Fatal("invalid public-zero intents compared equal")
	}
}

func TestCommonStatusValidationAndClone(t *testing.T) {
	t.Parallel()

	status := CommonStatus{
		ObservedGeneration: 1,
		Conditions: []condition.Condition{{
			Type:               "Ready",
			Status:             condition.StatusTrue,
			Reason:             "Observed",
			Message:            "Ready.",
			ObservedGeneration: 1,
			LastTransitionAt:   "2026-09-03T01:02:03.000Z",
		}},
	}
	if err := ValidateCommonStatus(status, 1); err != nil {
		t.Fatalf("ValidateCommonStatus(valid) error = %v", err)
	}
	if got := status.ObservedGenerations(); len(got) != 2 || got[0] != 1 || got[1] != 1 {
		t.Fatalf("ObservedGenerations() = %#v", got)
	}
	clone := CloneCommonStatus(status)
	clone.Conditions[0].Reason = "Changed"
	if status.Conditions[0].Reason != "Observed" {
		t.Fatal("CloneCommonStatus retained a condition slice alias")
	}
	if err := ValidateCommonStatus(CommonStatus{}, 1); !errors.Is(err, ErrObservationCollectionRequired) {
		t.Fatalf("ValidateCommonStatus(nil conditions) error = %v", err)
	}
	if err := ValidateCommonStatus(CommonStatus{ObservedGeneration: 2, Conditions: []condition.Condition{}}, 1); !errors.Is(err, ErrInvalidObservedGeneration) {
		t.Fatalf("ValidateCommonStatus(future) error = %v", err)
	}
	if err := ValidateCommonStatus(CommonStatus{Conditions: []condition.Condition{}}, 1); err != nil {
		t.Fatalf("ValidateCommonStatus(explicit empty) error = %v", err)
	}
}

func TestStatusWriteClosedSumAllKindsAndAliases(t *testing.T) {
	t.Parallel()

	common := CommonStatus{ObservedGeneration: 0, Conditions: []condition.Condition{}}
	workspace, err := NewWorkspaceStatusWrite(common, 1)
	if err != nil {
		t.Fatalf("NewWorkspaceStatusWrite() error = %v", err)
	}
	environment, err := NewEnvironmentStatusWrite(common, 1)
	if err != nil {
		t.Fatalf("NewEnvironmentStatusWrite() error = %v", err)
	}
	application, err := NewApplicationStatusWrite(common, 1)
	if err != nil {
		t.Fatalf("NewApplicationStatusWrite() error = %v", err)
	}
	component, err := NewComponentStatusWrite(common, 1)
	if err != nil {
		t.Fatalf("NewComponentStatusWrite() error = %v", err)
	}
	policy, err := NewPolicyStatusWrite(PolicyStatus{ObservedGeneration: 0, Conditions: []condition.Condition{}}, 1)
	if err != nil {
		t.Fatalf("NewPolicyStatusWrite() error = %v", err)
	}
	requested, available := "3", "10"
	providerStatus := ProviderConnectionStatus{
		ObservedGeneration: 1,
		Conditions:         []condition.Condition{},
		Capabilities: []ProviderCapability{{
			Name: "compute.instances", State: CapabilitySupported, Source: "provider-observation",
			ObservedAt: "2026-09-03T01:02:03.000Z", Reason: "CapabilityDiscovered",
		}},
		QuotaChecks: []QuotaCheck{{
			Name: "compute.instances", State: QuotaWithinLimit, Requested: &requested, Available: &available,
			Source: "provider-observation", ObservedAt: "2026-09-03T01:02:03.000Z", Reason: "QuotaAvailable",
		}},
	}
	connection, err := NewProviderConnectionStatusWrite(providerStatus, 1)
	if err != nil {
		t.Fatalf("NewProviderConnectionStatusWrite() error = %v", err)
	}

	tests := []struct {
		value StatusWrite
		kind  hierarchy.Kind
	}{
		{workspace, hierarchy.KindWorkspace},
		{environment, hierarchy.KindEnvironment},
		{application, hierarchy.KindApplication},
		{component, hierarchy.KindComponent},
		{policy, hierarchy.KindPolicy},
		{connection, hierarchy.KindProviderConnection},
	}
	for _, test := range tests {
		if err := ValidateStatusWrite(test.value, 1); err != nil {
			t.Fatalf("ValidateStatusWrite(%s) error = %v", test.kind, err)
		}
		if test.value.Kind() != test.kind {
			t.Fatalf("StatusWrite.Kind() = %s, want %s", test.value.Kind(), test.kind)
		}
		clone := CloneStatusWrite(test.value)
		if !EqualStatusWrite(test.value, clone) {
			t.Fatalf("CloneStatusWrite(%s) changed semantic value", test.kind)
		}
	}
	secondGeneration, err := NewWorkspaceStatusWrite(common, 2)
	if err != nil {
		t.Fatalf("NewWorkspaceStatusWrite(generation 2) error = %v", err)
	}
	if EqualStatusWrite(workspace, secondGeneration) {
		t.Fatal("status writes admitted against different generations compared equal")
	}
	if err := ValidateStatusWrite(workspace, 2); !errors.Is(err, ErrInvalidStatusWrite) {
		t.Fatalf("ValidateStatusWrite(generation mismatch) error = %v", err)
	}

	providerClone := connection.Status()
	*providerClone.QuotaChecks[0].Requested = "9"
	if *connection.Status().QuotaChecks[0].Requested != "3" {
		t.Fatal("ProviderConnectionStatusWrite.Status retained a decimal pointer alias")
	}

	statusNilTests := []struct {
		name   string
		value  StatusWrite
		kind   hierarchy.Kind
		access func()
	}{
		{"Workspace", (*WorkspaceStatusWrite)(nil), hierarchy.KindWorkspace, func() { _ = (*WorkspaceStatusWrite)(nil).Status() }},
		{"Environment", (*EnvironmentStatusWrite)(nil), hierarchy.KindEnvironment, func() { _ = (*EnvironmentStatusWrite)(nil).Status() }},
		{"Application", (*ApplicationStatusWrite)(nil), hierarchy.KindApplication, func() { _ = (*ApplicationStatusWrite)(nil).Status() }},
		{"Component", (*ComponentStatusWrite)(nil), hierarchy.KindComponent, func() { _ = (*ComponentStatusWrite)(nil).Status() }},
		{"Policy", (*PolicyStatusWrite)(nil), hierarchy.KindPolicy, func() { _ = (*PolicyStatusWrite)(nil).Status() }},
		{"ProviderConnection", (*ProviderConnectionStatusWrite)(nil), hierarchy.KindProviderConnection, func() {
			_ = (*ProviderConnectionStatusWrite)(nil).Status()
		}},
	}
	for _, test := range statusNilTests {
		if err := ValidateStatusWrite(test.value, 1); !errors.Is(err, ErrInvalidStatusWrite) {
			t.Fatalf("ValidateStatusWrite(%s typed nil) error = %v", test.name, err)
		}
		if CloneStatusWrite(test.value) != nil {
			t.Fatalf("CloneStatusWrite(%s typed nil) did not return nil", test.name)
		}
		if EqualStatusWrite(test.value, test.value) {
			t.Fatalf("invalid %s typed-nil status writes compared equal", test.name)
		}
		if test.value.Kind() != test.kind {
			t.Fatalf("%s typed-nil Kind() = %s, want %s", test.name, test.value.Kind(), test.kind)
		}
		if test.value.ObservedGenerations() != nil {
			t.Fatalf("%s typed-nil ObservedGenerations() = %#v, want nil", test.name, test.value.ObservedGenerations())
		}
		if test.value.ResourceGeneration() != 0 {
			t.Fatalf("%s typed-nil ResourceGeneration() = %d, want zero", test.name, test.value.ResourceGeneration())
		}
		test.access()
	}
	zero := &WorkspaceStatusWrite{}
	if CloneStatusWrite(zero) != nil {
		t.Fatal("CloneStatusWrite(public zero) did not reject the invalid value")
	}
	if EqualStatusWrite(zero, zero) {
		t.Fatal("invalid public-zero status writes compared equal")
	}

	invalid, err := NewWorkspaceStatusWrite(CommonStatus{}, 1)
	if !errors.Is(err, ErrInvalidCommonStatus) {
		t.Fatalf("NewWorkspaceStatusWrite(invalid status) error = %v", err)
	}
	if invalid != nil {
		t.Fatalf("NewWorkspaceStatusWrite(invalid status) = %#v, want nil", invalid)
	}
}

func validProviderSpec() ProviderConnectionSpec {
	return ProviderConnectionSpec{
		Provider: "aws",
		CredentialRef: CredentialReference{
			ReferenceID: validCredentialID,
			Version:     "current",
		},
	}
}

func mustWriteMetadata(t *testing.T, displayName string, labels map[string]string) WriteMetadata {
	t.Helper()
	metadata, err := NewWriteMetadata(displayName, labels)
	if err != nil {
		t.Fatalf("NewWriteMetadata() error = %v", err)
	}
	return metadata
}
