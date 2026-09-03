package v1alpha1

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"maps"
	"os"
	"reflect"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/model"
)

const validCredentialID = "cred_01J0000000000000000000000"

func TestWorkspaceWriteFixturesHaveSemanticDefaultRoundTrip(t *testing.T) {
	t.Parallel()

	var baseline model.Intent
	for _, name := range []string{"workspace-omitted-write.json", "workspace-explicit-false-write.json"} {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", name, err)
		}
		var source WorkspaceWrite
		if err := jsonv2.Unmarshal(data, &source, jsonv2.RejectUnknownMembers(true)); err != nil {
			t.Fatalf("Unmarshal(%s) error = %v", name, err)
		}
		hub, err := ToHubWorkspaceIntent(DefaultWorkspaceWrite(source))
		if err != nil {
			t.Fatalf("ToHubWorkspaceIntent(%s) error = %v", name, err)
		}
		canonical, err := FromHubWorkspaceIntent(hub)
		if err != nil {
			t.Fatalf("FromHubWorkspaceIntent(%s) error = %v", name, err)
		}
		if canonical.Spec.SuspendReconciliation == nil || *canonical.Spec.SuspendReconciliation {
			t.Fatalf("canonical %s Workspace spec = %#v, want explicit false", name, canonical.Spec)
		}
		if baseline != nil && !model.EqualIntent(baseline, hub) {
			t.Fatalf("%s did not default to the omitted fixture's hub meaning", name)
		}
		baseline = hub
	}
}

func TestWorkspaceDefaultingIsPureDeterministicAndIdempotent(t *testing.T) {
	t.Parallel()

	labels := map[string]string{"team": "platform"}
	source := WorkspaceWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindWorkspace.String(),
		Metadata:   WriteMetadata{DisplayName: "payments", Labels: labels},
		Spec:       WorkspaceWriteSpec{},
	}
	first := DefaultWorkspaceWrite(source)
	second := DefaultWorkspaceWrite(first)
	if first.Spec.SuspendReconciliation == nil || *first.Spec.SuspendReconciliation {
		t.Fatalf("omitted default = %#v, want explicit false", first.Spec)
	}
	if second.Spec.SuspendReconciliation == nil || *second.Spec.SuspendReconciliation {
		t.Fatalf("second default = %#v, want explicit false", second.Spec)
	}
	if source.Spec.SuspendReconciliation != nil {
		t.Fatal("DefaultWorkspaceWrite mutated the source spec")
	}
	first.Metadata.Labels["team"] = "changed"
	if labels["team"] != "platform" {
		t.Fatal("DefaultWorkspaceWrite retained a label map alias")
	}
	*first.Spec.SuspendReconciliation = true
	if *second.Spec.SuspendReconciliation {
		t.Fatal("repeated defaulting retained a boolean pointer alias")
	}

	for _, value := range []bool{false, true} {
		value := value
		explicit := WorkspaceWriteSpec{SuspendReconciliation: &value}
		defaulted := DefaultWorkspaceWriteSpec(explicit)
		if defaulted.SuspendReconciliation == nil || *defaulted.SuspendReconciliation != value {
			t.Fatalf("DefaultWorkspaceWriteSpec(%t) = %#v", value, defaulted)
		}
		*defaulted.SuspendReconciliation = !value
		if *explicit.SuspendReconciliation != value {
			t.Fatal("DefaultWorkspaceWriteSpec retained an input pointer alias")
		}
	}
}

func TestClosedSpecDefaultingIsPureAndIdempotent(t *testing.T) {
	t.Parallel()

	metadata := validMetadata()
	assertNoOpDefaulting(t, EnvironmentWrite{
		APIVersion: APIVersion, Kind: hierarchy.KindEnvironment.String(), Metadata: metadata, Spec: EnvironmentSpec{},
	}, DefaultEnvironmentWrite)
	assertNoOpDefaulting(t, ApplicationWrite{
		APIVersion: APIVersion, Kind: hierarchy.KindApplication.String(), Metadata: metadata, Spec: ApplicationSpec{},
	}, DefaultApplicationWrite)
	assertNoOpDefaulting(t, ComponentWrite{
		APIVersion: APIVersion, Kind: hierarchy.KindComponent.String(), Metadata: metadata, Spec: ComponentSpec{},
	}, DefaultComponentWrite)
	assertNoOpDefaulting(t, PolicyWrite{
		APIVersion: APIVersion, Kind: hierarchy.KindPolicy.String(), Metadata: metadata, Spec: PolicySpec{},
	}, DefaultPolicyWrite)
	assertNoOpDefaulting(t, ProviderConnectionWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindProviderConnection.String(),
		Metadata:   metadata,
		Spec:       validProviderConnectionWrite().Spec,
	}, DefaultProviderConnectionWrite)
}

func TestIntentConversionsRoundTripThroughUnversionedHub(t *testing.T) {
	t.Parallel()

	workspaceSource := DefaultWorkspaceWrite(WorkspaceWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindWorkspace.String(),
		Metadata:   validMetadata(),
		Spec:       WorkspaceWriteSpec{},
	})
	environmentSource := validEnvironmentWrite()
	applicationSource := validApplicationWrite()
	componentSource := validComponentWrite()
	policySource := validPolicyWrite()
	providerSource := validProviderConnectionWrite()

	tests := []struct {
		name      string
		toHub     func() (model.Intent, error)
		roundTrip func(model.Intent) (model.Intent, error)
		kind      hierarchy.Kind
	}{
		{
			name:  "Workspace",
			toHub: func() (model.Intent, error) { return ToHubWorkspaceIntent(workspaceSource) },
			roundTrip: func(intent model.Intent) (model.Intent, error) {
				source, err := FromHubWorkspaceIntent(intent.(*model.WorkspaceIntent))
				if err != nil {
					return nil, err
				}
				if source.Spec.SuspendReconciliation == nil || *source.Spec.SuspendReconciliation {
					t.Fatalf("Workspace hub output = %#v, want explicit false", source.Spec)
				}
				if !reflect.DeepEqual(source, workspaceSource) {
					t.Fatalf("Workspace first hub conversion changed source: got %#v, want %#v", source, workspaceSource)
				}
				return ToHubWorkspaceIntent(source)
			},
			kind: hierarchy.KindWorkspace,
		},
		{
			name:  "Environment",
			toHub: func() (model.Intent, error) { return ToHubEnvironmentIntent(environmentSource) },
			roundTrip: func(intent model.Intent) (model.Intent, error) {
				source, err := FromHubEnvironmentIntent(intent.(*model.EnvironmentIntent))
				if err != nil {
					return nil, err
				}
				if !reflect.DeepEqual(source, environmentSource) {
					t.Fatalf("Environment first hub conversion changed source: got %#v, want %#v", source, environmentSource)
				}
				return ToHubEnvironmentIntent(source)
			},
			kind: hierarchy.KindEnvironment,
		},
		{
			name:  "Application",
			toHub: func() (model.Intent, error) { return ToHubApplicationIntent(applicationSource) },
			roundTrip: func(intent model.Intent) (model.Intent, error) {
				source, err := FromHubApplicationIntent(intent.(*model.ApplicationIntent))
				if err != nil {
					return nil, err
				}
				if !reflect.DeepEqual(source, applicationSource) {
					t.Fatalf("Application first hub conversion changed source: got %#v, want %#v", source, applicationSource)
				}
				return ToHubApplicationIntent(source)
			},
			kind: hierarchy.KindApplication,
		},
		{
			name:  "Component",
			toHub: func() (model.Intent, error) { return ToHubComponentIntent(componentSource) },
			roundTrip: func(intent model.Intent) (model.Intent, error) {
				source, err := FromHubComponentIntent(intent.(*model.ComponentIntent))
				if err != nil {
					return nil, err
				}
				if !reflect.DeepEqual(source, componentSource) {
					t.Fatalf("Component first hub conversion changed source: got %#v, want %#v", source, componentSource)
				}
				return ToHubComponentIntent(source)
			},
			kind: hierarchy.KindComponent,
		},
		{
			name:  "Policy",
			toHub: func() (model.Intent, error) { return ToHubPolicyIntent(policySource) },
			roundTrip: func(intent model.Intent) (model.Intent, error) {
				source, err := FromHubPolicyIntent(intent.(*model.PolicyIntent))
				if err != nil {
					return nil, err
				}
				if !reflect.DeepEqual(source, policySource) {
					t.Fatalf("Policy first hub conversion changed source: got %#v, want %#v", source, policySource)
				}
				return ToHubPolicyIntent(source)
			},
			kind: hierarchy.KindPolicy,
		},
		{
			name: "ProviderConnection",
			toHub: func() (model.Intent, error) {
				return ToHubProviderConnectionIntent(providerSource)
			},
			roundTrip: func(intent model.Intent) (model.Intent, error) {
				source, err := FromHubProviderConnectionIntent(intent.(*model.ProviderConnectionIntent))
				if err != nil {
					return nil, err
				}
				if !reflect.DeepEqual(source, providerSource) {
					t.Fatalf("ProviderConnection first hub conversion changed source: got %#v, want %#v", source, providerSource)
				}
				return ToHubProviderConnectionIntent(source)
			},
			kind: hierarchy.KindProviderConnection,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			first, err := test.toHub()
			if err != nil {
				t.Fatalf("ToHub%sIntent() error = %v", test.name, err)
			}
			if first.Kind() != test.kind {
				t.Fatalf("hub kind = %s, want %s", first.Kind(), test.kind)
			}
			second, err := test.roundTrip(first)
			if err != nil {
				t.Fatalf("%s hub round trip error = %v", test.name, err)
			}
			if !model.EqualIntent(first, second) {
				t.Fatalf("%s hub round trip changed meaning", test.name)
			}
		})
	}
}

func TestStatusConversionsRoundTripAndDoNotAlias(t *testing.T) {
	t.Parallel()

	conditionValue := condition.Condition{
		Type: "Ready", Status: condition.StatusTrue, Reason: "Observed", Message: "ready",
		ObservedGeneration: 2, LastTransitionAt: "2026-09-03T01:02:03.000Z",
	}
	common := CommonStatus{ObservedGeneration: 2, Conditions: []condition.Condition{conditionValue}}
	policy := PolicyStatus{ObservedGeneration: 2, Conditions: []condition.Condition{conditionValue}}
	provider := validProviderStatus()
	provider.ObservedGeneration = 2
	provider.Conditions = []condition.Condition{conditionValue}
	const resourceGeneration int64 = 3
	tests := []struct {
		name      string
		toHub     func() (model.StatusWrite, error)
		roundTrip func(model.StatusWrite) (model.StatusWrite, error)
		read      func(model.StatusWrite) any
		want      any
	}{
		{
			name: "Workspace",
			toHub: func() (model.StatusWrite, error) {
				return ToHubWorkspaceStatusWrite(WorkspaceStatusWrite{APIVersion: APIVersion, Kind: "Workspace", Status: common}, resourceGeneration)
			},
			roundTrip: func(write model.StatusWrite) (model.StatusWrite, error) {
				source, err := FromHubWorkspaceStatusWrite(write.(*model.WorkspaceStatusWrite))
				if err != nil {
					return nil, err
				}
				return ToHubWorkspaceStatusWrite(source, resourceGeneration)
			},
			read: func(write model.StatusWrite) any { return write.(*model.WorkspaceStatusWrite).Status() },
			want: model.CommonStatus(common),
		},
		{
			name: "Environment",
			toHub: func() (model.StatusWrite, error) {
				return ToHubEnvironmentStatusWrite(EnvironmentStatusWrite{APIVersion: APIVersion, Kind: "Environment", Status: common}, resourceGeneration)
			},
			roundTrip: func(write model.StatusWrite) (model.StatusWrite, error) {
				source, err := FromHubEnvironmentStatusWrite(write.(*model.EnvironmentStatusWrite))
				if err != nil {
					return nil, err
				}
				return ToHubEnvironmentStatusWrite(source, resourceGeneration)
			},
			read: func(write model.StatusWrite) any { return write.(*model.EnvironmentStatusWrite).Status() },
			want: model.CommonStatus(common),
		},
		{
			name: "Application",
			toHub: func() (model.StatusWrite, error) {
				return ToHubApplicationStatusWrite(ApplicationStatusWrite{APIVersion: APIVersion, Kind: "Application", Status: common}, resourceGeneration)
			},
			roundTrip: func(write model.StatusWrite) (model.StatusWrite, error) {
				source, err := FromHubApplicationStatusWrite(write.(*model.ApplicationStatusWrite))
				if err != nil {
					return nil, err
				}
				return ToHubApplicationStatusWrite(source, resourceGeneration)
			},
			read: func(write model.StatusWrite) any { return write.(*model.ApplicationStatusWrite).Status() },
			want: model.CommonStatus(common),
		},
		{
			name: "Component",
			toHub: func() (model.StatusWrite, error) {
				return ToHubComponentStatusWrite(ComponentStatusWrite{APIVersion: APIVersion, Kind: "Component", Status: common}, resourceGeneration)
			},
			roundTrip: func(write model.StatusWrite) (model.StatusWrite, error) {
				source, err := FromHubComponentStatusWrite(write.(*model.ComponentStatusWrite))
				if err != nil {
					return nil, err
				}
				return ToHubComponentStatusWrite(source, resourceGeneration)
			},
			read: func(write model.StatusWrite) any { return write.(*model.ComponentStatusWrite).Status() },
			want: model.CommonStatus(common),
		},
		{
			name: "Policy",
			toHub: func() (model.StatusWrite, error) {
				return ToHubPolicyStatusWrite(PolicyStatusWrite{
					APIVersion: APIVersion, Kind: "Policy",
					Status: policy,
				}, resourceGeneration)
			},
			roundTrip: func(write model.StatusWrite) (model.StatusWrite, error) {
				source, err := FromHubPolicyStatusWrite(write.(*model.PolicyStatusWrite))
				if err != nil {
					return nil, err
				}
				return ToHubPolicyStatusWrite(source, resourceGeneration)
			},
			read: func(write model.StatusWrite) any { return write.(*model.PolicyStatusWrite).Status() },
			want: model.PolicyStatus(policy),
		},
		{
			name: "ProviderConnection",
			toHub: func() (model.StatusWrite, error) {
				return ToHubProviderConnectionStatusWrite(ProviderConnectionStatusWrite{
					APIVersion: APIVersion, Kind: "ProviderConnection", Status: provider,
				}, resourceGeneration)
			},
			roundTrip: func(write model.StatusWrite) (model.StatusWrite, error) {
				source, err := FromHubProviderConnectionStatusWrite(write.(*model.ProviderConnectionStatusWrite))
				if err != nil {
					return nil, err
				}
				return ToHubProviderConnectionStatusWrite(source, resourceGeneration)
			},
			read: func(write model.StatusWrite) any { return write.(*model.ProviderConnectionStatusWrite).Status() },
			want: model.ProviderConnectionStatus(provider),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			first, err := test.toHub()
			if err != nil {
				t.Fatalf("ToHub%sStatusWrite() error = %v", test.name, err)
			}
			if first.ResourceGeneration() != resourceGeneration {
				t.Fatalf("%s hub resource generation = %d, want %d", test.name, first.ResourceGeneration(), resourceGeneration)
			}
			if got := test.read(first); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("%s first hub status = %#v, want %#v", test.name, got, test.want)
			}
			second, err := test.roundTrip(first)
			if err != nil {
				t.Fatalf("%s status round trip error = %v", test.name, err)
			}
			if !model.EqualStatusWrite(first, second) {
				t.Fatalf("%s status hub round trip changed meaning", test.name)
			}
		})
	}
}

func TestConversionsDoNotRetainOrExposeMutableSourceState(t *testing.T) {
	t.Parallel()

	workspaceSource := DefaultWorkspaceWrite(WorkspaceWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindWorkspace.String(),
		Metadata:   validMetadata(),
	})
	workspaceHub, err := ToHubWorkspaceIntent(workspaceSource)
	if err != nil {
		t.Fatalf("ToHubWorkspaceIntent() error = %v", err)
	}
	workspaceSource.Metadata.Labels["team"] = "changed"
	*workspaceSource.Spec.SuspendReconciliation = true
	if workspaceHub.Metadata().Labels()["team"] != "platform" || workspaceHub.Spec().SuspendReconciliation {
		t.Fatal("Workspace hub retained mutable source aliases")
	}
	workspaceOutput, err := FromHubWorkspaceIntent(workspaceHub)
	if err != nil {
		t.Fatalf("FromHubWorkspaceIntent() error = %v", err)
	}
	workspaceOutput.Metadata.Labels["team"] = "changed-again"
	*workspaceOutput.Spec.SuspendReconciliation = true
	if workspaceHub.Metadata().Labels()["team"] != "platform" || workspaceHub.Spec().SuspendReconciliation {
		t.Fatal("Workspace source conversion exposed mutable hub aliases")
	}

	providerSource := ProviderConnectionStatusWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindProviderConnection.String(),
		Status:     validProviderStatus(),
	}
	providerHub, err := ToHubProviderConnectionStatusWrite(providerSource, 1)
	if err != nil {
		t.Fatalf("ToHubProviderConnectionStatusWrite() error = %v", err)
	}
	*providerSource.Status.QuotaChecks[0].Requested = "9"
	providerSource.Status.Capabilities[0].Name = "changed"
	if got := providerHub.Status(); *got.QuotaChecks[0].Requested != "3" || got.Capabilities[0].Name != "compute.instances" {
		t.Fatal("ProviderConnection hub retained mutable source aliases")
	}
	providerOutput, err := FromHubProviderConnectionStatusWrite(providerHub)
	if err != nil {
		t.Fatalf("FromHubProviderConnectionStatusWrite() error = %v", err)
	}
	*providerOutput.Status.QuotaChecks[0].Requested = "8"
	providerOutput.Status.Capabilities[0].Name = "changed-again"
	if got := providerHub.Status(); *got.QuotaChecks[0].Requested != "3" || got.Capabilities[0].Name != "compute.instances" {
		t.Fatal("ProviderConnection source conversion exposed mutable hub aliases")
	}
}

func TestConversionRejectsNoncanonicalSourceIdentityAndNilHub(t *testing.T) {
	t.Parallel()

	workspace := WorkspaceWrite{APIVersion: APIVersion, Kind: "Workspace", Metadata: validMetadata()}
	if _, err := ToHubWorkspaceIntent(workspace); !errors.Is(err, ErrSourceNotDefaulted) {
		t.Fatalf("ToHubWorkspaceIntent(nondefaulted) error = %v", err)
	}
	workspace = DefaultWorkspaceWrite(workspace)
	workspace.APIVersion = "v1beta1"
	if _, err := ToHubWorkspaceIntent(workspace); !errors.Is(err, hierarchy.ErrUnsupportedAPIVersion) {
		t.Fatalf("ToHubWorkspaceIntent(version) error = %v", err)
	}
	workspace.APIVersion = APIVersion
	workspace.Kind = "Environment"
	if _, err := ToHubWorkspaceIntent(workspace); !errors.Is(err, ErrSourceKindMismatch) {
		t.Fatalf("ToHubWorkspaceIntent(kind) error = %v", err)
	}
	if _, err := FromHubWorkspaceIntent(nil); !errors.Is(err, ErrNilHubValue) || !errors.Is(err, ErrInvalidHubValue) {
		t.Fatalf("FromHubWorkspaceIntent(nil) error = %v", err)
	}

	invalidProvider := validProviderConnectionWrite()
	invalidProvider.Spec = ProviderConnectionSpec{}
	providerHub, err := ToHubProviderConnectionIntent(invalidProvider)
	if providerHub != nil || !errors.Is(err, ErrInvalidSource) || !errors.Is(err, model.ErrInvalidIntent) {
		t.Fatalf("ToHubProviderConnectionIntent(invalid) = %#v, %v", providerHub, err)
	}
	statusHub, err := ToHubWorkspaceStatusWrite(WorkspaceStatusWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindWorkspace.String(),
		Status:     CommonStatus{},
	}, 1)
	if statusHub != nil || !errors.Is(err, ErrInvalidSource) || !errors.Is(err, model.ErrInvalidStatusWrite) {
		t.Fatalf("ToHubWorkspaceStatusWrite(invalid) = %#v, %v", statusHub, err)
	}
}

func TestConversionRejectsPublicZeroHubValues(t *testing.T) {
	t.Parallel()

	intentTests := []struct {
		name    string
		convert func() error
	}{
		{"Workspace", func() error { _, err := FromHubWorkspaceIntent(&model.WorkspaceIntent{}); return err }},
		{"Environment", func() error { _, err := FromHubEnvironmentIntent(&model.EnvironmentIntent{}); return err }},
		{"Application", func() error { _, err := FromHubApplicationIntent(&model.ApplicationIntent{}); return err }},
		{"Component", func() error { _, err := FromHubComponentIntent(&model.ComponentIntent{}); return err }},
		{"Policy", func() error { _, err := FromHubPolicyIntent(&model.PolicyIntent{}); return err }},
		{"ProviderConnection", func() error {
			_, err := FromHubProviderConnectionIntent(&model.ProviderConnectionIntent{})
			return err
		}},
	}
	for _, test := range intentTests {
		if err := test.convert(); !errors.Is(err, ErrInvalidHubValue) {
			t.Fatalf("FromHub%sIntent(zero) error = %v", test.name, err)
		}
	}

	statusTests := []struct {
		name    string
		convert func() error
	}{
		{"Workspace", func() error { _, err := FromHubWorkspaceStatusWrite(&model.WorkspaceStatusWrite{}); return err }},
		{"Environment", func() error { _, err := FromHubEnvironmentStatusWrite(&model.EnvironmentStatusWrite{}); return err }},
		{"Application", func() error { _, err := FromHubApplicationStatusWrite(&model.ApplicationStatusWrite{}); return err }},
		{"Component", func() error { _, err := FromHubComponentStatusWrite(&model.ComponentStatusWrite{}); return err }},
		{"Policy", func() error { _, err := FromHubPolicyStatusWrite(&model.PolicyStatusWrite{}); return err }},
		{"ProviderConnection", func() error {
			_, err := FromHubProviderConnectionStatusWrite(&model.ProviderConnectionStatusWrite{})
			return err
		}},
	}
	for _, test := range statusTests {
		if err := test.convert(); !errors.Is(err, ErrInvalidHubValue) {
			t.Fatalf("FromHub%sStatusWrite(zero) error = %v", test.name, err)
		}
	}
}

func FuzzWorkspaceDefaultAndHubRoundTrip(f *testing.F) {
	f.Add(false, false)
	f.Add(true, false)
	f.Add(true, true)
	f.Fuzz(func(t *testing.T, explicit, value bool) {
		var pointer *bool
		if explicit {
			valueCopy := value
			pointer = &valueCopy
		}
		source := WorkspaceWrite{
			APIVersion: APIVersion,
			Kind:       hierarchy.KindWorkspace.String(),
			Metadata:   validMetadata(),
			Spec:       WorkspaceWriteSpec{SuspendReconciliation: pointer},
		}
		defaulted := DefaultWorkspaceWrite(source)
		hub, err := ToHubWorkspaceIntent(defaulted)
		if err != nil {
			t.Fatalf("ToHubWorkspaceIntent() error = %v", err)
		}
		roundTrip, err := FromHubWorkspaceIntent(hub)
		if err != nil {
			t.Fatalf("FromHubWorkspaceIntent() error = %v", err)
		}
		hubAgain, err := ToHubWorkspaceIntent(roundTrip)
		if err != nil {
			t.Fatalf("second ToHubWorkspaceIntent() error = %v", err)
		}
		if !model.EqualIntent(hub, hubAgain) {
			t.Fatal("Workspace hub round trip changed meaning")
		}
	})
}

func validMetadata() WriteMetadata {
	return WriteMetadata{DisplayName: "payments", Labels: map[string]string{"team": "platform"}}
}

func validEnvironmentWrite() EnvironmentWrite {
	return EnvironmentWrite{APIVersion: APIVersion, Kind: "Environment", Metadata: validMetadata(), Spec: EnvironmentSpec{}}
}

func validApplicationWrite() ApplicationWrite {
	return ApplicationWrite{APIVersion: APIVersion, Kind: "Application", Metadata: validMetadata(), Spec: ApplicationSpec{}}
}

func validComponentWrite() ComponentWrite {
	return ComponentWrite{APIVersion: APIVersion, Kind: "Component", Metadata: validMetadata(), Spec: ComponentSpec{}}
}

func validPolicyWrite() PolicyWrite {
	return PolicyWrite{APIVersion: APIVersion, Kind: "Policy", Metadata: validMetadata(), Spec: PolicySpec{}}
}

func validProviderConnectionWrite() ProviderConnectionWrite {
	return ProviderConnectionWrite{
		APIVersion: APIVersion,
		Kind:       "ProviderConnection",
		Metadata:   validMetadata(),
		Spec: ProviderConnectionSpec{
			Provider: "aws",
			CredentialRef: model.CredentialReference{
				ReferenceID: validCredentialID,
				Version:     "current",
			},
		},
	}
}

func validProviderStatus() ProviderConnectionStatus {
	requested, available := "3", "10"
	return ProviderConnectionStatus{
		ObservedGeneration: 1,
		Conditions:         []condition.Condition{},
		Capabilities: []model.ProviderCapability{{
			Name: "compute.instances", State: model.CapabilitySupported, Source: "provider-observation",
			ObservedAt: "2026-09-03T01:02:03.000Z", Reason: "CapabilityDiscovered",
		}},
		QuotaChecks: []model.QuotaCheck{{
			Name: "compute.instances", State: model.QuotaWithinLimit, Requested: &requested, Available: &available,
			Source: "provider-observation", ObservedAt: "2026-09-03T01:02:03.000Z", Reason: "QuotaAvailable",
		}},
	}
}

func assertNoOpDefaulting[Spec comparable](
	t *testing.T,
	source DesiredWrite[Spec],
	defaultValue func(DesiredWrite[Spec]) DesiredWrite[Spec],
) {
	t.Helper()
	first := defaultValue(source)
	second := defaultValue(first)
	if first.APIVersion != source.APIVersion || first.Kind != source.Kind ||
		first.Metadata.DisplayName != source.Metadata.DisplayName || first.Spec != source.Spec ||
		!maps.Equal(first.Metadata.Labels, source.Metadata.Labels) {
		t.Fatalf("first default changed source meaning: got %#v, want %#v", first, source)
	}
	if second.APIVersion != first.APIVersion || second.Kind != first.Kind ||
		second.Metadata.DisplayName != first.Metadata.DisplayName || second.Spec != first.Spec ||
		!maps.Equal(second.Metadata.Labels, first.Metadata.Labels) {
		t.Fatalf("second default was not idempotent: got %#v, want %#v", second, first)
	}
	first.Metadata.Labels["team"] = "changed"
	if source.Metadata.Labels["team"] != "platform" || second.Metadata.Labels["team"] != "platform" {
		t.Fatal("defaulting retained a label map alias")
	}
}
