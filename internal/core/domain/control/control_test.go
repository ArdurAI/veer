package control

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	controlWorkspaceID   resource.ID = "wsp_01J00000000000000000000000"
	controlEnvironmentID resource.ID = "env_01J00000000000000000000000"
	policyID             resource.ID = "pol_01J00000000000000000000000"
	providerConnectionID resource.ID = "pvc_01J00000000000000000000000"
)

var controlFixtureTime = time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)

type controlFixtureSpec struct{}

type controlFixtureStatus struct {
	ObservedGeneration int64                 `json:"observedGeneration"`
	Conditions         []condition.Condition `json:"conditions"`
}

func (status controlFixtureStatus) ObservedGenerations() []int64 {
	return []int64{status.ObservedGeneration}
}

func TestProviderConnectionSpecAndCredentialReference(t *testing.T) {
	t.Parallel()

	valid := validProviderConnectionSpec()
	if err := ValidateProviderConnectionSpec(valid); err != nil {
		t.Fatalf("ValidateProviderConnectionSpec(valid) error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*ProviderConnectionSpec)
		want   error
	}{
		{name: "provider empty", mutate: func(spec *ProviderConnectionSpec) { spec.Provider = "" }, want: ErrInvalidProvider},
		{name: "provider uppercase", mutate: func(spec *ProviderConnectionSpec) { spec.Provider = "AWS" }, want: ErrInvalidProvider},
		{name: "provider path", mutate: func(spec *ProviderConnectionSpec) { spec.Provider = "aws/role" }, want: ErrInvalidProvider},
		{name: "reference empty", mutate: func(spec *ProviderConnectionSpec) { spec.CredentialRef.ReferenceID = "" }, want: ErrInvalidCredentialReference},
		{name: "reference URL", mutate: func(spec *ProviderConnectionSpec) { spec.CredentialRef.ReferenceID = "https://secret.example/value" }, want: ErrInvalidCredentialReference},
		{name: "reference path", mutate: func(spec *ProviderConnectionSpec) { spec.CredentialRef.ReferenceID = "../../secret/value" }, want: ErrInvalidCredentialReference},
		{name: "version empty", mutate: func(spec *ProviderConnectionSpec) { spec.CredentialRef.Version = "" }, want: ErrInvalidCredentialReference},
		{name: "version path", mutate: func(spec *ProviderConnectionSpec) { spec.CredentialRef.Version = "../latest" }, want: ErrInvalidCredentialReference},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			test.mutate(&candidate)
			err := ValidateProviderConnectionSpec(candidate)
			if !errors.Is(err, ErrInvalidProviderConnectionSpec) || !errors.Is(err, test.want) {
				t.Fatalf("ValidateProviderConnectionSpec() error = %v, want spec and %v", err, test.want)
			}
		})
	}
}

func TestProviderCapabilityStateMatrix(t *testing.T) {
	t.Parallel()

	for _, state := range []CapabilityState{
		CapabilitySupported,
		CapabilityUnsupported,
		CapabilityUnknown,
	} {
		capability := validCapability("compute.instances", state)
		if err := ValidateProviderCapability(capability); err != nil {
			t.Fatalf("ValidateProviderCapability(%q) error = %v", state, err)
		}
	}
	invalid := validCapability("compute.instances", "Maybe")
	if err := ValidateProviderCapability(invalid); !errors.Is(err, ErrInvalidCapabilityState) {
		t.Fatalf("ValidateProviderCapability(invalid state) error = %v", err)
	}
}

func TestQuotaKnownAndUnknownMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		quota QuotaCheck
		want  error
	}{
		{name: "within less", quota: knownQuota("3", "10", QuotaWithinLimit)},
		{name: "within equal", quota: knownQuota("10", "10", QuotaWithinLimit)},
		{name: "exceeded", quota: knownQuota("10.01", "10", QuotaExceeded)},
		{name: "unknown", quota: unknownQuota("network.load-balancers")},
		{name: "within contradiction", quota: knownQuota("11", "10", QuotaWithinLimit), want: ErrInvalidQuotaState},
		{name: "exceeded equal", quota: knownQuota("10", "10", QuotaExceeded), want: ErrInvalidQuotaState},
		{name: "known missing requested", quota: knownQuota("3", "10", QuotaWithinLimit), want: ErrInvalidQuotaState},
		{name: "unknown carries requested", quota: unknownQuota("network.load-balancers"), want: ErrInvalidQuotaState},
		{name: "noncanonical requested", quota: knownQuota("03", "10", QuotaWithinLimit), want: ErrInvalidDecimal},
		{name: "noncanonical available", quota: knownQuota("3", "10.0", QuotaWithinLimit), want: ErrInvalidDecimal},
	}
	tests[6].quota.Requested = nil
	tests[7].quota.Requested = decimalPointer("1")
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateQuotaCheck(test.quota)
			if test.want == nil {
				if err != nil {
					t.Fatalf("ValidateQuotaCheck() error = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidQuotaCheck) || !errors.Is(err, test.want) {
				t.Fatalf("ValidateQuotaCheck() error = %v, want quota and %v", err, test.want)
			}
		})
	}
}

func TestCostKnownAndUnknownMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		estimate CostEstimate
		want     error
	}{
		{name: "known low", estimate: knownCost("0", ConfidenceLow)},
		{name: "known medium", estimate: knownCost("12.34", ConfidenceMedium)},
		{name: "known high", estimate: knownCost("999999999.99", ConfidenceHigh)},
		{name: "unknown", estimate: unknownCost()},
		{name: "known amount missing", estimate: knownCost("1", ConfidenceHigh), want: ErrInvalidCostState},
		{name: "known confidence unknown", estimate: knownCost("1", ConfidenceUnknown), want: ErrInvalidCostState},
		{name: "unknown carries amount", estimate: unknownCost(), want: ErrInvalidCostState},
		{name: "unknown claims confidence", estimate: unknownCost(), want: ErrInvalidCostState},
		{name: "noncanonical amount", estimate: knownCost("1.20", ConfidenceHigh), want: ErrInvalidDecimal},
		{name: "bad currency", estimate: knownCost("1", ConfidenceHigh), want: ErrInvalidCostEstimate},
		{name: "bad region", estimate: knownCost("1", ConfidenceHigh), want: ErrInvalidCostEstimate},
	}
	tests[4].estimate.Amount = nil
	tests[6].estimate.Amount = decimalPointer("1")
	tests[7].estimate.Confidence = ConfidenceHigh
	tests[9].estimate.Currency = "usd"
	tests[10].estimate.Region = "US East 1"
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateCostEstimate(test.estimate)
			if test.want == nil {
				if err != nil {
					t.Fatalf("ValidateCostEstimate() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateCostEstimate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestObservationMetadataMatrix(t *testing.T) {
	t.Parallel()

	valid := validCapability("compute.instances", CapabilitySupported)
	yearZero := valid
	yearZero.ObservedAt = "0000-01-01T00:00:00.000Z"
	if err := ValidateProviderCapability(yearZero); err != nil {
		t.Fatalf("ValidateProviderCapability(year zero) error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*ProviderCapability)
		want   error
	}{
		{name: "name", mutate: func(value *ProviderCapability) { value.Name = "Compute Instances" }, want: ErrInvalidObservationName},
		{name: "source", mutate: func(value *ProviderCapability) { value.Source = "https://provider.example" }, want: ErrInvalidObservationSource},
		{name: "timestamp offset", mutate: func(value *ProviderCapability) { value.ObservedAt = "2026-09-03T01:02:03.000+00:00" }, want: ErrInvalidObservationTimestamp},
		{name: "timestamp precision", mutate: func(value *ProviderCapability) { value.ObservedAt = "2026-09-03T01:02:03Z" }, want: ErrInvalidObservationTimestamp},
		{name: "timestamp byte preflight", mutate: func(value *ProviderCapability) { value.ObservedAt = strings.Repeat("0", 1<<20) }, want: ErrInvalidObservationTimestamp},
		{name: "reason", mutate: func(value *ProviderCapability) { value.Reason = "provider error" }, want: ErrInvalidObservationReason},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			test.mutate(&candidate)
			err := ValidateProviderCapability(candidate)
			if !errors.Is(err, ErrInvalidProviderCapability) || !errors.Is(err, test.want) {
				t.Fatalf("ValidateProviderCapability() error = %v, want capability and %v", err, test.want)
			}
		})
	}
}

func TestPolicyStatusValidation(t *testing.T) {
	t.Parallel()

	valid := PolicyStatus{ObservedGeneration: 0, Conditions: []condition.Condition{}}
	if err := ValidatePolicyStatus(valid, 1); err != nil {
		t.Fatalf("ValidatePolicyStatus(valid) error = %v", err)
	}
	if err := ValidatePolicyStatus(PolicyStatus{}, 1); !errors.Is(err, ErrObservationCollectionRequired) {
		t.Fatalf("ValidatePolicyStatus(nil conditions) error = %v", err)
	}
	valid.ObservedGeneration = 2
	if err := ValidatePolicyStatus(valid, 1); !errors.Is(err, ErrInvalidObservationGeneration) {
		t.Fatalf("ValidatePolicyStatus(future) error = %v", err)
	}
}

func TestProviderConnectionStatusOrderingBoundsAndClone(t *testing.T) {
	t.Parallel()

	valid := validProviderConnectionStatus()
	if err := ValidateProviderConnectionStatus(valid, 1); err != nil {
		t.Fatalf("ValidateProviderConnectionStatus(valid) error = %v", err)
	}

	unsortedCapabilities := CloneProviderConnectionStatus(valid)
	unsortedCapabilities.Capabilities[0], unsortedCapabilities.Capabilities[1] =
		unsortedCapabilities.Capabilities[1], unsortedCapabilities.Capabilities[0]
	if err := ValidateProviderConnectionStatus(unsortedCapabilities, 1); !errors.Is(err, ErrObservationOrder) {
		t.Fatalf("ValidateProviderConnectionStatus(unsorted capability) error = %v", err)
	}

	duplicateQuotas := CloneProviderConnectionStatus(valid)
	duplicateQuotas.QuotaChecks[1].Name = duplicateQuotas.QuotaChecks[0].Name
	if err := ValidateProviderConnectionStatus(duplicateQuotas, 1); !errors.Is(err, ErrDuplicateObservation) {
		t.Fatalf("ValidateProviderConnectionStatus(duplicate quota) error = %v", err)
	}

	tooManyCapabilities := CloneProviderConnectionStatus(valid)
	tooManyCapabilities.Capabilities = make([]ProviderCapability, MaxProviderCapabilities+1)
	if err := ValidateProviderConnectionStatus(tooManyCapabilities, 1); !errors.Is(err, ErrTooManyProviderCapabilities) {
		t.Fatalf("ValidateProviderConnectionStatus(capability bound) error = %v", err)
	}

	tooManyQuotas := CloneProviderConnectionStatus(valid)
	tooManyQuotas.QuotaChecks = make([]QuotaCheck, MaxQuotaChecks+1)
	if err := ValidateProviderConnectionStatus(tooManyQuotas, 1); !errors.Is(err, ErrTooManyQuotaChecks) {
		t.Fatalf("ValidateProviderConnectionStatus(quota bound) error = %v", err)
	}

	missing := valid
	missing.Capabilities = nil
	if err := ValidateProviderConnectionStatus(missing, 1); !errors.Is(err, ErrObservationCollectionRequired) {
		t.Fatalf("ValidateProviderConnectionStatus(nil capability set) error = %v", err)
	}
	missing = valid
	missing.QuotaChecks = nil
	missingClone := CloneProviderConnectionStatus(missing)
	if missingClone.QuotaChecks != nil {
		t.Fatal("CloneProviderConnectionStatus() changed nil quota checks to an empty collection")
	}
	if err := ValidateProviderConnectionStatus(missingClone, 1); !errors.Is(err, ErrObservationCollectionRequired) {
		t.Fatalf("ValidateProviderConnectionStatus(cloned nil quota set) error = %v", err)
	}

	clone := CloneProviderConnectionStatus(valid)
	clone.Capabilities[0].Reason = "Changed"
	*clone.QuotaChecks[0].Requested = "4"
	if valid.Capabilities[0].Reason == clone.Capabilities[0].Reason || *valid.QuotaChecks[0].Requested == "4" {
		t.Fatal("CloneProviderConnectionStatus() retained aliases")
	}
}

func TestCostCloneAndEquality(t *testing.T) {
	t.Parallel()

	original := knownCost("12.34", ConfidenceHigh)
	clone := CloneCostEstimate(original)
	if !EqualCostEstimate(original, clone) {
		t.Fatal("equal cost estimates differ")
	}
	*clone.Amount = "13"
	if EqualCostEstimate(original, clone) || *original.Amount != "12.34" {
		t.Fatal("cost clone retained an amount alias")
	}
	if EqualCostEstimate(unknownCost(), original) {
		t.Fatal("unknown and known costs compare equal")
	}
}

func TestControlResourceGoldensAndSecretRejection(t *testing.T) {
	t.Parallel()

	policy, connection := newControlResources(t)
	assertControlGolden(t, "policy", policy)
	assertControlGolden(t, "provider-connection", connection)

	data, err := resource.MarshalCanonical(connection)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	malformed := bytes.Replace(
		data,
		[]byte(`"credentialRef":{"referenceId":"cred_01J0000000000000000000000","version":"ver_01J00000000000000000000000"}`),
		[]byte(`"credentialRef":{"referenceId":"cred_01J0000000000000000000000","version":"ver_01J00000000000000000000000","secret":"CustomerSecretValue"}`),
		1,
	)
	if bytes.Equal(malformed, data) {
		t.Fatal("test failed to add a secret field")
	}
	_, err = resource.UnmarshalCanonical[ProviderConnectionSpec, ProviderConnectionStatus](malformed)
	if err == nil {
		t.Fatal("UnmarshalCanonical(embedded secret) unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "CustomerSecretValue") {
		t.Fatalf("decoder error contains rejected value: %q", err)
	}

	policyData, err := resource.MarshalCanonical(policy)
	if err != nil {
		t.Fatalf("MarshalCanonical(policy) error = %v", err)
	}
	policyWithRule := bytes.Replace(policyData, []byte(`"spec":{}`), []byte(`"spec":{"allow":"*"}`), 1)
	if _, err := resource.UnmarshalCanonical[PolicySpec, PolicyStatus](policyWithRule); err == nil {
		t.Fatal("UnmarshalCanonical(unadopted policy language) unexpectedly succeeded")
	}
}

func TestControlPlacementKinds(t *testing.T) {
	t.Parallel()

	rootPlacement, err := hierarchy.DeriveWorkspace(controlWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewPolicyResource(rootPlacement, hierarchy.CreateInput[PolicySpec, PolicyStatus]{
		DisplayName: "policy", ResourceVersion: "rv_policy", CreatedAt: controlFixtureTime,
		Spec: PolicySpec{}, Status: PolicyStatus{Conditions: []condition.Condition{}},
	})
	if !errors.Is(err, ErrInvalidControlPlacement) {
		t.Fatalf("NewPolicyResource(workspace placement) error = %v", err)
	}
}

func TestErrorsDoNotContainObservationValues(t *testing.T) {
	t.Parallel()

	sensitive := "customer-secret-observation"
	value := validCapability("compute.instances", CapabilitySupported)
	value.Source = sensitive + "/path"
	err := ValidateProviderCapability(value)
	if err == nil {
		t.Fatal("ValidateProviderCapability() unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatalf("error contains observation value: %q", err)
	}
}

func newControlResources(
	t *testing.T,
) (resource.Resource[PolicySpec, PolicyStatus], resource.Resource[ProviderConnectionSpec, ProviderConnectionStatus]) {
	t.Helper()

	rootPlacement, err := hierarchy.DeriveWorkspace(controlWorkspaceID)
	if err != nil {
		t.Fatalf("DeriveWorkspace() error = %v", err)
	}
	root, err := hierarchy.NewResource(rootPlacement, hierarchy.CreateInput[controlFixtureSpec, controlFixtureStatus]{
		DisplayName: "payments", ResourceVersion: "rv_root", CreatedAt: controlFixtureTime,
		Spec: controlFixtureSpec{}, Status: controlFixtureStatus{Conditions: []condition.Condition{}},
	})
	if err != nil {
		t.Fatalf("NewResource(root) error = %v", err)
	}
	rootRecord, err := hierarchy.RecordFrom(root.APIVersion(), root.Kind(), root.Metadata())
	if err != nil {
		t.Fatalf("RecordFrom(root) error = %v", err)
	}
	rootSnapshot, err := hierarchy.NewSnapshot(controlWorkspaceID, []hierarchy.Record{rootRecord})
	if err != nil {
		t.Fatalf("NewSnapshot(root) error = %v", err)
	}

	policyPlacement, err := rootSnapshot.DeriveChild(hierarchy.KindPolicy, policyID, controlWorkspaceID)
	if err != nil {
		t.Fatalf("DeriveChild(Policy) error = %v", err)
	}
	policy, err := NewPolicyResource(policyPlacement, hierarchy.CreateInput[PolicySpec, PolicyStatus]{
		DisplayName:     "workspace-defaults",
		Labels:          map[string]string{"team": "platform"},
		ResourceVersion: "rv_01J00000000000000000000010",
		CreatedAt:       controlFixtureTime.Add(time.Minute),
		Spec:            PolicySpec{},
		Status:          PolicyStatus{ObservedGeneration: 0, Conditions: []condition.Condition{}},
	})
	if err != nil {
		t.Fatalf("NewPolicyResource() error = %v", err)
	}

	environmentPlacement, err := rootSnapshot.DeriveChild(
		hierarchy.KindEnvironment,
		controlEnvironmentID,
		controlWorkspaceID,
	)
	if err != nil {
		t.Fatalf("DeriveChild(Environment) error = %v", err)
	}
	environment, err := hierarchy.NewResource(environmentPlacement, hierarchy.CreateInput[controlFixtureSpec, controlFixtureStatus]{
		DisplayName: "production", ResourceVersion: "rv_environment", CreatedAt: controlFixtureTime,
		Spec: controlFixtureSpec{}, Status: controlFixtureStatus{Conditions: []condition.Condition{}},
	})
	if err != nil {
		t.Fatalf("NewResource(environment) error = %v", err)
	}
	environmentRecord, err := hierarchy.RecordFrom(environment.APIVersion(), environment.Kind(), environment.Metadata())
	if err != nil {
		t.Fatalf("RecordFrom(environment) error = %v", err)
	}
	environmentSnapshot, err := hierarchy.NewSnapshot(
		controlWorkspaceID,
		[]hierarchy.Record{rootRecord, environmentRecord},
	)
	if err != nil {
		t.Fatalf("NewSnapshot(environment) error = %v", err)
	}
	connectionPlacement, err := environmentSnapshot.DeriveChild(
		hierarchy.KindProviderConnection,
		providerConnectionID,
		controlEnvironmentID,
	)
	if err != nil {
		t.Fatalf("DeriveChild(ProviderConnection) error = %v", err)
	}
	connection, err := NewProviderConnectionResource(
		connectionPlacement,
		hierarchy.CreateInput[ProviderConnectionSpec, ProviderConnectionStatus]{
			DisplayName:     "production-aws",
			Labels:          map[string]string{"provider": "aws", "team": "platform"},
			ResourceVersion: "rv_01J00000000000000000000020",
			CreatedAt:       controlFixtureTime.Add(2 * time.Minute),
			Spec:            validProviderConnectionSpec(),
			Status:          validProviderConnectionStatus(),
		},
	)
	if err != nil {
		t.Fatalf("NewProviderConnectionResource() error = %v", err)
	}
	return policy, connection
}

func assertControlGolden[Spec any, Status resource.GenerationObservations](
	t *testing.T,
	name string,
	value resource.Resource[Spec, Status],
) {
	t.Helper()
	want, err := os.ReadFile("testdata/" + name + ".golden.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	want = bytes.TrimSpace(want)
	got, err := resource.MarshalCanonical(value)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes:\n got %s\nwant %s", got, want)
	}
	restored, err := resource.UnmarshalCanonical[Spec, Status](want)
	if err != nil {
		t.Fatalf("UnmarshalCanonical() error = %v", err)
	}
	roundTrip, err := resource.MarshalCanonical(restored)
	if err != nil {
		t.Fatalf("round-trip MarshalCanonical() error = %v", err)
	}
	if !bytes.Equal(roundTrip, want) {
		t.Fatalf("round-trip bytes:\n got %s\nwant %s", roundTrip, want)
	}
}

func validProviderConnectionSpec() ProviderConnectionSpec {
	return ProviderConnectionSpec{
		Provider: "aws",
		CredentialRef: CredentialReference{
			ReferenceID: "cred_01J0000000000000000000000",
			Version:     "ver_01J00000000000000000000000",
		},
	}
}

func validProviderConnectionStatus() ProviderConnectionStatus {
	return ProviderConnectionStatus{
		ObservedGeneration: 1,
		Conditions:         []condition.Condition{},
		Capabilities: []ProviderCapability{
			validCapability("compute.instances", CapabilitySupported),
			validCapability("network.ingress", CapabilityUnknown),
		},
		QuotaChecks: []QuotaCheck{
			knownQuota("3", "10", QuotaWithinLimit),
			unknownQuota("network.load-balancers"),
		},
	}
}

func validCapability(name string, state CapabilityState) ProviderCapability {
	reason := "CapabilityDiscovered"
	if state == CapabilityUnknown {
		reason = "ObservationUnavailable"
	}
	return ProviderCapability{
		Name: name, State: state, Source: "provider-observation",
		ObservedAt: "2026-09-03T01:02:03.000Z", Reason: reason,
	}
}

func knownQuota(requested, available string, state QuotaState) QuotaCheck {
	return QuotaCheck{
		Name: "compute.instances", State: state,
		Requested: decimalPointer(requested), Available: decimalPointer(available),
		Source: "provider-observation", ObservedAt: "2026-09-03T01:02:03.000Z",
		Reason: "QuotaAvailable",
	}
}

func unknownQuota(name string) QuotaCheck {
	return QuotaCheck{
		Name: name, State: QuotaUnknown, Source: "provider-observation",
		ObservedAt: "2026-09-03T01:02:03.000Z", Reason: "ObservationUnavailable",
	}
}

func knownCost(amount string, confidence Confidence) CostEstimate {
	return CostEstimate{
		State: CostKnown, Amount: decimalPointer(amount), Currency: "USD", Region: "us-east-1",
		Source: "provider-observation", ObservedAt: "2026-09-03T01:02:03.000Z",
		Confidence: confidence, Reason: "ProviderCatalog",
	}
}

func unknownCost() CostEstimate {
	return CostEstimate{
		State: CostUnknown, Currency: "USD", Region: "us-east-1",
		Source: "provider-observation", ObservedAt: "2026-09-03T01:02:03.000Z",
		Confidence: ConfidenceUnknown, Reason: "ObservationUnavailable",
	}
}

func decimalPointer(value string) *string {
	return &value
}
