package credential

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func TestDigestWireOracle(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	source := hex.EncodeToString(fixture.request.source.digest.digest[:])
	binding := hex.EncodeToString(fixture.request.binding.digest[:])
	if source != "2b4364acd1b497939e88b65caa2299190745c1f6fee4f8e5d81291ba19b4c218" {
		t.Fatal("source digest framing changed")
	}
	if binding != "250ea38a8336e98677dc9ac750ed2ea055f01b3845fd92dd1360d7784a009043" {
		t.Fatal("binding digest framing changed")
	}
}

func TestDigestIgnoresStatusAndResourceVersionOnlyChanges(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)

	connectionStatusOnly, err := fixture.connection.ReplaceStatus(
		control.ProviderConnectionStatus{
			ObservedGeneration: 1,
			Conditions:         []condition.Condition{},
			Capabilities:       []control.ProviderCapability{},
			QuotaChecks:        []control.QuotaCheck{},
		},
		"resource_2",
		testNow.Add(time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	connectionMetadataOnly, err := fixture.connection.Rename(
		"renamed connection",
		"resource_3",
		testNow.Add(2*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	targetStatusOnly, err := fixture.component.ReplaceStatus(
		fixtureStatus{ObservedGeneration: 1},
		"resource_2",
		testNow.Add(time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	targetMetadataOnly, err := fixture.component.Rename(
		"renamed target",
		"resource_3",
		testNow.Add(2*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	targetStatusView, err := NewResourceView(targetStatusOnly)
	if err != nil {
		t.Fatal(err)
	}
	targetMetadataView, err := NewResourceView(targetMetadataOnly)
	if err != nil {
		t.Fatal(err)
	}

	requests := []struct {
		name       string
		connection resource.Resource[control.ProviderConnectionSpec, control.ProviderConnectionStatus]
		target     ResourceView
	}{
		{name: "connection status and resource version", connection: connectionStatusOnly, target: fixture.target},
		{name: "connection metadata and resource version", connection: connectionMetadataOnly, target: fixture.target},
		{name: "target status and resource version", connection: fixture.connection, target: targetStatusView},
		{name: "target metadata and resource version", connection: fixture.connection, target: targetMetadataView},
	}
	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			request, err := NewRequest(
				fixture.snapshot,
				test.connection,
				test.target,
				fixture.operation,
				authorization.ActionProviderApply,
				fixture.recipient,
			)
			if err != nil {
				t.Fatal(err)
			}
			assertSameDigests(t, fixture.request, request)
		})
	}
}

func TestEverySourceLineageDimensionChangesBothDigests(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	otherWorkspace := resource.ID("wsp_01J11111111111111111111111")
	otherReference := resource.ID("sec_01J11111111111111111111111")

	tests := []struct {
		name   string
		mutate func(*SourceLookup)
	}{
		{name: "workspace", mutate: func(value *SourceLookup) { value.workspaceID = otherWorkspace }},
		{name: "environment", mutate: func(value *SourceLookup) { value.environmentID = testEnvironmentB }},
		{name: "connection", mutate: func(value *SourceLookup) { value.providerConnectionID = testConnectionB }},
		{name: "connection generation", mutate: func(value *SourceLookup) { value.connectionGeneration++ }},
		{name: "provider", mutate: func(value *SourceLookup) { value.provider = "kubernetes" }},
		{name: "reference identity", mutate: func(value *SourceLookup) { value.referenceID = otherReference }},
		{name: "credential version", mutate: func(value *SourceLookup) { value.version = "version_2" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := fixture.request.source
			test.mutate(&source)
			source.digest = deriveSourceDigest(source)
			request := fixture.request
			request.source = source
			request.workspaceID = source.workspaceID
			request.environmentID = source.environmentID
			request.providerConnectionID = source.providerConnectionID
			request.connectionGeneration = source.connectionGeneration
			request.provider = source.provider
			request.recipient.provider = source.provider
			request.binding = deriveBindingDigest(request)
			if err := ValidateRequest(request); err != nil {
				t.Fatalf("coherent source-lineage mutation is invalid: %v", err)
			}
			if source.digest.Equal(fixture.request.source.digest) {
				t.Fatal("source-lineage mutation preserved SourceDigest")
			}
			if request.binding.Equal(fixture.request.binding) {
				t.Fatal("source-lineage mutation preserved BindingDigest")
			}
		})
	}
}

func TestEveryBindingOnlyDimensionChangesOnlyBindingDigest(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "operation", mutate: func(value *Request) { value.operationID = testConnectionB }},
		{name: "target resource", mutate: func(value *Request) { value.targetResourceID = testApplicationA }},
		{name: "target kind", mutate: func(value *Request) { value.targetKind = hierarchy.KindApplication }},
		{name: "target generation", mutate: func(value *Request) { value.targetGeneration++ }},
		{name: "provider action", mutate: func(value *Request) { value.action = authorization.ActionProviderObserve }},
		{name: "recipient", mutate: func(value *Request) { value.recipient.name = "different-adapter" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := fixture.request
			test.mutate(&request)
			request.binding = deriveBindingDigest(request)
			if err := ValidateRequest(request); err != nil {
				t.Fatalf("coherent binding mutation is invalid: %v", err)
			}
			if !request.source.digest.Equal(fixture.request.source.digest) {
				t.Fatal("binding-only mutation changed SourceDigest")
			}
			if request.binding.Equal(fixture.request.binding) {
				t.Fatal("binding-only mutation preserved BindingDigest")
			}
		})
	}
}

func TestVersionRotationChangesSourceAndBindingDigest(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	spec, err := fixture.connection.Spec()
	if err != nil {
		t.Fatal(err)
	}
	spec.CredentialRef.Version = "version_2"
	rotated, err := fixture.connection.ReplaceSpec(
		spec,
		"resource_2",
		testNow.Add(time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest(
		fixture.snapshot,
		rotated,
		fixture.target,
		fixture.operation,
		authorization.ActionProviderApply,
		fixture.recipient,
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.ConnectionGeneration() != fixture.request.ConnectionGeneration()+1 ||
		request.SourceLookup().Version() != "version_2" {
		t.Fatal("rotation did not bind the new generation and credential version")
	}
	if request.SourceLookup().Digest().Equal(fixture.request.SourceLookup().Digest()) ||
		request.BindingDigest().Equal(fixture.request.BindingDigest()) {
		t.Fatal("version rotation preserved a credential digest")
	}
}

func assertSameDigests(t testing.TB, left, right Request) {
	t.Helper()
	if !left.SourceLookup().Digest().Equal(right.SourceLookup().Digest()) {
		t.Fatal("non-lineage change changed SourceDigest")
	}
	if !left.BindingDigest().Equal(right.BindingDigest()) {
		t.Fatal("non-binding change changed BindingDigest")
	}
}
