package credential

import (
	"errors"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func TestNewRequestSealsExactScope(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	request := fixture.request

	if !request.Valid() || ValidateRequest(request) != nil {
		t.Fatal("valid request was rejected")
	}
	if request.WorkspaceID() != testWorkspaceID ||
		request.EnvironmentID() != testEnvironmentA ||
		request.ProviderConnectionID() != testConnectionA ||
		request.ConnectionGeneration() != fixture.connection.Metadata().Generation() ||
		request.OperationID() != testOperationA ||
		request.TargetResourceID() != testComponentA ||
		request.TargetKind() != hierarchy.KindComponent ||
		request.TargetGeneration() != fixture.component.Metadata().Generation() ||
		request.Provider() != "aws" ||
		request.Action() != authorization.ActionProviderApply ||
		request.Recipient().Name() != "provider-adapter" {
		t.Fatal("request accessors do not match sealed inputs")
	}
	source := request.SourceLookup()
	if !source.Valid() || source.WorkspaceID() != testWorkspaceID ||
		source.EnvironmentID() != testEnvironmentA ||
		source.ProviderConnectionID() != testConnectionA ||
		source.ConnectionGeneration() != fixture.connection.Metadata().Generation() ||
		source.Provider() != "aws" || source.ReferenceID() != testReferenceA ||
		source.Version() != "version_1" || !source.Digest().Valid() ||
		!request.BindingDigest().Valid() {
		t.Fatal("source lookup or digest does not match sealed connection")
	}

	replay, err := NewRequest(
		fixture.snapshot,
		fixture.connection,
		fixture.target,
		fixture.operation,
		authorization.ActionProviderApply,
		fixture.recipient,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.SourceLookup().Digest().Equal(source.Digest()) ||
		!replay.BindingDigest().Equal(request.BindingDigest()) {
		t.Fatal("exact replay produced different digests")
	}

	observe, err := NewRequest(
		fixture.snapshot,
		fixture.connection,
		fixture.target,
		fixture.operation,
		authorization.ActionProviderObserve,
		fixture.recipient,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !observe.SourceLookup().Digest().Equal(source.Digest()) {
		t.Fatal("provider action unexpectedly changed source-cache identity")
	}
	if observe.BindingDigest().Equal(request.BindingDigest()) {
		t.Fatal("provider action did not change the session binding")
	}
}

func TestNewRequestRejectsUnsealedOrMismatchedInputs(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)

	tests := []struct {
		name      string
		snapshot  hierarchy.Snapshot
		target    ResourceView
		op        operation.Operation
		action    authorization.Action
		recipient Recipient
		want      error
	}{
		{
			name:      "zero snapshot",
			target:    fixture.target,
			op:        fixture.operation,
			action:    authorization.ActionProviderApply,
			recipient: fixture.recipient,
			want:      ErrConnectionNotRetained,
		},
		{
			name:      "zero target",
			snapshot:  fixture.snapshot,
			op:        fixture.operation,
			action:    authorization.ActionProviderApply,
			recipient: fixture.recipient,
			want:      ErrInvalidResourceView,
		},
		{
			name:      "operation pending",
			snapshot:  fixture.snapshot,
			target:    fixture.target,
			op:        pendingOperation(fixture.operation),
			action:    authorization.ActionProviderApply,
			recipient: fixture.recipient,
			want:      ErrOperationNotRunning,
		},
		{
			name:      "target generation mismatch",
			snapshot:  fixture.snapshot,
			target:    fixture.target,
			op:        operationGeneration(fixture.operation, 2),
			action:    authorization.ActionProviderApply,
			recipient: fixture.recipient,
			want:      ErrTargetGenerationMismatch,
		},
		{
			name:      "non provider action",
			snapshot:  fixture.snapshot,
			target:    fixture.target,
			op:        fixture.operation,
			action:    authorization.ActionCredentialResolve,
			recipient: fixture.recipient,
			want:      ErrUnsupportedProviderAction,
		},
		{
			name:     "zero recipient",
			snapshot: fixture.snapshot,
			target:   fixture.target,
			op:       fixture.operation,
			action:   authorization.ActionProviderApply,
			want:     ErrInvalidRecipient,
		},
		{
			name:      "different provider recipient",
			snapshot:  fixture.snapshot,
			target:    fixture.target,
			op:        fixture.operation,
			action:    authorization.ActionProviderApply,
			recipient: mustRecipient(t, "kubernetes", "provider-adapter"),
			want:      ErrScopeMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRequest(
				test.snapshot,
				fixture.connection,
				test.target,
				test.op,
				test.action,
				test.recipient,
			)
			if !errors.Is(err, test.want) || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("NewRequest() error = %v, want %v and ErrInvalidRequest", err, test.want)
			}
		})
	}
}

func TestNewRequestRejectsWorkspaceTarget(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	view, err := NewResourceView(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	op := mustRunningOperation(t, testWorkspaceID, fixture.workspace.Metadata().Generation().Int64())
	_, err = NewRequest(
		fixture.snapshot,
		fixture.connection,
		view,
		op,
		authorization.ActionProviderObserve,
		fixture.recipient,
	)
	if !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("NewRequest(Workspace target) error = %v, want ErrScopeMismatch", err)
	}
}

func TestValidateRequestRejectsEveryForgedBindingDimension(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	mutations := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "workspace", mutate: func(value *Request) { value.workspaceID = testEnvironmentA }},
		{name: "environment", mutate: func(value *Request) { value.environmentID = testWorkspaceID }},
		{name: "connection", mutate: func(value *Request) { value.providerConnectionID = testConnectionB }},
		{name: "connection generation", mutate: func(value *Request) { value.connectionGeneration++ }},
		{name: "operation", mutate: func(value *Request) { value.operationID = testConnectionB }},
		{name: "target", mutate: func(value *Request) { value.targetResourceID = testApplicationA }},
		{name: "target kind", mutate: func(value *Request) { value.targetKind = hierarchy.KindApplication }},
		{name: "target generation", mutate: func(value *Request) { value.targetGeneration++ }},
		{name: "provider", mutate: func(value *Request) { value.provider = "kubernetes" }},
		{name: "action", mutate: func(value *Request) { value.action = authorization.ActionProviderDelete }},
		{name: "recipient", mutate: func(value *Request) { value.recipient.name = "other-adapter" }},
		{name: "source version", mutate: func(value *Request) { value.source.version = "version_2" }},
		{name: "source digest", mutate: func(value *Request) { value.source.digest = SourceDigest{} }},
		{name: "binding digest", mutate: func(value *Request) { value.binding = BindingDigest{} }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			value := fixture.request
			mutation.mutate(&value)
			if err := ValidateRequest(value); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ValidateRequest(forged %s) = %v", mutation.name, err)
			}
		})
	}
}

func TestRecipientBounds(t *testing.T) {
	t.Parallel()
	for _, input := range [][2]string{
		{"", "adapter"},
		{"AWS", "adapter"},
		{"aws", ""},
		{"aws", "adapter_name"},
		{"aws", string(make([]byte, MaxRecipientBytes+1))},
	} {
		if _, err := NewRecipient(input[0], input[1]); !errors.Is(err, ErrInvalidRecipient) {
			t.Fatalf("NewRecipient(invalid) error = %v", err)
		}
	}
}

func pendingOperation(value operation.Operation) operation.Operation {
	value.Phase = operation.PhasePending
	return value
}

func operationGeneration(value operation.Operation, generation int64) operation.Operation {
	value.Generation = generation
	return value
}

func mustRecipient(t testing.TB, provider, name string) Recipient {
	t.Helper()
	recipient, err := NewRecipient(provider, name)
	if err != nil {
		t.Fatal(err)
	}
	return recipient
}

func TestResourceViewRejectsZeroResource(t *testing.T) {
	t.Parallel()
	var zero resource.Resource[fixtureSpec, fixtureStatus]
	if _, err := NewResourceView(zero); !errors.Is(err, ErrInvalidResourceView) {
		t.Fatalf("NewResourceView(zero) error = %v", err)
	}
}
