package referenceauthorization

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/adapters/store/memory"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/reconciliation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/service/reference"
)

type authorizationFixture struct {
	raw             *reference.Service
	runtime         *Service
	clock           *authorizationClock
	principal       identity.Principal
	member          authorization.MemberRecord
	directory       authorization.MemberDirectory
	workspaceID     resource.ID
	resourceVersion string
	policyID        resource.ID
	policyVersion   string
}

type authorizationClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *authorizationClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *authorizationClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

func TestDeniedMutationLeavesResourceAndOperationIssuerUntouched(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	ctx := context.Background()
	before, err := fixture.raw.Get(ctx, fixture.principal, fixture.workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	outsider := testPrincipal(t, "outsider")
	command := reference.ReplaceCommand{
		Principal: outsider, Kind: hierarchy.KindWorkspace, ResourceID: fixture.workspaceID,
		ExpectedResourceVersion: fixture.resourceVersion,
		CanonicalTarget:         "reference:test:replace", IdempotencyKey: "denied-replace-0001",
		Body: workspaceBody("denied", true),
	}
	if _, err := fixture.runtime.Replace(ctx, command); !errors.Is(err, ErrDenied) {
		t.Fatalf("Replace(denied) error = %v", err)
	}
	if _, err := fixture.runtime.Create(ctx, reference.CreateCommand{Principal: outsider}); !errors.Is(err, ErrDenied) {
		t.Fatalf("Create(reserved) error = %v", err)
	}
	if _, err := fixture.runtime.ReplaceStatus(ctx, reference.StatusCommand{Principal: fixture.principal}); !errors.Is(err, ErrDenied) {
		t.Fatalf("ReplaceStatus(reserved) error = %v", err)
	}
	after, err := fixture.raw.Get(ctx, fixture.principal, fixture.workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.Canonical, before.Canonical) ||
		after.Metadata.ResourceVersion() != before.Metadata.ResourceVersion() {
		t.Fatal("denied mutation changed retained Workspace")
	}

	command.Principal = fixture.principal
	command.IdempotencyKey = "allowed-replace-0001"
	receipt, err := fixture.runtime.Replace(ctx, command)
	if err != nil {
		t.Fatalf("Replace(allowed) error = %v", err)
	}
	if receipt.OperationID != resource.ID("op_0000000000000003") {
		t.Fatalf("allowed Operation ID = %s, want issuer unchanged by denials", receipt.OperationID)
	}
}

func TestPolicyReplacementRejectsCallerSuppliedMemberDirectory(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	ctx := context.Background()
	before, err := fixture.raw.Get(ctx, fixture.principal, fixture.policyID)
	if err != nil {
		t.Fatal(err)
	}
	forgedPrincipal := testPrincipal(t, "forged-policy-member")
	forgedMember := testMember(t, resource.ID("mem_reference_forged_001"), fixture.workspaceID, forgedPrincipal)
	forgedDirectory, err := authorization.NewMemberDirectory(
		fixture.workspaceID, []authorization.MemberRecord{forgedMember},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runtime.Replace(ctx, reference.ReplaceCommand{
		Principal: fixture.principal, Kind: hierarchy.KindPolicy, ResourceID: fixture.policyID,
		ExpectedResourceVersion: fixture.policyVersion,
		CanonicalTarget:         "reference:test:forged-policy", IdempotencyKey: "forged-policy-0001",
		Body: policyBody(forgedMember.ID()), Members: forgedDirectory,
	}); err == nil {
		t.Fatal("Policy replacement accepted a caller-supplied member directory")
	}
	after, err := fixture.raw.Get(ctx, fixture.principal, fixture.policyID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.Canonical, before.Canonical) {
		t.Fatal("rejected forged Policy replacement changed retained state")
	}
}

func TestListFiltersUnauthorizedRowsBeforePagination(t *testing.T) {
	fixture := newAuthorizationFixture(t, true)
	page, err := fixture.runtime.List(context.Background(), reference.ListQuery{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace, PageSize: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Metadata.ID() != fixture.workspaceID || page.NextPageToken != "" {
		t.Fatalf("authorized page = ids %v, token %q", pageIDs(page), page.NextPageToken)
	}

	outsider := testPrincipal(t, "list-outsider")
	page, err = fixture.runtime.List(context.Background(), reference.ListQuery{
		Principal: outsider, Kind: hierarchy.KindWorkspace, PageSize: 1,
	})
	if err != nil || len(page.Items) != 0 || page.NextPageToken != "" {
		t.Fatalf("outsider page = %v, token %q, error %v", pageIDs(page), page.NextPageToken, err)
	}
}

func TestResourceAndOperationReadsUseCurrentPolicy(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	ctx := context.Background()
	value, err := fixture.runtime.Get(ctx, fixture.principal, fixture.workspaceID)
	if err != nil || value.Metadata.ID() != fixture.workspaceID {
		t.Fatalf("Get(authorized) = %s, %v", value.Metadata.ID(), err)
	}
	operationValue, err := fixture.runtime.GetOperation(
		ctx, fixture.principal, resource.ID("op_0000000000000001"),
	)
	if err != nil || operationValue.Value.ResourceID != fixture.workspaceID {
		t.Fatalf("GetOperation(authorized) = %s, %v", operationValue.Value.ResourceID, err)
	}
	outsider := testPrincipal(t, "read-outsider")
	if _, err := fixture.runtime.Get(ctx, outsider, fixture.workspaceID); !errors.Is(err, ErrDenied) {
		t.Fatalf("Get(outsider) error = %v", err)
	}
	if _, err := fixture.runtime.GetOperation(
		ctx, outsider, resource.ID("op_0000000000000001"),
	); !errors.Is(err, ErrDenied) {
		t.Fatalf("GetOperation(outsider) error = %v", err)
	}
	if _, err := fixture.runtime.Delete(ctx, reference.DeleteCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace, ResourceID: fixture.workspaceID,
		ExpectedResourceVersion: fixture.resourceVersion,
		CanonicalTarget:         "reference:test:delete", IdempotencyKey: "delete-conflict-0001",
	}); !errors.Is(err, reference.ErrLifecycleConflict) {
		t.Fatalf("Delete(retained Policy child) error = %v", err)
	}
}

func TestMissingResourceAndOperationReadsAreIndistinguishableFromDenial(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	ctx := context.Background()
	if _, err := fixture.runtime.Get(
		ctx, fixture.principal, resource.ID("wsp_missing_runtime_0001"),
	); !errors.Is(err, ErrDenied) {
		t.Fatalf("Get(missing) error = %v, want denial", err)
	}
	if _, err := fixture.runtime.GetOperation(
		ctx, fixture.principal, resource.ID("op_missing_runtime_0001"),
	); !errors.Is(err, ErrDenied) {
		t.Fatalf("GetOperation(missing) error = %v, want denial", err)
	}
}

func TestDeleteReplayAndExecutionUseRetainedAuthorizationTargets(t *testing.T) {
	fixture, environment := newDeleteAuthorizationFixture(t)
	ctx := context.Background()
	command := reference.DeleteCommand{
		Principal: fixture.principal, Kind: hierarchy.KindEnvironment, ResourceID: environment.ResourceID,
		ExpectedResourceVersion: environment.ResourceVersion,
		CanonicalTarget:         "reference:test:delete-environment", IdempotencyKey: "delete-environment-0001",
	}
	receipt, err := fixture.runtime.Delete(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := fixture.runtime.Delete(ctx, command)
	if err != nil || replay != receipt {
		t.Fatalf("Delete(replay) = %#v, %v; want %#v", replay, err, receipt)
	}
	if _, err := fixture.runtime.Get(ctx, fixture.principal, environment.ResourceID); !errors.Is(err, ErrDenied) {
		t.Fatalf("Get(deleted) error = %v, want denial", err)
	}
	operationValue, err := fixture.runtime.GetOperation(ctx, fixture.principal, receipt.OperationID)
	if err != nil || operationValue.Value.ResourceID != environment.ResourceID {
		t.Fatalf("GetOperation(delete) resource/error = %s/%v", operationValue.Value.ResourceID, err)
	}
	plan, err := fixture.runtime.NewPlan(ctx, receipt.OperationID, planInput(t))
	if err != nil {
		t.Fatal(err)
	}
	var effects atomic.Int32
	if err := fixture.runtime.WithExecutionAuthorization(ctx, plan, func() error {
		effects.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("WithExecutionAuthorization(delete) error = %v", err)
	}
	if effects.Load() != 1 {
		t.Fatalf("delete effect calls = %d, want 1", effects.Load())
	}
}

func TestConfigurationAndFailureClassification(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	if _, err := New(Config{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("New(empty) error = %v", err)
	}
	if _, err := New(Config{
		Reference: fixture.raw, MemberDirectories: []authorization.MemberDirectory{fixture.directory},
		MaximumAdmissions: -1,
	}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("New(negative capacity) error = %v", err)
	}
	if _, err := New(Config{
		Reference:         fixture.raw,
		MemberDirectories: []authorization.MemberDirectory{fixture.directory, fixture.directory},
	}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("New(duplicate Workspace) error = %v", err)
	}
	if err := (*Service)(nil).ReplaceMembers(fixture.directory); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("ReplaceMembers(nil service) error = %v", err)
	}
	unknownWorkspace := resource.ID("wsp_unknown_runtime_0001")
	unknownDirectory, err := authorization.NewMemberDirectory(unknownWorkspace, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.ReplaceMembers(unknownDirectory); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("ReplaceMembers(unknown Workspace) error = %v", err)
	}
	if !errors.Is(classifyStateError(authorization.ErrMemberNotFound), ErrDenied) {
		t.Fatal("member-not-found state was not classified as denial")
	}
	for _, expected := range []error{context.Canceled, context.DeadlineExceeded, reference.ErrNotFound} {
		if got := classifyStateError(expected); !errors.Is(got, expected) {
			t.Fatalf("classifyStateError(%v) = %v", expected, got)
		}
	}
	if got := classifyStateError(errors.New("store failed")); !errors.Is(got, ErrUnavailable) {
		t.Fatalf("classifyStateError(store failure) = %v", got)
	}
	if _, err := fixture.runtime.NewPlan(
		context.Background(), resource.ID("op_missing_runtime_0001"), planInput(t),
	); !errors.Is(err, ErrDenied) {
		t.Fatalf("NewPlan(without admission) error = %v", err)
	}
	if err := fixture.runtime.WithExecutionAuthorization(
		context.Background(), reconciliation.Plan{}, func() error { return nil },
	); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("WithExecutionAuthorization(invalid Plan) error = %v", err)
	}
}

func TestPlanBindsAdmissionAndExecutionRejectsPolicyDriftAndRevocation(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	ctx := context.Background()
	receipt, err := fixture.runtime.Replace(ctx, reference.ReplaceCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace, ResourceID: fixture.workspaceID,
		ExpectedResourceVersion: fixture.resourceVersion,
		CanonicalTarget:         "reference:test:plan", IdempotencyKey: "plan-replace-0001",
		Body: workspaceBody("planned", true),
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := fixture.runtime.NewPlan(ctx, receipt.OperationID, planInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if plan.ActorKind() != fixture.principal.Kind() ||
		plan.ActorFingerprint() != fixture.principal.Fingerprint().String() ||
		plan.PolicyVersion() == "" || plan.AuthorizationInput() == "" {
		t.Fatal("Plan did not bind the admitted actor and decision")
	}
	var effects atomic.Int32
	if err := fixture.runtime.WithExecutionAuthorization(ctx, plan, func() error {
		effects.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("WithExecutionAuthorization(current) error = %v", err)
	}

	extraPrincipal := testPrincipal(t, "unbound-member")
	extraMember := testMember(t, resource.ID("mem_reference_extra_0001"), fixture.workspaceID, extraPrincipal)
	changedDirectory, err := authorization.NewMemberDirectory(
		fixture.workspaceID, []authorization.MemberRecord{fixture.member, extraMember},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.ReplaceMembers(changedDirectory); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.WithExecutionAuthorization(ctx, plan, func() error {
		effects.Add(1)
		return nil
	}); !errors.Is(err, ErrStaleAuthorization) {
		t.Fatalf("WithExecutionAuthorization(policy drift) error = %v", err)
	}

	revoked, err := authorization.NewMemberDirectory(fixture.workspaceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.ReplaceMembers(revoked); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.WithExecutionAuthorization(ctx, plan, func() error {
		effects.Add(1)
		return nil
	}); !errors.Is(err, ErrDenied) {
		t.Fatalf("WithExecutionAuthorization(revoked) error = %v", err)
	}
	if effects.Load() != 1 {
		t.Fatalf("effect calls = %d, want only current-authority call", effects.Load())
	}
}

func TestMemberRevocationPreservesRemainingAdministratorAccess(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	ctx := context.Background()
	remainingPrincipal := testPrincipal(t, "remaining-administrator")
	remainingMember := testMember(
		t, resource.ID("mem_reference_admin_0002"), fixture.workspaceID, remainingPrincipal,
	)
	both, err := authorization.NewMemberDirectory(
		fixture.workspaceID, []authorization.MemberRecord{fixture.member, remainingMember},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.ReplaceMembers(both); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runtime.Replace(ctx, reference.ReplaceCommand{
		Principal: fixture.principal, Kind: hierarchy.KindPolicy, ResourceID: fixture.policyID,
		ExpectedResourceVersion: fixture.policyVersion,
		CanonicalTarget:         "reference:test:two-administrators", IdempotencyKey: "two-administrators-0001",
		Body: policyBody(fixture.member.ID(), remainingMember.ID()),
	}); err != nil {
		t.Fatal(err)
	}
	remaining, err := authorization.NewMemberDirectory(
		fixture.workspaceID, []authorization.MemberRecord{remainingMember},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.ReplaceMembers(remaining); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runtime.Get(ctx, fixture.principal, fixture.workspaceID); !errors.Is(err, ErrDenied) {
		t.Fatalf("Get(revoked administrator) error = %v, want denial", err)
	}
	if _, err := fixture.runtime.Get(ctx, remainingPrincipal, fixture.workspaceID); err != nil {
		t.Fatalf("Get(remaining administrator) error = %v", err)
	}
}

func TestExecutionRejectsResourceGenerationDrift(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	ctx := context.Background()
	first, err := fixture.runtime.Replace(ctx, reference.ReplaceCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace, ResourceID: fixture.workspaceID,
		ExpectedResourceVersion: fixture.resourceVersion,
		CanonicalTarget:         "reference:test:first-generation", IdempotencyKey: "first-generation-0001",
		Body: workspaceBody("first generation", true),
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := fixture.runtime.NewPlan(ctx, first.OperationID, planInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runtime.Replace(ctx, reference.ReplaceCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace, ResourceID: fixture.workspaceID,
		ExpectedResourceVersion: first.ResourceVersion,
		CanonicalTarget:         "reference:test:next-generation", IdempotencyKey: "next-generation-0001",
		Body: workspaceBody("next generation", false),
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := fixture.runtime.WithExecutionAuthorization(ctx, plan, func() error {
		called = true
		return nil
	}); !errors.Is(err, ErrStaleAuthorization) || called {
		t.Fatalf("generation-drift execution = %v, called %t", err, called)
	}
}

func TestAdmissionCapacityFailsBeforePersistence(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	fixture.runtime.maximum = 1
	ctx := context.Background()
	first, err := fixture.runtime.Replace(ctx, reference.ReplaceCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace, ResourceID: fixture.workspaceID,
		ExpectedResourceVersion: fixture.resourceVersion,
		CanonicalTarget:         "reference:test:first-capacity", IdempotencyKey: "first-capacity-0001",
		Body: workspaceBody("first capacity", true),
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := fixture.raw.Get(ctx, fixture.principal, fixture.workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	second := reference.ReplaceCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace, ResourceID: fixture.workspaceID,
		ExpectedResourceVersion: first.ResourceVersion,
		CanonicalTarget:         "reference:test:second-capacity", IdempotencyKey: "second-capacity-0001",
		Body: workspaceBody("second capacity", false),
	}
	if _, err := fixture.runtime.Replace(ctx, second); !errors.Is(err, reference.ErrCapacity) {
		t.Fatalf("Replace(at admission capacity) error = %v", err)
	}
	after, err := fixture.raw.Get(ctx, fixture.principal, fixture.workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.Canonical, before.Canonical) {
		t.Fatal("admission capacity failure changed retained state")
	}
	fixture.runtime.maximum = 2
	receipt, err := fixture.runtime.Replace(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.OperationID != resource.ID("op_0000000000000004") {
		t.Fatalf("post-capacity Operation ID = %s, want untouched next issuer value", receipt.OperationID)
	}
}

func TestExpiredReplayRotatesAdmissionToNewOperation(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	ctx := context.Background()
	command := reference.ReplaceCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace, ResourceID: fixture.workspaceID,
		ExpectedResourceVersion: fixture.resourceVersion,
		CanonicalTarget:         "reference:test:replay-epoch", IdempotencyKey: "replay-epoch-0001",
		Body: workspaceBody("first replay epoch", true),
	}
	first, err := fixture.runtime.Replace(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runtime.NewPlan(ctx, first.OperationID, planInput(t)); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(reconciliation.HTTPIdempotencyWindow)
	command.ExpectedResourceVersion = first.ResourceVersion
	command.Body = workspaceBody("second replay epoch", false)
	second, err := fixture.runtime.Replace(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if second.OperationID == first.OperationID {
		t.Fatalf("expired replay Operation ID = %s, want a new epoch", second.OperationID)
	}
	if _, err := fixture.runtime.NewPlan(ctx, first.OperationID, planInput(t)); !errors.Is(err, ErrDenied) {
		t.Fatalf("NewPlan(retired epoch) error = %v, want denial", err)
	}
	if _, err := fixture.runtime.NewPlan(ctx, second.OperationID, planInput(t)); err != nil {
		t.Fatalf("NewPlan(current epoch) error = %v", err)
	}
	if len(fixture.runtime.admissions) != 1 || len(fixture.runtime.requests) != 1 {
		t.Fatalf("rotated admission/request sizes = %d/%d, want 1/1",
			len(fixture.runtime.admissions), len(fixture.runtime.requests))
	}
}

func TestAdmissionAndRevocationRaceHasOnlySerializedOutcomes(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	ctx := context.Background()
	revoked, err := authorization.NewMemberDirectory(fixture.workspaceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	command := reference.ReplaceCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace, ResourceID: fixture.workspaceID,
		ExpectedResourceVersion: fixture.resourceVersion,
		CanonicalTarget:         "reference:test:admission-race", IdempotencyKey: "admission-race-0001",
		Body: workspaceBody("raced", true),
	}
	start := make(chan struct{})
	var receipt reference.MutationReceipt
	var mutationErr, revokeErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		receipt, mutationErr = fixture.runtime.Replace(ctx, command)
	}()
	go func() {
		defer wait.Done()
		<-start
		revokeErr = fixture.runtime.ReplaceMembers(revoked)
	}()
	close(start)
	wait.Wait()
	if revokeErr != nil {
		t.Fatal(revokeErr)
	}
	current, err := fixture.raw.Get(ctx, fixture.principal, fixture.workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case mutationErr == nil:
		if current.Metadata.ResourceVersion().String() == fixture.resourceVersion {
			t.Fatal("accepted raced mutation did not persist")
		}
		plan, err := fixture.runtime.NewPlan(ctx, receipt.OperationID, planInput(t))
		if err != nil {
			t.Fatal(err)
		}
		called := false
		if err := fixture.runtime.WithExecutionAuthorization(ctx, plan, func() error {
			called = true
			return nil
		}); !errors.Is(err, ErrDenied) || called {
			t.Fatalf("post-race execution = %v, called %t", err, called)
		}
	case errors.Is(mutationErr, ErrDenied):
		if current.Metadata.ResourceVersion().String() != fixture.resourceVersion {
			t.Fatal("denied raced mutation changed retained state")
		}
	default:
		t.Fatalf("raced mutation error = %v", mutationErr)
	}
}

func TestExecutionCallbackExcludesConcurrentRevocation(t *testing.T) {
	fixture := newAuthorizationFixture(t, false)
	ctx := context.Background()
	receipt, err := fixture.runtime.Replace(ctx, reference.ReplaceCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace, ResourceID: fixture.workspaceID,
		ExpectedResourceVersion: fixture.resourceVersion,
		CanonicalTarget:         "reference:test:effect-race", IdempotencyKey: "effect-race-0001",
		Body: workspaceBody("effect", true),
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := fixture.runtime.NewPlan(ctx, receipt.OperationID, planInput(t))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := authorization.NewMemberDirectory(fixture.workspaceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	exited := make(chan struct{})
	executionResult := make(chan error, 1)
	go func() {
		executionResult <- fixture.runtime.WithExecutionAuthorization(ctx, plan, func() error {
			close(entered)
			<-release
			close(exited)
			return nil
		})
	}()
	<-entered
	revocationResult := make(chan error, 1)
	revocationReached := make(chan struct{})
	fixture.runtime.beforeReplaceMembersLock = func() { close(revocationReached) }
	go func() {
		revocationResult <- fixture.runtime.ReplaceMembers(revoked)
	}()
	<-revocationReached
	select {
	case err := <-revocationResult:
		t.Fatalf("ReplaceMembers completed while execution callback held the lock: %v", err)
	default:
	}
	close(release)
	if err := <-executionResult; err != nil {
		t.Fatal(err)
	}
	if err := <-revocationResult; err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("revocation completed while execution callback was active")
	}
}

func newAuthorizationFixture(t *testing.T, includeHiddenWorkspace bool) authorizationFixture {
	t.Helper()
	fixture, _ := newAuthorizationFixtureWithOptions(t, includeHiddenWorkspace, false)
	return fixture
}

func newDeleteAuthorizationFixture(t *testing.T) (authorizationFixture, reference.MutationReceipt) {
	t.Helper()
	return newAuthorizationFixtureWithOptions(t, false, true)
}

func newAuthorizationFixtureWithOptions(
	t *testing.T,
	includeHiddenWorkspace bool,
	includeEnvironment bool,
) (authorizationFixture, reference.MutationReceipt) {
	t.Helper()
	principal := testPrincipal(t, "administrator")
	clock := &authorizationClock{now: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)}
	raw, err := reference.New(reference.Config{
		Store: memory.NewStore(), Clock: clock,
		Issuer: &reference.SequentialIssuer{}, PageTokenKey: bytes.Repeat([]byte{0x31}, 32),
		MaximumPageTokens: 32, MaximumReplays: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := raw.Create(context.Background(), reference.CreateCommand{
		Principal: principal, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "reference:test:workspace", IdempotencyKey: "workspace-create-0001",
		Body: workspaceBody("authorized", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	member := testMember(t, resource.ID("mem_reference_admin_0001"), workspace.ResourceID, principal)
	directory, err := authorization.NewMemberDirectory(workspace.ResourceID, []authorization.MemberRecord{member})
	if err != nil {
		t.Fatal(err)
	}
	parentID := workspace.ResourceID
	policyDocument := policyBody(member.ID())
	if includeEnvironment {
		policyDocument = operatorAdministratorPolicyBody(member.ID())
	}
	policy, err := raw.Create(context.Background(), reference.CreateCommand{
		Principal: principal, Kind: hierarchy.KindPolicy, WorkspaceID: workspace.ResourceID, ParentID: &parentID,
		CanonicalTarget: "reference:test:policy", IdempotencyKey: "policy-create-0001",
		Body: policyDocument, Members: directory,
	})
	if err != nil {
		t.Fatal(err)
	}
	var environment reference.MutationReceipt
	if includeEnvironment {
		environment, err = raw.Create(context.Background(), reference.CreateCommand{
			Principal: principal, Kind: hierarchy.KindEnvironment,
			WorkspaceID: workspace.ResourceID, ParentID: &parentID,
			CanonicalTarget: "reference:test:environment", IdempotencyKey: "environment-create-0001",
			Body: environmentBody("deletable"), Members: directory,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if includeHiddenWorkspace {
		if _, err := raw.Create(context.Background(), reference.CreateCommand{
			Principal: principal, Kind: hierarchy.KindWorkspace,
			CanonicalTarget: "reference:test:hidden", IdempotencyKey: "hidden-create-0001",
			Body: workspaceBody("hidden", false),
		}); err != nil {
			t.Fatal(err)
		}
	}
	runtime, err := New(Config{
		Reference: raw, MemberDirectories: []authorization.MemberDirectory{directory}, MaximumAdmissions: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authorizationFixture{
		raw: raw, runtime: runtime, clock: clock, principal: principal, member: member, directory: directory,
		workspaceID: workspace.ResourceID, resourceVersion: workspace.ResourceVersion,
		policyID: policy.ResourceID, policyVersion: policy.ResourceVersion,
	}, environment
}

func testPrincipal(t *testing.T, subject string) identity.Principal {
	t.Helper()
	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindHuman, Issuer: "https://authorization.example", Subject: subject,
		Audiences: []string{"veer-api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func testMember(
	t *testing.T,
	id resource.ID,
	workspaceID resource.ID,
	principal identity.Principal,
) authorization.MemberRecord {
	t.Helper()
	member, err := authorization.NewMemberRecord(authorization.MemberInput{
		ID: id, WorkspaceID: workspaceID, Kind: principal.Kind(), LogicalIdentity: principal.LogicalIdentity(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return member
}

func workspaceBody(name string, suspended bool) []byte {
	value := "false"
	if suspended {
		value = "true"
	}
	return []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","metadata":{"displayName":"` + name + `"},"spec":{"suspendReconciliation":` + value + `}}`)
}

func environmentBody(name string) []byte {
	return []byte(`{"apiVersion":"v1alpha1","kind":"Environment","metadata":{"displayName":"` + name + `"},"spec":{}}`)
}

func policyBody(memberIDs ...resource.ID) []byte {
	identifiers := make([]string, len(memberIDs))
	for index, memberID := range memberIDs {
		identifiers[index] = memberID.String()
	}
	sort.Strings(identifiers)
	bindings := make([]string, len(identifiers))
	for index, memberID := range identifiers {
		bindings[index] = `{"memberId":"` + memberID + `","role":"WorkspaceAdministrator","scope":{"kind":"Workspace"}}`
	}
	return []byte(`{"apiVersion":"v1alpha1","kind":"Policy","metadata":{"displayName":"administrator"},"spec":{"bindings":[` + strings.Join(bindings, ",") + `]}}`)
}

func operatorAdministratorPolicyBody(memberID resource.ID) []byte {
	return []byte(`{"apiVersion":"v1alpha1","kind":"Policy","metadata":{"displayName":"operator administrator"},"spec":{"bindings":[` +
		`{"memberId":"` + memberID.String() + `","role":"Operator","scope":{"kind":"Workspace"}},` +
		`{"memberId":"` + memberID.String() + `","role":"WorkspaceAdministrator","scope":{"kind":"Workspace"}}]}}`)
}

func planInput(t *testing.T) reconciliation.PlanInput {
	t.Helper()
	evidence := func(kind reconciliation.EvidenceKind) reconciliation.Evidence {
		value, err := reconciliation.NewEvidence(kind, "reference-v1", []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	return reconciliation.PlanInput{
		ID:               resource.ID("pln_reference_auth_0001"),
		Revision:         1,
		Kind:             reconciliation.PlanKindForward,
		PlannerVersion:   "reference-planner-v1",
		DesiredIntent:    evidence(reconciliation.EvidenceDesiredIntent),
		ObservedSnapshot: evidence(reconciliation.EvidenceObservedSnapshot),
		Capability:       evidence(reconciliation.EvidenceCapability),
		Quota:            evidence(reconciliation.EvidenceQuota),
		Cost:             evidence(reconciliation.EvidenceCost),
	}
}

func pageIDs(page reference.Page) []resource.ID {
	result := make([]resource.ID, len(page.Items))
	for index, item := range page.Items {
		result[index] = item.Metadata.ID()
	}
	return result
}
