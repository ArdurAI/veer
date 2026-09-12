package reference_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/adapters/store/memory"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/service/reference"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type fixture struct {
	service   *reference.Service
	store     *memory.Store
	clock     *testClock
	principal identity.Principal
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindHuman, Issuer: "https://issuer.example", Subject: "reference-user", Audiences: []string{"veer-api"},
	})
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}
	clock := &testClock{now: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)}
	store := memory.NewStore()
	service, err := reference.New(reference.Config{
		Store: store, Clock: clock, Issuer: &reference.SequentialIssuer{},
		PageTokenKey: []byte("0123456789abcdef0123456789abcdef"), MaximumPageTokens: 64, MaximumReplays: 256,
	})
	if err != nil {
		t.Fatalf("reference.New() error = %v", err)
	}
	return fixture{service: service, store: store, clock: clock, principal: principal}
}

func TestEveryResourceKindCompletesPositiveAndNegativeLifecycle(t *testing.T) {
	fixture := newFixture(t)
	ctx := context.Background()
	ids := make(map[hierarchy.Kind]resource.ID)
	receipts := make(map[hierarchy.Kind]reference.MutationReceipt)

	workspaceCommand := reference.CreateCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "/api/v1alpha1/workspaces", IdempotencyKey: "create-workspace-0001",
		Body: intentBody(hierarchy.KindWorkspace, "workspace", false),
	}
	workspaceReceipt, err := fixture.service.Create(ctx, workspaceCommand)
	if err != nil {
		t.Fatalf("Create(Workspace) error = %v", err)
	}
	ids[hierarchy.KindWorkspace] = workspaceReceipt.ResourceID
	receipts[hierarchy.KindWorkspace] = workspaceReceipt

	replayedWorkspace, err := fixture.service.Create(ctx, workspaceCommand)
	if err != nil || !reflect.DeepEqual(replayedWorkspace, workspaceReceipt) {
		t.Fatalf("Create(Workspace replay) = %#v, %v; want %#v", replayedWorkspace, err, workspaceReceipt)
	}
	conflictingCreate := workspaceCommand
	conflictingCreate.Body = intentBody(hierarchy.KindWorkspace, "different", false)
	if _, err := fixture.service.Create(ctx, conflictingCreate); !errors.Is(err, reference.ErrIdempotencyConflict) {
		t.Fatalf("Create(conflicting replay) error = %v, want idempotency conflict", err)
	}

	members, err := authorization.NewMemberDirectory(workspaceReceipt.ResourceID, nil)
	if err != nil {
		t.Fatalf("NewMemberDirectory() error = %v", err)
	}
	createCases := []struct {
		kind   hierarchy.Kind
		parent hierarchy.Kind
	}{
		{hierarchy.KindEnvironment, hierarchy.KindWorkspace},
		{hierarchy.KindApplication, hierarchy.KindEnvironment},
		{hierarchy.KindComponent, hierarchy.KindApplication},
		{hierarchy.KindPolicy, hierarchy.KindWorkspace},
		{hierarchy.KindProviderConnection, hierarchy.KindEnvironment},
	}
	for index, test := range createCases {
		fixture.clock.Advance(time.Millisecond)
		parent := ids[test.parent]
		command := reference.CreateCommand{
			Principal: fixture.principal, Kind: test.kind, WorkspaceID: workspaceReceipt.ResourceID, ParentID: &parent,
			CanonicalTarget: "reference:create:" + test.kind.String(), IdempotencyKey: idempotencyKey("create", index),
			Body: intentBody(test.kind, test.kind.String(), false), Members: members,
		}
		receipt, err := fixture.service.Create(ctx, command)
		if err != nil {
			t.Fatalf("Create(%s) error = %v", test.kind, err)
		}
		ids[test.kind] = receipt.ResourceID
		receipts[test.kind] = receipt
		got, err := fixture.service.Get(ctx, fixture.principal, workspaceReceipt.ResourceID, receipt.ResourceID)
		if err != nil || got.Kind != test.kind || got.Metadata.Generation().Int64() != 1 {
			t.Fatalf("Get(%s) = %q/%d, %v", test.kind, got.Kind, got.Metadata.Generation(), err)
		}
	}

	negativePlacements := []struct {
		kind   hierarchy.Kind
		parent hierarchy.Kind
	}{
		{hierarchy.KindWorkspace, hierarchy.KindWorkspace},
		{hierarchy.KindEnvironment, hierarchy.KindEnvironment},
		{hierarchy.KindApplication, hierarchy.KindWorkspace},
		{hierarchy.KindComponent, hierarchy.KindEnvironment},
		{hierarchy.KindPolicy, hierarchy.KindEnvironment},
		{hierarchy.KindProviderConnection, hierarchy.KindWorkspace},
	}
	for index, test := range negativePlacements {
		parent := ids[test.parent]
		command := reference.CreateCommand{
			Principal: fixture.principal, Kind: test.kind, WorkspaceID: workspaceReceipt.ResourceID, ParentID: &parent,
			CanonicalTarget: "reference:invalid:" + test.kind.String(), IdempotencyKey: idempotencyKey("invalid", index),
			Body: intentBody(test.kind, "invalid", false), Members: members,
		}
		if _, err := fixture.service.Create(ctx, command); err == nil {
			t.Fatalf("Create(%s invalid placement) succeeded", test.kind)
		}
	}

	kinds := []hierarchy.Kind{
		hierarchy.KindWorkspace, hierarchy.KindEnvironment, hierarchy.KindApplication,
		hierarchy.KindComponent, hierarchy.KindPolicy, hierarchy.KindProviderConnection,
	}
	for index, kind := range kinds {
		before, err := fixture.service.Get(ctx, fixture.principal, workspaceReceipt.ResourceID, ids[kind])
		if err != nil {
			t.Fatalf("Get(%s before replace) error = %v", kind, err)
		}
		fixture.clock.Advance(time.Millisecond)
		replace := reference.ReplaceCommand{
			Principal: fixture.principal, WorkspaceID: workspaceReceipt.ResourceID,
			Kind: kind, ResourceID: ids[kind],
			ExpectedResourceVersion: before.Metadata.ResourceVersion().String(),
			CanonicalTarget:         "reference:replace:" + ids[kind].String(), IdempotencyKey: idempotencyKey("replace", index),
			Body: intentBody(kind, "updated-"+kind.String(), kind == hierarchy.KindWorkspace), Members: members,
		}
		receipt, err := fixture.service.Replace(ctx, replace)
		if err != nil {
			t.Fatalf("Replace(%s) error = %v", kind, err)
		}
		replay, err := fixture.service.Replace(ctx, replace)
		if err != nil || !reflect.DeepEqual(replay, receipt) {
			t.Fatalf("Replace(%s replay) = %#v, %v; want %#v", kind, replay, err, receipt)
		}
		stale := replace
		stale.IdempotencyKey = idempotencyKey("stale-replace", index)
		if _, err := fixture.service.Replace(ctx, stale); !errors.Is(err, reference.ErrPreconditionFailed) {
			t.Fatalf("Replace(%s stale) error = %v", kind, err)
		}

		current, err := fixture.service.Get(ctx, fixture.principal, workspaceReceipt.ResourceID, ids[kind])
		if err != nil || current.Metadata.DisplayName() != "updated-"+kind.String() {
			t.Fatalf("Get(%s after replace) name/error = %q/%v", kind, current.Metadata.DisplayName(), err)
		}
		fixture.clock.Advance(time.Millisecond)
		status := reference.StatusCommand{
			Principal: fixture.principal, WorkspaceID: workspaceReceipt.ResourceID,
			Kind: kind, ResourceID: ids[kind],
			ExpectedResourceVersion: current.Metadata.ResourceVersion().String(),
			CanonicalTarget:         "reference:status:" + ids[kind].String(), IdempotencyKey: idempotencyKey("status", index),
			Body: statusBody(kind, current.Metadata.Generation().Int64()),
		}
		statusReceipt, err := fixture.service.ReplaceStatus(ctx, status)
		if err != nil {
			t.Fatalf("ReplaceStatus(%s) error = %v", kind, err)
		}
		statusReplay, err := fixture.service.ReplaceStatus(ctx, status)
		if err != nil || !reflect.DeepEqual(statusReplay, statusReceipt) {
			t.Fatalf("ReplaceStatus(%s replay) = %#v, %v; want %#v", kind, statusReplay, err, statusReceipt)
		}
		staleStatus := status
		staleStatus.IdempotencyKey = idempotencyKey("stale-status", index)
		if _, err := fixture.service.ReplaceStatus(ctx, staleStatus); !errors.Is(err, reference.ErrPreconditionFailed) {
			t.Fatalf("ReplaceStatus(%s stale) error = %v", kind, err)
		}
	}

	workspace, err := fixture.service.Get(
		ctx, fixture.principal, workspaceReceipt.ResourceID, ids[hierarchy.KindWorkspace],
	)
	if err != nil {
		t.Fatal(err)
	}
	blockedDelete := reference.DeleteCommand{
		Principal: fixture.principal, WorkspaceID: workspaceReceipt.ResourceID,
		Kind: hierarchy.KindWorkspace, ResourceID: workspace.Metadata.ID(),
		ExpectedResourceVersion: workspace.Metadata.ResourceVersion().String(),
		CanonicalTarget:         "reference:delete:workspace", IdempotencyKey: "delete-blocked-0001",
	}
	if _, err := fixture.service.Delete(ctx, blockedDelete); !errors.Is(err, reference.ErrLifecycleConflict) {
		t.Fatalf("Delete(Workspace with children) error = %v", err)
	}

	deleteOrder := []hierarchy.Kind{
		hierarchy.KindComponent, hierarchy.KindApplication, hierarchy.KindProviderConnection,
		hierarchy.KindEnvironment, hierarchy.KindPolicy, hierarchy.KindWorkspace,
	}
	for index, kind := range deleteOrder {
		current, err := fixture.service.Get(ctx, fixture.principal, workspaceReceipt.ResourceID, ids[kind])
		if err != nil {
			t.Fatalf("Get(%s before delete) error = %v", kind, err)
		}
		command := reference.DeleteCommand{
			Principal: fixture.principal, WorkspaceID: workspaceReceipt.ResourceID,
			Kind: kind, ResourceID: ids[kind],
			ExpectedResourceVersion: current.Metadata.ResourceVersion().String(),
			CanonicalTarget:         "reference:delete:" + ids[kind].String(), IdempotencyKey: idempotencyKey("delete", index),
		}
		receipt, err := fixture.service.Delete(ctx, command)
		if err != nil {
			t.Fatalf("Delete(%s) error = %v", kind, err)
		}
		replay, err := fixture.service.Delete(ctx, command)
		if err != nil || !reflect.DeepEqual(replay, receipt) {
			t.Fatalf("Delete(%s replay) = %#v, %v; want %#v", kind, replay, err, receipt)
		}
		if _, err := fixture.service.Get(
			ctx, fixture.principal, workspaceReceipt.ResourceID, ids[kind],
		); !errors.Is(err, reference.ErrNotFound) {
			t.Fatalf("Get(%s deleted) error = %v", kind, err)
		}
		operationValue, err := fixture.service.GetOperation(
			ctx, fixture.principal, workspaceReceipt.ResourceID, receipt.OperationID,
		)
		if err != nil || operationValue.Value.ResourceID != ids[kind] {
			t.Fatalf("GetOperation(%s delete) target/error = %q/%v", kind, operationValue.Value.ResourceID, err)
		}
	}
}

func TestListFilteringOrderingPaginationAndTokenBinding(t *testing.T) {
	fixture := newFixture(t)
	ctx := context.Background()
	workspaceIDs := make([]resource.ID, 0, 6)
	for index, test := range []struct {
		name string
		team string
	}{
		{"one", "platform"}, {"two", "other"}, {"three", "platform"}, {"four", "platform"},
	} {
		if index > 0 {
			fixture.clock.Advance(time.Second)
		}
		receipt, err := fixture.service.Create(ctx, reference.CreateCommand{
			Principal: fixture.principal, Kind: hierarchy.KindWorkspace,
			CanonicalTarget: "/api/v1alpha1/workspaces", IdempotencyKey: idempotencyKey("page-create", index),
			Body: workspaceBody(test.name, test.team, false),
		})
		if err != nil {
			t.Fatalf("Create(%s) error = %v", test.name, err)
		}
		workspaceIDs = append(workspaceIDs, receipt.ResourceID)
	}
	fixture.clock.Advance(time.Second)
	receipt, err := fixture.service.Create(ctx, reference.CreateCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "/api/v1alpha1/workspaces", IdempotencyKey: "page-create-missing-label",
		Body: []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","metadata":{"displayName":"missing-label"},"spec":{}}`),
	})
	if err != nil {
		t.Fatalf("Create(missing label) error = %v", err)
	}
	workspaceIDs = append(workspaceIDs, receipt.ResourceID)
	fixture.clock.Advance(time.Second)
	receipt, err = fixture.service.Create(ctx, reference.CreateCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "/api/v1alpha1/workspaces", IdempotencyKey: "page-create-empty-label",
		Body: workspaceBody("empty-label", "", false),
	})
	if err != nil {
		t.Fatalf("Create(empty label) error = %v", err)
	}
	workspaceIDs = append(workspaceIDs, receipt.ResourceID)
	emptyLabelPage, err := fixture.service.List(ctx, reference.ListQuery{
		Principal: fixture.principal, WorkspaceIDs: workspaceIDs, Kind: hierarchy.KindWorkspace,
		MatchLabels: map[string]string{"team": ""},
	})
	if err != nil || len(emptyLabelPage.Items) != 1 ||
		emptyLabelPage.Items[0].Metadata.DisplayName() != "empty-label" {
		t.Fatalf("List(explicit empty label) items/error = %d/%v", len(emptyLabelPage.Items), err)
	}

	query := reference.ListQuery{
		Principal: fixture.principal, WorkspaceIDs: workspaceIDs, Kind: hierarchy.KindWorkspace,
		MatchLabels: map[string]string{"team": "platform"}, PageSize: 2,
	}
	first, err := fixture.service.List(ctx, query)
	if err != nil || len(first.Items) != 2 || first.NextPageToken == "" {
		t.Fatalf("List(first) items/token/error = %d/%q/%v", len(first.Items), first.NextPageToken, err)
	}
	again, err := fixture.service.List(ctx, query)
	if err != nil || again.NextPageToken != first.NextPageToken {
		t.Fatalf("List(deterministic first) token/error = %q/%v, want %q", again.NextPageToken, err, first.NextPageToken)
	}
	query.PageToken = first.NextPageToken
	second, err := fixture.service.List(ctx, query)
	if err != nil || len(second.Items) != 1 || second.NextPageToken != "" {
		t.Fatalf("List(second) items/token/error = %d/%q/%v", len(second.Items), second.NextPageToken, err)
	}
	retained := 0
	filteredSecond, err := fixture.service.ListWhere(ctx, query, func(
		reference.Resource,
		reference.AuthorizationStateResolver,
	) (bool, error) {
		retained++
		return true, nil
	})
	if err != nil || len(filteredSecond.Items) != 1 || retained != 3 {
		t.Fatalf("ListWhere(second) items/retained/error = %d/%d/%v, want 1/3/nil",
			len(filteredSecond.Items), retained, err)
	}
	if first.Items[0].Metadata.ID() == first.Items[1].Metadata.ID() ||
		first.Items[1].Metadata.ID() == second.Items[0].Metadata.ID() {
		t.Fatal("pagination duplicated a resource")
	}
	if !first.Items[0].Metadata.CreatedAt().Before(first.Items[1].Metadata.CreatedAt()) ||
		!first.Items[1].Metadata.CreatedAt().Before(second.Items[0].Metadata.CreatedAt()) {
		t.Fatal("workspace page order is not ascending by creation time")
	}

	wrongFilter := query
	wrongFilter.MatchLabels = map[string]string{"team": "other"}
	if _, err := fixture.service.List(ctx, wrongFilter); !errors.Is(err, reference.ErrInvalidPageToken) {
		t.Fatalf("List(cross-filter token) error = %v", err)
	}
	fixture.clock.Advance(reference.PageTokenLifetime)
	if _, err := fixture.service.List(ctx, query); !errors.Is(err, reference.ErrInvalidPageToken) {
		t.Fatalf("List(expired token) error = %v", err)
	}
}

func TestWorkspaceScopeIsMandatoryAcrossCRUDListsAndOperations(t *testing.T) {
	fixture := newFixture(t)
	ctx := context.Background()

	workspaceA, err := fixture.service.Create(ctx, reference.CreateCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "reference:isolation:create-a", IdempotencyKey: "isolation-create-a-0001",
		Body: workspaceBody("shared-display-name", "platform", false),
	})
	if err != nil {
		t.Fatalf("Create(Workspace A) error = %v", err)
	}
	fixture.clock.Advance(time.Millisecond)
	workspaceB, err := fixture.service.Create(ctx, reference.CreateCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "reference:isolation:create-b", IdempotencyKey: "isolation-create-b-0001",
		Body: workspaceBody("shared-display-name", "platform", false),
	})
	if err != nil {
		t.Fatalf("Create(Workspace B) error = %v", err)
	}

	if _, err := fixture.service.Get(
		ctx, fixture.principal, "", workspaceA.ResourceID,
	); !errors.Is(err, reference.ErrInvalidCommand) {
		t.Fatalf("Get(missing scope) error = %v, want ErrInvalidCommand", err)
	}
	if _, err := fixture.service.GetOperation(
		ctx, fixture.principal, "", workspaceA.OperationID,
	); !errors.Is(err, reference.ErrInvalidCommand) {
		t.Fatalf("GetOperation(missing scope) error = %v, want ErrInvalidCommand", err)
	}
	if _, err := fixture.service.Get(
		ctx, fixture.principal, workspaceB.ResourceID, workspaceA.ResourceID,
	); !errors.Is(err, reference.ErrNotFound) {
		t.Fatalf("Get(A through B scope) error = %v, want ErrNotFound", err)
	}
	if _, err := fixture.service.GetOperation(
		ctx, fixture.principal, workspaceB.ResourceID, workspaceA.OperationID,
	); !errors.Is(err, reference.ErrNotFound) {
		t.Fatalf("GetOperation(A through B scope) error = %v, want ErrNotFound", err)
	}

	before, err := fixture.service.Get(ctx, fixture.principal, workspaceA.ResourceID, workspaceA.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	correctReplace := reference.ReplaceCommand{
		Principal: fixture.principal, WorkspaceID: workspaceA.ResourceID,
		Kind: hierarchy.KindWorkspace, ResourceID: workspaceA.ResourceID,
		ExpectedResourceVersion: before.Metadata.ResourceVersion().String(),
		CanonicalTarget:         "reference:isolation:replace", IdempotencyKey: "isolation-replace-0001",
		Body: workspaceBody("updated-in-workspace-a", "platform", true),
	}
	missingScopeReplace := correctReplace
	missingScopeReplace.WorkspaceID = ""
	if _, err := fixture.service.Replace(ctx, missingScopeReplace); !errors.Is(err, reference.ErrInvalidCommand) {
		t.Fatalf("Replace(missing scope) error = %v, want ErrInvalidCommand", err)
	}
	receipt, err := fixture.service.Replace(ctx, correctReplace)
	if err != nil {
		t.Fatalf("Replace(A through A scope) error = %v", err)
	}
	wrongScopeReplace := correctReplace
	wrongScopeReplace.WorkspaceID = workspaceB.ResourceID
	if _, err := fixture.service.Replace(ctx, wrongScopeReplace); !errors.Is(err, reference.ErrNotFound) {
		t.Fatalf("Replace(A replay identity through B scope) error = %v, want ErrNotFound; A receipt was %#v",
			err, receipt)
	}
	current, err := fixture.service.Get(ctx, fixture.principal, workspaceA.ResourceID, workspaceA.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.ReplaceStatus(ctx, reference.StatusCommand{
		Principal: fixture.principal, WorkspaceID: workspaceB.ResourceID,
		Kind: hierarchy.KindWorkspace, ResourceID: workspaceA.ResourceID,
		ExpectedResourceVersion: current.Metadata.ResourceVersion().String(),
		CanonicalTarget:         "reference:isolation:status", IdempotencyKey: "isolation-status-0001",
		Body: statusBody(hierarchy.KindWorkspace, current.Metadata.Generation().Int64()),
	}); !errors.Is(err, reference.ErrNotFound) {
		t.Fatalf("ReplaceStatus(A through B scope) error = %v, want ErrNotFound", err)
	}
	if _, err := fixture.service.Delete(ctx, reference.DeleteCommand{
		Principal: fixture.principal, WorkspaceID: workspaceB.ResourceID,
		Kind: hierarchy.KindWorkspace, ResourceID: workspaceA.ResourceID,
		ExpectedResourceVersion: current.Metadata.ResourceVersion().String(),
		CanonicalTarget:         "reference:isolation:delete", IdempotencyKey: "isolation-delete-0001",
	}); !errors.Is(err, reference.ErrNotFound) {
		t.Fatalf("Delete(A through B scope) error = %v, want ErrNotFound", err)
	}
	after, err := fixture.service.Get(ctx, fixture.principal, workspaceA.ResourceID, workspaceA.ResourceID)
	if err != nil || after.Metadata.ResourceVersion() != current.Metadata.ResourceVersion() ||
		after.Metadata.DisplayName() != "updated-in-workspace-a" {
		t.Fatalf("Workspace A after rejected writes = %q/%q, %v",
			after.Metadata.DisplayName(), after.Metadata.ResourceVersion(), err)
	}

	members, err := authorization.NewMemberDirectory(workspaceA.ResourceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	foreignParent := workspaceB.ResourceID
	if _, err := fixture.service.Create(ctx, reference.CreateCommand{
		Principal: fixture.principal, Kind: hierarchy.KindEnvironment,
		WorkspaceID: workspaceA.ResourceID, ParentID: &foreignParent,
		CanonicalTarget: "reference:isolation:cross-parent", IdempotencyKey: "isolation-cross-parent-0001",
		Body: intentBody(hierarchy.KindEnvironment, "cross-parent", false), Members: members,
	}); err == nil {
		t.Fatal("Create(Environment with foreign parent) succeeded")
	}

	if _, err := fixture.service.List(ctx, reference.ListQuery{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace,
	}); !errors.Is(err, reference.ErrInvalidCommand) {
		t.Fatalf("List(missing root scopes) error = %v, want ErrInvalidCommand", err)
	}
	if _, err := fixture.service.List(ctx, reference.ListQuery{
		Principal: fixture.principal, Kind: hierarchy.KindEnvironment,
	}); !errors.Is(err, reference.ErrInvalidCommand) {
		t.Fatalf("List(missing child scope) error = %v, want ErrInvalidCommand", err)
	}
	if _, err := fixture.service.List(ctx, reference.ListQuery{
		Principal: fixture.principal, WorkspaceIDs: []resource.ID{workspaceA.ResourceID, workspaceA.ResourceID},
		Kind: hierarchy.KindWorkspace,
	}); !errors.Is(err, reference.ErrInvalidCommand) {
		t.Fatalf("List(duplicate scopes) error = %v, want ErrInvalidCommand", err)
	}
	oneScope, err := fixture.service.List(ctx, reference.ListQuery{
		Principal: fixture.principal, WorkspaceIDs: []resource.ID{workspaceA.ResourceID},
		Kind: hierarchy.KindWorkspace,
	})
	if err != nil || len(oneScope.Items) != 1 || oneScope.Items[0].Metadata.ID() != workspaceA.ResourceID {
		t.Fatalf("List(A scope) = %d items, %v", len(oneScope.Items), err)
	}
	unionQuery := reference.ListQuery{
		Principal:    fixture.principal,
		WorkspaceIDs: []resource.ID{workspaceB.ResourceID, workspaceA.ResourceID},
		Kind:         hierarchy.KindWorkspace, PageSize: 1,
	}
	first, err := fixture.service.List(ctx, unionQuery)
	if err != nil || len(first.Items) != 1 || first.NextPageToken == "" {
		t.Fatalf("List(A+B first page) = %d/%q, %v", len(first.Items), first.NextPageToken, err)
	}
	if _, err := fixture.service.List(ctx, reference.ListQuery{
		Principal: fixture.principal, WorkspaceIDs: []resource.ID{workspaceA.ResourceID},
		Kind: hierarchy.KindWorkspace, PageSize: 1, PageToken: first.NextPageToken,
	}); !errors.Is(err, reference.ErrInvalidPageToken) {
		t.Fatalf("List(token under narrowed scope) error = %v, want ErrInvalidPageToken", err)
	}
}

func TestConcurrentKeyReplayHasOneLogicalMutation(t *testing.T) {
	fixture := newFixture(t)
	command := reference.CreateCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "/api/v1alpha1/workspaces", IdempotencyKey: "concurrent-create-0001",
		Body: intentBody(hierarchy.KindWorkspace, "concurrent", false),
	}
	const workers = 32
	results := make(chan reference.MutationReceipt, workers)
	errorsSeen := make(chan error, workers)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			receipt, err := fixture.service.Create(context.Background(), command)
			if err != nil {
				errorsSeen <- err
				return
			}
			results <- receipt
		}()
	}
	group.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("concurrent Create() error = %v", err)
	}
	var first reference.MutationReceipt
	for receipt := range results {
		if first.ResourceID == "" {
			first = receipt
			continue
		}
		if !reflect.DeepEqual(receipt, first) {
			t.Fatalf("concurrent receipt = %#v, want %#v", receipt, first)
		}
	}
	page, err := fixture.service.List(context.Background(), reference.ListQuery{
		Principal: fixture.principal, WorkspaceIDs: []resource.ID{first.ResourceID}, Kind: hierarchy.KindWorkspace,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("List() after concurrent replay = %d items, %v", len(page.Items), err)
	}
}

func TestConcurrentDistinctWritesHaveOneETagWinner(t *testing.T) {
	fixture := newFixture(t)
	created, err := fixture.service.Create(context.Background(), reference.CreateCommand{
		Principal: fixture.principal, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "/api/v1alpha1/workspaces", IdempotencyKey: "etag-create-000001",
		Body: intentBody(hierarchy.KindWorkspace, "before", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	commands := []reference.ReplaceCommand{
		{
			Principal: fixture.principal, WorkspaceID: created.ResourceID,
			Kind: hierarchy.KindWorkspace, ResourceID: created.ResourceID,
			ExpectedResourceVersion: created.ResourceVersion, CanonicalTarget: "reference:race:replace",
			IdempotencyKey: "etag-racer-one-0001", Body: intentBody(hierarchy.KindWorkspace, "racer-one", true),
		},
		{
			Principal: fixture.principal, WorkspaceID: created.ResourceID,
			Kind: hierarchy.KindWorkspace, ResourceID: created.ResourceID,
			ExpectedResourceVersion: created.ResourceVersion, CanonicalTarget: "reference:race:replace",
			IdempotencyKey: "etag-racer-two-0001", Body: intentBody(hierarchy.KindWorkspace, "racer-two", true),
		},
	}
	start := make(chan struct{})
	var successes atomic.Int32
	var stale atomic.Int32
	var group sync.WaitGroup
	for _, command := range commands {
		command := command
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := fixture.service.Replace(context.Background(), command)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, reference.ErrPreconditionFailed):
				stale.Add(1)
			default:
				t.Errorf("Replace(racer) error = %v", err)
			}
		}()
	}
	close(start)
	group.Wait()
	if successes.Load() != 1 || stale.Load() != 1 {
		t.Fatalf("race outcomes success/stale = %d/%d, want 1/1", successes.Load(), stale.Load())
	}
}

func TestReplayCapacityIsClassified(t *testing.T) {
	fixture := newFixture(t)
	service, err := reference.New(reference.Config{
		Store: fixture.store, Clock: fixture.clock, Issuer: &reference.SequentialIssuer{},
		PageTokenKey: []byte("0123456789abcdef0123456789abcdef"), MaximumPageTokens: 64, MaximumReplays: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, name := range []string{"first", "second"} {
		_, err = service.Create(context.Background(), reference.CreateCommand{
			Principal: fixture.principal, Kind: hierarchy.KindWorkspace,
			CanonicalTarget: "/api/v1alpha1/workspaces", IdempotencyKey: idempotencyKey("capacity", index),
			Body: intentBody(hierarchy.KindWorkspace, name, false),
		})
		if index == 0 && err != nil {
			t.Fatalf("Create(first) error = %v", err)
		}
		if index == 1 && !errors.Is(err, reference.ErrCapacity) {
			t.Fatalf("Create(at replay capacity) error = %v, want ErrCapacity", err)
		}
	}
}

func intentBody(kind hierarchy.Kind, name string, suspend bool) []byte {
	switch kind {
	case hierarchy.KindWorkspace:
		return workspaceBody(name, "platform", suspend)
	case hierarchy.KindProviderConnection:
		return []byte(`{"apiVersion":"v1alpha1","kind":"ProviderConnection","metadata":{"displayName":"` + name + `","labels":{"team":"platform"}},"spec":{"provider":"aws","credentialRef":{"referenceId":"sec_000000000001","version":"v1"}}}`)
	case hierarchy.KindPolicy:
		return []byte(`{"apiVersion":"v1alpha1","kind":"Policy","metadata":{"displayName":"` + name + `","labels":{"team":"platform"}},"spec":{"bindings":[]}}`)
	default:
		return []byte(`{"apiVersion":"v1alpha1","kind":"` + kind.String() + `","metadata":{"displayName":"` + name + `","labels":{"team":"platform"}},"spec":{}}`)
	}
}

func workspaceBody(name, team string, suspend bool) []byte {
	value := "false"
	if suspend {
		value = "true"
	}
	return []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","metadata":{"displayName":"` + name + `","labels":{"team":"` + team + `"}},"spec":{"suspendReconciliation":` + value + `}}`)
}

func statusBody(kind hierarchy.Kind, generation int64) []byte {
	status := `{"observedGeneration":` + integer(generation) + `,"conditions":[]}`
	if kind == hierarchy.KindProviderConnection {
		status = `{"observedGeneration":` + integer(generation) + `,"conditions":[],"capabilities":[],"quotaChecks":[]}`
	}
	return []byte(`{"apiVersion":"v1alpha1","kind":"` + kind.String() + `","status":` + status + `}`)
}

func idempotencyKey(prefix string, index int) string {
	return prefix + "-0000000000000000-" + integer(int64(index))
}

func integer(value int64) string {
	if value == 0 {
		return "0"
	}
	result := make([]byte, 0, 20)
	for value > 0 {
		result = append(result, byte('0'+value%10))
		value /= 10
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return string(result)
}
