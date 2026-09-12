package memory

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/isolation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
)

var fixtureID = resource.ID("wsp_000000000001")

func TestUpdateIsAtomicAndOwnershipSafe(t *testing.T) {
	t.Parallel()

	store := NewStore()
	scope := mustScope(t, fixtureID)
	scopes := mustScopes(t, fixtureID)
	original := []byte(`{"state":"initial"}`)
	if err := store.Update(context.Background(), scope, func(tx ports.ReferenceTransaction) error {
		tx.PutResource(fixtureID, original)
		return nil
	}); err != nil {
		t.Fatalf("seed Update() error = %v", err)
	}
	original[0] = 'x'

	wantFailure := errors.New("injected failure")
	if err := store.Update(context.Background(), scope, func(tx ports.ReferenceTransaction) error {
		value, exists := tx.GetResource(fixtureID)
		if !exists {
			t.Fatal("working transaction did not see seeded resource")
		}
		value[0] = 'x'
		tx.PutResource(fixtureID, []byte(`{"state":"changed"}`))
		return wantFailure
	}); !errors.Is(err, wantFailure) {
		t.Fatalf("failed Update() error = %v, want injected failure", err)
	}

	if err := store.View(context.Background(), scopes, func(reader ports.ReferenceReader) error {
		value, exists := reader.GetResource(fixtureID)
		if !exists || string(value) != `{"state":"initial"}` {
			t.Fatalf("stored resource = %q / %t", value, exists)
		}
		value[0] = 'x'
		again, _ := reader.GetResource(fixtureID)
		if string(again) != `{"state":"initial"}` {
			t.Fatalf("reader alias mutated stored value: %q", again)
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func TestConcurrentUpdatesAreSerializable(t *testing.T) {
	t.Parallel()

	store := NewStore()
	scope := mustScope(t, fixtureID)
	scopes := mustScopes(t, fixtureID)
	const workers = 32
	var group sync.WaitGroup
	group.Add(workers)
	for index := 0; index < workers; index++ {
		index := index
		go func() {
			defer group.Done()
			id := resource.ID("wsp_" + leftPad(index))
			if err := store.Update(context.Background(), scope, func(tx ports.ReferenceTransaction) error {
				tx.PutResource(id, []byte(id))
				return nil
			}); err != nil {
				t.Errorf("Update(%d) error = %v", index, err)
			}
		}()
	}
	group.Wait()

	if err := store.View(context.Background(), scopes, func(reader ports.ReferenceReader) error {
		if got := len(reader.ListResources()); got != workers {
			t.Fatalf("resource count = %d, want %d", got, workers)
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func TestWorkspaceScopesFailClosedAndCannotCrossRead(t *testing.T) {
	t.Parallel()

	store := NewStore()
	workspaceA := resource.ID("wsp_01JSTORE000000000000000A")
	workspaceB := resource.ID("wsp_01JSTORE000000000000000B")
	sharedID := resource.ID("env_01JSTORE0000000000000000")

	called := false
	if err := store.Update(context.Background(), isolation.WorkspaceScope{}, func(ports.ReferenceTransaction) error {
		called = true
		return nil
	}); !errors.Is(err, isolation.ErrInvalidWorkspaceScope) || called {
		t.Fatalf("zero-scope Update() = %v / called %t", err, called)
	}
	if err := store.View(context.Background(), isolation.WorkspaceScopeSet{}, func(ports.ReferenceReader) error {
		called = true
		return nil
	}); !errors.Is(err, isolation.ErrInvalidWorkspaceScope) || called {
		t.Fatalf("zero-scope View() = %v / called %t", err, called)
	}
	wrongKindScope, err := isolation.NewWorkspaceScope(resource.ID("env_01JSTORE0000000000000000"))
	if !errors.Is(err, isolation.ErrInvalidWorkspaceScope) {
		t.Fatalf("NewWorkspaceScope(non-Workspace ID) error = %v", err)
	}
	called = false
	if err := store.Update(context.Background(), wrongKindScope, func(ports.ReferenceTransaction) error {
		called = true
		return nil
	}); !errors.Is(err, isolation.ErrInvalidWorkspaceScope) || called {
		t.Fatalf("non-Workspace-scope Update() = %v / called %t", err, called)
	}

	for workspaceID, canonical := range map[resource.ID]string{
		workspaceA: `{"workspace":"A"}`,
		workspaceB: `{"workspace":"B"}`,
	} {
		if err := store.Update(context.Background(), mustScope(t, workspaceID), func(tx ports.ReferenceTransaction) error {
			tx.PutResource(sharedID, []byte(canonical))
			return nil
		}); err != nil {
			t.Fatalf("Update(%s) error = %v", workspaceID, err)
		}
	}

	if err := store.View(context.Background(), mustScopes(t, workspaceA), func(reader ports.ReferenceReader) error {
		value, exists := reader.GetResource(sharedID)
		if !exists || string(value) != `{"workspace":"A"}` {
			t.Fatalf("Workspace A read = %q / %t", value, exists)
		}
		return nil
	}); err != nil {
		t.Fatalf("View(Workspace A) error = %v", err)
	}
	if err := store.View(context.Background(), mustScopes(t, workspaceB), func(reader ports.ReferenceReader) error {
		value, exists := reader.GetResource(sharedID)
		if !exists || string(value) != `{"workspace":"B"}` {
			t.Fatalf("Workspace B read = %q / %t", value, exists)
		}
		return nil
	}); err != nil {
		t.Fatalf("View(Workspace B) error = %v", err)
	}
	if err := store.View(context.Background(), mustScopes(t, workspaceA, workspaceB), func(ports.ReferenceReader) error {
		called = true
		return nil
	}); !errors.Is(err, ErrIdentityCollision) {
		t.Fatalf("colliding multi-scope View() error = %v", err)
	}
}

func mustScope(t *testing.T, workspaceID resource.ID) isolation.WorkspaceScope {
	t.Helper()
	scope, err := isolation.NewWorkspaceScope(workspaceID)
	if err != nil {
		t.Fatalf("NewWorkspaceScope(%q) error = %v", workspaceID, err)
	}
	return scope
}

func mustScopes(t *testing.T, workspaceIDs ...resource.ID) isolation.WorkspaceScopeSet {
	t.Helper()
	scopes, err := isolation.NewWorkspaceScopeSet(workspaceIDs...)
	if err != nil {
		t.Fatalf("NewWorkspaceScopeSet(%q) error = %v", workspaceIDs, err)
	}
	return scopes
}

func leftPad(value int) string {
	digits := []byte("000000000000")
	for index := len(digits) - 1; value > 0; index-- {
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits)
}
