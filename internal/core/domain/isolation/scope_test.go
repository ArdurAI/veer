package isolation

import (
	"errors"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

var (
	workspaceA = resource.ID("wsp_01JISOLATION000000000000A")
	workspaceB = resource.ID("wsp_01JISOLATION000000000000B")
)

func TestWorkspaceScopeRejectsMissingAndMalformedIDs(t *testing.T) {
	t.Parallel()

	for _, workspaceID := range []resource.ID{"", "production", "this is a mutable display name"} {
		if _, err := NewWorkspaceScope(workspaceID); !errors.Is(err, ErrInvalidWorkspaceScope) {
			t.Fatalf("NewWorkspaceScope(%q) error = %v, want ErrInvalidWorkspaceScope", workspaceID, err)
		}
	}
	if err := ValidateWorkspaceScope(WorkspaceScope{}); !errors.Is(err, ErrInvalidWorkspaceScope) {
		t.Fatalf("ValidateWorkspaceScope(zero) error = %v", err)
	}
}

func TestWorkspaceScopeSetIsCanonicalAndOwnershipSafe(t *testing.T) {
	t.Parallel()

	set, err := NewWorkspaceScopeSet(workspaceB, workspaceA)
	if err != nil {
		t.Fatalf("NewWorkspaceScopeSet() error = %v", err)
	}
	if err := ValidateWorkspaceScopeSet(set); err != nil {
		t.Fatalf("ValidateWorkspaceScopeSet() error = %v", err)
	}
	ids := set.WorkspaceIDs()
	if len(ids) != 2 || ids[0] != workspaceA || ids[1] != workspaceB {
		t.Fatalf("WorkspaceIDs() = %#v", ids)
	}
	ids[0] = workspaceB
	if set.WorkspaceIDs()[0] != workspaceA {
		t.Fatal("WorkspaceIDs() leaked its owned representation")
	}
	if _, err := NewWorkspaceScopeSet(workspaceA, workspaceA); !errors.Is(err, ErrInvalidWorkspaceScope) {
		t.Fatalf("duplicate scope error = %v", err)
	}
	overLimit := make([]resource.ID, MaxWorkspaceScopes+1)
	for index := range overLimit {
		overLimit[index] = workspaceA
	}
	if _, err := NewWorkspaceScopeSet(overLimit...); !errors.Is(err, ErrInvalidWorkspaceScope) {
		t.Fatalf("over-limit scope-set error = %v", err)
	}
	if err := ValidateWorkspaceScopeSet(WorkspaceScopeSet{
		scopes: make([]WorkspaceScope, MaxWorkspaceScopes+1),
	}); !errors.Is(err, ErrInvalidWorkspaceScope) {
		t.Fatalf("ValidateWorkspaceScopeSet(over limit) error = %v", err)
	}
	if err := ValidateWorkspaceScopeSet(WorkspaceScopeSet{}); !errors.Is(err, ErrInvalidWorkspaceScope) {
		t.Fatalf("zero scope set error = %v", err)
	}
}
