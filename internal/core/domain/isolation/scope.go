// Package isolation defines the stable Workspace scope values that bind every
// tenant-owned storage operation. Display names are deliberately absent from
// this boundary.
package isolation

import (
	"errors"
	"sort"
	"strings"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// MaxWorkspaceScopes bounds one explicit multi-Workspace read.
const MaxWorkspaceScopes = 4_096

const workspaceIDPrefix = "wsp_"

// ErrInvalidWorkspaceScope marks a missing, malformed, duplicate, or otherwise
// non-canonical Workspace scope.
var ErrInvalidWorkspaceScope = errors.New("invalid Workspace scope")

// WorkspaceScope is one validated stable Workspace ownership key. Its zero
// value is invalid so omitted scope fails closed at adapter boundaries.
type WorkspaceScope struct{ workspaceID resource.ID }

// NewWorkspaceScope validates one already-issued stable Workspace ID.
func NewWorkspaceScope(workspaceID resource.ID) (WorkspaceScope, error) {
	parsed, err := resource.ParseID(workspaceID.String())
	if err != nil || !strings.HasPrefix(parsed.String(), workspaceIDPrefix) {
		return WorkspaceScope{}, ErrInvalidWorkspaceScope
	}
	return WorkspaceScope{workspaceID: parsed}, nil
}

// ValidateWorkspaceScope checks a scope received across a package boundary.
func ValidateWorkspaceScope(scope WorkspaceScope) error {
	parsed, err := resource.ParseID(scope.workspaceID.String())
	if err != nil || parsed != scope.workspaceID || !strings.HasPrefix(parsed.String(), workspaceIDPrefix) {
		return ErrInvalidWorkspaceScope
	}
	return nil
}

// WorkspaceID returns the stable opaque ownership key.
func (scope WorkspaceScope) WorkspaceID() resource.ID { return scope.workspaceID }

// WorkspaceScopeSet is one non-empty, sorted, duplicate-free collection of
// explicit Workspace scopes. Its zero value is invalid.
type WorkspaceScopeSet struct{ scopes []WorkspaceScope }

// NewWorkspaceScopeSet validates, sorts, and owns the supplied stable IDs.
func NewWorkspaceScopeSet(workspaceIDs ...resource.ID) (WorkspaceScopeSet, error) {
	if len(workspaceIDs) == 0 || len(workspaceIDs) > MaxWorkspaceScopes {
		return WorkspaceScopeSet{}, ErrInvalidWorkspaceScope
	}
	scopes := make([]WorkspaceScope, len(workspaceIDs))
	for index, workspaceID := range workspaceIDs {
		scope, err := NewWorkspaceScope(workspaceID)
		if err != nil {
			return WorkspaceScopeSet{}, err
		}
		scopes[index] = scope
	}
	sort.Slice(scopes, func(left, right int) bool {
		return scopes[left].workspaceID.String() < scopes[right].workspaceID.String()
	})
	for index := 1; index < len(scopes); index++ {
		if scopes[index-1].workspaceID == scopes[index].workspaceID {
			return WorkspaceScopeSet{}, ErrInvalidWorkspaceScope
		}
	}
	return WorkspaceScopeSet{scopes: scopes}, nil
}

// ValidateWorkspaceScopeSet checks the non-empty canonical representation.
func ValidateWorkspaceScopeSet(set WorkspaceScopeSet) error {
	if len(set.scopes) == 0 || len(set.scopes) > MaxWorkspaceScopes {
		return ErrInvalidWorkspaceScope
	}
	for index, scope := range set.scopes {
		if ValidateWorkspaceScope(scope) != nil {
			return ErrInvalidWorkspaceScope
		}
		if index > 0 && set.scopes[index-1].workspaceID.String() >= scope.workspaceID.String() {
			return ErrInvalidWorkspaceScope
		}
	}
	return nil
}

// Scopes returns a defensive copy in canonical order.
func (set WorkspaceScopeSet) Scopes() []WorkspaceScope {
	return append([]WorkspaceScope(nil), set.scopes...)
}

// WorkspaceIDs returns the stable keys in canonical order.
func (set WorkspaceScopeSet) WorkspaceIDs() []resource.ID {
	result := make([]resource.ID, len(set.scopes))
	for index, scope := range set.scopes {
		result[index] = scope.workspaceID
	}
	return result
}

// Contains reports whether the canonical set includes one stable Workspace ID.
func (set WorkspaceScopeSet) Contains(workspaceID resource.ID) bool {
	index := sort.Search(len(set.scopes), func(index int) bool {
		return set.scopes[index].workspaceID.String() >= workspaceID.String()
	})
	return index < len(set.scopes) && set.scopes[index].workspaceID == workspaceID
}

// Len returns the number of explicit scopes.
func (set WorkspaceScopeSet) Len() int { return len(set.scopes) }
