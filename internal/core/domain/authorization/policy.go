package authorization

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// BindingField identifies one stable field within a PolicySpec binding. It is
// intentionally a closed value so admission can map failures to exact paths
// without parsing error text.
type BindingField uint8

const (
	BindingFieldMemberID BindingField = iota + 1
	BindingFieldRole
	BindingFieldScopeKind
	BindingFieldEnvironmentID
)

func (field BindingField) String() string {
	switch field {
	case BindingFieldMemberID:
		return "memberId"
	case BindingFieldRole:
		return "role"
	case BindingFieldScopeKind:
		return "scope.kind"
	case BindingFieldEnvironmentID:
		return "scope.environmentId"
	default:
		return "binding"
	}
}

// BindingError retains only a bounded index, a closed field, and a safe
// sentinel cause. It never includes a submitted member or environment ID.
type BindingError struct {
	index int
	field BindingField
	cause error
}

func (err *BindingError) Error() string {
	if err == nil {
		return "authorization policy binding error"
	}
	return fmt.Sprintf("authorization policy binding %d field %s: %v", err.index, err.field, err.cause)
}

// Unwrap exposes stable error classification to errors.Is.
func (err *BindingError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

// BindingIndex is the zero-based binding index.
func (err *BindingError) BindingIndex() int {
	if err == nil {
		return 0
	}
	return err.index
}

// Field is the exact failing field class.
func (err *BindingError) Field() BindingField {
	if err == nil {
		return 0
	}
	return err.field
}

// Scope is one exact Workspace or Environment grant root. Workspace grants
// descend to every Environment in that Workspace. Environment grants descend
// only within the named Environment.
type Scope struct {
	Kind          ScopeKind    `json:"kind"`
	EnvironmentID *resource.ID `json:"environmentId,omitempty"`
}

// RoleBinding grants one role to one opaque member at one scope root.
type RoleBinding struct {
	MemberID resource.ID `json:"memberId"`
	Role     Role        `json:"role"`
	Scope    Scope       `json:"scope"`
}

// PolicySpec is the bounded, canonical, provider-independent Policy desired
// state. Bindings are required and ordered by memberId, scope kind,
// environmentId, then role using exact wire strings.
type PolicySpec struct {
	Bindings []RoleBinding `json:"bindings"`
}

// ValidatePolicySpec rejects incomplete, non-canonical, duplicate, or
// over-limit policy bindings without resolving references.
func ValidatePolicySpec(spec PolicySpec) error {
	if spec.Bindings == nil {
		return fmt.Errorf("%w: %w", ErrInvalidPolicySpec, ErrBindingsRequired)
	}
	if len(spec.Bindings) > MaxBindingsPerPolicy {
		return fmt.Errorf("%w: %w", ErrInvalidPolicySpec, ErrTooManyBindings)
	}
	for index, binding := range spec.Bindings {
		if err := validateRoleBinding(binding); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidPolicySpec, bindingError(index, err.field, err.cause))
		}
		if index == 0 {
			continue
		}
		comparison := CompareRoleBindings(spec.Bindings[index-1], binding)
		switch {
		case comparison == 0:
			return fmt.Errorf("%w: %w", ErrInvalidPolicySpec,
				bindingError(index, BindingFieldMemberID, ErrDuplicateBinding))
		case comparison > 0:
			return fmt.Errorf("%w: %w", ErrInvalidPolicySpec,
				bindingError(index, BindingFieldMemberID, ErrInvalidBindingOrder))
		}
	}
	return nil
}

// ValidatePolicyReferences resolves every opaque binding reference against
// the exact Workspace snapshot and private member directory. Even a
// Workspace-only policy requires both valid views because member IDs remain
// references rather than embedded identity claims.
func ValidatePolicyReferences(
	spec PolicySpec,
	snapshot hierarchy.Snapshot,
	directory MemberDirectory,
) error {
	if err := ValidatePolicySpec(spec); err != nil {
		return err
	}
	root, err := snapshot.Lookup(snapshot.WorkspaceID())
	if err != nil {
		return fmt.Errorf("%w: invalid hierarchy snapshot", ErrInvalidPolicySpec)
	}
	if root.Kind() != hierarchy.KindWorkspace {
		return fmt.Errorf("%w: %w", ErrInvalidPolicySpec, ErrReferenceKindMismatch)
	}
	if err := ValidateMemberDirectory(directory); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPolicySpec, ErrInvalidMemberDirectory)
	}
	if directory.WorkspaceID() != snapshot.WorkspaceID() || root.WorkspaceID() != directory.WorkspaceID() {
		return fmt.Errorf("%w: %w", ErrInvalidPolicySpec, ErrWorkspaceMismatch)
	}

	for index, binding := range spec.Bindings {
		member, exists := directory.byID[binding.MemberID]
		if !exists {
			return fmt.Errorf("%w: %w", ErrInvalidPolicySpec,
				bindingError(index, BindingFieldMemberID, ErrMemberNotFound))
		}
		if member.WorkspaceID() != directory.WorkspaceID() {
			return fmt.Errorf("%w: %w", ErrInvalidPolicySpec,
				bindingError(index, BindingFieldMemberID, ErrWorkspaceMismatch))
		}
		if binding.Role == RoleWorkspaceAdministrator && member.Kind() != identity.KindHuman {
			return fmt.Errorf("%w: %w", ErrInvalidPolicySpec,
				bindingError(index, BindingFieldRole, ErrPrincipalKindNotAllowed))
		}
		if binding.Scope.Kind != ScopeKindEnvironment {
			continue
		}
		environment, err := snapshot.Lookup(*binding.Scope.EnvironmentID)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidPolicySpec,
				bindingError(index, BindingFieldEnvironmentID, ErrEnvironmentNotFound))
		}
		if environment.Kind() != hierarchy.KindEnvironment {
			return fmt.Errorf("%w: %w", ErrInvalidPolicySpec,
				bindingError(index, BindingFieldEnvironmentID, ErrReferenceKindMismatch))
		}
		if environment.WorkspaceID() != directory.WorkspaceID() {
			return fmt.Errorf("%w: %w", ErrInvalidPolicySpec,
				bindingError(index, BindingFieldEnvironmentID, ErrWorkspaceMismatch))
		}
	}
	return nil
}

// CompareRoleBindings returns -1, 0, or 1 in the canonical tuple order.
func CompareRoleBindings(left, right RoleBinding) int {
	if result := strings.Compare(left.MemberID.String(), right.MemberID.String()); result != 0 {
		return result
	}
	if result := strings.Compare(left.Scope.Kind.String(), right.Scope.Kind.String()); result != 0 {
		return result
	}
	if result := strings.Compare(scopeEnvironment(left.Scope), scopeEnvironment(right.Scope)); result != 0 {
		return result
	}
	return strings.Compare(left.Role.String(), right.Role.String())
}

// ClonePolicySpec returns an ownership-independent policy value while
// preserving nil versus explicitly empty collections.
func ClonePolicySpec(spec PolicySpec) PolicySpec {
	if spec.Bindings == nil {
		return PolicySpec{}
	}
	result := PolicySpec{Bindings: make([]RoleBinding, len(spec.Bindings))}
	for index, binding := range spec.Bindings {
		result.Bindings[index] = cloneRoleBinding(binding)
	}
	return result
}

// EqualPolicySpec compares exact policy meaning and collection presence.
func EqualPolicySpec(left, right PolicySpec) bool {
	return (left.Bindings == nil) == (right.Bindings == nil) &&
		slices.EqualFunc(left.Bindings, right.Bindings, equalRoleBinding)
}

type roleBindingError struct {
	field BindingField
	cause error
}

func validateRoleBinding(binding RoleBinding) *roleBindingError {
	if _, err := resource.ParseID(binding.MemberID.String()); err != nil {
		return &roleBindingError{field: BindingFieldMemberID, cause: ErrInvalidBinding}
	}
	if _, err := ParseRole(binding.Role.String()); err != nil {
		return &roleBindingError{field: BindingFieldRole, cause: ErrInvalidRole}
	}
	switch binding.Scope.Kind {
	case ScopeKindWorkspace:
		if binding.Scope.EnvironmentID != nil {
			return &roleBindingError{field: BindingFieldEnvironmentID, cause: ErrInvalidScope}
		}
	case ScopeKindEnvironment:
		if binding.Scope.EnvironmentID == nil {
			return &roleBindingError{field: BindingFieldEnvironmentID, cause: ErrInvalidScope}
		}
		if _, err := resource.ParseID(binding.Scope.EnvironmentID.String()); err != nil {
			return &roleBindingError{field: BindingFieldEnvironmentID, cause: ErrInvalidScope}
		}
		if binding.Role == RoleWorkspaceAdministrator {
			return &roleBindingError{field: BindingFieldScopeKind, cause: ErrInvalidScope}
		}
	default:
		return &roleBindingError{field: BindingFieldScopeKind, cause: ErrInvalidScope}
	}
	return nil
}

func bindingError(index int, field BindingField, cause error) *BindingError {
	return &BindingError{index: index, field: field, cause: cause}
}

func scopeEnvironment(scope Scope) string {
	if scope.EnvironmentID == nil {
		return ""
	}
	return scope.EnvironmentID.String()
}

func cloneRoleBinding(binding RoleBinding) RoleBinding {
	binding.Scope.EnvironmentID = cloneIDPointer(binding.Scope.EnvironmentID)
	return binding
}

func equalRoleBinding(left, right RoleBinding) bool {
	return left.MemberID == right.MemberID && left.Role == right.Role &&
		left.Scope.Kind == right.Scope.Kind && equalIDPointers(left.Scope.EnvironmentID, right.Scope.EnvironmentID)
}
