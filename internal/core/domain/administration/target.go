package administration

import (
	"fmt"
	"log/slog"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// Target is an opaque privileged scope derived from retained domain state.
// The platform-wide audit target is the sole target without object or scope
// IDs; every other target is resolved rather than caller-asserted.
type Target struct {
	initialized          bool
	kind                 TargetKind
	objectID             *resource.ID
	workspaceID          *resource.ID
	resourceID           *resource.ID
	environmentID        *resource.ID
	providerConnectionID *resource.ID
}

// ResolvePlatformAuditExportTarget seals the singleton platform audit scope.
func ResolvePlatformAuditExportTarget() Target {
	return Target{initialized: true, kind: TargetKindPlatformAudit}
}

// ResolveWorkspaceAuditExportTarget seals the root of one validated retained
// Workspace snapshot.
func ResolveWorkspaceAuditExportTarget(snapshot hierarchy.Snapshot) (Target, error) {
	workspaceID := snapshot.WorkspaceID()
	workspace, err := snapshot.Lookup(workspaceID)
	if err != nil || workspace.Kind() != hierarchy.KindWorkspace ||
		workspace.ID() != workspaceID || workspace.WorkspaceID() != workspaceID {
		return Target{}, ErrInvalidTarget
	}
	return newTarget(
		TargetKindWorkspaceAudit,
		idPointer(workspaceID),
		idPointer(workspaceID),
		idPointer(workspaceID),
		nil,
		nil,
	)
}

// ResolveOperationTarget validates an Operation and re-derives its retained
// resource, Workspace, Environment, and optional ProviderConnection binding
// from the supplied snapshot.
func ResolveOperationTarget(snapshot hierarchy.Snapshot, value operation.Operation) (Target, error) {
	if err := operation.Validate(value); err != nil {
		return Target{}, fmt.Errorf("%w: operation", ErrInvalidTarget)
	}
	if snapshot.WorkspaceID() != value.WorkspaceID {
		return Target{}, fmt.Errorf("%w: workspace", ErrInvalidTarget)
	}
	retained, err := snapshot.Lookup(value.ResourceID)
	if err != nil || retained.WorkspaceID() != value.WorkspaceID {
		return Target{}, fmt.Errorf("%w: retained resource", ErrInvalidTarget)
	}
	resolved, err := authorization.ResolveResourceTarget(snapshot, value.ResourceID)
	if err != nil || resolved.WorkspaceID() != value.WorkspaceID {
		return Target{}, fmt.Errorf("%w: retained resource scope", ErrInvalidTarget)
	}

	resolvedEnvironment, environmentPresent := resolved.EnvironmentID()
	if value.EnvironmentID != nil &&
		(!environmentPresent || resolvedEnvironment != *value.EnvironmentID) {
		return Target{}, fmt.Errorf("%w: environment binding", ErrInvalidTarget)
	}

	var providerID *resource.ID
	if value.ProviderConnectionID != nil {
		provider, lookupErr := snapshot.Lookup(*value.ProviderConnectionID)
		if lookupErr != nil || provider.Kind() != hierarchy.KindProviderConnection ||
			provider.WorkspaceID() != value.WorkspaceID || value.EnvironmentID == nil {
			return Target{}, fmt.Errorf("%w: provider connection binding", ErrInvalidTarget)
		}
		parentID, present := provider.Parent()
		if !present || parentID != *value.EnvironmentID {
			return Target{}, fmt.Errorf("%w: provider connection environment", ErrInvalidTarget)
		}
		providerID = idPointer(*value.ProviderConnectionID)
	}

	return newTarget(
		TargetKindOperation,
		idPointer(value.ID),
		idPointer(value.WorkspaceID),
		idPointer(value.ResourceID),
		cloneID(value.EnvironmentID),
		providerID,
	)
}

func newTarget(
	kind TargetKind,
	objectID, workspaceID, resourceID, environmentID, providerConnectionID *resource.ID,
) (Target, error) {
	target := Target{
		initialized:          true,
		kind:                 kind,
		objectID:             cloneID(objectID),
		workspaceID:          cloneID(workspaceID),
		resourceID:           cloneID(resourceID),
		environmentID:        cloneID(environmentID),
		providerConnectionID: cloneID(providerConnectionID),
	}
	if err := ValidateTarget(target); err != nil {
		return Target{}, err
	}
	return target, nil
}

// ValidateTarget checks the complete closed target shape.
func ValidateTarget(target Target) error {
	if !target.initialized || !validTargetKind(target.kind) {
		return ErrInvalidTarget
	}
	for _, id := range []*resource.ID{
		target.objectID,
		target.workspaceID,
		target.resourceID,
		target.environmentID,
		target.providerConnectionID,
	} {
		if id != nil {
			if _, err := resource.ParseID(id.String()); err != nil {
				return ErrInvalidTarget
			}
		}
	}
	switch target.kind {
	case TargetKindPlatformAudit:
		if target.objectID != nil || target.workspaceID != nil || target.resourceID != nil ||
			target.environmentID != nil || target.providerConnectionID != nil {
			return ErrInvalidTarget
		}
	case TargetKindWorkspaceAudit:
		if target.objectID == nil || target.workspaceID == nil || target.resourceID == nil ||
			target.environmentID != nil || target.providerConnectionID != nil ||
			*target.objectID != *target.workspaceID || *target.resourceID != *target.workspaceID {
			return ErrInvalidTarget
		}
	case TargetKindOperation:
		if target.objectID == nil || target.workspaceID == nil || target.resourceID == nil ||
			(target.environmentID == nil) != (target.providerConnectionID == nil) {
			return ErrInvalidTarget
		}
	default:
		return ErrInvalidTarget
	}
	return nil
}

func validActionTarget(action authorization.Action, target Target) bool {
	if !validAction(action) || ValidateTarget(target) != nil {
		return false
	}
	switch action {
	case authorization.ActionAuditExport:
		return target.kind == TargetKindPlatformAudit || target.kind == TargetKindWorkspaceAudit
	case authorization.ActionOperationQuarantine, authorization.ActionWorkRedrive:
		return target.kind == TargetKindOperation
	default:
		return false
	}
}

// Kind returns the closed privileged target classification.
func (target Target) Kind() TargetKind { return target.kind }

func (target Target) ObjectID() (resource.ID, bool)      { return optionalID(target.objectID) }
func (target Target) WorkspaceID() (resource.ID, bool)   { return optionalID(target.workspaceID) }
func (target Target) ResourceID() (resource.ID, bool)    { return optionalID(target.resourceID) }
func (target Target) EnvironmentID() (resource.ID, bool) { return optionalID(target.environmentID) }
func (target Target) ProviderConnectionID() (resource.ID, bool) {
	return optionalID(target.providerConnectionID)
}

func equalTarget(left, right Target) bool {
	return ValidateTarget(left) == nil && ValidateTarget(right) == nil &&
		left.kind == right.kind && equalID(left.objectID, right.objectID) &&
		equalID(left.workspaceID, right.workspaceID) && equalID(left.resourceID, right.resourceID) &&
		equalID(left.environmentID, right.environmentID) &&
		equalID(left.providerConnectionID, right.providerConnectionID)
}

func cloneTarget(target Target) Target {
	target.objectID = cloneID(target.objectID)
	target.workspaceID = cloneID(target.workspaceID)
	target.resourceID = cloneID(target.resourceID)
	target.environmentID = cloneID(target.environmentID)
	target.providerConnectionID = cloneID(target.providerConnectionID)
	return target
}

func cloneID(value *resource.ID) *resource.ID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func idPointer(value resource.ID) *resource.ID { return &value }

func optionalID(value *resource.ID) (resource.ID, bool) {
	if value == nil {
		return "", false
	}
	return *value, true
}

func equalID(left, right *resource.ID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (target Target) String() string {
	if ValidateTarget(target) != nil {
		return "administration-target(invalid)"
	}
	return "administration-target(kind=" + string(target.kind) + ",scope=redacted)"
}

func (target Target) GoString() string { return target.String() }
func (target Target) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, target.String())
}
func (target Target) LogValue() slog.Value    { return redactedLogValue(target.String()) }
func (Target) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Target) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Target) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Target) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
