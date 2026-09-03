package authorization

import (
	"fmt"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// Target is an opaque authorization target sealed from a hierarchy Snapshot
// or Placement. Callers cannot assert Workspace or Environment ownership.
type Target struct {
	initialized          bool
	objectKind           ObjectKind
	objectID             resource.ID
	resourceKind         hierarchy.Kind
	resourceID           resource.ID
	workspaceID          resource.ID
	environmentID        *resource.ID
	providerConnectionID *resource.ID
}

// ResolveResourceTarget seals one retained hierarchy resource.
func ResolveResourceTarget(snapshot hierarchy.Snapshot, id resource.ID) (Target, error) {
	record, err := snapshot.Lookup(id)
	if err != nil {
		return Target{}, fmt.Errorf("%w: resource lookup", ErrInvalidTarget)
	}
	return targetFromRecord(snapshot, ObjectKindResource, id, record, nil)
}

// ResolveCreateTarget seals one server-derived hierarchy Placement. A root
// Workspace placement is self-authenticating but remains a reserved action;
// every non-root placement is re-derived against the supplied snapshot.
func ResolveCreateTarget(snapshot hierarchy.Snapshot, placement hierarchy.Placement) (Target, error) {
	placement = placement.Clone()
	if _, err := hierarchy.ParseKind(placement.Kind().String()); err != nil {
		return Target{}, ErrInvalidTarget
	}
	if _, err := resource.ParseID(placement.ID().String()); err != nil {
		return Target{}, ErrInvalidTarget
	}
	if _, err := resource.ParseID(placement.WorkspaceID().String()); err != nil {
		return Target{}, ErrInvalidTarget
	}

	if placement.Kind() == hierarchy.KindWorkspace {
		derived, err := hierarchy.DeriveWorkspace(placement.ID())
		if err != nil || !equalPlacement(derived, placement) {
			return Target{}, ErrInvalidTarget
		}
		return newTarget(
			ObjectKindResource,
			placement.ID(),
			hierarchy.KindWorkspace,
			placement.ID(),
			placement.WorkspaceID(),
			nil,
			nil,
		)
	}

	parentID, present := placement.Parent()
	if !present {
		return Target{}, ErrInvalidTarget
	}
	derived, err := snapshot.DeriveChild(placement.Kind(), placement.ID(), parentID)
	if err != nil || !equalPlacement(derived, placement) {
		return Target{}, fmt.Errorf("%w: placement does not match hierarchy", ErrInvalidTarget)
	}
	environmentID, err := resolvePlacementEnvironment(snapshot, placement)
	if err != nil {
		return Target{}, err
	}
	return newTarget(
		ObjectKindResource,
		placement.ID(),
		placement.Kind(),
		placement.ID(),
		placement.WorkspaceID(),
		environmentID,
		nil,
	)
}

// ResolveWorkspaceObjectTarget seals a Workspace-scoped Membership or Audit
// object without accepting caller-provided scope identifiers.
func ResolveWorkspaceObjectTarget(
	snapshot hierarchy.Snapshot,
	kind ObjectKind,
	id resource.ID,
) (Target, error) {
	if kind != ObjectKindMembership && kind != ObjectKindAudit {
		return Target{}, ErrInvalidTarget
	}
	if _, err := resource.ParseID(id.String()); err != nil {
		return Target{}, ErrInvalidTarget
	}
	workspace, err := snapshot.Lookup(snapshot.WorkspaceID())
	if err != nil || workspace.Kind() != hierarchy.KindWorkspace || workspace.ID() != workspace.WorkspaceID() {
		return Target{}, ErrInvalidTarget
	}
	return newTarget(
		kind,
		id,
		hierarchy.KindWorkspace,
		workspace.ID(),
		workspace.WorkspaceID(),
		nil,
		nil,
	)
}

// ValidateTarget checks a complete sealed value.
func ValidateTarget(target Target) error {
	if !target.initialized {
		return ErrInvalidTarget
	}
	if _, err := ParseObjectKind(target.objectKind.String()); err != nil {
		return ErrInvalidTarget
	}
	if _, err := hierarchy.ParseKind(target.resourceKind.String()); err != nil {
		return ErrInvalidTarget
	}
	for _, id := range []resource.ID{target.objectID, target.resourceID, target.workspaceID} {
		if _, err := resource.ParseID(id.String()); err != nil {
			return ErrInvalidTarget
		}
	}
	if target.resourceKind == hierarchy.KindWorkspace && target.resourceID != target.workspaceID {
		return ErrInvalidTarget
	}
	wantsEnvironment := target.resourceKind == hierarchy.KindEnvironment ||
		target.resourceKind == hierarchy.KindApplication ||
		target.resourceKind == hierarchy.KindComponent ||
		target.resourceKind == hierarchy.KindProviderConnection
	if wantsEnvironment != (target.environmentID != nil) {
		return ErrInvalidTarget
	}
	if target.environmentID != nil {
		if _, err := resource.ParseID(target.environmentID.String()); err != nil {
			return ErrInvalidTarget
		}
	}
	if target.providerConnectionID != nil {
		if target.environmentID == nil {
			return ErrInvalidTarget
		}
		if _, err := resource.ParseID(target.providerConnectionID.String()); err != nil {
			return ErrInvalidTarget
		}
	}
	switch target.objectKind {
	case ObjectKindResource:
		if target.objectID != target.resourceID || target.providerConnectionID != nil {
			return ErrInvalidTarget
		}
	case ObjectKindMembership:
		if target.resourceKind != hierarchy.KindWorkspace || target.resourceID != target.workspaceID ||
			target.providerConnectionID != nil {
			return ErrInvalidTarget
		}
	case ObjectKindAudit:
		if target.providerConnectionID != nil {
			return ErrInvalidTarget
		}
	case ObjectKindOperation, ObjectKindPlan:
	default:
		return ErrInvalidTarget
	}
	return nil
}

func (target Target) ObjectKind() ObjectKind       { return target.objectKind }
func (target Target) ObjectID() resource.ID        { return target.objectID }
func (target Target) ResourceKind() hierarchy.Kind { return target.resourceKind }
func (target Target) ResourceID() resource.ID      { return target.resourceID }
func (target Target) WorkspaceID() resource.ID     { return target.workspaceID }

func (target Target) EnvironmentID() (resource.ID, bool) {
	if target.environmentID == nil {
		return "", false
	}
	return *target.environmentID, true
}

func (target Target) ProviderConnectionID() (resource.ID, bool) {
	if target.providerConnectionID == nil {
		return "", false
	}
	return *target.providerConnectionID, true
}

func (target Target) String() string {
	if ValidateTarget(target) != nil {
		return "authorization-target(invalid)"
	}
	return "authorization-target(object=" + target.objectKind.String() +
		",resourceKind=" + target.resourceKind.String() + ")"
}

func (target Target) GoString() string { return target.String() }

func (target Target) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, target.String())
}

func (Target) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Target) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }

func targetFromRecord(
	snapshot hierarchy.Snapshot,
	objectKind ObjectKind,
	objectID resource.ID,
	record hierarchy.Record,
	providerID *resource.ID,
) (Target, error) {
	environmentID, err := resolveRecordEnvironment(snapshot, record)
	if err != nil {
		return Target{}, err
	}
	return newTarget(
		objectKind,
		objectID,
		record.Kind(),
		record.ID(),
		record.WorkspaceID(),
		environmentID,
		providerID,
	)
}

func newTarget(
	objectKind ObjectKind,
	objectID resource.ID,
	resourceKind hierarchy.Kind,
	resourceID resource.ID,
	workspaceID resource.ID,
	environmentID *resource.ID,
	providerConnectionID *resource.ID,
) (Target, error) {
	target := Target{
		initialized:          true,
		objectKind:           objectKind,
		objectID:             objectID,
		resourceKind:         resourceKind,
		resourceID:           resourceID,
		workspaceID:          workspaceID,
		environmentID:        cloneIDPointer(environmentID),
		providerConnectionID: cloneIDPointer(providerConnectionID),
	}
	if err := ValidateTarget(target); err != nil {
		return Target{}, err
	}
	return target, nil
}

func resolveRecordEnvironment(snapshot hierarchy.Snapshot, record hierarchy.Record) (*resource.ID, error) {
	switch record.Kind() {
	case hierarchy.KindWorkspace, hierarchy.KindPolicy:
		return nil, nil
	case hierarchy.KindEnvironment:
		return idPointer(record.ID()), nil
	case hierarchy.KindApplication, hierarchy.KindProviderConnection:
		parentID, present := record.Parent()
		if !present {
			return nil, ErrInvalidTarget
		}
		parent, err := snapshot.Lookup(parentID)
		if err != nil || parent.Kind() != hierarchy.KindEnvironment ||
			parent.WorkspaceID() != record.WorkspaceID() {
			return nil, ErrInvalidTarget
		}
		return idPointer(parent.ID()), nil
	case hierarchy.KindComponent:
		applicationID, present := record.Parent()
		if !present {
			return nil, ErrInvalidTarget
		}
		application, err := snapshot.Lookup(applicationID)
		if err != nil || application.Kind() != hierarchy.KindApplication ||
			application.WorkspaceID() != record.WorkspaceID() {
			return nil, ErrInvalidTarget
		}
		environmentID, present := application.Parent()
		if !present {
			return nil, ErrInvalidTarget
		}
		environment, err := snapshot.Lookup(environmentID)
		if err != nil || environment.Kind() != hierarchy.KindEnvironment ||
			environment.WorkspaceID() != record.WorkspaceID() {
			return nil, ErrInvalidTarget
		}
		return idPointer(environment.ID()), nil
	default:
		return nil, ErrInvalidTarget
	}
}

func resolvePlacementEnvironment(
	snapshot hierarchy.Snapshot,
	placement hierarchy.Placement,
) (*resource.ID, error) {
	switch placement.Kind() {
	case hierarchy.KindWorkspace, hierarchy.KindPolicy:
		return nil, nil
	case hierarchy.KindEnvironment:
		return idPointer(placement.ID()), nil
	case hierarchy.KindApplication, hierarchy.KindProviderConnection:
		parentID, present := placement.Parent()
		if !present {
			return nil, ErrInvalidTarget
		}
		return idPointer(parentID), nil
	case hierarchy.KindComponent:
		applicationID, present := placement.Parent()
		if !present {
			return nil, ErrInvalidTarget
		}
		application, err := snapshot.Lookup(applicationID)
		if err != nil || application.Kind() != hierarchy.KindApplication {
			return nil, ErrInvalidTarget
		}
		environmentID, present := application.Parent()
		if !present {
			return nil, ErrInvalidTarget
		}
		return idPointer(environmentID), nil
	default:
		return nil, ErrInvalidTarget
	}
}

func equalPlacement(left, right hierarchy.Placement) bool {
	if left.ID() != right.ID() || left.Kind() != right.Kind() || left.WorkspaceID() != right.WorkspaceID() {
		return false
	}
	leftParent, leftPresent := left.Parent()
	rightParent, rightPresent := right.Parent()
	return leftPresent == rightPresent && (!leftPresent || leftParent == rightParent)
}

func idPointer(id resource.ID) *resource.ID {
	return cloneIDPointer(&id)
}
