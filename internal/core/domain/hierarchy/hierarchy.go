// Package hierarchy defines Veer's provider-independent v1alpha1 product tree.
package hierarchy

import (
	"errors"
	"fmt"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	// APIVersion is the only representation version admitted by this package.
	APIVersion = "v1alpha1"
	// MaxSnapshotRecords is one Workspace plus the Environment, Application,
	// Component, Policy, and ProviderConnection maxima in ADR 0001's
	// target-scale qualification profile.
	MaxSnapshotRecords = 1 + 1_000 + 10_000 + 50_000 + 2_500 + 500

	// KindWorkspace is the root authorization and ownership boundary.
	KindWorkspace Kind = "Workspace"
	// KindEnvironment is a direct child of a Workspace.
	KindEnvironment Kind = "Environment"
	// KindApplication is a direct child of an Environment.
	KindApplication Kind = "Application"
	// KindComponent is a direct child of an Application.
	KindComponent Kind = "Component"
	// KindPolicy is a direct child of a Workspace.
	KindPolicy Kind = "Policy"
	// KindProviderConnection is a direct child of an Environment.
	KindProviderConnection Kind = "ProviderConnection"
)

var (
	ErrUnsupportedAPIVersion = errors.New("unsupported hierarchy API version")
	ErrUnsupportedKind       = errors.New("unsupported hierarchy kind")
	ErrInvalidSnapshot       = errors.New("invalid hierarchy snapshot")
	ErrSnapshotTooLarge      = errors.New("hierarchy snapshot exceeds alpha record limit")
	ErrInvalidPlacement      = errors.New("invalid hierarchy placement")
	ErrDuplicateID           = errors.New("duplicate resource ID")
	ErrWorkspaceRootMissing  = errors.New("workspace root is missing")
	ErrWorkspaceMismatch     = errors.New("resource workspace ownership does not match")
	ErrRootHasParent         = errors.New("workspace root cannot have a parent")
	ErrParentRequired        = errors.New("non-root resource requires a parent")
	ErrParentNotFound        = errors.New("resource parent was not found")
	ErrParentKindMismatch    = errors.New("resource parent kind does not match")
	ErrCycle                 = errors.New("hierarchy contains a cycle")
	ErrResourceNotFound      = errors.New("resource was not found")
	ErrImmutableID           = errors.New("resource ID is immutable")
	ErrImmutableKind         = errors.New("resource kind is immutable")
	ErrImmutableParent       = errors.New("resource parent is immutable")
	ErrImmutableWorkspaceID  = errors.New("resource workspace ownership is immutable")
	ErrDeleteRestricted      = errors.New("resource deletion is restricted by retained children")
)

// Kind is one of the six v1alpha1 product ownership kinds.
type Kind string

// String returns the canonical wire spelling.
func (kind Kind) String() string { return string(kind) }

// Record is the immutable subset of a resource needed to validate ownership
// and parentage. Display names are deliberately absent: they are presentation
// metadata, never hierarchy or authorization keys.
type Record struct {
	apiVersion  string
	id          resource.ID
	kind        Kind
	workspaceID resource.ID
	parent      *resource.ID
}

// RecordFrom projects validated envelope metadata into a hierarchy record.
// Graph-wide relationships are checked when the record joins a Snapshot.
func RecordFrom(apiVersion, kind string, metadata resource.Metadata) (Record, error) {
	if apiVersion != APIVersion {
		return Record{}, ErrUnsupportedAPIVersion
	}
	parsedKind, err := ParseKind(kind)
	if err != nil {
		return Record{}, err
	}
	if _, err := resource.ParseID(metadata.ID().String()); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}
	if _, err := resource.ParseID(metadata.WorkspaceID().String()); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}

	record := Record{
		apiVersion:  apiVersion,
		id:          metadata.ID(),
		kind:        parsedKind,
		workspaceID: metadata.WorkspaceID(),
	}
	if parent, present := metadata.Parent(); present {
		if _, err := resource.ParseID(parent.String()); err != nil {
			return Record{}, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
		}
		record.parent = cloneID(parent)
	}
	return record, nil
}

// APIVersion returns the representation version projected into the record.
func (record Record) APIVersion() string { return record.apiVersion }

// ID returns the stable resource identity.
func (record Record) ID() resource.ID { return record.id }

// Kind returns the concrete product hierarchy kind.
func (record Record) Kind() Kind { return record.kind }

// WorkspaceID returns the immutable root ownership key.
func (record Record) WorkspaceID() resource.ID { return record.workspaceID }

// Parent returns the immediate parent's stable ID and whether one is present.
func (record Record) Parent() (resource.ID, bool) {
	if record.parent == nil {
		return "", false
	}
	return *record.parent, true
}

// Placement is server-derived immutable identity and ownership input for a new
// common resource envelope. Its fields are private so workspace ownership
// cannot be asserted by an untrusted create payload.
type Placement struct {
	id          resource.ID
	kind        Kind
	workspaceID resource.ID
	parent      *resource.ID
}

// DeriveWorkspace creates root placement. Workspace roots own themselves and
// never carry a parent reference.
func DeriveWorkspace(id resource.ID) (Placement, error) {
	if _, err := resource.ParseID(id.String()); err != nil {
		return Placement{}, fmt.Errorf("%w: %v", ErrInvalidPlacement, err)
	}
	return Placement{id: id, kind: KindWorkspace, workspaceID: id}, nil
}

// ID returns the server-issued identity captured by the placement.
func (placement Placement) ID() resource.ID { return placement.id }

// Kind returns the concrete kind captured by the placement.
func (placement Placement) Kind() Kind { return placement.kind }

// WorkspaceID returns the ownership key derived from the hierarchy.
func (placement Placement) WorkspaceID() resource.ID { return placement.workspaceID }

// Parent returns the derived parent ID and whether one is present.
func (placement Placement) Parent() (resource.ID, bool) {
	if placement.parent == nil {
		return "", false
	}
	return *placement.parent, true
}

// CreateInput contains caller-owned state plus server-issued version and
// time values. Immutable ID, kind, parent, and workspace ownership come only
// from Placement.
type CreateInput[Spec any, Status resource.GenerationObservations] struct {
	DisplayName     string
	Labels          map[string]string
	ResourceVersion string
	CreatedAt       time.Time
	Spec            Spec
	Status          Status
}

// NewResource creates a common resource envelope from sealed hierarchy
// placement and admitted typed desired and observed state.
func NewResource[Spec any, Status resource.GenerationObservations](
	placement Placement,
	input CreateInput[Spec, Status],
) (resource.Resource[Spec, Status], error) {
	var zero resource.Resource[Spec, Status]
	if err := validatePlacement(placement); err != nil {
		return zero, err
	}

	return resource.New(resource.CreateInput[Spec, Status]{
		APIVersion:      APIVersion,
		Kind:            placement.kind.String(),
		ID:              placement.id.String(),
		WorkspaceID:     placement.workspaceID.String(),
		DisplayName:     input.DisplayName,
		Parent:          cloneIDPointer(placement.parent),
		Labels:          input.Labels,
		ResourceVersion: input.ResourceVersion,
		CreatedAt:       input.CreatedAt,
		Spec:            input.Spec,
		Status:          input.Status,
	})
}

// Snapshot is one validated workspace-scoped hierarchy view. It has no
// persistence behavior and owns a copy of the supplied record index.
type Snapshot struct {
	initialized bool
	workspaceID resource.ID
	records     map[resource.ID]Record
	hasChild    map[resource.ID]struct{}
}

// NewSnapshot validates a complete workspace-scoped record set in O(V+E)
// time and O(V) auxiliary memory. Validation is iterative so a malformed deep
// chain cannot exhaust the call stack.
func NewSnapshot(workspaceID resource.ID, records []Record) (Snapshot, error) {
	if _, err := resource.ParseID(workspaceID.String()); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}
	if len(records) > MaxSnapshotRecords {
		return Snapshot{}, fmt.Errorf(
			"%w: %w: maximum %d records",
			ErrInvalidSnapshot,
			ErrSnapshotTooLarge,
			MaxSnapshotRecords,
		)
	}
	if err := validateRecords(records); err != nil {
		return Snapshot{}, err
	}

	index := make(map[resource.ID]Record, len(records))
	for _, record := range records {
		if _, exists := index[record.id]; exists {
			return Snapshot{}, ErrDuplicateID
		}
		index[record.id] = cloneRecord(record)
	}

	// Ownership validation precedes graph validation so a scoped persistence
	// query can never make a foreign record look like a local orphan.
	for _, record := range index {
		if record.workspaceID != workspaceID {
			return Snapshot{}, ErrWorkspaceMismatch
		}
		if record.kind == KindWorkspace && record.id != workspaceID {
			return Snapshot{}, ErrWorkspaceMismatch
		}
	}

	root, exists := index[workspaceID]
	if !exists || root.kind != KindWorkspace {
		return Snapshot{}, ErrWorkspaceRootMissing
	}

	for _, record := range index {
		if record.kind == KindWorkspace && record.parent != nil {
			return Snapshot{}, ErrRootHasParent
		}
	}
	for _, record := range index {
		if record.kind != KindWorkspace && record.parent == nil {
			return Snapshot{}, ErrParentRequired
		}
	}

	for _, record := range index {
		if record.parent == nil {
			continue
		}
		if _, exists := index[*record.parent]; !exists {
			return Snapshot{}, ErrParentNotFound
		}
	}

	if err := checkCycles(index); err != nil {
		return Snapshot{}, err
	}

	for _, record := range index {
		if record.parent == nil {
			continue
		}
		parent := index[*record.parent]
		if expectedParentKind(record.kind) != parent.kind {
			return Snapshot{}, ErrParentKindMismatch
		}
	}

	hasChild := make(map[resource.ID]struct{}, len(index))
	for _, record := range index {
		if record.parent != nil {
			hasChild[*record.parent] = struct{}{}
		}
	}

	return Snapshot{
		initialized: true,
		workspaceID: workspaceID,
		records:     index,
		hasChild:    hasChild,
	}, nil
}

// WorkspaceID returns the workspace scope represented by the snapshot.
func (snapshot Snapshot) WorkspaceID() resource.ID { return snapshot.workspaceID }

// Len returns the number of records in the validated workspace view.
func (snapshot Snapshot) Len() int { return len(snapshot.records) }

// DeriveChild creates placement for a direct child of a record in this
// validated workspace. The workspace ID is copied from the snapshot, never
// accepted from a create payload.
func (snapshot Snapshot) DeriveChild(kind Kind, id, parentID resource.ID) (Placement, error) {
	if !snapshot.initialized {
		return Placement{}, ErrInvalidSnapshot
	}
	if kind == KindWorkspace {
		return Placement{}, ErrInvalidPlacement
	}
	if _, err := ParseKind(kind.String()); err != nil {
		return Placement{}, err
	}
	if _, err := resource.ParseID(id.String()); err != nil {
		return Placement{}, fmt.Errorf("%w: %v", ErrInvalidPlacement, err)
	}
	if _, err := resource.ParseID(parentID.String()); err != nil {
		return Placement{}, fmt.Errorf("%w: %v", ErrInvalidPlacement, err)
	}
	if _, exists := snapshot.records[id]; exists {
		return Placement{}, ErrDuplicateID
	}
	parent, exists := snapshot.records[parentID]
	if !exists {
		return Placement{}, ErrParentNotFound
	}
	if expectedParentKind(kind) != parent.kind {
		return Placement{}, ErrParentKindMismatch
	}
	if parent.workspaceID != snapshot.workspaceID {
		return Placement{}, ErrWorkspaceMismatch
	}

	return Placement{
		id:          id,
		kind:        kind,
		workspaceID: snapshot.workspaceID,
		parent:      cloneID(parentID),
	}, nil
}

// CheckTransition rejects changes to fields owned by hierarchy admission.
// Rename, label, spec, status, version, and timestamp changes do not appear in
// Record and therefore cannot accidentally become authorization keys here.
func CheckTransition(before, after Record) error {
	if err := validateRecord(before); err != nil {
		return err
	}
	if err := validateRecord(after); err != nil {
		return err
	}
	if before.id != after.id {
		return ErrImmutableID
	}
	if before.kind != after.kind {
		return ErrImmutableKind
	}
	if !equalIDPointers(before.parent, after.parent) {
		return ErrImmutableParent
	}
	if before.workspaceID != after.workspaceID {
		return ErrImmutableWorkspaceID
	}
	return nil
}

// CheckDelete applies RESTRICT semantics without mutating or persisting the
// snapshot. Storage issue #30 owns making this precondition atomic with delete.
func (snapshot Snapshot) CheckDelete(id resource.ID) error {
	if !snapshot.initialized {
		return ErrInvalidSnapshot
	}
	if _, exists := snapshot.records[id]; !exists {
		return ErrResourceNotFound
	}
	if _, retained := snapshot.hasChild[id]; retained {
		return ErrDeleteRestricted
	}
	return nil
}

// ParseKind validates and returns one of the six exact v1alpha1 kind names.
func ParseKind(value string) (Kind, error) {
	kind := Kind(value)
	switch kind {
	case KindWorkspace, KindEnvironment, KindApplication, KindComponent,
		KindPolicy, KindProviderConnection:
		return kind, nil
	default:
		return "", ErrUnsupportedKind
	}
}

func expectedParentKind(kind Kind) Kind {
	switch kind {
	case KindEnvironment:
		return KindWorkspace
	case KindApplication:
		return KindEnvironment
	case KindComponent:
		return KindApplication
	case KindPolicy:
		return KindWorkspace
	case KindProviderConnection:
		return KindEnvironment
	default:
		return ""
	}
}

func validateRecord(record Record) error {
	if record.apiVersion != APIVersion {
		return ErrUnsupportedAPIVersion
	}
	if _, err := ParseKind(record.kind.String()); err != nil {
		return err
	}
	if _, err := resource.ParseID(record.id.String()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}
	if _, err := resource.ParseID(record.workspaceID.String()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}
	if record.parent != nil {
		if _, err := resource.ParseID(record.parent.String()); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
		}
	}
	return nil
}

func validateRecords(records []Record) error {
	for _, record := range records {
		if record.apiVersion != APIVersion {
			return ErrUnsupportedAPIVersion
		}
	}
	for _, record := range records {
		if _, err := ParseKind(record.kind.String()); err != nil {
			return err
		}
	}
	for _, record := range records {
		if _, err := resource.ParseID(record.id.String()); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
		}
		if _, err := resource.ParseID(record.workspaceID.String()); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
		}
		if record.parent != nil {
			if _, err := resource.ParseID(record.parent.String()); err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
			}
		}
	}
	return nil
}

func validatePlacement(placement Placement) error {
	if _, err := ParseKind(placement.kind.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPlacement, err)
	}
	if _, err := resource.ParseID(placement.id.String()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPlacement, err)
	}
	if _, err := resource.ParseID(placement.workspaceID.String()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPlacement, err)
	}
	if placement.kind == KindWorkspace {
		if placement.parent != nil || placement.workspaceID != placement.id {
			return ErrInvalidPlacement
		}
		return nil
	}
	if placement.parent == nil {
		return ErrInvalidPlacement
	}
	if _, err := resource.ParseID(placement.parent.String()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPlacement, err)
	}
	return nil
}

func checkCycles(records map[resource.ID]Record) error {
	// 0 is unseen, 1 is on the current walk, and 2 is fully processed.
	state := make(map[resource.ID]uint8, len(records))
	path := make([]resource.ID, 0, len(records))
	for start := range records {
		if state[start] != 0 {
			continue
		}
		path = path[:0]
		current := start
		for {
			switch state[current] {
			case 1:
				return ErrCycle
			case 2:
				for _, id := range path {
					state[id] = 2
				}
				goto nextStart
			}

			state[current] = 1
			path = append(path, current)
			parent := records[current].parent
			if parent == nil {
				for _, id := range path {
					state[id] = 2
				}
				goto nextStart
			}
			current = *parent
		}
	nextStart:
	}
	return nil
}

func cloneRecord(record Record) Record {
	record.parent = cloneIDPointer(record.parent)
	return record
}

func cloneID(id resource.ID) *resource.ID {
	copy := id
	return &copy
}

func cloneIDPointer(id *resource.ID) *resource.ID {
	if id == nil {
		return nil
	}
	return cloneID(*id)
}

func equalIDPointers(left, right *resource.ID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
