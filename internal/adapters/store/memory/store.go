// Package memory implements deterministic process-local adapters for public
// contract and unit tests. It is not durable and must not be used to claim
// production recovery semantics.
package memory

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/ArdurAI/veer/internal/core/domain/isolation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
)

var (
	ErrInvalidCallback   = errors.New("invalid reference-store callback")
	ErrIdentityCollision = errors.New("reference-store identity exists in multiple Workspace scopes")
)

// Store is a serializable, copy-on-write reference store. Copy-on-write makes
// callback failure observably atomic without leaking a mutable map alias.
type Store struct {
	mu         sync.RWMutex
	resources  map[resource.ID]map[resource.ID][]byte
	operations map[resource.ID]map[resource.ID][]byte
}

// NewStore creates an empty initialized reference store.
func NewStore() *Store {
	return &Store{
		resources:  make(map[resource.ID]map[resource.ID][]byte),
		operations: make(map[resource.ID]map[resource.ID][]byte),
	}
}

// View runs callback against one locked view containing only explicit scopes.
func (store *Store) View(
	ctx context.Context,
	scopes isolation.WorkspaceScopeSet,
	callback func(ports.ReferenceReader) error,
) error {
	if store == nil || callback == nil {
		return ErrInvalidCallback
	}
	if err := isolation.ValidateWorkspaceScopeSet(scopes); err != nil {
		return err
	}
	if ctx == nil {
		return ErrInvalidCallback
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	resources, err := scopedView(store.resources, scopes)
	if err != nil {
		return err
	}
	operations, err := scopedView(store.operations, scopes)
	if err != nil {
		return err
	}
	if err := callback(reader{resources: resources, operations: operations}); err != nil {
		return err
	}
	return ctx.Err()
}

// Update commits the callback's private working copy only after the callback
// and its context both succeed.
func (store *Store) Update(
	ctx context.Context,
	scope isolation.WorkspaceScope,
	callback func(ports.ReferenceTransaction) error,
) error {
	if store == nil || callback == nil {
		return ErrInvalidCallback
	}
	if err := isolation.ValidateWorkspaceScope(scope); err != nil {
		return err
	}
	if ctx == nil {
		return ErrInvalidCallback
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	workspaceID := scope.WorkspaceID()
	working := &transaction{
		reader: reader{
			resources:  cloneMap(store.resources[workspaceID]),
			operations: cloneMap(store.operations[workspaceID]),
		},
	}
	if err := callback(working); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.resources[workspaceID] = working.resources
	store.operations[workspaceID] = working.operations
	return nil
}

type reader struct {
	resources  map[resource.ID][]byte
	operations map[resource.ID][]byte
}

func (view reader) GetResource(id resource.ID) ([]byte, bool) {
	value, exists := view.resources[id]
	return bytes.Clone(value), exists
}

func (view reader) ListResources() [][]byte {
	result := make([][]byte, 0, len(view.resources))
	for _, value := range view.resources {
		result = append(result, bytes.Clone(value))
	}
	return result
}

func (view reader) GetOperation(id resource.ID) ([]byte, bool) {
	value, exists := view.operations[id]
	return bytes.Clone(value), exists
}

type transaction struct{ reader }

func (tx *transaction) PutResource(id resource.ID, value []byte) {
	tx.resources[id] = bytes.Clone(value)
}

func (tx *transaction) DeleteResource(id resource.ID) {
	delete(tx.resources, id)
}

func (tx *transaction) PutOperation(id resource.ID, value []byte) {
	tx.operations[id] = bytes.Clone(value)
}

func cloneMap(source map[resource.ID][]byte) map[resource.ID][]byte {
	result := make(map[resource.ID][]byte, len(source))
	for key, value := range source {
		result[key] = bytes.Clone(value)
	}
	return result
}

func scopedView(
	source map[resource.ID]map[resource.ID][]byte,
	scopes isolation.WorkspaceScopeSet,
) (map[resource.ID][]byte, error) {
	result := make(map[resource.ID][]byte)
	for _, scope := range scopes.Scopes() {
		for id, value := range source[scope.WorkspaceID()] {
			if _, exists := result[id]; exists {
				return nil, ErrIdentityCollision
			}
			result[id] = value
		}
	}
	return result, nil
}

var _ ports.ReferenceStore = (*Store)(nil)
