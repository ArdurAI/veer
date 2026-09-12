// Package reference implements Veer's deterministic, provider-free resource
// lifecycle service. It is a contract oracle, not a production control plane.
package reference

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
)

const (
	DefaultPageSize    = 50
	MaxPageSize        = 100
	MaxPageBytes       = resource.MaxCanonicalBytes
	PageTokenLifetime  = 15 * time.Minute
	MaxPageTokenBytes  = 1_024
	defaultTokenLimit  = 4_096
	defaultReplayLimit = 4_096
	timestampLayout    = "2006-01-02T15:04:05.000Z"
)

var (
	ErrInvalidConfiguration = errors.New("invalid reference-service configuration")
	ErrInvalidCommand       = errors.New("invalid reference-service command")
	ErrNotFound             = errors.New("reference resource was not found")
	ErrAlreadyExists        = errors.New("reference resource already exists")
	ErrPreconditionFailed   = errors.New("reference resource version is stale")
	ErrLifecycleConflict    = errors.New("reference resource lifecycle conflict")
	ErrIdempotencyConflict  = errors.New("reference idempotency key conflicts")
	ErrReplayUnavailable    = errors.New("reference idempotency result is unavailable")
	ErrCapacity             = errors.New("reference service capacity is exhausted")
	ErrInvalidPageToken     = errors.New("invalid reference page token")
	ErrPageTooLarge         = errors.New("reference page cannot make progress within byte limit")
	ErrInternal             = errors.New("reference service invariant failure")
)

// Clock supplies the transaction time used by deterministic tests.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

func (function ClockFunc) Now() time.Time { return function() }

// Issuer owns opaque resource, operation, and revision allocation.
type Issuer interface {
	ResourceID(hierarchy.Kind) (resource.ID, error)
	OperationID() (resource.ID, error)
	ResourceVersion() (string, error)
}

// SequentialIssuer is a concurrency-safe deterministic issuer for the
// process-local reference server. Its values carry no tenant or provider data.
type SequentialIssuer struct {
	mu         sync.Mutex
	resources  uint64
	operations uint64
	versions   uint64
}

func (issuer *SequentialIssuer) ResourceID(kind hierarchy.Kind) (resource.ID, error) {
	if _, err := hierarchy.ParseKind(kind.String()); err != nil {
		return "", ErrInvalidCommand
	}
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if issuer.resources == ^uint64(0) {
		return "", ErrInternal
	}
	issuer.resources++
	prefix := map[hierarchy.Kind]string{
		hierarchy.KindWorkspace:          "wsp",
		hierarchy.KindEnvironment:        "env",
		hierarchy.KindApplication:        "app",
		hierarchy.KindComponent:          "cmp",
		hierarchy.KindPolicy:             "pol",
		hierarchy.KindProviderConnection: "pvc",
	}[kind]
	return resource.ParseID(fmt.Sprintf("%s_%016x", prefix, issuer.resources))
}

func (issuer *SequentialIssuer) OperationID() (resource.ID, error) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if issuer.operations == ^uint64(0) {
		return "", ErrInternal
	}
	issuer.operations++
	return resource.ParseID(fmt.Sprintf("op_%016x", issuer.operations))
}

func (issuer *SequentialIssuer) ResourceVersion() (string, error) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if issuer.versions == ^uint64(0) {
		return "", ErrInternal
	}
	issuer.versions++
	return fmt.Sprintf("rv_%016x", issuer.versions), nil
}

// Config contains every process-local dependency. PageTokenKey is used only
// as an HMAC key and must contain at least 32 bytes of runtime-provided entropy.
type Config struct {
	Store             ports.ReferenceStore
	Clock             Clock
	Issuer            Issuer
	PageTokenKey      []byte
	MaximumPageTokens int
	MaximumReplays    int
}

// CreateCommand describes a versioned desired-state creation. CanonicalTarget
// is supplied by the transport boundary and participates in idempotency scope.
type CreateCommand struct {
	Principal       identity.Principal
	Kind            hierarchy.Kind
	WorkspaceID     resource.ID
	ParentID        *resource.ID
	CanonicalTarget string
	IdempotencyKey  string
	Body            []byte
	Members         authorization.MemberDirectory
}

// ReplaceCommand describes a complete caller-owned desired-state replacement.
type ReplaceCommand struct {
	Principal               identity.Principal
	Kind                    hierarchy.Kind
	ResourceID              resource.ID
	ExpectedResourceVersion string
	CanonicalTarget         string
	IdempotencyKey          string
	Body                    []byte
	Members                 authorization.MemberDirectory
}

// DeleteCommand describes one generation-fenced RESTRICT deletion.
type DeleteCommand struct {
	Principal               identity.Principal
	Kind                    hierarchy.Kind
	ResourceID              resource.ID
	ExpectedResourceVersion string
	CanonicalTarget         string
	IdempotencyKey          string
}

// StatusCommand describes a status-only replacement.
type StatusCommand struct {
	Principal               identity.Principal
	Kind                    hierarchy.Kind
	ResourceID              resource.ID
	ExpectedResourceVersion string
	CanonicalTarget         string
	IdempotencyKey          string
	Body                    []byte
}

// MutationReceipt is the bounded logical result of an accepted desired-state
// mutation. AcceptedAt is a canonical UTC millisecond timestamp.
type MutationReceipt struct {
	ResourceID      resource.ID `json:"resourceId"`
	OperationID     resource.ID `json:"operationId"`
	Generation      int64       `json:"generation"`
	ResourceVersion string      `json:"resourceVersion"`
	AcceptedAt      string      `json:"acceptedAt"`
}

// StatusReceipt is the bounded logical result of a status-only write.
type StatusReceipt struct {
	ResourceID         resource.ID `json:"resourceId"`
	ObservedGeneration int64       `json:"observedGeneration"`
	ResourceVersion    string      `json:"resourceVersion"`
	UpdatedAt          string      `json:"updatedAt"`
}

// Resource is one immutable canonical resource representation plus indexed
// metadata used by transport-independent callers.
type Resource struct {
	Canonical []byte
	Kind      hierarchy.Kind
	Metadata  resource.Metadata
}

// Operation is one immutable canonical asynchronous-operation snapshot.
type Operation struct {
	Canonical []byte
	Value     operation.Operation
}

// ListQuery selects one deterministic resource collection. MatchLabels uses
// exact AND semantics. Workspace roots may be listed across all workspaces by
// leaving WorkspaceID empty; child kinds require a WorkspaceID.
type ListQuery struct {
	Principal   identity.Principal
	WorkspaceID resource.ID
	Kind        hierarchy.Kind
	ParentID    *resource.ID
	MatchLabels map[string]string
	PageSize    int
	PageToken   string
}

// Page is one keyset-ordered bounded collection page.
type Page struct {
	Items         []Resource
	NextPageToken string
}

// PreconditionError exposes only the current opaque revision needed by an
// authorized caller to retry. It never includes resource identity.
type PreconditionError struct{ CurrentResourceVersion string }

func (failure *PreconditionError) Error() string { return ErrPreconditionFailed.Error() }
func (failure *PreconditionError) Unwrap() error { return ErrPreconditionFailed }
