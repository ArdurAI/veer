package credentialbroker

import (
	"context"
	"sync"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
)

const (
	MaxSourceEntries         = 500
	MaxSessionEntries        = 1_000
	MaxActiveLeases          = 1_000
	MaxTrackedConnections    = 500
	MaxTrackedOperations     = 10_000
	MaxConcurrentResolves    = 32
	MaxIssuerRegistrations   = 16
	MaxConcurrentRevocations = 16
	MaxSourceCacheTTL        = time.Hour
)

// Clock is the broker's sole authority for cache and session admission time.
// Production callers normally use a wall clock; tests can provide a manually
// advanced clock without sleeps.
type Clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// Stats is a label-free numeric snapshot. It deliberately exposes neither
// provider, reference, recipient, resource, operation, nor digest dimensions.
type Stats struct {
	SourceHits           uint64
	SourceMisses         uint64
	SourceResolves       uint64
	SourceWaits          uint64
	BudgetClaims         uint64
	BudgetConsumed       uint64
	BudgetReleased       uint64
	BudgetRetained       uint64
	SessionHits          uint64
	SessionIssues        uint64
	SessionWaits         uint64
	Refreshes            uint64
	Fallbacks            uint64
	Rotations            uint64
	Revocations          uint64
	RevocationPending    uint64
	StaleSuppressed      uint64
	Expired              uint64
	ActiveSources        uint64
	ActiveSessions       uint64
	ActiveSessionFlights uint64
	ActiveLeases         uint64
	ActiveResolves       uint64
	RegisteredIssuers    uint64
	TrackedConnections   uint64
	TrackedOperations    uint64
}

// Rotation is the result of one committed connection-lineage cutover.
// PriorRevocation is always valid. A Pending value reports revocation
// uncertainty without creating a lease-plus-error ambiguity after cutover.
type Rotation struct {
	lease           *Lease
	priorRevocation ports.RevocationResult
}

func (rotation Rotation) Lease() *Lease { return rotation.lease }

func (rotation Rotation) PriorRevocation() ports.RevocationResult {
	return rotation.priorRevocation
}

func (rotation Rotation) Valid() bool {
	return rotation.lease != nil && rotation.priorRevocation.Valid()
}

type connectionKey struct {
	workspaceID   resource.ID
	environmentID resource.ID
	connectionID  resource.ID
}

type operationKey struct {
	workspaceID   resource.ID
	environmentID resource.ID
	operationID   resource.ID
}

type issuerKey struct {
	provider string
	name     string
}

type lineageState struct {
	generation       resource.Generation
	provider         string
	referenceID      resource.ID
	version          string
	sourceDigest     credential.SourceDigest
	epoch            uint64
	revokedThrough   resource.Generation
	expiryBoundUntil time.Time
}

type operationState struct {
	binding          credential.BindingDigest
	epoch            uint64
	terminal         bool
	expiryBoundUntil time.Time
}

type sourceEntry struct {
	key        connectionKey
	digest     credential.SourceDigest
	generation resource.Generation
	epoch      uint64
	material   *credential.SourceMaterial
	expiresAt  time.Time
	lastUsed   uint64
	borrows    uint64
	invalid    bool
	retired    bool
}

type flightSource struct {
	mu          sync.Mutex
	material    *credential.SourceMaterial
	invalid     bool
	destroyDone chan struct{}
}

type sourceFlight struct {
	digest          credential.SourceDigest
	request         credential.Request
	priority        ports.SecretReadPriority
	connKey         connectionKey
	connEpoch       uint64
	sourceExpiresAt time.Time
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	waiters         uint64
	finished        bool
	abandoned       bool
	source          *flightSource
	entry           *sourceEntry
	err             error
}

type sourceBorrow struct {
	broker *Broker
	entry  *sourceEntry
	once   sync.Once
}

type sessionCell struct {
	request       credential.Request
	issuer        ports.SessionIssuer
	session       *credential.IssuedSession
	connKey       connectionKey
	opKey         operationKey
	binding       credential.BindingDigest
	connEpoch     uint64
	opEpoch       uint64
	lastUsed      uint64
	refs          uint64
	flightPins    uint64
	invalid       bool
	draining      bool
	revocation    *revocationAttempt
	invalidCtx    context.Context
	invalidCancel context.CancelFunc
}

type sessionFlight struct {
	request       credential.Request
	connKey       connectionKey
	opKey         operationKey
	binding       credential.BindingDigest
	connEpoch     uint64
	opEpoch       uint64
	refresh       bool
	fallback      *sessionCell
	issuer        ports.SessionIssuer
	reserved      bool
	pinned        *sessionCell
	ctx           context.Context
	cancel        context.CancelFunc
	done          chan struct{}
	waiters       uint64
	finished      bool
	abandoned     bool
	cell          *sessionCell
	revocation    ports.RevocationResult
	revocationErr error
	err           error
}

type rotationFlight struct {
	request           credential.Request
	connKey           connectionKey
	binding           credential.BindingDigest
	issuer            ports.SessionIssuer
	fromEpoch         uint64
	fromGen           resource.Generation
	ctx               context.Context
	cancel            context.CancelFunc
	done              chan struct{}
	waiters           uint64
	finished          bool
	abandoned         bool
	cell              *sessionCell
	source            *flightSource
	reserved          bool
	sourceExpiresAt   time.Time
	sourceReserved    bool
	resolveActive     bool
	operationReserved bool
	leaseReserved     uint64
	committed         bool
	leases            []*Lease
	revocation        ports.RevocationResult
	err               error
}

type revocationAttempt struct {
	cell     *sessionCell
	done     chan struct{}
	started  bool
	finished bool
	result   ports.RevocationResult
	err      error
}

// Lease is one caller-owned handle to a shared issued-session cell. Close is
// handle-local; connection/operation invalidation uses explicit broker APIs.
type Lease struct {
	leaseDiagnostic
	state *leaseState
}

type leaseState struct {
	broker       *Broker
	cell         *sessionCell
	mu           sync.Mutex
	closed       bool
	closedCtx    context.Context
	closedCancel context.CancelFunc
}
