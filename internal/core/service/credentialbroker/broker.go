package credentialbroker

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

// Broker owns all process-local credential state. Callers needing replica-wide
// exclusion or durable revocation must provide that control-plane coordination
// outside this type.
type Broker struct {
	brokerDiagnostic
	*brokerState
}

type brokerState struct {
	mu sync.Mutex

	clockSamples atomic.Uint64

	resolver ports.SecretResolver
	budget   ports.SecretReadBudget
	clock    Clock

	issuers map[issuerKey]ports.SessionIssuer

	lineages   map[connectionKey]*lineageState
	operations map[operationKey]*operationState

	sources        map[credential.SourceDigest]*sourceEntry
	retiredSources map[*sourceEntry]struct{}
	sourceFlights  map[credential.SourceDigest]*sourceFlight

	sessions       map[credential.BindingDigest]*sessionCell
	cells          map[*sessionCell]struct{}
	sessionFlights map[credential.BindingDigest]*sessionFlight
	rotations      map[connectionKey]*rotationFlight

	activeLeases          uint64
	activeResolves        uint64
	sourceReservations    uint64
	sessionReservations   uint64
	operationReservations uint64
	leaseReservations     uint64
	invalidationGate      chan struct{}
	revocationSlots       chan struct{}
	nextEpoch             uint64
	nextUse               uint64
	lastClockSample       uint64
	lastNow               time.Time
	closed                bool
	stats                 Stats
}

// New constructs an empty broker. A nil Clock selects the wall clock; typed
// nil dependencies are rejected. No backend call occurs during construction.
func New(
	resolver ports.SecretResolver,
	budget ports.SecretReadBudget,
	clock Clock,
) (*Broker, error) {
	if isNilInterface(resolver) || isNilInterface(budget) ||
		(clock != nil && isNilInterface(clock)) {
		return nil, ErrInvalid
	}
	if clock == nil {
		clock = wallClock{}
	}
	broker := &Broker{
		brokerDiagnostic: brokerDiagnostic{initialized: true},
		brokerState: &brokerState{
			resolver:         resolver,
			budget:           budget,
			clock:            clock,
			issuers:          make(map[issuerKey]ports.SessionIssuer),
			lineages:         make(map[connectionKey]*lineageState),
			operations:       make(map[operationKey]*operationState),
			sources:          make(map[credential.SourceDigest]*sourceEntry),
			retiredSources:   make(map[*sourceEntry]struct{}),
			sourceFlights:    make(map[credential.SourceDigest]*sourceFlight),
			sessions:         make(map[credential.BindingDigest]*sessionCell),
			cells:            make(map[*sessionCell]struct{}),
			sessionFlights:   make(map[credential.BindingDigest]*sessionFlight),
			rotations:        make(map[connectionKey]*rotationFlight),
			invalidationGate: make(chan struct{}, 1),
			revocationSlots:  make(chan struct{}, MaxConcurrentRevocations),
		},
	}
	sample := broker.sampleNow()
	broker.mu.Lock()
	_, err := broker.observeNowLocked(sample)
	broker.mu.Unlock()
	if err != nil {
		return nil, ErrInvalid
	}
	return broker, nil
}

func (broker *Broker) beginInvalidation() func() {
	broker.invalidationGate <- struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() { <-broker.invalidationGate })
	}
}

// RegisterIssuer binds one exact (provider, recipient-name) pair. Duplicate
// registration is always rejected; live replacement and unregistration are
// intentionally absent from the alpha lifecycle.
func (broker *Broker) RegisterIssuer(
	recipient credential.Recipient,
	issuer ports.SessionIssuer,
) error {
	if broker == nil || !broker.initialized || !recipient.Valid() || isNilInterface(issuer) {
		return ErrInvalid
	}
	key := issuerKey{provider: recipient.Provider(), name: recipient.Name()}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if broker.closed {
		return ErrClosed
	}
	if _, exists := broker.issuers[key]; exists {
		return ErrConflict
	}
	if len(broker.issuers) >= MaxIssuerRegistrations {
		return ErrCapacity
	}
	broker.issuers[key] = issuer
	return nil
}

// Stats returns a numeric, label-free snapshot and remains safe after Close.
func (broker *Broker) Stats() Stats {
	if broker == nil || !broker.initialized {
		return Stats{}
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	snapshot := broker.stats
	snapshot.ActiveSources = uint64(len(broker.sources) + len(broker.retiredSources))
	snapshot.ActiveSessions = uint64(len(broker.cells))
	snapshot.ActiveSessionFlights = uint64(len(broker.sessionFlights) + len(broker.rotations))
	snapshot.ActiveLeases = broker.activeLeases
	snapshot.ActiveResolves = broker.activeResolves
	snapshot.RegisteredIssuers = uint64(len(broker.issuers))
	snapshot.TrackedConnections = uint64(len(broker.lineages))
	snapshot.TrackedOperations = uint64(len(broker.operations))
	return snapshot
}

type clockSample struct {
	sequence uint64
	observed time.Time
	err      error
}

func (broker *Broker) sampleNow() clockSample {
	if broker == nil || broker.brokerState == nil {
		return clockSample{err: ErrUnavailable}
	}
	var sequence uint64
	for {
		current := broker.clockSamples.Load()
		if current == ^uint64(0) {
			return clockSample{err: ErrUnavailable}
		}
		if broker.clockSamples.CompareAndSwap(current, current+1) {
			sequence = current + 1
			break
		}
	}

	broker.mu.Lock()
	clock := broker.clock
	broker.mu.Unlock()
	if isNilInterface(clock) {
		return clockSample{sequence: sequence, err: ErrUnavailable}
	}
	return clockSample{sequence: sequence, observed: clock.Now()}
}

func (broker *Broker) observeNowLocked(sample clockSample) (time.Time, error) {
	if sample.sequence == 0 {
		return time.Time{}, ErrUnavailable
	}
	if sample.err != nil || sample.observed.IsZero() {
		if sample.sequence > broker.lastClockSample {
			broker.lastClockSample = sample.sequence
		}
		return time.Time{}, ErrUnavailable
	}
	if sample.sequence <= broker.lastClockSample {
		if broker.lastNow.IsZero() {
			return time.Time{}, ErrUnavailable
		}
		return broker.lastNow, nil
	}

	// Advance the ordered-observation fence even when this fresh sample is
	// rejected. Otherwise an older overlapping sample could later appear fresh.
	broker.lastClockSample = sample.sequence
	now := sample.observed.UTC()
	if now.Before(broker.lastNow) {
		return time.Time{}, ErrUnavailable
	}
	broker.lastNow = now
	return now, nil
}

func (broker *Broker) newEpochLocked() (uint64, error) {
	return broker.reserveEpochsLocked(1)
}

func (broker *Broker) reserveEpochsLocked(count uint64) (uint64, error) {
	if count == 0 {
		return 0, nil
	}
	if count > ^uint64(0)-broker.nextEpoch {
		return 0, ErrUnavailable
	}
	first := broker.nextEpoch + 1
	broker.nextEpoch += count
	return first, nil
}

func (broker *Broker) touchLocked() uint64 {
	if broker.nextUse != ^uint64(0) {
		broker.nextUse++
	}
	return broker.nextUse
}

func increment(counter *uint64) {
	if *counter != ^uint64(0) {
		*counter++
	}
}

func keyForConnection(request credential.Request) connectionKey {
	return connectionKey{
		workspaceID:   request.WorkspaceID(),
		environmentID: request.EnvironmentID(),
		connectionID:  request.ProviderConnectionID(),
	}
}

func keyForOperation(request credential.Request) operationKey {
	return operationKey{
		workspaceID:   request.WorkspaceID(),
		environmentID: request.EnvironmentID(),
		operationID:   request.OperationID(),
	}
}

func keyForIssuer(request credential.Request) issuerKey {
	recipient := request.Recipient()
	return issuerKey{provider: request.Provider(), name: recipient.Name()}
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func detachedBackendContext(parent context.Context) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(credential.BackendTimeout)
	if parentDeadline, present := parent.Deadline(); present && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	stop := context.AfterFunc(parent, cancel)
	if parent.Err() != nil {
		cancel()
	}
	return ctx, func() {
		stop()
		cancel()
	}
}

func contextFailure(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return ErrUnavailable
}

func destroySource(material *credential.SourceMaterial) {
	if material != nil {
		material.Destroy()
	}
}

func destroySession(session *credential.IssuedSession) {
	if session != nil {
		session.Destroy()
	}
}

// ExpiresAt returns the provider-reported expiration for this handle.
func (lease *Lease) ExpiresAt() time.Time {
	if lease == nil || lease.state == nil || lease.state.cell == nil ||
		lease.state.cell.session == nil {
		return time.Time{}
	}
	return lease.state.cell.session.ExpiresAt()
}

// Close releases this handle only. It is idempotent and never revokes or
// invalidates a shared session used by another lease.
func (lease *Lease) Close() error {
	if lease == nil || lease.state == nil {
		return ErrInvalid
	}
	state := lease.state
	state.mu.Lock()
	if state.closed {
		state.mu.Unlock()
		return nil
	}
	state.closed = true
	state.closedCancel()
	state.mu.Unlock()

	broker := state.broker
	disposal := disposals{broker: broker}
	broker.mu.Lock()
	if state.cell.refs > 0 {
		state.cell.refs--
	}
	if broker.activeLeases > 0 {
		broker.activeLeases--
	}
	revocationRunning := state.cell.revocation != nil && !state.cell.revocation.finished
	if state.cell.refs == 0 && !revocationRunning &&
		(state.cell.invalid || state.cell.draining) {
		broker.recordExpiryEvidenceLocked(state.cell, broker.lastNow)
		delete(broker.cells, state.cell)
		disposal.addSessionLocked(state.cell.session)
	}
	broker.mu.Unlock()
	disposal.destroy()
	return nil
}

// Use exposes an ephemeral copy to one callback under a baggage-free context.
// Non-context callback failures are collapsed to ErrUnavailable so provider
// response text cannot escape through the broker boundary.
func (lease *Lease) Use(
	ctx context.Context,
	callback func(context.Context, []byte) error,
) error {
	if lease == nil || lease.state == nil ||
		ctx == nil || callback == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	state := lease.state
	state.mu.Lock()
	if state.closed {
		state.mu.Unlock()
		return ErrRevoked
	}
	closedCtx := state.closedCtx
	state.mu.Unlock()

	broker := state.broker
	sample := broker.sampleNow()
	broker.mu.Lock()
	now, err := broker.observeNowLocked(sample)
	if err != nil {
		broker.mu.Unlock()
		return err
	}
	cell := state.cell
	if broker.closed {
		broker.mu.Unlock()
		return ErrClosed
	}
	if cell.invalid {
		broker.mu.Unlock()
		return ErrRevoked
	}
	if !cell.session.CanStartUse(now) {
		cell.draining = true
		broker.mu.Unlock()
		return ErrExpired
	}
	cell.lastUsed = broker.touchLocked()
	expires := cell.session.ExpiresAt().Add(-credential.SessionExpirySkew)
	remaining := expires.Sub(now)
	invalidCtx := cell.invalidCtx
	broker.mu.Unlock()

	useCtx, cancel := context.WithTimeout(context.Background(), remaining)
	stopCaller := context.AfterFunc(ctx, cancel)
	stopLease := context.AfterFunc(closedCtx, cancel)
	stopCell := context.AfterFunc(invalidCtx, cancel)
	callbackErr := cell.session.WithBytes(func(value []byte) error {
		return callback(useCtx, value)
	})
	useErr := useCtx.Err()
	stopCaller()
	stopLease()
	stopCell()
	cancel()

	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-closedCtx.Done():
		return ErrRevoked
	default:
	}
	select {
	case <-invalidCtx.Done():
		return ErrRevoked
	default:
	}
	if useErr == context.DeadlineExceeded {
		return ErrExpired
	}
	if useErr != nil {
		return ErrUnavailable
	}
	sample = broker.sampleNow()
	broker.mu.Lock()
	finishedAt, timeErr := broker.observeNowLocked(sample)
	if timeErr == nil && broker.closed {
		timeErr = ErrClosed
	}
	if timeErr == nil && !broker.cellCurrentLocked(cell) {
		timeErr = ErrRevoked
	}
	broker.mu.Unlock()
	if timeErr != nil {
		return timeErr
	}
	if !finishedAt.Before(expires) {
		return ErrExpired
	}
	if callbackErr != nil {
		return ErrUnavailable
	}
	return nil
}
