package credentialbroker

import (
	"context"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

type disposals struct {
	broker        *Broker
	flightSources []*flightSource
	sources       []*credential.SourceMaterial
	sessions      []*credential.IssuedSession
	sourceSlots   uint64
	sessionSlots  uint64
}

type cancellationBatch struct {
	callbacks []context.CancelFunc
}

func (batch *cancellationBatch) add(cancel context.CancelFunc) {
	if cancel != nil {
		batch.callbacks = append(batch.callbacks, cancel)
	}
}

func (batch *cancellationBatch) publish() {
	for _, cancel := range batch.callbacks {
		cancel()
	}
	batch.callbacks = nil
}

func (disposals *disposals) destroy() {
	for _, source := range disposals.flightSources {
		source.invalidate()
	}
	for _, source := range disposals.sources {
		destroySource(source)
	}
	for _, session := range disposals.sessions {
		destroySession(session)
	}
	if disposals.broker == nil ||
		(disposals.sourceSlots == 0 && disposals.sessionSlots == 0) {
		return
	}
	disposals.broker.mu.Lock()
	if disposals.sourceSlots <= disposals.broker.sourceReservations {
		disposals.broker.sourceReservations -= disposals.sourceSlots
	} else {
		disposals.broker.sourceReservations = 0
	}
	if disposals.sessionSlots <= disposals.broker.sessionReservations {
		disposals.broker.sessionReservations -= disposals.sessionSlots
	} else {
		disposals.broker.sessionReservations = 0
	}
	disposals.sourceSlots = 0
	disposals.sessionSlots = 0
	disposals.broker.mu.Unlock()
}

// addSourceLocked and addSessionLocked transfer one retained material slot to
// an out-of-lock destruction batch. The slot remains charged until destroy
// completes, so concurrent admission cannot exceed the material ceiling.
func (disposals *disposals) addSourceLocked(material *credential.SourceMaterial) {
	if material == nil {
		return
	}
	disposals.sources = append(disposals.sources, material)
	disposals.sourceSlots++
	disposals.broker.sourceReservations++
}

// addFlightSourceLocked queues private material whose retained slot is already
// represented by its owning flight reservation.
func (disposals *disposals) addFlightSourceLocked(source *flightSource) {
	if source != nil {
		disposals.flightSources = append(disposals.flightSources, source)
	}
}

func (disposals *disposals) addSessionLocked(session *credential.IssuedSession) {
	if session == nil {
		return
	}
	disposals.sessions = append(disposals.sessions, session)
	disposals.sessionSlots++
	disposals.broker.sessionReservations++
}

func (broker *Broker) prepareRequestLocked(
	request credential.Request,
) (*lineageState, *operationState, ports.SessionIssuer, error) {
	issuer, registered := broker.issuers[keyForIssuer(request)]
	if !registered || isNilInterface(issuer) {
		return nil, nil, nil, ErrUnavailable
	}

	connKey := keyForConnection(request)
	opKey := keyForOperation(request)
	if broker.lineages[connKey] == nil && len(broker.lineages) >= MaxTrackedConnections {
		return nil, nil, nil, ErrCapacity
	}
	if broker.operations[opKey] == nil &&
		uint64(len(broker.operations))+broker.operationReservations >= MaxTrackedOperations {
		return nil, nil, nil, ErrCapacity
	}
	lineage := broker.lineages[connKey]
	if lineage != nil {
		switch {
		case request.ConnectionGeneration() < lineage.generation:
			return nil, nil, nil, ErrStale
		case request.ConnectionGeneration() > lineage.generation:
			return nil, nil, nil, ErrCredentialRotationRequired
		case !sameLineageRequest(lineage, request):
			return nil, nil, nil, ErrConflict
		}
	}
	if lineage != nil && lineage.revokedThrough >= request.ConnectionGeneration() {
		return nil, nil, nil, ErrRevoked
	}

	operation := broker.operations[opKey]
	if operation != nil {
		if operation.terminal {
			return nil, nil, nil, ErrOperationTerminated
		}
		if !operation.binding.Equal(request.BindingDigest()) {
			return nil, nil, nil, ErrConflict
		}
	}
	missing := uint64(0)
	if lineage == nil {
		missing++
	}
	if operation == nil {
		missing++
	}
	firstEpoch, err := broker.reserveEpochsLocked(missing)
	if err != nil {
		return nil, nil, nil, err
	}
	nextEpoch := firstEpoch
	if lineage == nil {
		lineage = newLineageState(request, nextEpoch)
		broker.lineages[connKey] = lineage
		if operation == nil {
			nextEpoch++
		}
	}
	if operation == nil {
		operation = &operationState{
			binding: request.BindingDigest(),
			epoch:   nextEpoch,
		}
		broker.operations[opKey] = operation
	}
	return lineage, operation, issuer, nil
}

func newLineageState(request credential.Request, epoch uint64) *lineageState {
	source := request.SourceLookup()
	return &lineageState{
		generation:   request.ConnectionGeneration(),
		provider:     request.Provider(),
		referenceID:  source.ReferenceID(),
		version:      source.Version(),
		sourceDigest: source.Digest(),
		epoch:        epoch,
	}
}

func sameLineageRequest(lineage *lineageState, request credential.Request) bool {
	if lineage == nil {
		return false
	}
	source := request.SourceLookup()
	return lineage.generation == request.ConnectionGeneration() &&
		lineage.provider == request.Provider() &&
		lineage.referenceID == source.ReferenceID() &&
		lineage.version == source.Version() &&
		lineage.sourceDigest.Equal(source.Digest())
}

func (broker *Broker) cellCurrentLocked(cell *sessionCell) bool {
	if cell == nil || cell.invalid || cell.session == nil || !cell.session.Valid() {
		return false
	}
	lineage := broker.lineages[cell.connKey]
	operation := broker.operations[cell.opKey]
	return lineage != nil && operation != nil && !operation.terminal &&
		lineage.epoch == cell.connEpoch && operation.epoch == cell.opEpoch &&
		lineage.revokedThrough < lineage.generation &&
		operation.binding.Equal(cell.binding)
}

func (broker *Broker) newLeaseLocked(
	cell *sessionCell,
	now time.Time,
) (*Lease, error) {
	if broker.activeLeases+broker.leaseReservations >= MaxActiveLeases {
		return nil, ErrCapacity
	}
	if !broker.cellCurrentLocked(cell) {
		return nil, ErrRevoked
	}
	if !cell.session.CanStartUse(now) {
		return nil, ErrExpired
	}
	return broker.allocateLeaseLocked(cell), nil
}

func (broker *Broker) allocateLeaseLocked(cell *sessionCell) *Lease {
	closedCtx, closedCancel := context.WithCancel(context.Background())
	lease := &Lease{
		leaseDiagnostic: leaseDiagnostic{initialized: true},
		state: &leaseState{
			broker:       broker,
			cell:         cell,
			closedCtx:    closedCtx,
			closedCancel: closedCancel,
		},
	}
	cell.refs++
	cell.lastUsed = broker.touchLocked()
	broker.activeLeases++
	return lease
}

func (broker *Broker) sweepLocked(now time.Time) disposals {
	disposal := disposals{broker: broker}
	broker.sweepExpiryEvidenceLocked(now)
	for digest, entry := range broker.sources {
		if now.Before(entry.expiresAt) && entry.material != nil && entry.material.Valid() {
			continue
		}
		delete(broker.sources, digest)
		entry.invalid = true
		increment(&broker.stats.Expired)
		if entry.borrows == 0 {
			disposal.addSourceLocked(entry.material)
		} else {
			entry.retired = true
			broker.retiredSources[entry] = struct{}{}
		}
	}
	for binding, cell := range broker.sessions {
		if cell.session != nil && cell.session.CanStartUse(now) {
			continue
		}
		delete(broker.sessions, binding)
		cell.draining = true
		increment(&broker.stats.Expired)
		if cell.refs == 0 {
			broker.recordExpiryEvidenceLocked(cell, now)
			delete(broker.cells, cell)
			disposal.addSessionLocked(cell.session)
		}
	}
	return disposal
}

func (broker *Broker) invalidateCellLocked(
	cell *sessionCell,
	holdForRevocation bool,
	cancellations *cancellationBatch,
) *credential.IssuedSession {
	if cell == nil {
		return nil
	}
	if current := broker.sessions[cell.binding]; current == cell {
		delete(broker.sessions, cell.binding)
	}
	if !cell.invalid {
		cell.invalid = true
		cell.draining = true
		if cancellations == nil {
			cell.invalidCancel()
		} else {
			cancellations.add(cell.invalidCancel)
		}
	}
	if holdForRevocation {
		if cell.revocation == nil {
			cell.revocation = &revocationAttempt{
				cell:   cell,
				done:   make(chan struct{}),
				result: ports.RevocationNotRequired,
			}
		}
		return nil
	}
	if cell.refs == 0 && (cell.revocation == nil || cell.revocation.finished) {
		delete(broker.cells, cell)
	}
	return cell.session
}

func (broker *Broker) drainCellLocked(cell *sessionCell) *credential.IssuedSession {
	if cell == nil {
		return nil
	}
	if current := broker.sessions[cell.binding]; current == cell {
		delete(broker.sessions, cell.binding)
	}
	cell.draining = true
	if cell.refs == 0 {
		broker.recordExpiryEvidenceLocked(cell, broker.lastNow)
		delete(broker.cells, cell)
		return cell.session
	}
	return nil
}

func (broker *Broker) makeSourceRoomLocked() (*credential.SourceMaterial, bool) {
	return broker.makeSourceRoomExceptLocked(connectionKey{})
}

func (broker *Broker) makeSourceRoomForRotationLocked(
	protected connectionKey,
) (*credential.SourceMaterial, bool) {
	return broker.makeSourceRoomExceptLocked(protected)
}

func (broker *Broker) makeSourceRoomExceptLocked(
	protected connectionKey,
) (*credential.SourceMaterial, bool) {
	if len(broker.sources)+len(broker.retiredSources)+len(broker.sourceFlights)+
		int(broker.sourceReservations) < MaxSourceEntries {
		return nil, true
	}
	var oldest *sourceEntry
	for _, entry := range broker.sources {
		if entry.borrows != 0 || entry.invalid ||
			(protected != (connectionKey{}) && entry.key == protected) {
			continue
		}
		if oldest == nil || entry.lastUsed < oldest.lastUsed {
			oldest = entry
		}
	}
	if oldest == nil {
		return nil, false
	}
	delete(broker.sources, oldest.digest)
	oldest.invalid = true
	return oldest.material, true
}

func (broker *Broker) makeSessionRoomLocked() (*credential.IssuedSession, bool) {
	return broker.makeSessionRoomExceptLocked(connectionKey{})
}

func (broker *Broker) makeSessionRoomForRotationLocked(
	protected connectionKey,
) (*credential.IssuedSession, bool) {
	return broker.makeSessionRoomExceptLocked(protected)
}

func (broker *Broker) makeSessionRoomExceptLocked(
	protected connectionKey,
) (*credential.IssuedSession, bool) {
	if uint64(len(broker.cells))+broker.sessionReservations < MaxSessionEntries {
		return nil, true
	}
	var oldest *sessionCell
	for cell := range broker.cells {
		if cell.refs != 0 || cell.flightPins != 0 ||
			(cell.revocation != nil && !cell.revocation.finished) ||
			(protected != (connectionKey{}) && cell.connKey == protected) {
			continue
		}
		if oldest == nil || cell.lastUsed < oldest.lastUsed {
			oldest = cell
		}
	}
	if oldest == nil {
		return nil, false
	}
	if current := broker.sessions[oldest.binding]; current == oldest {
		delete(broker.sessions, oldest.binding)
	}
	oldest.invalid = true
	oldest.draining = true
	oldest.invalidCancel()
	broker.recordExpiryEvidenceLocked(oldest, broker.lastNow)
	delete(broker.cells, oldest)
	return oldest.session, true
}

func (broker *Broker) recordExpiryEvidenceLocked(
	cell *sessionCell,
	now time.Time,
) {
	if cell == nil || cell.session == nil || !cell.session.Valid() ||
		cell.revocation != nil {
		return
	}
	expiresAt := cell.session.ExpiresAt()
	if !now.Before(expiresAt) {
		return
	}
	broker.recordExpiryUntilLocked(cell, expiresAt)
}

func (broker *Broker) recordExpiryUntilLocked(
	cell *sessionCell,
	expiresAt time.Time,
) {
	if lineage := broker.lineages[cell.connKey]; lineage != nil &&
		lineage.expiryBoundUntil.Before(expiresAt) {
		lineage.expiryBoundUntil = expiresAt
	}
	if operation := broker.operations[cell.opKey]; operation != nil &&
		operation.expiryBoundUntil.Before(expiresAt) {
		operation.expiryBoundUntil = expiresAt
	}
}

func (broker *Broker) sweepExpiryEvidenceLocked(now time.Time) {
	for _, lineage := range broker.lineages {
		if !lineage.expiryBoundUntil.IsZero() &&
			!now.Before(lineage.expiryBoundUntil) {
			lineage.expiryBoundUntil = time.Time{}
		}
	}
	for _, operation := range broker.operations {
		if !operation.expiryBoundUntil.IsZero() &&
			!now.Before(operation.expiryBoundUntil) {
			operation.expiryBoundUntil = time.Time{}
		}
	}
}

func (broker *Broker) connectionExpiryEvidenceLocked(
	key connectionKey,
	now time.Time,
) ports.RevocationResult {
	lineage := broker.lineages[key]
	if lineage != nil && now.Before(lineage.expiryBoundUntil) {
		return ports.RevocationExpiryBound
	}
	return ports.RevocationNotRequired
}

func (broker *Broker) operationExpiryEvidenceLocked(
	key operationKey,
	now time.Time,
) ports.RevocationResult {
	operation := broker.operations[key]
	if operation != nil && now.Before(operation.expiryBoundUntil) {
		return ports.RevocationExpiryBound
	}
	return ports.RevocationNotRequired
}

func (broker *Broker) allExpiryEvidenceLocked(now time.Time) ports.RevocationResult {
	for _, lineage := range broker.lineages {
		if now.Before(lineage.expiryBoundUntil) {
			return ports.RevocationExpiryBound
		}
	}
	return ports.RevocationNotRequired
}

// SweepExpired performs deterministic opportunistic cleanup. It does not run
// a background timer and therefore makes no claim about cleanup while idle.
func (broker *Broker) SweepExpired() error {
	if broker == nil || !broker.initialized {
		return ErrInvalid
	}
	sample := broker.sampleNow()
	broker.mu.Lock()
	if broker.closed {
		broker.mu.Unlock()
		return ErrClosed
	}
	now, err := broker.observeNowLocked(sample)
	if err != nil {
		broker.mu.Unlock()
		return err
	}
	disposal := broker.sweepLocked(now)
	broker.mu.Unlock()
	disposal.destroy()
	return nil
}
