package credentialbroker

import (
	"context"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

// Rotate prepares a higher connection generation, then atomically cuts over
// this process-local broker. Ordinary Acquire never performs this transition.
func (broker *Broker) Rotate(
	ctx context.Context,
	next credential.Request,
) (Rotation, error) {
	if broker == nil || !broker.initialized || ctx == nil || !next.Valid() {
		return Rotation{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Rotation{}, err
	}
	sample := broker.sampleNow()
	broker.mu.Lock()
	if broker.closed {
		broker.mu.Unlock()
		return Rotation{}, ErrClosed
	}
	now, err := broker.observeNowLocked(sample)
	if err != nil {
		broker.mu.Unlock()
		return Rotation{}, err
	}
	disposal := broker.sweepLocked(now)
	if broker.activeLeases+broker.leaseReservations >= MaxActiveLeases {
		broker.mu.Unlock()
		disposal.destroy()
		return Rotation{}, ErrCapacity
	}
	key := keyForConnection(next)
	lineage := broker.lineages[key]
	if err := validateRotationTarget(lineage, next); err != nil {
		broker.mu.Unlock()
		disposal.destroy()
		return Rotation{}, err
	}
	issuer, registered := broker.issuers[keyForIssuer(next)]
	if !registered || isNilInterface(issuer) {
		broker.mu.Unlock()
		disposal.destroy()
		return Rotation{}, ErrUnavailable
	}
	if operation := broker.operations[keyForOperation(next)]; operation != nil {
		if operation.terminal {
			broker.mu.Unlock()
			disposal.destroy()
			return Rotation{}, ErrOperationTerminated
		}
		if !operation.binding.Equal(next.BindingDigest()) {
			broker.mu.Unlock()
			disposal.destroy()
			return Rotation{}, ErrConflict
		}
	}
	flight := broker.rotations[key]
	if flight != nil {
		if flight.abandoned || !flight.binding.Equal(next.BindingDigest()) ||
			flight.fromEpoch != lineage.epoch || flight.committed {
			broker.mu.Unlock()
			disposal.destroy()
			return Rotation{}, ErrConflict
		}
		broker.leaseReservations++
		flight.leaseReserved++
		flight.waiters++
		broker.mu.Unlock()
		disposal.destroy()
		return broker.waitRotation(ctx, flight)
	}
	operationMissing := broker.operations[keyForOperation(next)] == nil
	if operationMissing &&
		uint64(len(broker.operations))+broker.operationReservations >= MaxTrackedOperations {
		broker.mu.Unlock()
		disposal.destroy()
		return Rotation{}, ErrCapacity
	}
	start := false
	if flight == nil {
		if broker.activeResolves >= MaxConcurrentResolves {
			broker.mu.Unlock()
			disposal.destroy()
			return Rotation{}, ErrCapacity
		}
		evictedSource, sourceRoom := broker.makeSourceRoomForRotationLocked(key)
		if !sourceRoom {
			broker.mu.Unlock()
			disposal.destroy()
			return Rotation{}, ErrCapacity
		}
		if evictedSource != nil {
			disposal.addSourceLocked(evictedSource)
		}
		broker.sourceReservations++
		evictedSession, sessionRoom := broker.makeSessionRoomForRotationLocked(key)
		if !sessionRoom {
			broker.sourceReservations--
			broker.mu.Unlock()
			disposal.destroy()
			return Rotation{}, ErrCapacity
		}
		if evictedSession != nil {
			disposal.addSessionLocked(evictedSession)
		}
		broker.sessionReservations++
		if operationMissing {
			broker.operationReservations++
		}
		broker.activeResolves++
		broker.leaseReservations++
		flightCtx, cancel := context.WithCancel(context.Background())
		flight = &rotationFlight{
			request:           next,
			connKey:           key,
			binding:           next.BindingDigest(),
			issuer:            issuer,
			fromEpoch:         lineage.epoch,
			fromGen:           lineage.generation,
			source:            &flightSource{},
			ctx:               flightCtx,
			cancel:            cancel,
			done:              make(chan struct{}),
			waiters:           1,
			reserved:          true,
			sourceReserved:    true,
			resolveActive:     true,
			operationReserved: operationMissing,
			leaseReserved:     1,
			revocation:        ports.RevocationNotRequired,
		}
		broker.rotations[key] = flight
		start = true
	}
	broker.mu.Unlock()
	disposal.destroy()
	if start {
		go broker.runRotation(flight)
	}
	return broker.waitRotation(ctx, flight)
}

func validateRotationTarget(lineage *lineageState, next credential.Request) error {
	if lineage == nil {
		return ErrConflict
	}
	source := next.SourceLookup()
	switch {
	case lineage.revokedThrough >= next.ConnectionGeneration():
		return ErrRevoked
	case next.ConnectionGeneration() <= lineage.generation:
		return ErrStale
	case next.Provider() != lineage.provider:
		return ErrConflict
	case source.ReferenceID() != lineage.referenceID:
		return ErrConflict
	case source.Version() == lineage.version:
		return ErrConflict
	default:
		return nil
	}
}

func (broker *Broker) waitRotation(
	ctx context.Context,
	flight *rotationFlight,
) (Rotation, error) {
	select {
	case <-ctx.Done():
		if !broker.cancelRotationWaiter(flight) {
			return Rotation{}, ctx.Err()
		}
		// Atomic commit won the race. Cancellation cannot roll back the
		// lineage transition or discard this waiter's reserved entitlement.
		<-flight.done
	case <-flight.done:
	}
	broker.mu.Lock()
	if flight.waiters > 0 {
		flight.waiters--
	}
	committed := flight.committed
	err := flight.err
	revocation := flight.revocation
	var lease *Lease
	if committed && len(flight.leases) != 0 {
		last := len(flight.leases) - 1
		lease = flight.leases[last]
		flight.leases[last] = nil
		flight.leases = flight.leases[:last]
	}
	broker.mu.Unlock()
	if committed {
		if lease == nil {
			return Rotation{}, ErrUnavailable
		}
		return Rotation{lease: lease, priorRevocation: revocation}, nil
	}
	if callerErr := ctx.Err(); callerErr != nil {
		return Rotation{}, callerErr
	}
	if err != nil {
		return Rotation{}, err
	}
	return Rotation{}, ErrUnavailable
}

func (broker *Broker) cancelRotationWaiter(flight *rotationFlight) bool {
	broker.mu.Lock()
	if flight.committed {
		broker.mu.Unlock()
		return true
	}
	if flight.waiters > 0 {
		flight.waiters--
	}
	if flight.leaseReserved > 0 {
		flight.leaseReserved--
		if broker.leaseReservations > 0 {
			broker.leaseReservations--
		}
	}
	if !flight.finished && flight.waiters == 0 {
		flight.abandoned = true
		broker.mu.Unlock()
		flight.source.invalidate()
		flight.cancel()
		return false
	}
	broker.mu.Unlock()
	return false
}

func (broker *Broker) runRotation(flight *rotationFlight) {
	source, sourceExpiresAt, err := broker.resolveOwned(
		flight.ctx,
		flight.request.SourceLookup(),
		ports.SecretReadCritical,
		flight.source,
	)
	var sourceTimeErr error
	var sourceNow time.Time
	if err == nil {
		sample := broker.sampleNow()
		broker.mu.Lock()
		sourceNow, sourceTimeErr = broker.observeNowLocked(sample)
		broker.mu.Unlock()
	}
	broker.mu.Lock()
	flight.sourceExpiresAt = sourceExpiresAt
	if flight.resolveActive {
		flight.resolveActive = false
		if broker.activeResolves > 0 {
			broker.activeResolves--
		}
	}
	broker.mu.Unlock()
	if err != nil {
		broker.finishRotationFailure(flight, source, nil, err)
		return
	}
	if sourceTimeErr != nil || sourceExpiresAt.IsZero() ||
		!sourceNow.Before(sourceExpiresAt) {
		broker.finishRotationFailure(flight, source, nil, ErrUnavailable)
		return
	}
	if err := flight.ctx.Err(); err != nil {
		broker.finishRotationFailure(flight, source, nil, err)
		return
	}
	issueCtx, cancelIssue := detachedBackendContext(flight.ctx)
	broker.mu.Lock()
	increment(&broker.stats.SessionIssues)
	broker.mu.Unlock()
	issued, issueErr := flight.issuer.Issue(issueCtx, flight.request, source)
	issueContextErr := issueCtx.Err()
	cancelIssue()
	if issueErr != nil || issueContextErr != nil {
		broker.finishRotationFailure(flight, source, issued, ErrUnavailable)
		return
	}
	broker.commitRotation(flight, source, issued)
}

func (broker *Broker) commitRotation(
	flight *rotationFlight,
	source *credential.SourceMaterial,
	issued *credential.IssuedSession,
) {
	sample := broker.sampleNow()
	releaseInvalidation := broker.beginInvalidation()
	defer releaseInvalidation()
	disposal := disposals{broker: broker}
	cancellations := cancellationBatch{}
	var revoke []*revocationAttempt
	var priorSessionFlights []*sessionFlight
	var priorSourceFlights []*sourceFlight
	priorExpiryEvidence := ports.RevocationNotRequired
	committed := false
	resultErr := error(nil)
	broker.mu.Lock()
	now, timeErr := broker.observeNowLocked(sample)
	lineage := broker.lineages[flight.connKey]
	operation := broker.operations[keyForOperation(flight.request)]
	switch {
	case timeErr != nil:
		resultErr = timeErr
	case broker.closed:
		resultErr = ErrClosed
	case broker.rotations[flight.connKey] != flight:
		resultErr = ErrConflict
	case flight.abandoned || flight.waiters == 0 || flight.ctx.Err() != nil:
		resultErr = ErrUnavailable
	case lineage == nil || lineage.epoch != flight.fromEpoch ||
		lineage.generation != flight.fromGen:
		resultErr = ErrRevoked
	case validateRotationTarget(lineage, flight.request) != nil:
		resultErr = ErrConflict
	case operation != nil && operation.terminal:
		resultErr = ErrOperationTerminated
	case operation != nil && !operation.binding.Equal(flight.binding):
		resultErr = ErrConflict
	case flight.leaseReserved == 0 || flight.leaseReserved != flight.waiters ||
		broker.leaseReservations < flight.leaseReserved:
		resultErr = ErrUnavailable
	case flight.sourceExpiresAt.IsZero() ||
		!now.Before(flight.sourceExpiresAt):
		resultErr = ErrUnavailable
	case source == nil || !source.Valid() ||
		!validIssuedSession(flight.request, issued, now):
		resultErr = ErrUnavailable
	case flight.source == nil || !flight.source.owns(source):
		resultErr = ErrUnavailable
	}
	var connEpoch, opEpoch uint64
	if resultErr == nil {
		connEpoch, resultErr = broker.reserveEpochsLocked(2)
		if resultErr == nil {
			opEpoch = connEpoch + 1
		}
	}
	if resultErr == nil {
		if !flight.source.take(source) {
			resultErr = ErrUnavailable
		}
	}
	if resultErr == nil {
		priorExpiryEvidence = broker.connectionExpiryEvidenceLocked(
			flight.connKey,
			now,
		)
		revoke = broker.invalidateConnectionLocked(
			flight.connKey,
			now,
			&disposal,
			&cancellations,
			flight,
		)
		priorSessionFlights, priorSourceFlights = broker.connectionFlightsLocked(
			flight.connKey,
		)
		nextSource := flight.request.SourceLookup()
		lineage.generation = flight.request.ConnectionGeneration()
		lineage.provider = flight.request.Provider()
		lineage.referenceID = nextSource.ReferenceID()
		lineage.version = nextSource.Version()
		lineage.sourceDigest = nextSource.Digest()
		lineage.epoch = connEpoch

		opKey := keyForOperation(flight.request)
		if operation == nil {
			operation = &operationState{}
			broker.operations[opKey] = operation
		}
		operation.binding = flight.binding
		operation.epoch = opEpoch
		operation.terminal = false

		entry := &sourceEntry{
			key:        flight.connKey,
			digest:     nextSource.Digest(),
			generation: flight.request.ConnectionGeneration(),
			epoch:      connEpoch,
			material:   source,
			expiresAt:  flight.sourceExpiresAt,
			lastUsed:   broker.touchLocked(),
		}
		broker.sources[entry.digest] = entry
		invalidCtx, invalidCancel := context.WithCancel(context.Background())
		cell := &sessionCell{
			request:       flight.request,
			issuer:        flight.issuer,
			session:       issued,
			connKey:       flight.connKey,
			opKey:         opKey,
			binding:       flight.binding,
			connEpoch:     connEpoch,
			opEpoch:       opEpoch,
			lastUsed:      broker.touchLocked(),
			invalidCtx:    invalidCtx,
			invalidCancel: invalidCancel,
		}
		broker.sessions[flight.binding] = cell
		broker.cells[cell] = struct{}{}
		flight.cell = cell
		for flight.leaseReserved > 0 {
			flight.leases = append(flight.leases, broker.allocateLeaseLocked(cell))
			flight.leaseReserved--
			broker.leaseReservations--
		}
		broker.consumeRotationPublishReservationsLocked(flight)
		flight.committed = true
		increment(&broker.stats.Rotations)
		committed = true
	}
	broker.mu.Unlock()
	disposal.destroy()
	cancellations.publish()
	releaseInvalidation()
	if !committed {
		broker.finishRotationFailure(flight, source, issued, resultErr)
		return
	}
	revocation, revokeErr := broker.waitLifecycleCleanup(
		flight.ctx,
		revoke,
		priorSessionFlights,
		priorSourceFlights,
	)
	if revokeErr != nil {
		revocation = ports.RevocationPending
	}
	revocation = mergeRevocation(revocation, priorExpiryEvidence)
	broker.mu.Lock()
	flight.revocation = revocation
	flight.err = nil
	flight.finished = true
	if current := broker.rotations[flight.connKey]; current == flight {
		delete(broker.rotations, flight.connKey)
	}
	flight.cancel()
	close(flight.done)
	broker.mu.Unlock()
}

func (broker *Broker) finishRotationFailure(
	flight *rotationFlight,
	source *credential.SourceMaterial,
	issued *credential.IssuedSession,
	err error,
) {
	broker.mu.Lock()
	lineage := broker.lineages[flight.connKey]
	operation := broker.operations[keyForOperation(flight.request)]
	switch {
	case broker.closed:
		err = ErrClosed
	case lineage == nil || lineage.epoch != flight.fromEpoch:
		err = ErrRevoked
	case operation != nil && operation.terminal:
		err = ErrOperationTerminated
	}
	flight.err = normalizeFlightError(err)
	broker.mu.Unlock()

	flight.source.invalidate()
	flight.cancel()
	flight.revocation, _ = broker.cleanupUnpublished(
		flight.request,
		flight.issuer,
		issued,
	)

	broker.mu.Lock()
	if current := broker.rotations[flight.connKey]; current == flight {
		delete(broker.rotations, flight.connKey)
	}
	broker.releaseRotationReservationsLocked(flight)
	if flight.resolveActive {
		flight.resolveActive = false
		if broker.activeResolves > 0 {
			broker.activeResolves--
		}
	}
	flight.finished = true
	close(flight.done)
	broker.mu.Unlock()
}

func (broker *Broker) consumeRotationPublishReservationsLocked(
	flight *rotationFlight,
) {
	if flight.reserved {
		flight.reserved = false
		if broker.sessionReservations > 0 {
			broker.sessionReservations--
		}
	}
	if flight.sourceReserved {
		flight.sourceReserved = false
		if broker.sourceReservations > 0 {
			broker.sourceReservations--
		}
	}
	if flight.operationReserved {
		flight.operationReserved = false
		if broker.operationReservations > 0 {
			broker.operationReservations--
		}
	}
}

func (broker *Broker) releaseRotationReservationsLocked(flight *rotationFlight) {
	broker.consumeRotationPublishReservationsLocked(flight)
	if flight.leaseReserved > 0 {
		if flight.leaseReserved <= broker.leaseReservations {
			broker.leaseReservations -= flight.leaseReserved
		} else {
			broker.leaseReservations = 0
		}
		flight.leaseReserved = 0
	}
}
