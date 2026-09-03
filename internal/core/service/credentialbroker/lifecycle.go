package credentialbroker

import (
	"context"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

// RevokeConnection installs a revoked-through tombstone and advances the
// process-local connection epoch before attempting bounded upstream revocation.
func (broker *Broker) RevokeConnection(
	ctx context.Context,
	request credential.Request,
) (ports.RevocationResult, error) {
	if broker == nil || !broker.initialized || ctx == nil || !request.Valid() {
		return ports.RevocationNotRequired, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return ports.RevocationNotRequired, err
	}
	sample := broker.sampleNow()
	releaseInvalidation := broker.beginInvalidation()
	defer releaseInvalidation()
	cancellations := cancellationBatch{}
	broker.mu.Lock()
	if broker.closed {
		broker.mu.Unlock()
		return ports.RevocationNotRequired, ErrClosed
	}
	now, err := broker.observeNowLocked(sample)
	if err != nil {
		broker.mu.Unlock()
		return ports.RevocationNotRequired, err
	}
	disposal := broker.sweepLocked(now)
	pending := broker.pendingRotationForConnectionLocked(request)
	if pending != nil {
		lineage := broker.lineages[keyForConnection(request)]
		if lineage != nil && lineage.epoch != pending.fromEpoch &&
			lineage.revokedThrough >= request.ConnectionGeneration() {
			attempts := broker.unfinishedRevocationsLocked(
				func(cell *sessionCell) bool {
					return cell.connKey == keyForConnection(request)
				},
			)
			sessionFlights, sourceFlights := broker.connectionFlightsLocked(
				keyForConnection(request),
			)
			expiryEvidence := broker.connectionExpiryEvidenceLocked(
				keyForConnection(request),
				now,
			)
			broker.mu.Unlock()
			disposal.destroy()
			releaseInvalidation()
			result, revokeErr := broker.waitLifecycleCleanup(
				ctx,
				attempts,
				sessionFlights,
				sourceFlights,
			)
			if revokeErr != nil {
				return result, revokeErr
			}
			result = mergeRevocation(result, expiryEvidence)
			return mergeRevocation(result, ports.RevocationPending), nil
		}
		if lineage == nil || lineage.epoch != pending.fromEpoch {
			broker.mu.Unlock()
			disposal.destroy()
			return ports.RevocationNotRequired, ErrRevoked
		}
		epoch, epochErr := broker.newEpochLocked()
		if epochErr != nil {
			broker.mu.Unlock()
			disposal.destroy()
			return ports.RevocationNotRequired, epochErr
		}
		lineage.epoch = epoch
		if lineage.revokedThrough < request.ConnectionGeneration() {
			lineage.revokedThrough = request.ConnectionGeneration()
		}
		cells := broker.invalidateConnectionLocked(
			keyForConnection(request),
			now,
			&disposal,
			&cancellations,
			nil,
		)
		sessionFlights, sourceFlights := broker.connectionFlightsLocked(
			keyForConnection(request),
		)
		expiryEvidence := broker.connectionExpiryEvidenceLocked(
			keyForConnection(request),
			now,
		)
		broker.mu.Unlock()
		disposal.destroy()
		cancellations.publish()
		releaseInvalidation()
		result, revokeErr := broker.waitLifecycleCleanup(
			ctx,
			cells,
			sessionFlights,
			sourceFlights,
		)
		if revokeErr != nil {
			return result, revokeErr
		}
		result = mergeRevocation(result, expiryEvidence)
		return mergeRevocation(result, ports.RevocationPending), nil
	}
	lineage := broker.lineages[keyForConnection(request)]
	if lineage != nil {
		switch {
		case request.ConnectionGeneration() < lineage.generation:
			broker.mu.Unlock()
			disposal.destroy()
			return ports.RevocationNotRequired, ErrStale
		case request.ConnectionGeneration() == lineage.generation &&
			!sameLineageRequest(lineage, request):
			broker.mu.Unlock()
			disposal.destroy()
			return ports.RevocationNotRequired, ErrConflict
		}
	}
	if lineage != nil && lineage.revokedThrough >= request.ConnectionGeneration() {
		attempts := broker.unfinishedRevocationsLocked(
			func(cell *sessionCell) bool {
				return cell.connKey == keyForConnection(request)
			},
		)
		sessionFlights, sourceFlights := broker.connectionFlightsLocked(
			keyForConnection(request),
		)
		rotationPending := broker.connectionRotationPendingLocked(
			keyForConnection(request),
		)
		expiryEvidence := broker.connectionExpiryEvidenceLocked(
			keyForConnection(request),
			now,
		)
		broker.mu.Unlock()
		disposal.destroy()
		releaseInvalidation()
		result, revokeErr := broker.waitLifecycleCleanup(
			ctx,
			attempts,
			sessionFlights,
			sourceFlights,
		)
		if revokeErr != nil {
			return result, revokeErr
		}
		if rotationPending {
			result = mergeRevocation(result, ports.RevocationPending)
		}
		return mergeRevocation(result, expiryEvidence), nil
	}
	if broker.lineages[keyForConnection(request)] == nil &&
		len(broker.lineages) >= MaxTrackedConnections {
		broker.mu.Unlock()
		disposal.destroy()
		return ports.RevocationNotRequired, ErrCapacity
	}
	lineage, err = broker.validateLifecycleLineageLocked(request)
	if err != nil {
		broker.mu.Unlock()
		disposal.destroy()
		return ports.RevocationNotRequired, err
	}
	epoch, err := broker.newEpochLocked()
	if err != nil {
		broker.mu.Unlock()
		disposal.destroy()
		return ports.RevocationNotRequired, err
	}
	if lineage == nil {
		lineage = newLineageState(request, epoch)
		broker.lineages[keyForConnection(request)] = lineage
	}
	lineage.epoch = epoch
	lineage.revokedThrough = request.ConnectionGeneration()
	rotationPending := false
	if rotation := broker.rotations[keyForConnection(request)]; rotation != nil && !rotation.finished {
		rotationPending = true
		if !rotation.committed &&
			lineage.revokedThrough < rotation.request.ConnectionGeneration() {
			lineage.revokedThrough = rotation.request.ConnectionGeneration()
		}
	}
	cells := broker.invalidateConnectionLocked(
		keyForConnection(request),
		now,
		&disposal,
		&cancellations,
		nil,
	)
	sessionFlights, sourceFlights := broker.connectionFlightsLocked(
		keyForConnection(request),
	)
	expiryEvidence := broker.connectionExpiryEvidenceLocked(
		keyForConnection(request),
		now,
	)
	broker.mu.Unlock()
	disposal.destroy()
	cancellations.publish()
	releaseInvalidation()
	result, revokeErr := broker.waitLifecycleCleanup(
		ctx,
		cells,
		sessionFlights,
		sourceFlights,
	)
	if revokeErr != nil {
		return result, revokeErr
	}
	if rotationPending {
		result = mergeRevocation(result, ports.RevocationPending)
	}
	result = mergeRevocation(result, expiryEvidence)
	return result, nil
}

// CancelOperation permanently terminates one operation ID for this broker
// lifetime. The tombstone is process-local and is not a persistence claim.
func (broker *Broker) CancelOperation(
	ctx context.Context,
	request credential.Request,
) (ports.RevocationResult, error) {
	return broker.terminateOperation(ctx, request)
}

// CloseOperation has the same authority transition as CancelOperation; the
// separate method lets callers preserve their domain lifecycle distinction.
func (broker *Broker) CloseOperation(
	ctx context.Context,
	request credential.Request,
) (ports.RevocationResult, error) {
	return broker.terminateOperation(ctx, request)
}

func (broker *Broker) terminateOperation(
	ctx context.Context,
	request credential.Request,
) (ports.RevocationResult, error) {
	if broker == nil || !broker.initialized || ctx == nil || !request.Valid() {
		return ports.RevocationNotRequired, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return ports.RevocationNotRequired, err
	}
	sample := broker.sampleNow()
	releaseInvalidation := broker.beginInvalidation()
	defer releaseInvalidation()
	cancellations := cancellationBatch{}
	broker.mu.Lock()
	if broker.closed {
		broker.mu.Unlock()
		return ports.RevocationNotRequired, ErrClosed
	}
	now, err := broker.observeNowLocked(sample)
	if err != nil {
		broker.mu.Unlock()
		return ports.RevocationNotRequired, err
	}
	disposal := broker.sweepLocked(now)
	pending, pendingErr := broker.pendingRotationForLifecycleLocked(request)
	if pendingErr != nil {
		broker.mu.Unlock()
		disposal.destroy()
		return ports.RevocationNotRequired, pendingErr
	}
	opKey := keyForOperation(request)
	operation := broker.operations[opKey]
	if operation != nil && !operation.binding.Equal(request.BindingDigest()) {
		broker.mu.Unlock()
		disposal.destroy()
		return ports.RevocationNotRequired, ErrConflict
	}
	if operation != nil && operation.terminal {
		attempts := broker.unfinishedRevocationsLocked(
			func(cell *sessionCell) bool { return cell.opKey == opKey },
		)
		sessionFlights := broker.operationFlightsLocked(opKey)
		expiryEvidence := broker.operationExpiryEvidenceLocked(opKey, now)
		broker.mu.Unlock()
		disposal.destroy()
		releaseInvalidation()
		result, revokeErr := broker.waitLifecycleCleanup(
			ctx,
			attempts,
			sessionFlights,
			nil,
		)
		if revokeErr != nil {
			return result, revokeErr
		}
		if pending != nil {
			result = mergeRevocation(result, ports.RevocationPending)
		}
		return mergeRevocation(result, expiryEvidence), nil
	}
	if pending == nil &&
		((broker.lineages[keyForConnection(request)] == nil &&
			len(broker.lineages) >= MaxTrackedConnections) ||
			(operation == nil &&
				uint64(len(broker.operations))+broker.operationReservations >= MaxTrackedOperations)) {
		broker.mu.Unlock()
		disposal.destroy()
		return ports.RevocationNotRequired, ErrCapacity
	}
	var lineage *lineageState
	if pending == nil {
		lineage, err = broker.validateLifecycleLineageLocked(request)
		if err != nil {
			broker.mu.Unlock()
			disposal.destroy()
			return ports.RevocationNotRequired, err
		}
	} else {
		lineage = broker.lineages[keyForConnection(request)]
		if lineage == nil || lineage.epoch != pending.fromEpoch {
			broker.mu.Unlock()
			disposal.destroy()
			return ports.RevocationNotRequired, ErrRevoked
		}
	}
	epochCount := uint64(1)
	if lineage == nil {
		epochCount++
	}
	firstEpoch, err := broker.reserveEpochsLocked(epochCount)
	if err != nil {
		broker.mu.Unlock()
		disposal.destroy()
		return ports.RevocationNotRequired, err
	}
	operationEpoch := firstEpoch
	if lineage == nil {
		lineage = newLineageState(request, firstEpoch)
		broker.lineages[keyForConnection(request)] = lineage
		operationEpoch++
	}
	if operation == nil {
		if pending != nil && pending.operationReserved {
			pending.operationReserved = false
			if broker.operationReservations > 0 {
				broker.operationReservations--
			}
		}
		operation = &operationState{binding: request.BindingDigest()}
		broker.operations[opKey] = operation
	}
	operation.epoch = operationEpoch
	operation.terminal = true
	for _, flight := range broker.sessionFlights {
		if flight.opKey == opKey {
			cancellations.add(flight.cancel)
		}
	}
	for _, flight := range broker.rotations {
		if keyForOperation(flight.request) == opKey {
			disposal.addFlightSourceLocked(flight.source)
			cancellations.add(flight.cancel)
		}
	}
	cells := broker.invalidateMatchingCellsLocked(
		func(cell *sessionCell) bool { return cell.opKey == opKey },
		now,
		&disposal,
		&cancellations,
	)
	sessionFlights := broker.operationFlightsLocked(opKey)
	expiryEvidence := broker.operationExpiryEvidenceLocked(opKey, now)
	broker.mu.Unlock()
	disposal.destroy()
	cancellations.publish()
	releaseInvalidation()
	result, revokeErr := broker.waitLifecycleCleanup(
		ctx,
		cells,
		sessionFlights,
		nil,
	)
	if revokeErr != nil {
		return result, revokeErr
	}
	if pending != nil {
		result = mergeRevocation(result, ports.RevocationPending)
	}
	result = mergeRevocation(result, expiryEvidence)
	return result, nil
}

func (broker *Broker) pendingRotationForLifecycleLocked(
	request credential.Request,
) (*rotationFlight, error) {
	flight := broker.rotations[keyForConnection(request)]
	if flight == nil || flight.committed || flight.finished {
		return nil, nil
	}
	sameOperation := keyForOperation(flight.request) == keyForOperation(request)
	if sameOperation && !flight.binding.Equal(request.BindingDigest()) {
		return nil, ErrConflict
	}
	if !sameOperation || !flight.binding.Equal(request.BindingDigest()) ||
		flight.request.ConnectionGeneration() != request.ConnectionGeneration() {
		return nil, nil
	}
	return flight, nil
}

func (broker *Broker) pendingRotationForConnectionLocked(
	request credential.Request,
) *rotationFlight {
	flight := broker.rotations[keyForConnection(request)]
	if flight == nil || flight.committed || flight.finished ||
		flight.request.ConnectionGeneration() != request.ConnectionGeneration() ||
		flight.request.Provider() != request.Provider() {
		return nil
	}
	want := flight.request.SourceLookup()
	got := request.SourceLookup()
	if want.ReferenceID() != got.ReferenceID() || want.Version() != got.Version() ||
		!want.Digest().Equal(got.Digest()) {
		return nil
	}
	return flight
}

func (broker *Broker) validateLifecycleLineageLocked(
	request credential.Request,
) (*lineageState, error) {
	key := keyForConnection(request)
	lineage := broker.lineages[key]
	if lineage == nil {
		return nil, nil
	}
	switch {
	case request.ConnectionGeneration() < lineage.generation:
		return nil, ErrStale
	case request.ConnectionGeneration() > lineage.generation:
		return nil, ErrCredentialRotationRequired
	case !sameLineageRequest(lineage, request):
		return nil, ErrConflict
	default:
		return lineage, nil
	}
}

func (broker *Broker) invalidateConnectionLocked(
	key connectionKey,
	now time.Time,
	disposal *disposals,
	cancellations *cancellationBatch,
	excludeRotation *rotationFlight,
) []*revocationAttempt {
	for digest, entry := range broker.sources {
		if entry.key != key {
			continue
		}
		delete(broker.sources, digest)
		entry.invalid = true
		disposal.addSourceLocked(entry.material)
	}
	for entry := range broker.retiredSources {
		if entry.key != key {
			continue
		}
		delete(broker.retiredSources, entry)
		entry.retired = false
		disposal.addSourceLocked(entry.material)
	}
	for _, flight := range broker.sourceFlights {
		if flight.connKey == key {
			disposal.addFlightSourceLocked(flight.source)
			cancellations.add(flight.cancel)
		}
	}
	for _, flight := range broker.sessionFlights {
		if flight.connKey == key {
			cancellations.add(flight.cancel)
		}
	}
	if flight := broker.rotations[key]; flight != nil && flight != excludeRotation {
		disposal.addFlightSourceLocked(flight.source)
		cancellations.add(flight.cancel)
	}
	return broker.invalidateMatchingCellsLocked(
		func(cell *sessionCell) bool { return cell.connKey == key },
		now,
		disposal,
		cancellations,
	)
}

func (broker *Broker) invalidateMatchingCellsLocked(
	matches func(*sessionCell) bool,
	now time.Time,
	disposal *disposals,
	cancellations *cancellationBatch,
) []*revocationAttempt {
	var revoke []*revocationAttempt
	for cell := range broker.cells {
		if !matches(cell) {
			continue
		}
		if cell.revocation != nil && !cell.revocation.finished {
			revoke = append(revoke, cell.revocation)
			continue
		}
		if cell.revocation != nil {
			continue
		}
		liveUpstream := cell.session != nil && now.Before(cell.session.ExpiresAt())
		if liveUpstream {
			broker.invalidateCellLocked(cell, true, cancellations)
			revoke = append(revoke, cell.revocation)
			continue
		}
		if session := broker.invalidateCellLocked(cell, false, cancellations); session != nil {
			disposal.addSessionLocked(session)
		}
	}
	return revoke
}

func (broker *Broker) unfinishedRevocationsLocked(
	matches func(*sessionCell) bool,
) []*revocationAttempt {
	var attempts []*revocationAttempt
	for cell := range broker.cells {
		if matches(cell) && cell.revocation != nil && !cell.revocation.finished {
			attempts = append(attempts, cell.revocation)
		}
	}
	return attempts
}

func (broker *Broker) connectionFlightsLocked(
	key connectionKey,
) ([]*sessionFlight, []*sourceFlight) {
	var sessions []*sessionFlight
	for _, flight := range broker.sessionFlights {
		if flight.connKey == key && !flight.finished {
			sessions = append(sessions, flight)
		}
	}
	var sources []*sourceFlight
	for _, flight := range broker.sourceFlights {
		if flight.connKey == key && !flight.finished {
			sources = append(sources, flight)
		}
	}
	return sessions, sources
}

func (broker *Broker) operationFlightsLocked(
	key operationKey,
) []*sessionFlight {
	var flights []*sessionFlight
	for _, flight := range broker.sessionFlights {
		if flight.opKey == key && !flight.finished {
			flights = append(flights, flight)
		}
	}
	return flights
}

func (broker *Broker) allNonRotationFlightsLocked() (
	[]*sessionFlight,
	[]*sourceFlight,
) {
	var sessions []*sessionFlight
	for _, flight := range broker.sessionFlights {
		if !flight.finished {
			sessions = append(sessions, flight)
		}
	}
	var sources []*sourceFlight
	for _, flight := range broker.sourceFlights {
		if !flight.finished {
			sources = append(sources, flight)
		}
	}
	return sessions, sources
}

func (broker *Broker) revokeAttempts(
	ctx context.Context,
	attempts []*revocationAttempt,
) (ports.RevocationResult, error) {
	return broker.waitLifecycleCleanup(ctx, attempts, nil, nil)
}

func (broker *Broker) waitLifecycleCleanup(
	ctx context.Context,
	attempts []*revocationAttempt,
	sessionFlights []*sessionFlight,
	sourceFlights []*sourceFlight,
) (ports.RevocationResult, error) {
	if len(attempts) == 0 && len(sessionFlights) == 0 &&
		len(sourceFlights) == 0 {
		return ports.RevocationNotRequired, nil
	}
	waitCtx, cancelWait := context.WithTimeout(ctx, credential.BackendTimeout)
	defer cancelWait()
	unique := make([]*revocationAttempt, 0, len(attempts))
	seen := make(map[*revocationAttempt]struct{}, len(attempts))
	broker.mu.Lock()
	for _, attempt := range attempts {
		if attempt == nil {
			continue
		}
		if _, exists := seen[attempt]; exists {
			continue
		}
		seen[attempt] = struct{}{}
		unique = append(unique, attempt)
		if !attempt.started {
			attempt.started = true
			go broker.runRevocation(attempt)
		}
	}
	broker.mu.Unlock()
	aggregate := ports.RevocationNotRequired
	failed := false
	for _, attempt := range unique {
		select {
		case <-attempt.done:
			broker.mu.Lock()
			result, err := attempt.result, attempt.err
			broker.mu.Unlock()
			aggregate = mergeRevocation(aggregate, result)
			if err != nil {
				failed = true
			}
		case <-waitCtx.Done():
			aggregate = ports.RevocationPending
			failed = true
		}
	}
	seenSessions := make(map[*sessionFlight]struct{}, len(sessionFlights))
	for _, flight := range sessionFlights {
		if flight == nil {
			continue
		}
		if _, exists := seenSessions[flight]; exists {
			continue
		}
		seenSessions[flight] = struct{}{}
		select {
		case <-flight.done:
			broker.mu.Lock()
			result, err := flight.revocation, flight.revocationErr
			broker.mu.Unlock()
			aggregate = mergeRevocation(aggregate, result)
			if err != nil {
				failed = true
			}
		case <-waitCtx.Done():
			aggregate = ports.RevocationPending
			failed = true
		}
	}
	seenSources := make(map[*sourceFlight]struct{}, len(sourceFlights))
	for _, flight := range sourceFlights {
		if flight == nil {
			continue
		}
		if _, exists := seenSources[flight]; exists {
			continue
		}
		seenSources[flight] = struct{}{}
		select {
		case <-flight.done:
		case <-waitCtx.Done():
			aggregate = ports.RevocationPending
			failed = true
		}
	}
	if err := ctx.Err(); err != nil {
		return ports.RevocationPending, err
	}
	if failed {
		return ports.RevocationPending, ErrUnavailable
	}
	return aggregate, nil
}

func (broker *Broker) runRevocation(
	attempt *revocationAttempt,
) {
	cell := attempt.cell
	broker.revocationSlots <- struct{}{}
	callCtx, cancelCall := context.WithTimeout(
		context.Background(),
		credential.BackendTimeout,
	)
	broker.mu.Lock()
	increment(&broker.stats.Revocations)
	broker.mu.Unlock()
	result, err := cell.issuer.Revoke(callCtx, cell.request, cell.session)
	backendErr := callCtx.Err()
	cancelCall()
	<-broker.revocationSlots
	if backendErr != nil {
		err = ErrUnavailable
	}
	if err != nil || result == ports.RevocationNotRequired ||
		result == ports.RevocationPending || !result.Valid() {
		result = ports.RevocationPending
		err = ErrUnavailable
	}
	expiresAt := cell.session.ExpiresAt()
	destroySession(cell.session)
	broker.mu.Lock()
	if (result == ports.RevocationExpiryBound || result == ports.RevocationPending) &&
		broker.lastNow.Before(expiresAt) {
		broker.recordExpiryUntilLocked(cell, expiresAt)
	}
	if result == ports.RevocationPending {
		increment(&broker.stats.RevocationPending)
	}
	attempt.result = result
	attempt.err = err
	attempt.finished = true
	if cell.refs == 0 {
		delete(broker.cells, cell)
	}
	close(attempt.done)
	broker.mu.Unlock()
}

func (broker *Broker) cleanupUnpublished(
	request credential.Request,
	issuer ports.SessionIssuer,
	session *credential.IssuedSession,
) (ports.RevocationResult, error) {
	if session == nil || !session.Valid() || isNilInterface(issuer) {
		destroySession(session)
		return ports.RevocationNotRequired, nil
	}
	invalidCtx, invalidCancel := context.WithCancel(context.Background())
	invalidCancel()
	cell := &sessionCell{
		request:       request,
		issuer:        issuer,
		session:       session,
		connKey:       keyForConnection(request),
		opKey:         keyForOperation(request),
		binding:       request.BindingDigest(),
		invalid:       true,
		draining:      true,
		invalidCtx:    invalidCtx,
		invalidCancel: invalidCancel,
	}
	attempt := &revocationAttempt{
		cell:   cell,
		done:   make(chan struct{}),
		result: ports.RevocationNotRequired,
	}
	cell.revocation = attempt
	_, _ = broker.revokeAttempts(
		context.Background(),
		[]*revocationAttempt{attempt},
	)
	// A non-cooperative adapter may return after its context deadline. Keep the
	// issuing flight's capacity reservation until its actual return, upstream
	// cleanup classification, and local destruction are all complete.
	<-attempt.done
	broker.mu.Lock()
	result, err := attempt.result, attempt.err
	broker.mu.Unlock()
	return result, err
}

func mergeRevocation(
	left ports.RevocationResult,
	right ports.RevocationResult,
) ports.RevocationResult {
	if left == ports.RevocationPending || right == ports.RevocationPending {
		return ports.RevocationPending
	}
	if left == ports.RevocationExpiryBound || right == ports.RevocationExpiryBound {
		return ports.RevocationExpiryBound
	}
	if left == ports.RevocationProviderConfirmed ||
		right == ports.RevocationProviderConfirmed {
		return ports.RevocationProviderConfirmed
	}
	return ports.RevocationNotRequired
}

// Close locally invalidates every broker-owned cell and flight before bounded
// upstream revocation. It remains idempotent; leases can still be Close'd.
func (broker *Broker) Close(
	ctx context.Context,
) (ports.RevocationResult, error) {
	if broker == nil || !broker.initialized || ctx == nil {
		return ports.RevocationNotRequired, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return ports.RevocationNotRequired, err
	}
	sample := broker.sampleNow()
	releaseInvalidation := broker.beginInvalidation()
	defer releaseInvalidation()
	cancellations := cancellationBatch{}
	broker.mu.Lock()
	if broker.closed {
		now, clockErr := broker.observeNowLocked(sample)
		if clockErr == nil {
			broker.sweepExpiryEvidenceLocked(now)
		}
		attempts := broker.unfinishedRevocationsLocked(
			func(*sessionCell) bool { return true },
		)
		sessionFlights, sourceFlights := broker.allNonRotationFlightsLocked()
		rotationPending := broker.unfinishedRotationsLocked()
		expiryEvidence := broker.allExpiryEvidenceLocked(broker.lastNow)
		broker.mu.Unlock()
		releaseInvalidation()
		result, revokeErr := broker.waitLifecycleCleanup(
			ctx,
			attempts,
			sessionFlights,
			sourceFlights,
		)
		if revokeErr != nil {
			return result, revokeErr
		}
		if clockErr != nil {
			return ports.RevocationPending, clockErr
		}
		if rotationPending {
			result = mergeRevocation(result, ports.RevocationPending)
		}
		result = mergeRevocation(result, expiryEvidence)
		return result, nil
	}
	now := broker.lastNow
	clockErr := error(nil)
	if accepted, err := broker.observeNowLocked(sample); err == nil {
		now = accepted
	} else {
		clockErr = err
	}
	broker.closed = true
	sessionFlights, sourceFlights := broker.allNonRotationFlightsLocked()
	rotationPending := broker.unfinishedRotationsLocked()
	disposal := disposals{broker: broker}
	for _, flight := range broker.sourceFlights {
		disposal.addFlightSourceLocked(flight.source)
		cancellations.add(flight.cancel)
	}
	for _, flight := range broker.sessionFlights {
		cancellations.add(flight.cancel)
	}
	for _, flight := range broker.rotations {
		disposal.addFlightSourceLocked(flight.source)
		cancellations.add(flight.cancel)
	}
	for digest, entry := range broker.sources {
		delete(broker.sources, digest)
		entry.invalid = true
		disposal.addSourceLocked(entry.material)
	}
	for entry := range broker.retiredSources {
		delete(broker.retiredSources, entry)
		entry.retired = false
		disposal.addSourceLocked(entry.material)
	}
	cells := broker.invalidateMatchingCellsLocked(
		func(*sessionCell) bool { return true },
		now,
		&disposal,
		&cancellations,
	)
	expiryEvidence := broker.allExpiryEvidenceLocked(now)
	broker.mu.Unlock()
	disposal.destroy()
	cancellations.publish()
	releaseInvalidation()
	result, revokeErr := broker.waitLifecycleCleanup(
		ctx,
		cells,
		sessionFlights,
		sourceFlights,
	)
	if err := ctx.Err(); err != nil {
		return ports.RevocationPending, err
	}
	if revokeErr != nil {
		return result, revokeErr
	}
	if clockErr != nil {
		return ports.RevocationPending, clockErr
	}
	if rotationPending {
		result = mergeRevocation(result, ports.RevocationPending)
	}
	result = mergeRevocation(result, expiryEvidence)
	return result, nil
}

func (broker *Broker) unfinishedRotationsLocked() bool {
	for _, flight := range broker.rotations {
		if !flight.finished {
			return true
		}
	}
	return false
}

func (broker *Broker) connectionRotationPendingLocked(key connectionKey) bool {
	flight := broker.rotations[key]
	return flight != nil && !flight.finished
}
