package credentialbroker

import (
	"context"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

func (source *flightSource) publish(material *credential.SourceMaterial) bool {
	if source == nil || material == nil {
		destroySource(material)
		return false
	}
	source.mu.Lock()
	if source.invalid || source.material != nil {
		source.mu.Unlock()
		destroySource(material)
		return false
	}
	source.material = material
	source.mu.Unlock()
	return true
}

func (source *flightSource) current() *credential.SourceMaterial {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.invalid {
		return nil
	}
	return source.material
}

func (source *flightSource) owns(material *credential.SourceMaterial) bool {
	if source == nil || material == nil {
		return false
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return !source.invalid && source.material == material && material.Valid()
}

func (source *flightSource) take(material *credential.SourceMaterial) bool {
	if source == nil || material == nil {
		return false
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.invalid || source.material != material {
		return false
	}
	source.material = nil
	return true
}

func (source *flightSource) invalidate() {
	if source == nil {
		return
	}
	source.mu.Lock()
	if source.invalid {
		done := source.destroyDone
		source.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	source.invalid = true
	material := source.material
	source.material = nil
	done := make(chan struct{})
	source.destroyDone = done
	source.mu.Unlock()
	destroySource(material)
	close(done)
}

func (broker *Broker) acquireSource(
	ctx context.Context,
	request credential.Request,
	priority ports.SecretReadPriority,
	connEpoch uint64,
) (*sourceBorrow, error) {
	if ctx == nil || !priority.Valid() {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sample := broker.sampleNow()
	broker.mu.Lock()
	if broker.closed {
		broker.mu.Unlock()
		return nil, ErrClosed
	}
	now, err := broker.observeNowLocked(sample)
	if err != nil {
		broker.mu.Unlock()
		return nil, err
	}
	disposal := broker.sweepLocked(now)
	connKey := keyForConnection(request)
	lineage := broker.lineages[connKey]
	if lineage == nil || lineage.epoch != connEpoch ||
		lineage.revokedThrough >= lineage.generation ||
		!sameLineageRequest(lineage, request) {
		broker.mu.Unlock()
		disposal.destroy()
		return nil, ErrRevoked
	}
	digest := request.SourceLookup().Digest()
	if entry := broker.sources[digest]; entry != nil && !entry.invalid &&
		entry.epoch == connEpoch && now.Before(entry.expiresAt) &&
		entry.material != nil && entry.material.Valid() {
		entry.borrows++
		entry.lastUsed = broker.touchLocked()
		increment(&broker.stats.SourceHits)
		broker.mu.Unlock()
		disposal.destroy()
		return &sourceBorrow{broker: broker, entry: entry}, nil
	}
	increment(&broker.stats.SourceMisses)
	flight := broker.sourceFlights[digest]
	start := false
	if flight != nil {
		if flight.abandoned || flight.connEpoch != connEpoch {
			broker.mu.Unlock()
			disposal.destroy()
			return nil, ErrUnavailable
		}
		flight.waiters++
		increment(&broker.stats.SourceWaits)
	} else {
		if broker.activeResolves >= MaxConcurrentResolves {
			broker.mu.Unlock()
			disposal.destroy()
			return nil, ErrCapacity
		}
		evicted, room := broker.makeSourceRoomLocked()
		if !room {
			broker.mu.Unlock()
			disposal.destroy()
			return nil, ErrCapacity
		}
		if evicted != nil {
			disposal.addSourceLocked(evicted)
		}
		flightCtx, cancel := context.WithCancel(context.Background())
		flight = &sourceFlight{
			digest:    digest,
			request:   request,
			priority:  priority,
			connKey:   connKey,
			connEpoch: connEpoch,
			source:    &flightSource{},
			ctx:       flightCtx,
			cancel:    cancel,
			done:      make(chan struct{}),
			waiters:   1,
		}
		broker.sourceFlights[digest] = flight
		broker.activeResolves++
		start = true
	}
	broker.mu.Unlock()
	disposal.destroy()
	if start {
		go broker.runSourceFlight(flight)
	}
	return broker.waitSourceFlight(ctx, flight)
}

func (broker *Broker) waitSourceFlight(
	ctx context.Context,
	flight *sourceFlight,
) (*sourceBorrow, error) {
	select {
	case <-ctx.Done():
		broker.leaveSourceFlight(flight, true)
		return nil, ctx.Err()
	case <-flight.done:
		if err := ctx.Err(); err != nil {
			broker.leaveSourceFlight(flight, false)
			return nil, err
		}
	}
	broker.leaveSourceFlight(flight, false)

	sample := broker.sampleNow()
	broker.mu.Lock()
	now, err := broker.observeNowLocked(sample)
	if err == nil {
		err = flight.err
	}
	entry := flight.entry
	if err == nil {
		lineage := broker.lineages[flight.connKey]
		if broker.closed || lineage == nil || lineage.epoch != flight.connEpoch ||
			entry == nil || entry.invalid || !now.Before(entry.expiresAt) ||
			entry.material == nil || !entry.material.Valid() {
			err = ErrRevoked
		} else {
			entry.borrows++
			entry.lastUsed = broker.touchLocked()
		}
	}
	broker.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &sourceBorrow{broker: broker, entry: entry}, nil
}

func (broker *Broker) leaveSourceFlight(flight *sourceFlight, canceled bool) {
	broker.mu.Lock()
	if flight.waiters > 0 {
		flight.waiters--
	}
	abandoned := false
	if canceled && !flight.finished && flight.waiters == 0 {
		flight.abandoned = true
		abandoned = true
	}
	broker.mu.Unlock()
	if abandoned {
		flight.source.invalidate()
		flight.cancel()
	}
}

func (broker *Broker) runSourceFlight(flight *sourceFlight) {
	material, expiresAt, err := broker.resolveOwned(
		flight.ctx,
		flight.request.SourceLookup(),
		flight.priority,
		flight.source,
	)
	flight.sourceExpiresAt = expiresAt
	broker.finishSourceFlight(flight, material, err)
}

func (broker *Broker) resolveOwned(
	ctx context.Context,
	lookup credential.SourceLookup,
	priority ports.SecretReadPriority,
	owned *flightSource,
) (*credential.SourceMaterial, time.Time, error) {
	if ctx == nil || owned == nil {
		return nil, time.Time{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	claimCtx, cancelClaim := detachedBackendContext(ctx)
	broker.mu.Lock()
	increment(&broker.stats.BudgetClaims)
	broker.mu.Unlock()
	claim, claimErr := broker.budget.Claim(claimCtx, lookup, priority)
	claimContextErr := claimCtx.Err()
	cancelClaim()
	if claimErr != nil || claimContextErr != nil || isNilInterface(claim) {
		if !isNilInterface(claim) {
			_ = broker.settleClaim(claim, ports.SecretReadRetained)
		}
		owned.invalidate()
		return nil, time.Time{}, contextFailure(ctx)
	}

	var (
		material                     *credential.SourceMaterial
		outcome                      ports.SecretReadOutcome
		resolveErr                   error
		expiresAt                    time.Time
		timeErr                      error
		published                    bool
		providerReturnedWithoutError bool
		providerTupleValid           bool
	)
	if ctx.Err() != nil {
		outcome = ports.SecretReadReleased
		resolveErr = ctx.Err()
	} else {
		resolveCtx, cancelResolve := detachedBackendContext(ctx)
		broker.mu.Lock()
		increment(&broker.stats.SourceResolves)
		broker.mu.Unlock()
		material, outcome, resolveErr = broker.resolver.Resolve(resolveCtx, lookup)
		resolveContextErr := resolveCtx.Err()
		cancelResolve()
		providerReturnedWithoutError = resolveErr == nil
		providerTupleValid = providerReturnedWithoutError && material != nil && material.Valid() &&
			outcome == ports.SecretReadConsumed
		published = owned.publish(material)
		sample := broker.sampleNow()
		broker.mu.Lock()
		_, timeErr = broker.observeNowLocked(sample)
		broker.mu.Unlock()
		if timeErr == nil {
			// Cache retention is anchored to the raw Resolve-return sample,
			// even when an overlapping later sample already advanced logical
			// broker time and this one was clamped to that high-water mark.
			expiresAt = sample.observed.UTC().Add(MaxSourceCacheTTL)
		}
		if resolveContextErr != nil {
			resolveErr = resolveContextErr
		}
		if timeErr != nil {
			resolveErr = timeErr
		}
	}

	settlement := outcome
	if !outcome.Valid() || material != nil && outcome == ports.SecretReadReleased ||
		providerReturnedWithoutError && !providerTupleValid {
		settlement = ports.SecretReadRetained
	}
	settleErr := broker.settleClaim(claim, settlement)
	publishable := providerTupleValid && resolveErr == nil && published
	if settleErr != nil || !publishable {
		owned.invalidate()
		return nil, time.Time{}, contextFailure(ctx)
	}
	material = owned.current()
	if material == nil || !material.Valid() {
		owned.invalidate()
		return nil, time.Time{}, contextFailure(ctx)
	}
	return material, expiresAt, nil
}

func (broker *Broker) settleClaim(
	claim ports.SecretReadClaim,
	settlement ports.SecretReadOutcome,
) error {
	settleCtx, cancelSettle := context.WithTimeout(
		context.Background(),
		credential.BackendTimeout,
	)
	settleErr := claim.Settle(settleCtx, settlement)
	settleContextErr := settleCtx.Err()
	cancelSettle()
	broker.mu.Lock()
	if settleErr != nil || settleContextErr != nil {
		increment(&broker.stats.BudgetRetained)
	} else {
		switch settlement {
		case ports.SecretReadConsumed:
			increment(&broker.stats.BudgetConsumed)
		case ports.SecretReadReleased:
			increment(&broker.stats.BudgetReleased)
		case ports.SecretReadRetained:
			increment(&broker.stats.BudgetRetained)
		}
	}
	broker.mu.Unlock()
	if settleErr != nil || settleContextErr != nil {
		return ErrUnavailable
	}
	return nil
}

func (broker *Broker) finishSourceFlight(
	flight *sourceFlight,
	material *credential.SourceMaterial,
	resultErr error,
) {
	sample := broker.sampleNow()
	installed := false
	broker.mu.Lock()
	if resultErr == nil {
		now, timeErr := broker.observeNowLocked(sample)
		lineage := broker.lineages[flight.connKey]
		switch {
		case timeErr != nil:
			resultErr = timeErr
		case broker.closed:
			resultErr = ErrClosed
		case flight.abandoned || flight.waiters == 0 || flight.ctx.Err() != nil:
			resultErr = ErrUnavailable
		case lineage == nil || lineage.epoch != flight.connEpoch ||
			lineage.revokedThrough >= lineage.generation ||
			!sameLineageRequest(lineage, flight.request):
			resultErr = ErrRevoked
		case flight.sourceExpiresAt.IsZero() ||
			!now.Before(flight.sourceExpiresAt):
			resultErr = ErrUnavailable
		case material == nil || !material.Valid():
			resultErr = ErrUnavailable
		case flight.source == nil || !flight.source.take(material):
			resultErr = ErrUnavailable
		default:
			entry := &sourceEntry{
				key:        flight.connKey,
				digest:     flight.digest,
				generation: flight.request.ConnectionGeneration(),
				epoch:      flight.connEpoch,
				material:   material,
				expiresAt:  flight.sourceExpiresAt,
				lastUsed:   broker.touchLocked(),
			}
			broker.sources[flight.digest] = entry
			flight.entry = entry
			installed = true
		}
	}
	if !installed && resultErr == nil {
		resultErr = ErrUnavailable
	}
	if !installed && (resultErr == ErrRevoked || resultErr == ErrClosed) {
		increment(&broker.stats.StaleSuppressed)
	}
	flight.err = normalizeFlightError(resultErr)
	if installed {
		flight.cancel()
		if current := broker.sourceFlights[flight.digest]; current == flight {
			delete(broker.sourceFlights, flight.digest)
		}
		if broker.activeResolves > 0 {
			broker.activeResolves--
		}
		flight.finished = true
		close(flight.done)
		broker.mu.Unlock()
		return
	}
	broker.mu.Unlock()

	// Keep both the flight-map slot and active resolve charged until a rejected
	// material is no longer usable. Waiters cannot observe completion earlier.
	flight.source.invalidate()
	flight.cancel()

	broker.mu.Lock()
	if current := broker.sourceFlights[flight.digest]; current == flight {
		delete(broker.sourceFlights, flight.digest)
	}
	if broker.activeResolves > 0 {
		broker.activeResolves--
	}
	flight.finished = true
	close(flight.done)
	broker.mu.Unlock()
}

func (borrow *sourceBorrow) material() *credential.SourceMaterial {
	if borrow == nil || borrow.entry == nil {
		return nil
	}
	return borrow.entry.material
}

func (borrow *sourceBorrow) release() {
	if borrow == nil || borrow.broker == nil || borrow.entry == nil {
		return
	}
	borrow.once.Do(func() {
		disposal := disposals{broker: borrow.broker}
		borrow.broker.mu.Lock()
		if borrow.entry.borrows > 0 {
			borrow.entry.borrows--
		}
		if borrow.entry.invalid && borrow.entry.borrows == 0 &&
			borrow.entry.retired {
			delete(borrow.broker.retiredSources, borrow.entry)
			borrow.entry.retired = false
			disposal.addSourceLocked(borrow.entry.material)
		}
		borrow.broker.mu.Unlock()
		disposal.destroy()
	})
}
