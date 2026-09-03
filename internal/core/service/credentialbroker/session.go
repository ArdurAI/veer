package credentialbroker

import (
	"context"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

// Acquire returns one caller-owned handle for an exact sealed request. It
// refreshes proactively at SessionRefreshAhead and may reuse a still-admissible
// fallback only when that refresh fails with ErrUnavailable.
func (broker *Broker) Acquire(
	ctx context.Context,
	request credential.Request,
) (*Lease, error) {
	return broker.acquire(ctx, request, false)
}

// Refresh forces a new issued-session attempt for the exact binding. The old
// cell is not drained until a valid replacement commits.
func (broker *Broker) Refresh(
	ctx context.Context,
	request credential.Request,
) (*Lease, error) {
	return broker.acquire(ctx, request, true)
}

func (broker *Broker) acquire(
	ctx context.Context,
	request credential.Request,
	forceRefresh bool,
) (*Lease, error) {
	if broker == nil || !broker.initialized || ctx == nil || !request.Valid() {
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
	if broker.activeLeases+broker.leaseReservations >= MaxActiveLeases {
		broker.mu.Unlock()
		disposal.destroy()
		return nil, ErrCapacity
	}
	lineage, operation, issuer, err := broker.prepareRequestLocked(request)
	if err != nil {
		broker.mu.Unlock()
		disposal.destroy()
		return nil, err
	}
	binding := request.BindingDigest()
	cell := broker.sessions[binding]
	if cell != nil && broker.cellCurrentLocked(cell) &&
		cell.session.CanStartUse(now) && !forceRefresh &&
		!cell.session.RefreshDueAt(now) {
		lease, leaseErr := broker.newLeaseLocked(cell, now)
		if leaseErr == nil {
			increment(&broker.stats.SessionHits)
		}
		broker.mu.Unlock()
		disposal.destroy()
		if leaseErr != nil {
			return nil, leaseErr
		}
		if err := ctx.Err(); err != nil {
			_ = lease.Close()
			return nil, err
		}
		return lease, nil
	}
	var fallback *sessionCell
	if cell != nil && broker.cellCurrentLocked(cell) && cell.session.CanStartUse(now) {
		fallback = cell
	} else if cell != nil {
		if drained := broker.drainCellLocked(cell); drained != nil {
			disposal.addSessionLocked(drained)
		}
	}

	flight := broker.sessionFlights[binding]
	start := false
	if flight != nil {
		if flight.abandoned || flight.connEpoch != lineage.epoch ||
			flight.opEpoch != operation.epoch {
			broker.mu.Unlock()
			disposal.destroy()
			return nil, ErrUnavailable
		}
		flight.waiters++
		increment(&broker.stats.SessionWaits)
	} else {
		var pinned *sessionCell
		if fallback != nil {
			fallback.flightPins++
			pinned = fallback
		}
		evicted, room := broker.makeSessionRoomLocked()
		if !room {
			if pinned != nil && pinned.flightPins > 0 {
				pinned.flightPins--
			}
			broker.mu.Unlock()
			disposal.destroy()
			return nil, ErrCapacity
		}
		if evicted != nil {
			disposal.addSessionLocked(evicted)
		}
		broker.sessionReservations++
		flightCtx, cancel := context.WithCancel(context.Background())
		flight = &sessionFlight{
			request:   request,
			connKey:   keyForConnection(request),
			opKey:     keyForOperation(request),
			binding:   binding,
			connEpoch: lineage.epoch,
			opEpoch:   operation.epoch,
			refresh:   forceRefresh || fallback != nil,
			fallback:  fallback,
			issuer:    issuer,
			reserved:  true,
			pinned:    pinned,
			ctx:       flightCtx,
			cancel:    cancel,
			done:      make(chan struct{}),
			waiters:   1,
		}
		broker.sessionFlights[binding] = flight
		if flight.refresh {
			increment(&broker.stats.Refreshes)
		}
		start = true
	}
	broker.mu.Unlock()
	disposal.destroy()
	if start {
		go broker.runSessionFlight(flight)
	}
	return broker.waitSessionFlight(ctx, flight)
}

func (broker *Broker) waitSessionFlight(
	ctx context.Context,
	flight *sessionFlight,
) (*Lease, error) {
	select {
	case <-ctx.Done():
		broker.leaveSessionFlight(flight, true)
		return nil, ctx.Err()
	case <-flight.done:
		if err := ctx.Err(); err != nil {
			broker.leaveSessionFlight(flight, false)
			return nil, err
		}
	}
	broker.leaveSessionFlight(flight, false)

	sample := broker.sampleNow()
	broker.mu.Lock()
	now, err := broker.observeNowLocked(sample)
	if err == nil {
		err = flight.err
	}
	var lease *Lease
	if err == nil {
		lease, err = broker.newLeaseLocked(flight.cell, now)
	} else if err == ErrUnavailable && flight.refresh &&
		broker.fallbackCurrentLocked(flight, now) {
		lease, err = broker.newLeaseLocked(flight.fallback, now)
		if err == nil {
			increment(&broker.stats.Fallbacks)
		}
	}
	broker.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if callerErr := ctx.Err(); callerErr != nil {
		_ = lease.Close()
		return nil, callerErr
	}
	return lease, nil
}

func (broker *Broker) fallbackCurrentLocked(
	flight *sessionFlight,
	now time.Time,
) bool {
	cell := flight.fallback
	return cell != nil && broker.sessions[flight.binding] == cell &&
		broker.cellCurrentLocked(cell) && cell.connEpoch == flight.connEpoch &&
		cell.opEpoch == flight.opEpoch && cell.session.CanStartUse(now)
}

func (broker *Broker) leaveSessionFlight(flight *sessionFlight, canceled bool) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if flight.waiters > 0 {
		flight.waiters--
	}
	if canceled && !flight.finished && flight.waiters == 0 {
		flight.abandoned = true
		flight.cancel()
	}
}

func (broker *Broker) runSessionFlight(flight *sessionFlight) {
	borrow, err := broker.acquireSource(
		flight.ctx,
		flight.request,
		ports.SecretReadGeneral,
		flight.connEpoch,
	)
	if err != nil {
		broker.finishSessionFlight(flight, nil, err)
		return
	}
	defer borrow.release()
	if err := flight.ctx.Err(); err != nil {
		broker.finishSessionFlight(flight, nil, err)
		return
	}
	issueCtx, cancelIssue := detachedBackendContext(flight.ctx)
	broker.mu.Lock()
	increment(&broker.stats.SessionIssues)
	broker.mu.Unlock()
	issued, issueErr := flight.issuer.Issue(
		issueCtx,
		flight.request,
		borrow.material(),
	)
	issueContextErr := issueCtx.Err()
	cancelIssue()
	if issueErr != nil || issueContextErr != nil {
		broker.finishSessionFlight(flight, issued, contextFailure(flight.ctx))
		return
	}
	broker.finishSessionFlight(flight, issued, nil)
}

func (broker *Broker) finishSessionFlight(
	flight *sessionFlight,
	issued *credential.IssuedSession,
	resultErr error,
) {
	sample := broker.sampleNow()
	installed := false
	disposal := disposals{broker: broker}
	broker.mu.Lock()
	lineage := broker.lineages[flight.connKey]
	operation := broker.operations[flight.opKey]
	switch {
	case broker.closed:
		resultErr = ErrClosed
	case lineage == nil || lineage.epoch != flight.connEpoch ||
		lineage.revokedThrough >= lineage.generation:
		resultErr = ErrRevoked
	case operation == nil || operation.terminal || operation.epoch != flight.opEpoch ||
		!operation.binding.Equal(flight.binding):
		resultErr = ErrOperationTerminated
	case flight.abandoned || flight.waiters == 0 || flight.ctx.Err() != nil:
		resultErr = ErrUnavailable
	}
	var now time.Time
	if resultErr == nil {
		var timeErr error
		now, timeErr = broker.observeNowLocked(sample)
		if timeErr != nil {
			resultErr = timeErr
		}
	}
	if resultErr == nil && !validIssuedSession(flight.request, issued, now) {
		resultErr = ErrUnavailable
	}
	if resultErr == nil {
		var room bool
		if flight.reserved {
			room = true
		} else {
			var evicted *credential.IssuedSession
			evicted, room = broker.makeSessionRoomLocked()
			if evicted != nil {
				disposal.addSessionLocked(evicted)
			}
		}
		if !room {
			resultErr = ErrCapacity
		} else {
			invalidCtx, invalidCancel := context.WithCancel(context.Background())
			cell := &sessionCell{
				request:       flight.request,
				issuer:        flight.issuer,
				session:       issued,
				connKey:       flight.connKey,
				opKey:         flight.opKey,
				binding:       flight.binding,
				connEpoch:     flight.connEpoch,
				opEpoch:       flight.opEpoch,
				lastUsed:      broker.touchLocked(),
				invalidCtx:    invalidCtx,
				invalidCancel: invalidCancel,
			}
			if old := broker.sessions[flight.binding]; old != nil {
				if drained := broker.drainCellLocked(old); drained != nil {
					disposal.addSessionLocked(drained)
				}
			}
			broker.sessions[flight.binding] = cell
			broker.cells[cell] = struct{}{}
			flight.cell = cell
			installed = true
		}
	}
	if !installed && resultErr == nil {
		resultErr = ErrUnavailable
	}
	if !installed && (resultErr == ErrRevoked ||
		resultErr == ErrOperationTerminated || resultErr == ErrClosed) {
		increment(&broker.stats.StaleSuppressed)
	}
	flight.err = normalizeFlightError(resultErr)
	flight.cancel()
	if installed {
		broker.releaseSessionFlightLocked(flight)
	}
	broker.mu.Unlock()

	if !installed {
		flight.revocation, flight.revocationErr = broker.cleanupUnpublished(
			flight.request,
			flight.issuer,
			issued,
		)
		broker.mu.Lock()
		broker.releaseSessionFlightLocked(flight)
		broker.mu.Unlock()
	}
	disposal.destroy()

	broker.mu.Lock()
	flight.finished = true
	close(flight.done)
	broker.mu.Unlock()
}

func (broker *Broker) releaseSessionFlightLocked(flight *sessionFlight) {
	if current := broker.sessionFlights[flight.binding]; current == flight {
		delete(broker.sessionFlights, flight.binding)
	}
	if flight.reserved {
		flight.reserved = false
		if broker.sessionReservations > 0 {
			broker.sessionReservations--
		}
	}
	if flight.pinned != nil && flight.pinned.flightPins > 0 {
		flight.pinned.flightPins--
		flight.pinned = nil
	}
}

func validIssuedSession(
	request credential.Request,
	issued *credential.IssuedSession,
	now time.Time,
) bool {
	return issued != nil && issued.Valid() &&
		issued.BindingDigest().Equal(request.BindingDigest()) &&
		!issued.IssuedAt().After(now) &&
		issued.ExpiresAt().Sub(now) >= credential.MinIssuedSessionTTL &&
		issued.CanStartUse(now)
}

func normalizeFlightError(err error) error {
	if err == nil {
		return nil
	}
	if failure, ok := Classify(err); ok {
		return failure
	}
	return ErrUnavailable
}
