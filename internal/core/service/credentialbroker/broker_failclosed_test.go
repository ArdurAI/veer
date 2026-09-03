package credentialbroker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

type acquireOutcome struct {
	lease *Lease
	err   error
}

type lifecycleOutcome struct {
	result ports.RevocationResult
	err    error
}

func TestClockObservationOrderingClampsOverlapAndRejectsLaterRollback(t *testing.T) {
	baseClock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	broker := mustTestBroker(
		t,
		baseClock,
		&fakeBudget{},
		&fakeResolver{},
		&fakeIssuer{clock: baseClock},
		request.Recipient(),
	)
	firstEntered := make(chan struct{})
	firstRelease := make(chan struct{})
	secondEntered := make(chan struct{})
	secondRelease := make(chan struct{})
	reverse := &scriptedClock{
		fallback: testBrokerNow.Add(time.Second),
		steps: []clockStep{
			{now: testBrokerNow, entered: firstEntered, release: firstRelease},
			{now: testBrokerNow.Add(time.Second), entered: secondEntered, release: secondRelease},
		},
	}
	broker.mu.Lock()
	baselineSequence := broker.lastClockSample
	broker.clock = reverse
	broker.mu.Unlock()

	firstResult := make(chan error, 1)
	go func() { firstResult <- broker.SweepExpired() }()
	waitForSignal(t, firstEntered, "older clock sample")
	secondResult := make(chan error, 1)
	go func() { secondResult <- broker.SweepExpired() }()
	waitForSignal(t, secondEntered, "newer clock sample")
	close(secondRelease)
	if err := receiveResult(t, secondResult, "newer clock completion"); err != nil {
		t.Fatalf("newer SweepExpired() error = %v", err)
	}
	close(firstRelease)
	if err := receiveResult(t, firstResult, "older clock completion"); err != nil {
		t.Fatalf("older overlapping SweepExpired() error = %v", err)
	}
	broker.mu.Lock()
	sequenceAfterOverlap := broker.lastClockSample
	nowAfterOverlap := broker.lastNow
	broker.mu.Unlock()
	if sequenceAfterOverlap != baselineSequence+2 ||
		!nowAfterOverlap.Equal(testBrokerNow.Add(time.Second)) {
		t.Fatalf("ordered clock state = sequence:%d now:%v, want %d/%v",
			sequenceAfterOverlap,
			nowAfterOverlap,
			baselineSequence+2,
			testBrokerNow.Add(time.Second),
		)
	}

	recovery := newManualClock(testBrokerNow)
	broker.mu.Lock()
	broker.clock = recovery
	broker.mu.Unlock()
	if err := broker.SweepExpired(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("SweepExpired(sequential rollback) error = %v, want ErrUnavailable", err)
	}
	broker.mu.Lock()
	sequenceAfterRollback := broker.lastClockSample
	nowAfterRollback := broker.lastNow
	broker.mu.Unlock()
	if sequenceAfterRollback != baselineSequence+3 || !nowAfterRollback.Equal(nowAfterOverlap) {
		t.Fatalf("rollback state = sequence:%d now:%v, want %d/%v",
			sequenceAfterRollback,
			nowAfterRollback,
			baselineSequence+3,
			nowAfterOverlap,
		)
	}
	recovery.Set(testBrokerNow.Add(2 * time.Second))
	if err := broker.SweepExpired(); err != nil {
		t.Fatalf("SweepExpired(after rollback recovery) error = %v", err)
	}
	_, _ = broker.Close(context.Background())
}

func TestClockSampleSequenceOverflowFailsClosed(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	broker := mustTestBroker(
		t,
		clock,
		&fakeBudget{},
		&fakeResolver{},
		&fakeIssuer{clock: clock},
		request.Recipient(),
	)
	broker.clockSamples.Store(^uint64(0))
	if err := broker.SweepExpired(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("SweepExpired(at sample-sequence saturation) error = %v, want ErrUnavailable", err)
	}
	result, err := broker.Close(context.Background())
	if result != ports.RevocationPending || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Close(at sample-sequence saturation) = %v, %v, want pending, ErrUnavailable", result, err)
	}
	broker.mu.Lock()
	closed := broker.closed
	broker.mu.Unlock()
	if !closed {
		t.Fatal("Close did not invalidate broker after clock sample-sequence saturation")
	}
}

func TestOlderIssueCompletionClockSampleDoesNotDiscardValidOutput(t *testing.T) {
	baseClock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	issueEntered := make(chan struct{})
	issueRelease := make(chan struct{})
	issuedOut := make(chan *credential.IssuedSession, 1)
	issuer := &fakeIssuer{
		clock: baseClock,
		issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			session, err := newTestSession(request, testBrokerNow, credential.RequestedSessionTTL)
			if err != nil {
				return nil, err
			}
			issuedOut <- session
			close(issueEntered)
			<-issueRelease
			return session, nil
		},
	}
	broker := mustTestBroker(t, baseClock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
	acquired := make(chan acquireOutcome, 1)
	go func() {
		lease, err := broker.Acquire(context.Background(), request)
		acquired <- acquireOutcome{lease: lease, err: err}
	}()
	waitForSignal(t, issueEntered, "blocked Issue")
	issued := receiveResult(t, issuedOut, "blocked Issue output")
	firstEntered := make(chan struct{})
	firstRelease := make(chan struct{})
	secondEntered := make(chan struct{})
	secondRelease := make(chan struct{})
	reverse := &scriptedClock{
		fallback: testBrokerNow.Add(time.Second),
		steps: []clockStep{
			{now: testBrokerNow, entered: firstEntered, release: firstRelease},
			{now: testBrokerNow.Add(time.Second), entered: secondEntered, release: secondRelease},
		},
	}
	broker.mu.Lock()
	broker.clock = reverse
	broker.mu.Unlock()
	close(issueRelease)
	waitForSignal(t, firstEntered, "Issue completion clock sample")
	swept := make(chan error, 1)
	go func() { swept <- broker.SweepExpired() }()
	waitForSignal(t, secondEntered, "overlapping newer clock sample")
	close(secondRelease)
	if err := receiveResult(t, swept, "overlapping SweepExpired"); err != nil {
		t.Fatalf("SweepExpired() error = %v", err)
	}
	close(firstRelease)
	got := receiveResult(t, acquired, "Acquire after reverse clock completion")
	if got.err != nil || got.lease == nil {
		t.Fatalf("Acquire(after reverse clock completion) = %v, %v, want lease, nil", got.lease, got.err)
	}
	if !issued.Valid() {
		t.Fatal("valid Issue output was destroyed after an older overlapping clock sample")
	}
	if got := issuer.revokeCount(); got != 0 {
		t.Fatalf("unpublished cleanup Revoke calls = %d, want 0", got)
	}
	_ = got.lease.Close()
	_, _ = broker.Close(context.Background())
}

func TestResolverErrorWithMaterialAlwaysRetainsClaimAndFailsClosed(t *testing.T) {
	tests := []struct {
		name           string
		material       func(testing.TB) *credential.SourceMaterial
		wantSettlement ports.SecretReadOutcome
	}{
		{
			name: "valid material",
			material: func(t testing.TB) *credential.SourceMaterial {
				t.Helper()
				material, err := credential.NewSourceMaterial([]byte(testSourceCanary))
				if err != nil {
					t.Fatalf("NewSourceMaterial() error = %v", err)
				}
				return material
			},
			wantSettlement: ports.SecretReadRetained,
		},
		{
			name: "invalid non-nil material",
			material: func(t testing.TB) *credential.SourceMaterial {
				t.Helper()
				material, err := credential.NewSourceMaterial([]byte(testSourceCanary))
				if err != nil {
					t.Fatalf("NewSourceMaterial() error = %v", err)
				}
				material.Destroy()
				return material
			},
			wantSettlement: ports.SecretReadRetained,
		},
		{
			name:           "nil material",
			material:       func(testing.TB) *credential.SourceMaterial { return nil },
			wantSettlement: ports.SecretReadReleased,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			request := mustTestRequest(t, defaultTestRequestConfig())
			material := test.material(t)
			claim := &fakeClaim{}
			budget := &fakeBudget{claimFn: func(context.Context, credential.SourceLookup, ports.SecretReadPriority) (ports.SecretReadClaim, error) {
				return claim, nil
			}}
			resolver := &fakeResolver{resolveFn: func(context.Context, credential.SourceLookup) (*credential.SourceMaterial, ports.SecretReadOutcome, error) {
				return material, ports.SecretReadReleased, errors.New(testErrorCanary)
			}}
			issuer := &fakeIssuer{clock: clock}
			broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())

			lease, err := broker.Acquire(context.Background(), request)
			if lease != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Acquire() = %v, %v, want nil, ErrUnavailable", lease, err)
			}
			assertNoCanary(t, fmt.Sprint(err))
			if got := claim.outcomes(); len(got) != 1 || got[0] != test.wantSettlement {
				t.Fatalf("claim settlements = %v, want [%v]", got, test.wantSettlement)
			}
			if material != nil && material.Valid() {
				t.Fatal("resolver material remains valid after failed Acquire")
			}
			if got := issuer.issueCount(); got != 0 {
				t.Fatalf("Issue calls = %d, want 0", got)
			}
			_, _ = broker.Close(context.Background())
		})
	}
}

func TestAbandonedFlightBeforeLeaderStartMakesNoBackendCalls(t *testing.T) {
	t.Run("source miss", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		request := mustTestRequest(t, defaultTestRequestConfig())
		budget := &fakeBudget{}
		resolver := &fakeResolver{}
		issuer := &fakeIssuer{clock: clock}
		broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())
		flightCtx, cancelFlight := context.WithCancel(context.Background())
		broker.mu.Lock()
		lineage, _, _, err := broker.prepareRequestLocked(request)
		if err != nil {
			broker.mu.Unlock()
			t.Fatalf("prepareRequestLocked() error = %v", err)
		}
		flight := &sourceFlight{
			digest:    request.SourceLookup().Digest(),
			request:   request,
			priority:  ports.SecretReadGeneral,
			connKey:   keyForConnection(request),
			connEpoch: lineage.epoch,
			ctx:       flightCtx,
			cancel:    cancelFlight,
			done:      make(chan struct{}),
			waiters:   1,
		}
		broker.sourceFlights[flight.digest] = flight
		broker.activeResolves++
		broker.mu.Unlock()

		callerCtx, cancelCaller := context.WithCancel(context.Background())
		cancelCaller()
		borrow, err := broker.waitSourceFlight(callerCtx, flight)
		if borrow != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("waitSourceFlight(canceled) = %v, %v, want nil, context.Canceled", borrow, err)
		}
		broker.mu.Lock()
		abandoned := flight.abandoned
		broker.mu.Unlock()
		if !abandoned || flight.ctx.Err() == nil {
			t.Fatal("last canceled waiter did not abandon/cancel source flight")
		}

		broker.runSourceFlight(flight)
		if budget.callCount() != 0 || resolver.callCount() != 0 || issuer.issueCount() != 0 {
			t.Fatalf("backend calls after pre-start abandonment = claims:%d resolves:%d issues:%d", budget.callCount(), resolver.callCount(), issuer.issueCount())
		}
		broker.mu.Lock()
		flightPresent := broker.sourceFlights[flight.digest] != nil
		activeResolves := broker.activeResolves
		broker.mu.Unlock()
		if flightPresent || activeResolves != 0 {
			t.Fatalf("abandoned source flight leaked state: present=%v activeResolves=%d", flightPresent, activeResolves)
		}
		_, _ = broker.Close(context.Background())
	})

	t.Run("rotation", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		base := mustTestRequest(t, defaultTestRequestConfig())
		nextConfig := defaultTestRequestConfig()
		nextConfig.generation = 2
		nextConfig.version = "opaque_B"
		nextConfig.operation = 2
		next := mustTestRequest(t, nextConfig)
		budget := &fakeBudget{}
		resolver := &fakeResolver{}
		issuer := &fakeIssuer{clock: clock}
		broker := mustTestBroker(t, clock, budget, resolver, issuer, base.Recipient())
		flightCtx, cancelFlight := context.WithCancel(context.Background())
		broker.mu.Lock()
		lineage, _, registeredIssuer, err := broker.prepareRequestLocked(base)
		if err != nil {
			broker.mu.Unlock()
			t.Fatalf("prepareRequestLocked() error = %v", err)
		}
		flight := &rotationFlight{
			request:           next,
			connKey:           keyForConnection(next),
			binding:           next.BindingDigest(),
			issuer:            registeredIssuer,
			fromEpoch:         lineage.epoch,
			fromGen:           lineage.generation,
			ctx:               flightCtx,
			cancel:            cancelFlight,
			done:              make(chan struct{}),
			waiters:           1,
			reserved:          true,
			sourceReserved:    true,
			resolveActive:     true,
			operationReserved: true,
			leaseReserved:     1,
			revocation:        ports.RevocationNotRequired,
		}
		broker.rotations[flight.connKey] = flight
		broker.activeResolves++
		broker.sourceReservations++
		broker.sessionReservations++
		broker.operationReservations++
		broker.leaseReservations++
		broker.mu.Unlock()

		callerCtx, cancelCaller := context.WithCancel(context.Background())
		cancelCaller()
		rotation, err := broker.waitRotation(callerCtx, flight)
		if rotation.Valid() || !errors.Is(err, context.Canceled) {
			t.Fatalf("waitRotation(canceled) = %v, %v, want invalid, context.Canceled", rotation, err)
		}
		broker.mu.Lock()
		abandoned := flight.abandoned
		broker.mu.Unlock()
		if !abandoned || flight.ctx.Err() == nil {
			t.Fatal("last canceled waiter did not abandon/cancel rotation flight")
		}

		broker.runRotation(flight)
		if budget.callCount() != 0 || resolver.callCount() != 0 || issuer.issueCount() != 0 {
			t.Fatalf("backend calls after pre-start rotation abandonment = claims:%d resolves:%d issues:%d", budget.callCount(), resolver.callCount(), issuer.issueCount())
		}
		broker.mu.Lock()
		flightPresent := broker.rotations[flight.connKey] != nil
		activeResolves := broker.activeResolves
		reservations := broker.sourceReservations + broker.sessionReservations +
			broker.operationReservations + broker.leaseReservations
		broker.mu.Unlock()
		if flightPresent || activeResolves != 0 || reservations != 0 {
			t.Fatalf("abandoned rotation leaked state: present=%v activeResolves=%d reservations=%d", flightPresent, activeResolves, reservations)
		}
		_, _ = broker.Close(context.Background())
	})
}

func TestIssueResultAndErrorIsRevokedBeforeAcquireWaiterRelease(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	issuedOut := make(chan *credential.IssuedSession, 1)
	revokeEntered := make(chan struct{})
	revokeRelease := make(chan struct{})
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			session, err := newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
			if err != nil {
				return nil, err
			}
			issuedOut <- session
			return session, errors.New(testErrorCanary)
		},
		revokeFn: func(ctx context.Context, _ credential.Request, session *credential.IssuedSession) (ports.RevocationResult, error) {
			if !session.Valid() {
				return ports.RevocationPending, errors.New("session destroyed before Revoke")
			}
			close(revokeEntered)
			select {
			case <-revokeRelease:
				return ports.RevocationProviderConfirmed, nil
			case <-ctx.Done():
				return ports.RevocationPending, ctx.Err()
			}
		},
	}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
	resultOut := make(chan acquireOutcome, 1)
	go func() {
		lease, err := broker.Acquire(context.Background(), request)
		resultOut <- acquireOutcome{lease: lease, err: err}
	}()
	session := receiveResult(t, issuedOut, "Issue result+error session")
	waitForSignal(t, revokeEntered, "unpublished session Revoke")
	if !session.Valid() {
		t.Fatal("unpublished valid session destroyed before upstream Revoke completed")
	}
	assertNoResult(t, resultOut, "Acquire waiter before unpublished cleanup")
	close(revokeRelease)
	got := receiveResult(t, resultOut, "Acquire failure after unpublished cleanup")
	if got.lease != nil || !errors.Is(got.err, ErrUnavailable) {
		t.Fatalf("Acquire(result+error) = %v, %v, want nil, ErrUnavailable", got.lease, got.err)
	}
	assertNoCanary(t, fmt.Sprint(got.err))
	if session.Valid() {
		t.Fatal("unpublished session remains valid after Acquire waiter release")
	}
	if got := issuer.revokeCount(); got != 1 {
		t.Fatalf("Revoke calls = %d, want exactly 1", got)
	}
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
}

func TestTimeRegressionUnpublishedIssueIsRevokedBeforeWaiterRelease(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	issueEntered := make(chan struct{})
	issueRelease := make(chan struct{})
	issuedOut := make(chan *credential.IssuedSession, 1)
	revokeEntered := make(chan struct{})
	revokeRelease := make(chan struct{})
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			session, err := newTestSession(request, testBrokerNow, credential.RequestedSessionTTL)
			if err != nil {
				return nil, err
			}
			issuedOut <- session
			close(issueEntered)
			<-issueRelease
			return session, nil
		},
		revokeFn: func(ctx context.Context, _ credential.Request, _ *credential.IssuedSession) (ports.RevocationResult, error) {
			close(revokeEntered)
			select {
			case <-revokeRelease:
				return ports.RevocationProviderConfirmed, nil
			case <-ctx.Done():
				return ports.RevocationPending, ctx.Err()
			}
		},
	}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
	resultOut := make(chan acquireOutcome, 1)
	go func() {
		lease, err := broker.Acquire(context.Background(), request)
		resultOut <- acquireOutcome{lease: lease, err: err}
	}()
	waitForSignal(t, issueEntered, "Issue before clock regression")
	session := receiveResult(t, issuedOut, "time-regression session")
	clock.Set(testBrokerNow.Add(-1))
	close(issueRelease)
	waitForSignal(t, revokeEntered, "time-regression cleanup Revoke")
	assertNoResult(t, resultOut, "Acquire waiter during time-regression cleanup")
	close(revokeRelease)
	got := receiveResult(t, resultOut, "Acquire time-regression result")
	if got.lease != nil || !errors.Is(got.err, ErrUnavailable) {
		t.Fatalf("Acquire(time regression) = %v, %v, want nil, ErrUnavailable", got.lease, got.err)
	}
	if session.Valid() {
		t.Fatal("time-regression Issue output remains valid after waiter release")
	}
	clock.Set(testBrokerNow)
	_, _ = broker.Close(context.Background())
}

func TestLifecycleInvalidationWaitsForLateIssueCleanup(t *testing.T) {
	tests := []struct {
		name         string
		invalidate   func(*Broker, credential.Request) (ports.RevocationResult, error)
		wantAcquire  error
		closesBroker bool
	}{
		{
			name: "connection revoke",
			invalidate: func(broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.RevokeConnection(context.Background(), request)
			},
			wantAcquire: ErrRevoked,
		},
		{
			name: "operation cancel",
			invalidate: func(broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.CancelOperation(context.Background(), request)
			},
			wantAcquire: ErrOperationTerminated,
		},
		{
			name: "broker close",
			invalidate: func(broker *Broker, _ credential.Request) (ports.RevocationResult, error) {
				return broker.Close(context.Background())
			},
			wantAcquire:  ErrClosed,
			closesBroker: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			request := mustTestRequest(t, defaultTestRequestConfig())
			issueEntered := make(chan struct{})
			issueCanceled := make(chan struct{})
			issueReturn := make(chan struct{})
			issuedOut := make(chan *credential.IssuedSession, 1)
			revokeEntered := make(chan struct{})
			revokeRelease := make(chan struct{})
			issuer := &fakeIssuer{
				clock: clock,
				issueFn: func(ctx context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
					close(issueEntered)
					<-ctx.Done()
					close(issueCanceled)
					<-issueReturn
					session, err := newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
					if err == nil {
						issuedOut <- session
					}
					return session, err
				},
				revokeFn: func(ctx context.Context, _ credential.Request, session *credential.IssuedSession) (ports.RevocationResult, error) {
					if !session.Valid() {
						return ports.RevocationPending, errors.New("late session destroyed before Revoke")
					}
					close(revokeEntered)
					select {
					case <-revokeRelease:
						return ports.RevocationProviderConfirmed, nil
					case <-ctx.Done():
						return ports.RevocationPending, ctx.Err()
					}
				},
			}
			broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
			acquireResult := make(chan acquireOutcome, 1)
			go func() {
				lease, err := broker.Acquire(context.Background(), request)
				acquireResult <- acquireOutcome{lease: lease, err: err}
			}()
			waitForSignal(t, issueEntered, "in-flight Issue")
			lifecycleResult := make(chan lifecycleOutcome, 1)
			go func() {
				result, err := test.invalidate(broker, request)
				lifecycleResult <- lifecycleOutcome{result: result, err: err}
			}()
			waitForSignal(t, issueCanceled, "Issue cancellation from lifecycle")
			close(issueReturn)
			session := receiveResult(t, issuedOut, "late valid Issue output")
			waitForSignal(t, revokeEntered, "late Issue cleanup Revoke")
			assertNoResult(t, acquireResult, "Acquire waiter during late cleanup")
			var earlyLifecycle *lifecycleOutcome
			select {
			case value := <-lifecycleResult:
				earlyLifecycle = &value
				if value.err != nil || value.result != ports.RevocationPending {
					t.Errorf("lifecycle returned terminal/non-pending result before cleanup: %v, %v", value.result, value.err)
				}
			default:
			}
			broker.mu.Lock()
			flightPresent := broker.sessionFlights[request.BindingDigest()] != nil
			reserved := broker.sessionReservations
			broker.mu.Unlock()
			if !flightPresent || reserved == 0 {
				t.Errorf("cleanup capacity released early: flightPresent=%v sessionReservations=%d", flightPresent, reserved)
			}
			close(revokeRelease)
			acquired := receiveResult(t, acquireResult, "Acquire after late cleanup")
			if acquired.lease != nil || !errors.Is(acquired.err, test.wantAcquire) {
				t.Errorf("Acquire(after lifecycle invalidation) = %v, %v, want nil, %v", acquired.lease, acquired.err, test.wantAcquire)
			}
			invalidated := lifecycleOutcome{}
			if earlyLifecycle != nil {
				invalidated = *earlyLifecycle
			} else {
				invalidated = receiveResult(t, lifecycleResult, "lifecycle after late cleanup")
			}
			if invalidated.err != nil ||
				(invalidated.result != ports.RevocationProviderConfirmed && invalidated.result != ports.RevocationPending) {
				t.Errorf("lifecycle result = %v, %v, want honest pending or provider-confirmed", invalidated.result, invalidated.err)
			}
			if session.Valid() {
				t.Error("late Issue output remains valid after lifecycle success")
			}
			broker.mu.Lock()
			flightPresent = broker.sessionFlights[request.BindingDigest()] != nil
			reserved = broker.sessionReservations
			broker.mu.Unlock()
			if flightPresent || reserved != 0 {
				t.Errorf("cleanup capacity leaked: flightPresent=%v sessionReservations=%d", flightPresent, reserved)
			}
			if !test.closesBroker {
				_, _ = broker.Close(context.Background())
			}
		})
	}
}

func TestCloseCallerCancellationDuringLateIssueCleanupReturnsPending(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	issueEntered := make(chan struct{})
	issueReturn := make(chan struct{})
	revokeEntered := make(chan struct{})
	revokeRelease := make(chan struct{})
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(ctx context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			close(issueEntered)
			<-ctx.Done()
			<-issueReturn
			return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
		},
		revokeFn: func(ctx context.Context, _ credential.Request, _ *credential.IssuedSession) (ports.RevocationResult, error) {
			close(revokeEntered)
			select {
			case <-revokeRelease:
				return ports.RevocationProviderConfirmed, nil
			case <-ctx.Done():
				return ports.RevocationPending, ctx.Err()
			}
		},
	}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
	acquireResult := make(chan acquireOutcome, 1)
	go func() {
		lease, err := broker.Acquire(context.Background(), request)
		acquireResult <- acquireOutcome{lease: lease, err: err}
	}()
	waitForSignal(t, issueEntered, "Issue before Close")
	clockEntered := make(chan struct{}, 1)
	clockRelease := make(chan struct{})
	broker.mu.Lock()
	broker.clock = &barrierClock{now: clock.Now(), entered: clockEntered, release: clockRelease}
	broker.mu.Unlock()
	closeCtx, cancelClose := context.WithCancel(context.Background())
	closeResult := make(chan lifecycleOutcome, 1)
	go func() {
		result, err := broker.Close(closeCtx)
		closeResult <- lifecycleOutcome{result: result, err: err}
	}()
	receiveResult(t, clockEntered, "Close clock barrier")
	cancelClose()
	close(clockRelease)
	closed := receiveResult(t, closeResult, "canceled Close result")
	if closed.result != ports.RevocationPending || !errors.Is(closed.err, context.Canceled) {
		t.Fatalf("Close(canceled during cleanup) = %v, %v, want pending, context.Canceled", closed.result, closed.err)
	}
	broker.mu.Lock()
	broker.clock = clock
	broker.mu.Unlock()
	close(issueReturn)
	waitForSignal(t, revokeEntered, "late Issue cleanup Revoke")
	assertNoResult(t, acquireResult, "Acquire before independent cleanup completes")
	close(revokeRelease)
	acquired := receiveResult(t, acquireResult, "Acquire after canceled Close cleanup")
	if acquired.lease != nil || !errors.Is(acquired.err, ErrClosed) {
		t.Fatalf("Acquire(after Close) = %v, %v, want nil, ErrClosed", acquired.lease, acquired.err)
	}
	waitForCondition(t, "late Close cleanup destruction", func() bool {
		sessions := issuer.sessionSnapshot()
		return len(sessions) == 1 && sessions[0] != nil && !sessions[0].Valid()
	})
}

func TestLateBackendSuccessAfterCancellationFailsClosed(t *testing.T) {
	t.Run("Claim", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		request := mustTestRequest(t, defaultTestRequestConfig())
		claimEntered := make(chan struct{})
		settled := make(chan struct{})
		claim := &fakeClaim{settleFn: func(_ context.Context, outcome ports.SecretReadOutcome) error {
			if outcome != ports.SecretReadRetained {
				t.Errorf("late Claim settlement = %v, want retained", outcome)
			}
			close(settled)
			return nil
		}}
		budget := &fakeBudget{claimFn: func(ctx context.Context, _ credential.SourceLookup, _ ports.SecretReadPriority) (ports.SecretReadClaim, error) {
			close(claimEntered)
			<-ctx.Done()
			return claim, nil
		}}
		resolver := &fakeResolver{}
		issuer := &fakeIssuer{clock: clock}
		broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())
		ctx, cancel := context.WithCancel(context.Background())
		resultOut := make(chan acquireOutcome, 1)
		go func() {
			lease, err := broker.Acquire(ctx, request)
			resultOut <- acquireOutcome{lease: lease, err: err}
		}()
		waitForSignal(t, claimEntered, "Claim entry")
		cancel()
		got := receiveResult(t, resultOut, "Acquire canceled during Claim")
		if got.lease != nil || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("Acquire(canceled Claim) = %v, %v", got.lease, got.err)
		}
		waitForSignal(t, settled, "late Claim retained settlement")
		if resolver.callCount() != 0 || issuer.issueCount() != 0 {
			t.Fatalf("late Claim continued to resolver/issuer: resolves=%d issues=%d", resolver.callCount(), issuer.issueCount())
		}
		_, _ = broker.Close(context.Background())
	})

	t.Run("Resolve", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		request := mustTestRequest(t, defaultTestRequestConfig())
		resolveEntered := make(chan struct{})
		materialOut := make(chan *credential.SourceMaterial, 1)
		resolver := &fakeResolver{resolveFn: func(ctx context.Context, _ credential.SourceLookup) (*credential.SourceMaterial, ports.SecretReadOutcome, error) {
			close(resolveEntered)
			<-ctx.Done()
			material, err := credential.NewSourceMaterial([]byte(testSourceCanary))
			materialOut <- material
			return material, ports.SecretReadConsumed, err
		}}
		issuer := &fakeIssuer{clock: clock}
		broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, request.Recipient())
		ctx, cancel := context.WithCancel(context.Background())
		resultOut := make(chan acquireOutcome, 1)
		go func() {
			lease, err := broker.Acquire(ctx, request)
			resultOut <- acquireOutcome{lease: lease, err: err}
		}()
		waitForSignal(t, resolveEntered, "Resolve entry")
		cancel()
		got := receiveResult(t, resultOut, "Acquire canceled during Resolve")
		if got.lease != nil || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("Acquire(canceled Resolve) = %v, %v", got.lease, got.err)
		}
		material := receiveResult(t, materialOut, "late Resolve material")
		waitForCondition(t, "late Resolve material destruction", func() bool { return !material.Valid() })
		if issuer.issueCount() != 0 {
			t.Fatalf("Issue calls after late Resolve = %d, want 0", issuer.issueCount())
		}
		_, _ = broker.Close(context.Background())
	})

	t.Run("Issue", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		request := mustTestRequest(t, defaultTestRequestConfig())
		issueEntered := make(chan struct{})
		issuedOut := make(chan *credential.IssuedSession, 1)
		issuer := &fakeIssuer{
			clock: clock,
			issueFn: func(ctx context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
				close(issueEntered)
				<-ctx.Done()
				session, err := newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
				issuedOut <- session
				return session, err
			},
		}
		broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
		ctx, cancel := context.WithCancel(context.Background())
		resultOut := make(chan acquireOutcome, 1)
		go func() {
			lease, err := broker.Acquire(ctx, request)
			resultOut <- acquireOutcome{lease: lease, err: err}
		}()
		waitForSignal(t, issueEntered, "Issue entry")
		cancel()
		got := receiveResult(t, resultOut, "Acquire canceled during Issue")
		if got.lease != nil || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("Acquire(canceled Issue) = %v, %v", got.lease, got.err)
		}
		session := receiveResult(t, issuedOut, "late Issue session")
		waitForCondition(t, "late Issue revoke and destroy", func() bool { return !session.Valid() })
		if issuer.revokeCount() != 1 {
			t.Fatalf("late Issue Revoke calls = %d, want 1", issuer.revokeCount())
		}
		_, _ = broker.Close(context.Background())
	})

	t.Run("Revoke", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		request := mustTestRequest(t, defaultTestRequestConfig())
		revokeEntered := make(chan struct{})
		revokeRelease := make(chan struct{})
		issuer := &fakeIssuer{
			clock: clock,
			revokeFn: func(_ context.Context, _ credential.Request, _ *credential.IssuedSession) (ports.RevocationResult, error) {
				close(revokeEntered)
				<-revokeRelease
				return ports.RevocationProviderConfirmed, nil
			},
		}
		broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
		lease, err := broker.Acquire(context.Background(), request)
		if err != nil {
			t.Fatalf("Acquire() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		resultOut := make(chan lifecycleOutcome, 1)
		go func() {
			result, err := broker.RevokeConnection(ctx, request)
			resultOut <- lifecycleOutcome{result: result, err: err}
		}()
		waitForSignal(t, revokeEntered, "Revoke entry")
		cancel()
		got := receiveResult(t, resultOut, "late Revoke success classification")
		if got.result != ports.RevocationPending || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("RevokeConnection(late success) = %v, %v, want pending, context.Canceled", got.result, got.err)
		}
		if err := lease.Use(context.Background(), func(context.Context, []byte) error { return nil }); !errors.Is(err, ErrRevoked) {
			t.Fatalf("Lease.Use() during continuing Revoke error = %v, want ErrRevoked", err)
		}
		if got := issuer.revokeCount(); got != 1 {
			t.Fatalf("Revoke calls during canceled waiter = %d, want 1", got)
		}
		follower := make(chan lifecycleOutcome, 1)
		followerWaiting := make(chan struct{}, 1)
		followerCtx := &doneObservedContext{Context: context.Background(), observed: followerWaiting}
		go func() {
			result, err := broker.RevokeConnection(followerCtx, request)
			follower <- lifecycleOutcome{result: result, err: err}
		}()
		receiveResult(t, followerWaiting, "live revocation follower wait")
		assertNoResult(t, follower, "live revocation follower before provider release")
		close(revokeRelease)
		followed := receiveResult(t, follower, "live revocation follower")
		if followed.result != ports.RevocationProviderConfirmed || followed.err != nil {
			t.Fatalf("live RevokeConnection follower = %v, %v, want provider-confirmed, nil", followed.result, followed.err)
		}
		waitForCondition(t, "late Revoke success destruction", func() bool {
			sessions := issuer.sessionSnapshot()
			return len(sessions) == 1 && sessions[0] != nil && !sessions[0].Valid()
		})
		assertSessionsInvalid(t, issuer.sessionSnapshot()...)
		_ = lease.Close()
		_, _ = broker.Close(context.Background())
	})
}

func TestRotationIssueFailureRevokesBeforeReleasingWaiter(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 2
	next := mustTestRequest(t, nextConfig)
	issuedOut := make(chan *credential.IssuedSession, 1)
	revokeEntered := make(chan struct{})
	revokeRelease := make(chan struct{})
	var issueMu sync.Mutex
	issueCalls := 0
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			issueMu.Lock()
			issueCalls++
			call := issueCalls
			issueMu.Unlock()
			session, err := newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
			if call > 1 && err == nil {
				issuedOut <- session
				return session, errors.New(testErrorCanary)
			}
			return session, err
		},
		revokeFn: func(ctx context.Context, request credential.Request, _ *credential.IssuedSession) (ports.RevocationResult, error) {
			if request.BindingDigest().Equal(next.BindingDigest()) {
				close(revokeEntered)
				select {
				case <-revokeRelease:
					return ports.RevocationProviderConfirmed, nil
				case <-ctx.Done():
					return ports.RevocationPending, ctx.Err()
				}
			}
			return ports.RevocationProviderConfirmed, nil
		},
	}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, base.Recipient())
	prior, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	_ = prior.Close()
	type rotateOutcome struct {
		rotation Rotation
		err      error
	}
	resultOut := make(chan rotateOutcome, 1)
	go func() {
		rotation, err := broker.Rotate(context.Background(), next)
		resultOut <- rotateOutcome{rotation: rotation, err: err}
	}()
	session := receiveResult(t, issuedOut, "failed rotation Issue output")
	waitForSignal(t, revokeEntered, "failed rotation cleanup Revoke")
	assertNoResult(t, resultOut, "Rotate waiter before failure cleanup")
	close(revokeRelease)
	got := receiveResult(t, resultOut, "Rotate failure after cleanup")
	if got.rotation.Valid() || !errors.Is(got.err, ErrUnavailable) {
		t.Fatalf("Rotate(Issue result+error) = %v, %v, want invalid, ErrUnavailable", got.rotation, got.err)
	}
	if session.Valid() {
		t.Fatal("failed rotation Issue output remains valid after waiter release")
	}
	broker.mu.Lock()
	lineage := broker.lineages[keyForConnection(base)]
	reservations := broker.sourceReservations + broker.sessionReservations +
		broker.operationReservations + broker.leaseReservations
	broker.mu.Unlock()
	if lineage.generation != base.ConnectionGeneration() || reservations != 0 {
		t.Fatalf("failed rotation mutated generation/reservations = %d/%d", lineage.generation, reservations)
	}
	_, _ = broker.Close(context.Background())
}

func TestUnpublishedIssueCleanupRetainsFinalSessionSlot(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	otherConfig := defaultTestRequestConfig()
	otherConfig.operation = 2
	otherConfig.target = 2
	other := mustTestRequest(t, otherConfig)
	issuedOut := make(chan *credential.IssuedSession, 1)
	revokeEntered := make(chan struct{})
	revokeRelease := make(chan struct{})
	var issueMu sync.Mutex
	issueCalls := 0
	var revokeOnce sync.Once
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			issueMu.Lock()
			issueCalls++
			call := issueCalls
			issueMu.Unlock()
			session, err := newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
			if call == 1 && err == nil {
				issuedOut <- session
				return session, errors.New(testErrorCanary)
			}
			return session, err
		},
		revokeFn: func(ctx context.Context, _ credential.Request, _ *credential.IssuedSession) (ports.RevocationResult, error) {
			revokeOnce.Do(func() { close(revokeEntered) })
			select {
			case <-revokeRelease:
				return ports.RevocationProviderConfirmed, nil
			case <-ctx.Done():
				return ports.RevocationPending, ctx.Err()
			}
		},
	}
	budget := &fakeBudget{}
	broker := mustTestBroker(t, clock, budget, &fakeResolver{}, issuer, request.Recipient())
	dummies := addUnevictableSessionCells(broker, MaxSessionEntries-1)
	resultOut := make(chan acquireOutcome, 1)
	go func() {
		lease, err := broker.Acquire(context.Background(), request)
		resultOut <- acquireOutcome{lease: lease, err: err}
	}()
	session := receiveResult(t, issuedOut, "unpublished Issue output")
	waitForSignal(t, revokeEntered, "unpublished cleanup Revoke")
	broker.mu.Lock()
	charged := uint64(len(broker.cells)) + broker.sessionReservations
	reserved := broker.sessionReservations
	broker.mu.Unlock()
	if charged != MaxSessionEntries || reserved == 0 {
		t.Fatalf("session charge during cleanup = charged:%d reserved:%d, want %d/nonzero", charged, reserved, MaxSessionEntries)
	}
	blocked, err := broker.Acquire(context.Background(), other)
	if blocked != nil || !errors.Is(err, ErrCapacity) {
		t.Fatalf("Acquire(during unpublished cleanup) = %v, %v, want nil, ErrCapacity", blocked, err)
	}
	if issuer.issueCount() != 1 || budget.callCount() != 1 {
		t.Fatalf("capacity rejection called backend: issues=%d claims=%d, want 1/1", issuer.issueCount(), budget.callCount())
	}

	close(revokeRelease)
	failed := receiveResult(t, resultOut, "failed Acquire after cleanup")
	if failed.lease != nil || !errors.Is(failed.err, ErrUnavailable) {
		t.Fatalf("Acquire(result+error) = %v, %v, want nil, ErrUnavailable", failed.lease, failed.err)
	}
	if session.Valid() {
		t.Fatal("unpublished Issue output remains valid after cleanup")
	}
	admitted, err := broker.Acquire(context.Background(), other)
	if err != nil {
		t.Fatalf("Acquire(after cleanup released slot) error = %v", err)
	}
	removeTestSessionCells(broker, dummies)
	_ = admitted.Close()
	_, _ = broker.Close(context.Background())
}

func TestFailedRotationCleanupRetainsFinalSessionSlot(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 2
	next := mustTestRequest(t, nextConfig)
	issuedOut := make(chan *credential.IssuedSession, 1)
	revokeEntered := make(chan struct{})
	revokeRelease := make(chan struct{})
	var issueMu sync.Mutex
	issueCalls := 0
	var revokeOnce sync.Once
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			issueMu.Lock()
			issueCalls++
			call := issueCalls
			issueMu.Unlock()
			session, err := newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
			if call == 1 && err == nil {
				issuedOut <- session
				return session, errors.New(testErrorCanary)
			}
			return session, err
		},
		revokeFn: func(ctx context.Context, _ credential.Request, _ *credential.IssuedSession) (ports.RevocationResult, error) {
			revokeOnce.Do(func() { close(revokeEntered) })
			select {
			case <-revokeRelease:
				return ports.RevocationProviderConfirmed, nil
			case <-ctx.Done():
				return ports.RevocationPending, ctx.Err()
			}
		},
	}
	budget := &fakeBudget{}
	broker := mustTestBroker(t, clock, budget, &fakeResolver{}, issuer, base.Recipient())
	broker.mu.Lock()
	if _, _, _, err := broker.prepareRequestLocked(base); err != nil {
		broker.mu.Unlock()
		t.Fatalf("prepareRequestLocked(base) error = %v", err)
	}
	broker.mu.Unlock()
	dummies := addUnevictableSessionCells(broker, MaxSessionEntries-1)
	type rotateOutcome struct {
		rotation Rotation
		err      error
	}
	resultOut := make(chan rotateOutcome, 1)
	go func() {
		rotation, err := broker.Rotate(context.Background(), next)
		resultOut <- rotateOutcome{rotation: rotation, err: err}
	}()
	session := receiveResult(t, issuedOut, "failed rotation Issue output")
	waitForSignal(t, revokeEntered, "failed rotation cleanup Revoke")
	broker.mu.Lock()
	charged := uint64(len(broker.cells)) + broker.sessionReservations
	reserved := broker.sessionReservations
	broker.mu.Unlock()
	if charged != MaxSessionEntries || reserved == 0 {
		t.Fatalf("session charge during rotation cleanup = charged:%d reserved:%d, want %d/nonzero", charged, reserved, MaxSessionEntries)
	}
	blocked, err := broker.Acquire(context.Background(), base)
	if blocked != nil || !errors.Is(err, ErrCapacity) {
		t.Fatalf("Acquire(during rotation cleanup) = %v, %v, want nil, ErrCapacity", blocked, err)
	}
	if issuer.issueCount() != 1 || budget.callCount() != 1 {
		t.Fatalf("capacity rejection called backend: issues=%d claims=%d, want 1/1", issuer.issueCount(), budget.callCount())
	}

	close(revokeRelease)
	failed := receiveResult(t, resultOut, "failed Rotate after cleanup")
	if failed.rotation.Valid() || !errors.Is(failed.err, ErrUnavailable) {
		t.Fatalf("Rotate(result+error) = %v, %v, want invalid, ErrUnavailable", failed.rotation, failed.err)
	}
	if session.Valid() {
		t.Fatal("failed rotation Issue output remains valid after cleanup")
	}
	admitted, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(after rotation cleanup released slot) error = %v", err)
	}
	removeTestSessionCells(broker, dummies)
	_ = admitted.Close()
	_, _ = broker.Close(context.Background())
}

type testSessionCellSet struct {
	cells   []*sessionCell
	cancels []context.CancelFunc
}

func addUnevictableSessionCells(broker *Broker, count int) testSessionCellSet {
	set := testSessionCellSet{
		cells:   make([]*sessionCell, 0, count),
		cancels: make([]context.CancelFunc, 0, count),
	}
	broker.mu.Lock()
	for range count {
		invalidCtx, invalidCancel := context.WithCancel(context.Background())
		cell := &sessionCell{
			refs:          1,
			invalidCtx:    invalidCtx,
			invalidCancel: invalidCancel,
		}
		broker.cells[cell] = struct{}{}
		set.cells = append(set.cells, cell)
		set.cancels = append(set.cancels, invalidCancel)
	}
	broker.mu.Unlock()
	return set
}

func removeTestSessionCells(broker *Broker, set testSessionCellSet) {
	broker.mu.Lock()
	for _, cell := range set.cells {
		delete(broker.cells, cell)
	}
	broker.mu.Unlock()
	for _, cancel := range set.cancels {
		cancel()
	}
}

func assertNoResult[T any](t testing.TB, results chan T, label string) {
	t.Helper()
	select {
	case value := <-results:
		t.Errorf("%s completed prematurely", label)
		results <- value
	default:
	}
}
