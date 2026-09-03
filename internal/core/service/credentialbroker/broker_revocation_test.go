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

type blockingRevocations struct {
	mu      sync.Mutex
	active  int
	maximum int
	calls   int
	release <-chan struct{}
}

func (tracker *blockingRevocations) call(ctx context.Context) (ports.RevocationResult, error) {
	tracker.mu.Lock()
	tracker.calls++
	tracker.active++
	if tracker.active > tracker.maximum {
		tracker.maximum = tracker.active
	}
	tracker.mu.Unlock()
	select {
	case <-tracker.release:
	case <-ctx.Done():
		tracker.mu.Lock()
		tracker.active--
		tracker.mu.Unlock()
		return ports.RevocationPending, ctx.Err()
	}
	tracker.mu.Lock()
	tracker.active--
	tracker.mu.Unlock()
	return ports.RevocationProviderConfirmed, nil
}

func (tracker *blockingRevocations) snapshot() (active, maximum, calls int) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.active, tracker.maximum, tracker.calls
}

func TestConnectionRevocationReplayPreservesLineageFences(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	currentConfig := defaultTestRequestConfig()
	currentConfig.generation = 2
	currentConfig.version = "opaque_B"
	current := mustTestRequest(t, currentConfig)
	budget := &fakeBudget{}
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, current.Recipient())
	lease, err := broker.Acquire(context.Background(), current)
	if err != nil {
		t.Fatalf("Acquire(current) error = %v", err)
	}
	if result, revokeErr := broker.RevokeConnection(context.Background(), current); revokeErr != nil || result != ports.RevocationProviderConfirmed {
		t.Fatalf(
			"RevokeConnection(current) = %v, %v, want provider-confirmed, nil",
			result,
			revokeErr,
		)
	}

	staleConfig := defaultTestRequestConfig()
	stale := mustTestRequest(t, staleConfig)
	conflictConfig := currentConfig
	conflictConfig.version = "opaque_conflict"
	conflict := mustTestRequest(t, conflictConfig)

	broker.mu.Lock()
	lineage := broker.lineages[keyForConnection(current)]
	if lineage == nil {
		broker.mu.Unlock()
		t.Fatal("current lineage is absent after revocation")
	}
	lineageBefore := *lineage
	nextEpochBefore := broker.nextEpoch
	broker.mu.Unlock()
	claimsBefore, resolvesBefore := budget.callCount(), resolver.callCount()
	issuesBefore, revokesBefore := issuer.issueCount(), issuer.revokeCount()

	if result, staleErr := broker.RevokeConnection(context.Background(), stale); result != ports.RevocationNotRequired || !errors.Is(staleErr, ErrStale) {
		t.Fatalf(
			"RevokeConnection(stale) = %v, %v, want not-required, ErrStale",
			result,
			staleErr,
		)
	}
	if result, conflictErr := broker.RevokeConnection(context.Background(), conflict); result != ports.RevocationNotRequired || !errors.Is(conflictErr, ErrConflict) {
		t.Fatalf(
			"RevokeConnection(conflicting current generation) = %v, %v, want not-required, ErrConflict",
			result,
			conflictErr,
		)
	}
	if result, replayErr := broker.RevokeConnection(context.Background(), current); replayErr != nil || result != ports.RevocationNotRequired {
		t.Fatalf(
			"RevokeConnection(exact replay) = %v, %v, want not-required, nil",
			result,
			replayErr,
		)
	}

	if budget.callCount() != claimsBefore || resolver.callCount() != resolvesBefore ||
		issuer.issueCount() != issuesBefore || issuer.revokeCount() != revokesBefore {
		t.Fatal("revocation classification or replay called a backend")
	}
	broker.mu.Lock()
	lineageAfter := broker.lineages[keyForConnection(current)]
	nextEpochAfter := broker.nextEpoch
	broker.mu.Unlock()
	if lineageAfter == nil || *lineageAfter != lineageBefore || nextEpochAfter != nextEpochBefore {
		t.Fatalf(
			"revocation classification mutated lineage: before=%+v/%d after=%+v/%d",
			lineageBefore,
			nextEpochBefore,
			lineageAfter,
			nextEpochAfter,
		)
	}

	if closeErr := lease.Close(); closeErr != nil {
		t.Fatalf("Lease.Close() error = %v", closeErr)
	}
	if _, closeErr := broker.Close(context.Background()); closeErr != nil {
		t.Fatalf("Broker.Close() error = %v", closeErr)
	}
}

type barrierClock struct {
	now     time.Time
	entered chan<- struct{}
	release <-chan struct{}
}

func (clock *barrierClock) Now() time.Time {
	clock.entered <- struct{}{}
	<-clock.release
	return clock.now
}

func TestGlobalRevocationConcurrencyBoundAcrossOverlappingBatches(t *testing.T) {
	const sessionsPerConnection = 20
	clock := newManualClock(testBrokerNow)
	release := make(chan struct{})
	tracker := &blockingRevocations{release: release}
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{
		clock: clock,
		revokeFn: func(
			ctx context.Context,
			_ credential.Request,
			_ *credential.IssuedSession,
		) (ports.RevocationResult, error) {
			return tracker.call(ctx)
		},
	}
	firstRequest := mustTestRequest(t, defaultTestRequestConfig())
	broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, firstRequest.Recipient())

	requests := make([][]credential.Request, 2)
	for connectionIndex := range 2 {
		requests[connectionIndex] = make([]credential.Request, 0, sessionsPerConnection)
		for sessionIndex := range sessionsPerConnection {
			config := defaultTestRequestConfig()
			config.connection = connectionIndex + 1
			config.operation = 100*connectionIndex + sessionIndex + 1
			request := mustTestRequest(t, config)
			lease, err := broker.Acquire(context.Background(), request)
			if err != nil {
				t.Fatalf("Acquire(connection %d, session %d) error = %v", connectionIndex, sessionIndex, err)
			}
			if err := lease.Close(); err != nil {
				t.Fatalf("Lease.Close(connection %d, session %d) error = %v", connectionIndex, sessionIndex, err)
			}
			requests[connectionIndex] = append(requests[connectionIndex], request)
		}
	}

	type lifecycleResult struct {
		result ports.RevocationResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan lifecycleResult, 2)
	for connectionIndex := range 2 {
		request := requests[connectionIndex][0]
		go func() {
			<-start
			result, err := broker.RevokeConnection(context.Background(), request)
			results <- lifecycleResult{result: result, err: err}
		}()
	}
	close(start)
	waitForCondition(t, "global revocation slots to fill", func() bool {
		active, _, _ := tracker.snapshot()
		return active == MaxConcurrentRevocations
	})
	active, maximum, calls := tracker.snapshot()
	if active != MaxConcurrentRevocations || maximum != MaxConcurrentRevocations || calls != MaxConcurrentRevocations {
		t.Fatalf(
			"blocked revocations = active:%d maximum:%d calls:%d, want exactly %d dispatched",
			active,
			maximum,
			calls,
			MaxConcurrentRevocations,
		)
	}
	close(release)
	for range 2 {
		got := receiveResult(t, results, "RevokeConnection batch")
		if got.err != nil || got.result != ports.RevocationProviderConfirmed {
			t.Errorf("RevokeConnection() = %v, %v, want provider-confirmed, nil", got.result, got.err)
		}
	}
	active, maximum, calls = tracker.snapshot()
	if active != 0 || maximum > MaxConcurrentRevocations || calls != 2*sessionsPerConnection {
		t.Fatalf(
			"final revocations = active:%d maximum:%d calls:%d, want 0, <=%d, %d",
			active,
			maximum,
			calls,
			MaxConcurrentRevocations,
			2*sessionsPerConnection,
		)
	}
	if got := issuer.revokeCount(); got != 2*sessionsPerConnection {
		t.Fatalf("issuer Revoke calls = %d, want %d", got, 2*sessionsPerConnection)
	}
	assertSourcesInvalid(t, resolver.materialSnapshot()...)
	assertSessionsInvalid(t, issuer.sessionSnapshot()...)
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
}

func TestFailedUpstreamRevokePersistsScopedExpiryEvidence(t *testing.T) {
	lifecycles := []struct {
		name string
		call func(*Broker, credential.Request) (ports.RevocationResult, error)
	}{
		{
			name: "connection",
			call: func(broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.RevokeConnection(context.Background(), request)
			},
		},
		{
			name: "operation",
			call: func(broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.CancelOperation(context.Background(), request)
			},
		},
	}
	for _, lifecycle := range lifecycles {
		t.Run(lifecycle.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			request := mustTestRequest(t, defaultTestRequestConfig())
			issuer := &fakeIssuer{
				clock: clock,
				revokeFn: func(context.Context, credential.Request, *credential.IssuedSession) (ports.RevocationResult, error) {
					return ports.RevocationProviderConfirmed, errors.New(testErrorCanary)
				},
			}
			broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
			lease, err := broker.Acquire(context.Background(), request)
			if err != nil {
				t.Fatalf("Acquire() error = %v", err)
			}
			expiresAt := lease.ExpiresAt()

			result, err := lifecycle.call(broker, request)
			if result != ports.RevocationPending || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("first lifecycle = %v, %v, want pending, ErrUnavailable", result, err)
			}
			assertNoCanary(t, fmt.Sprint(err))
			assertSessionsInvalid(t, issuer.sessionSnapshot()...)
			if got := issuer.revokeCount(); got != 1 {
				t.Fatalf("upstream Revoke calls = %d, want 1", got)
			}

			clock.Set(expiresAt.Add(-time.Nanosecond))
			result, err = lifecycle.call(broker, request)
			if err != nil || result != ports.RevocationExpiryBound {
				t.Fatalf("repeated lifecycle before expiry = %v, %v, want expiry-bound, nil", result, err)
			}
			if got := issuer.revokeCount(); got != 1 {
				t.Fatalf("repeated lifecycle made %d Revoke calls, want 1 total", got)
			}

			clock.Set(expiresAt)
			result, err = lifecycle.call(broker, request)
			if err != nil || result != ports.RevocationNotRequired {
				t.Fatalf("repeated lifecycle at expiry = %v, %v, want not-required, nil", result, err)
			}
			if got := issuer.revokeCount(); got != 1 {
				t.Fatalf("lifecycle at expiry made %d Revoke calls, want 1 total", got)
			}
			_ = lease.Close()
			_, _ = broker.Close(context.Background())
		})
	}
}

func TestUnconfirmedRevocationResultsFailClosedAndPersistExpiryEvidence(t *testing.T) {
	tests := []struct {
		name   string
		result ports.RevocationResult
	}{
		{name: "invalid", result: ports.RevocationResult(0)},
		{name: "not required", result: ports.RevocationNotRequired},
		{name: "pending", result: ports.RevocationPending},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			request := mustTestRequest(t, defaultTestRequestConfig())
			issuer := &fakeIssuer{
				clock: clock,
				revokeFn: func(context.Context, credential.Request, *credential.IssuedSession) (ports.RevocationResult, error) {
					return test.result, nil
				},
			}
			broker := mustTestBroker(
				t,
				clock,
				&fakeBudget{},
				&fakeResolver{},
				issuer,
				request.Recipient(),
			)
			lease, err := broker.Acquire(context.Background(), request)
			if err != nil {
				t.Fatalf("Acquire() error = %v", err)
			}
			expiresAt := lease.ExpiresAt()

			result, err := broker.RevokeConnection(context.Background(), request)
			if result != ports.RevocationPending || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("first RevokeConnection = %v, %v, want pending, ErrUnavailable", result, err)
			}
			assertSessionsInvalid(t, issuer.sessionSnapshot()...)
			if got := issuer.revokeCount(); got != 1 {
				t.Fatalf("upstream Revoke calls = %d, want 1", got)
			}

			clock.Set(expiresAt.Add(-time.Nanosecond))
			result, err = broker.RevokeConnection(context.Background(), request)
			if err != nil || result != ports.RevocationExpiryBound {
				t.Fatalf("repeat before expiry = %v, %v, want expiry-bound, nil", result, err)
			}
			clock.Set(expiresAt)
			result, err = broker.RevokeConnection(context.Background(), request)
			if err != nil || result != ports.RevocationNotRequired {
				t.Fatalf("repeat at expiry = %v, %v, want not-required, nil", result, err)
			}
			if got := issuer.revokeCount(); got != 1 {
				t.Fatalf("idempotent repeats made %d Revoke calls, want 1 total", got)
			}
			_ = lease.Close()
			_, _ = broker.Close(context.Background())
		})
	}
}

func TestConcurrentLifecycleCallersJoinRevocationOrReturnPending(t *testing.T) {
	const joiners = 12
	tests := []struct {
		name    string
		first   func(*Broker, context.Context, credential.Request) (ports.RevocationResult, error)
		joining func(*Broker, context.Context, credential.Request, int) (ports.RevocationResult, error)
	}{
		{
			name: "connection revoke",
			first: func(broker *Broker, ctx context.Context, request credential.Request) (ports.RevocationResult, error) {
				return broker.RevokeConnection(ctx, request)
			},
			joining: func(broker *Broker, ctx context.Context, request credential.Request, _ int) (ports.RevocationResult, error) {
				return broker.RevokeConnection(ctx, request)
			},
		},
		{
			name: "operation cancel and close",
			first: func(broker *Broker, ctx context.Context, request credential.Request) (ports.RevocationResult, error) {
				return broker.CancelOperation(ctx, request)
			},
			joining: func(broker *Broker, ctx context.Context, request credential.Request, index int) (ports.RevocationResult, error) {
				if index%2 == 0 {
					return broker.CancelOperation(ctx, request)
				}
				return broker.CloseOperation(ctx, request)
			},
		},
		{
			name: "broker close",
			first: func(broker *Broker, ctx context.Context, _ credential.Request) (ports.RevocationResult, error) {
				return broker.Close(ctx)
			},
			joining: func(broker *Broker, ctx context.Context, _ credential.Request, _ int) (ports.RevocationResult, error) {
				return broker.Close(ctx)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseClock := newManualClock(testBrokerNow)
			request := mustTestRequest(t, defaultTestRequestConfig())
			revokeRelease := make(chan struct{})
			revokeEntered := make(chan struct{})
			var revokeOnce sync.Once
			issuer := &fakeIssuer{
				clock: baseClock,
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
			broker := mustTestBroker(t, baseClock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
			lease, err := broker.Acquire(context.Background(), request)
			if err != nil {
				t.Fatalf("Acquire() error = %v", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatalf("Lease.Close() error = %v", err)
			}

			type result struct {
				value ports.RevocationResult
				err   error
			}
			firstResult := make(chan result, 1)
			go func() {
				value, err := test.first(broker, context.Background(), request)
				firstResult <- result{value: value, err: err}
			}()
			waitForSignal(t, revokeEntered, "first upstream Revoke")

			clockEntered := make(chan struct{}, joiners)
			clockRelease := make(chan struct{})
			broker.mu.Lock()
			broker.clock = &barrierClock{now: baseClock.Now(), entered: clockEntered, release: clockRelease}
			broker.mu.Unlock()
			joinResults := make(chan result, joiners)
			cancels := make([]context.CancelFunc, 0, joiners)
			for index := range joiners {
				ctx, cancel := context.WithCancel(context.Background())
				cancels = append(cancels, cancel)
				go func() {
					value, err := test.joining(broker, ctx, request, index)
					joinResults <- result{value: value, err: err}
				}()
			}
			for range joiners {
				receiveResult(t, clockEntered, "lifecycle caller clock barrier")
			}
			for _, cancel := range cancels {
				cancel()
			}
			close(clockRelease)
			for range joiners {
				got := receiveResult(t, joinResults, "concurrent lifecycle result")
				if got.value != ports.RevocationPending || !errors.Is(got.err, context.Canceled) {
					t.Errorf("concurrent lifecycle result = %v, %v, want pending, context.Canceled", got.value, got.err)
				}
			}
			if got := issuer.revokeCount(); got != 1 {
				t.Fatalf("upstream Revoke calls before completion = %d, want coalesced 1", got)
			}
			close(revokeRelease)
			completed := receiveResult(t, firstResult, "first lifecycle completion")
			if completed.err != nil || completed.value != ports.RevocationProviderConfirmed {
				t.Fatalf("first lifecycle result = %v, %v, want provider-confirmed, nil", completed.value, completed.err)
			}
			if got := issuer.revokeCount(); got != 1 {
				t.Fatalf("upstream Revoke calls = %d, want exactly 1", got)
			}
		})
	}
}
