package credentialbroker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

func TestAcquireCachesExactSourceAndSession(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	budget := &fakeBudget{}
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())

	first, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire(first) error = %v", err)
	}
	second, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire(second) error = %v", err)
	}
	if first == second || first.state == second.state {
		t.Fatal("Acquire() reused a caller-owned Lease handle")
	}
	if first.state.cell != second.state.cell {
		t.Fatal("Acquire() did not reuse the exact cached session cell")
	}
	if got := budget.callCount(); got != 1 {
		t.Fatalf("budget Claim calls = %d, want 1", got)
	}
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("resolver Resolve calls = %d, want 1", got)
	}
	if got := issuer.issueCount(); got != 1 {
		t.Fatalf("issuer Issue calls = %d, want 1", got)
	}
	if err := first.Use(context.Background(), func(_ context.Context, value []byte) error {
		if string(value) != testSessionCanary {
			t.Errorf("Lease.Use() value did not match session canary")
		}
		return nil
	}); err != nil {
		t.Fatalf("Lease.Use() error = %v", err)
	}
	stats := broker.Stats()
	if stats.SourceResolves != 1 || stats.SessionIssues != 1 || stats.SessionHits != 1 ||
		stats.ActiveLeases != 2 || stats.ActiveSessions != 1 {
		t.Fatalf("Stats() = %+v, want one resolve/issue/hit, two leases, one session", stats)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("first Lease.Close() error = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Lease.Close() error = %v", err)
	}
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
	assertSourcesInvalid(t, resolver.materialSnapshot()...)
	assertSessionsInvalid(t, issuer.sessionSnapshot()...)
}

func TestAcquireSingleflightGivesEachWaiterAnIndependentLease(t *testing.T) {
	const callers = 24
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	budget := &fakeBudget{}
	resolver := &fakeResolver{}
	issueEntered := make(chan struct{})
	issueRelease := make(chan struct{})
	var enteredOnce sync.Once
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(
			_ context.Context,
			request credential.Request,
			_ *credential.SourceMaterial,
		) (*credential.IssuedSession, error) {
			enteredOnce.Do(func() { close(issueEntered) })
			<-issueRelease
			return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
		},
	}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())

	type result struct {
		lease *Lease
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, callers)
	for range callers {
		go func() {
			<-start
			lease, err := broker.Acquire(context.Background(), request)
			results <- result{lease: lease, err: err}
		}()
	}
	close(start)
	waitForSignal(t, issueEntered, "issuer Issue entry")
	waitForCondition(t, "all Acquire waiters to join", func() bool {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		flight := broker.sessionFlights[request.BindingDigest()]
		return flight != nil && flight.waiters == callers
	})
	close(issueRelease)

	seen := make(map[*leaseState]struct{}, callers)
	for range callers {
		got := receiveResult(t, results, "Acquire result")
		if got.err != nil {
			t.Fatalf("Acquire() error = %v", got.err)
		}
		if got.lease == nil || got.lease.state == nil {
			t.Fatal("Acquire() returned nil/invalid Lease")
		}
		if _, duplicate := seen[got.lease.state]; duplicate {
			t.Fatal("singleflight shared a caller-owned leaseState")
		}
		seen[got.lease.state] = struct{}{}
		if err := got.lease.Close(); err != nil {
			t.Fatalf("Lease.Close() error = %v", err)
		}
	}
	if got := budget.callCount(); got != 1 {
		t.Fatalf("budget Claim calls = %d, want 1", got)
	}
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("resolver Resolve calls = %d, want 1", got)
	}
	if got := issuer.issueCount(); got != 1 {
		t.Fatalf("issuer Issue calls = %d, want 1", got)
	}
	stats := broker.Stats()
	if stats.SourceWaits != 0 || stats.SessionWaits != callers-1 || stats.ActiveLeases != 0 {
		t.Fatalf("Stats() = %+v, want %d session waits and no active leases", stats, callers-1)
	}
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
}

func TestAcquireIsolatesDifferentBindingsWhileSharingExactSource(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	firstRequest := mustTestRequest(t, defaultTestRequestConfig())
	secondConfig := defaultTestRequestConfig()
	secondConfig.operation = 2
	secondRequest := mustTestRequest(t, secondConfig)
	if !firstRequest.SourceLookup().Digest().Equal(secondRequest.SourceLookup().Digest()) {
		t.Fatal("fixture requests do not share the exact source digest")
	}
	if firstRequest.BindingDigest().Equal(secondRequest.BindingDigest()) {
		t.Fatal("fixture requests unexpectedly share a binding digest")
	}
	budget := &fakeBudget{}
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, firstRequest.Recipient())

	first, err := broker.Acquire(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("Acquire(first binding) error = %v", err)
	}
	second, err := broker.Acquire(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("Acquire(second binding) error = %v", err)
	}
	if first.state.cell == second.state.cell {
		t.Fatal("different bindings shared a session cell")
	}
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("Resolve calls = %d, want exact-source cache reuse", got)
	}
	if got := issuer.issueCount(); got != 2 {
		t.Fatalf("Issue calls = %d, want one per exact binding", got)
	}
	if got := broker.Stats().ActiveSessions; got != 2 {
		t.Fatalf("ActiveSessions = %d, want 2", got)
	}

	_ = first.Close()
	_ = second.Close()
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
}

func TestAcquireRefreshBoundaryAndUnavailableFallback(t *testing.T) {
	t.Run("before exact refresh boundary reuses", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		request := mustTestRequest(t, defaultTestRequestConfig())
		issuer := &fakeIssuer{clock: clock}
		broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
		first, err := broker.Acquire(context.Background(), request)
		if err != nil {
			t.Fatalf("Acquire(first) error = %v", err)
		}
		clock.Set(first.ExpiresAt().Add(-credential.SessionRefreshAhead).Add(-time.Nanosecond))
		second, err := broker.Acquire(context.Background(), request)
		if err != nil {
			t.Fatalf("Acquire(before refresh boundary) error = %v", err)
		}
		if got := issuer.issueCount(); got != 1 {
			t.Fatalf("Issue calls = %d, want 1 before exact refresh boundary", got)
		}
		_ = first.Close()
		_ = second.Close()
		_, _ = broker.Close(context.Background())
	})

	t.Run("at exact refresh boundary renews", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		request := mustTestRequest(t, defaultTestRequestConfig())
		issuer := &fakeIssuer{clock: clock}
		broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
		first, err := broker.Acquire(context.Background(), request)
		if err != nil {
			t.Fatalf("Acquire(first) error = %v", err)
		}
		clock.Set(first.ExpiresAt().Add(-credential.SessionRefreshAhead))
		second, err := broker.Acquire(context.Background(), request)
		if err != nil {
			t.Fatalf("Acquire(at refresh boundary) error = %v", err)
		}
		if got := issuer.issueCount(); got != 2 {
			t.Fatalf("Issue calls = %d, want 2 at exact refresh boundary", got)
		}
		if first.state.cell == second.state.cell {
			t.Fatal("refresh boundary reused old session cell")
		}
		_ = first.Close()
		_ = second.Close()
		_, _ = broker.Close(context.Background())
	})

	t.Run("unavailable refresh falls back through exact new-use cutoff", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		request := mustTestRequest(t, defaultTestRequestConfig())
		var issueMu sync.Mutex
		issueCall := 0
		issuer := &fakeIssuer{
			clock: clock,
			issueFn: func(
				_ context.Context,
				request credential.Request,
				_ *credential.SourceMaterial,
			) (*credential.IssuedSession, error) {
				issueMu.Lock()
				defer issueMu.Unlock()
				issueCall++
				if issueCall > 1 {
					return nil, errors.New(testErrorCanary)
				}
				return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
			},
		}
		broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
		first, err := broker.Acquire(context.Background(), request)
		if err != nil {
			t.Fatalf("Acquire(first) error = %v", err)
		}
		newUseCutoff := first.ExpiresAt().Add(-credential.SessionExpirySkew - credential.MinNewUseLifetime)
		clock.Set(newUseCutoff)
		fallback, err := broker.Acquire(context.Background(), request)
		if err != nil {
			t.Fatalf("Acquire(exact new-use cutoff) error = %v, want fallback", err)
		}
		if fallback.state.cell != first.state.cell {
			t.Fatal("Acquire() did not return still-admissible fallback cell")
		}
		if got := broker.Stats().Fallbacks; got != 1 {
			t.Fatalf("Fallbacks = %d, want 1", got)
		}
		clock.Set(newUseCutoff.Add(time.Nanosecond))
		if lease, err := broker.Acquire(context.Background(), request); lease != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Acquire(after new-use cutoff) = %v, %v, want nil, ErrUnavailable", lease, err)
		}
		_ = first.Close()
		_ = fallback.Close()
		_, _ = broker.Close(context.Background())
	})
}

func TestRefreshReplacesCacheWithoutRevokingBorrowedPriorLease(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
	prior, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	replacement, err := broker.Refresh(context.Background(), request)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if prior.state.cell == replacement.state.cell {
		t.Fatal("Refresh() reused prior cell")
	}
	if err := prior.Use(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatalf("prior borrowed Lease.Use() error = %v", err)
	}
	if got := issuer.issueCount(); got != 2 {
		t.Fatalf("Issue calls = %d, want 2", got)
	}
	if got := broker.Stats().Refreshes; got != 1 {
		t.Fatalf("Refreshes = %d, want 1", got)
	}
	_ = prior.Close()
	_ = replacement.Close()
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
}

func TestAcquireDoesNotCollapseDifferentConnectionBindings(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	first := mustTestRequest(t, defaultTestRequestConfig())
	secondConfig := defaultTestRequestConfig()
	secondConfig.connection = 2
	secondConfig.operation = 2
	second := mustTestRequest(t, secondConfig)
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, first.Recipient())

	firstLease, firstErr := broker.Acquire(context.Background(), first)
	secondLease, secondErr := broker.Acquire(context.Background(), second)
	if firstErr != nil || secondErr != nil {
		t.Fatalf("Acquire(different connections) errors = %v, %v", firstErr, secondErr)
	}
	if got := resolver.callCount(); got != 2 {
		t.Fatalf("Resolve calls = %d, want distinct connection/source isolation", got)
	}
	if firstLease.state.cell == secondLease.state.cell {
		t.Fatal("different connection bindings shared a session cell")
	}
	_ = firstLease.Close()
	_ = secondLease.Close()
	if result, err := broker.Close(context.Background()); err != nil || result != ports.RevocationProviderConfirmed {
		t.Fatalf("Broker.Close() = %v, %v, want provider-confirmed, nil", result, err)
	}
}
