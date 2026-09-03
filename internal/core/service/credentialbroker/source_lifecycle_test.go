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

func TestSourceCacheTTLStartsAtResolveReturnBeforeSettlement(t *testing.T) {
	tests := []struct {
		name        string
		advance     time.Duration
		wantSuccess bool
	}{
		{name: "publish before expiry", advance: MaxSourceCacheTTL - time.Minute, wantSuccess: true},
		{name: "reject at exact expiry", advance: MaxSourceCacheTTL},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			request := mustTestRequest(t, defaultTestRequestConfig())
			settleEntered := make(chan struct{})
			settleRelease := make(chan struct{})
			claim := &fakeClaim{
				settleFn: func(context.Context, ports.SecretReadOutcome) error {
					close(settleEntered)
					<-settleRelease
					return nil
				},
			}
			budget := &fakeBudget{
				claimFn: func(context.Context, credential.SourceLookup, ports.SecretReadPriority) (ports.SecretReadClaim, error) {
					return claim, nil
				},
			}
			resolver := &fakeResolver{}
			issuer := &fakeIssuer{clock: clock}
			broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())
			resultOut := make(chan acquireOutcome, 1)
			go func() {
				lease, err := broker.Acquire(context.Background(), request)
				resultOut <- acquireOutcome{lease: lease, err: err}
			}()
			waitForSignal(t, settleEntered, "post-Resolve settlement")
			clock.Add(test.advance)
			close(settleRelease)
			got := receiveResult(t, resultOut, "Acquire after delayed settlement")
			materials := resolver.materialSnapshot()
			if len(materials) != 1 || materials[0] == nil {
				t.Fatalf("resolved materials = %v, want one owned material", materials)
			}
			wantExpiresAt := testBrokerNow.Add(MaxSourceCacheTTL)
			broker.mu.Lock()
			entry := broker.sources[request.SourceLookup().Digest()]
			broker.mu.Unlock()
			if test.wantSuccess {
				if got.err != nil || got.lease == nil {
					t.Fatalf("Acquire(before source expiry) = %v, %v, want lease, nil", got.lease, got.err)
				}
				if entry == nil || !entry.expiresAt.Equal(wantExpiresAt) {
					t.Fatalf("source expiry present/equal = %v/%v, want true/true", entry != nil, entry != nil && entry.expiresAt.Equal(wantExpiresAt))
				}
				_ = got.lease.Close()
			} else {
				if got.lease != nil || !errors.Is(got.err, ErrUnavailable) {
					t.Fatalf("Acquire(at source expiry) = %v, %v, want nil, ErrUnavailable", got.lease, got.err)
				}
				if entry != nil || materials[0].Valid() {
					t.Fatalf("expired source published or retained: entry=%v valid=%v", entry, materials[0].Valid())
				}
				if got := issuer.issueCount(); got != 0 {
					t.Fatalf("Issue calls at source expiry = %d, want 0", got)
				}
			}
			if outcomes := claim.outcomes(); len(outcomes) != 1 || outcomes[0] != ports.SecretReadConsumed {
				t.Fatalf("claim settlements = %v, want [consumed]", outcomes)
			}
			_, _ = broker.Close(context.Background())
		})
	}
}

func TestOverlappingResolveClockSamplePreservesRawTTLAndPublishes(t *testing.T) {
	baseClock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	resolveEntered := make(chan struct{})
	resolveRelease := make(chan struct{})
	resolver := &fakeResolver{
		resolveFn: func(_ context.Context, _ credential.SourceLookup) (*credential.SourceMaterial, ports.SecretReadOutcome, error) {
			close(resolveEntered)
			<-resolveRelease
			material, err := credential.NewSourceMaterial([]byte(testSourceCanary))
			return material, ports.SecretReadConsumed, err
		},
	}
	issuer := &fakeIssuer{clock: baseClock}
	broker := mustTestBroker(t, baseClock, &fakeBudget{}, resolver, issuer, request.Recipient())
	acquired := make(chan acquireOutcome, 1)
	go func() {
		lease, err := broker.Acquire(context.Background(), request)
		acquired <- acquireOutcome{lease: lease, err: err}
	}()
	waitForSignal(t, resolveEntered, "blocked Resolve")
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
	close(resolveRelease)
	waitForSignal(t, firstEntered, "Resolve-return clock sample")
	swept := make(chan error, 1)
	go func() { swept <- broker.SweepExpired() }()
	waitForSignal(t, secondEntered, "overlapping newer clock sample")
	close(secondRelease)
	if err := receiveResult(t, swept, "overlapping SweepExpired"); err != nil {
		t.Fatalf("SweepExpired() error = %v", err)
	}
	close(firstRelease)
	got := receiveResult(t, acquired, "Acquire after reverse Resolve clock completion")
	if got.err != nil || got.lease == nil {
		t.Fatalf("Acquire(after reverse Resolve clock completion) = %v, %v, want lease, nil", got.lease, got.err)
	}
	broker.mu.Lock()
	entry := broker.sources[request.SourceLookup().Digest()]
	broker.mu.Unlock()
	wantExpiresAt := testBrokerNow.Add(MaxSourceCacheTTL)
	if entry == nil || !entry.expiresAt.Equal(wantExpiresAt) {
		t.Fatalf("source expiry present/equal = %v/%v, want true/true (%v)",
			entry != nil,
			entry != nil && entry.expiresAt.Equal(wantExpiresAt),
			wantExpiresAt,
		)
	}
	if materials := resolver.materialSnapshot(); len(materials) != 1 ||
		materials[0] == nil || !materials[0].Valid() {
		t.Fatalf("resolved source publication = %v, want one valid material", materials)
	}
	if got := issuer.revokeCount(); got != 0 {
		t.Fatalf("unpublished cleanup Revoke calls = %d, want 0", got)
	}
	_ = got.lease.Close()
	_, _ = broker.Close(context.Background())
}

func TestExpiredBorrowedSourceRetainsCapacityUntilRelease(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	firstRequest := mustTestRequest(t, defaultTestRequestConfig())
	secondConfig := defaultTestRequestConfig()
	secondConfig.connection = 2
	secondConfig.operation = 2
	secondRequest := mustTestRequest(t, secondConfig)
	budget := &fakeBudget{}
	resolver := &fakeResolver{}
	issueEntered := make(chan struct{})
	issueRelease := make(chan struct{})
	var issueOnce sync.Once
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(
			_ context.Context,
			request credential.Request,
			_ *credential.SourceMaterial,
		) (*credential.IssuedSession, error) {
			blocked := false
			issueOnce.Do(func() {
				blocked = true
				close(issueEntered)
			})
			if blocked {
				<-issueRelease
			}
			return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
		},
	}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, firstRequest.Recipient())
	broker.mu.Lock()
	broker.sourceReservations = MaxSourceEntries - 1
	broker.mu.Unlock()

	type acquireResult struct {
		lease *Lease
		err   error
	}
	firstResult := make(chan acquireResult, 1)
	go func() {
		lease, err := broker.Acquire(context.Background(), firstRequest)
		firstResult <- acquireResult{lease: lease, err: err}
	}()
	waitForSignal(t, issueEntered, "first Issue with borrowed source")
	materials := resolver.materialSnapshot()
	if len(materials) != 1 || materials[0] == nil || !materials[0].Valid() {
		t.Fatalf("resolved source snapshot = %v, want one live material", materials)
	}

	clock.Add(MaxSourceCacheTTL)
	if err := broker.SweepExpired(); err != nil {
		t.Fatalf("SweepExpired() error = %v", err)
	}
	broker.mu.Lock()
	retired := len(broker.retiredSources)
	broker.mu.Unlock()
	if retired != 1 {
		t.Fatalf("retired borrowed source count = %d, want 1", retired)
	}
	if !materials[0].Valid() {
		t.Fatal("expired borrowed source was destroyed before release")
	}
	secondLease, err := broker.Acquire(context.Background(), secondRequest)
	if secondLease != nil || !errors.Is(err, ErrCapacity) {
		t.Fatalf("Acquire(while retired source owns final slot) = %v, %v, want nil, ErrCapacity", secondLease, err)
	}
	if got := budget.callCount(); got != 1 {
		t.Fatalf("budget Claim calls = %d, want no backend call for capacity rejection", got)
	}

	close(issueRelease)
	first := receiveResult(t, firstResult, "first Acquire completion")
	if first.err != nil {
		t.Fatalf("first Acquire() error = %v", first.err)
	}
	if materials[0].Valid() {
		t.Fatal("retired source remained valid after final borrow release")
	}
	broker.mu.Lock()
	retired = len(broker.retiredSources)
	broker.mu.Unlock()
	if retired != 0 {
		t.Fatalf("retired source count after release = %d, want 0", retired)
	}

	secondLease, err = broker.Acquire(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("Acquire(after retired slot release) error = %v", err)
	}
	_ = first.lease.Close()
	_ = secondLease.Close()
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
	assertSourcesInvalid(t, resolver.materialSnapshot()...)
	assertSessionsInvalid(t, issuer.sessionSnapshot()...)
}

func TestExplicitConnectionInvalidationDestroysBorrowedSourceImmediately(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	resolver := &fakeResolver{}
	issueEntered := make(chan struct{})
	issueCanceled := make(chan struct{})
	sourceValidAtCancel := make(chan bool, 1)
	issueReturn := make(chan struct{})
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(
			ctx context.Context,
			_ credential.Request,
			source *credential.SourceMaterial,
		) (*credential.IssuedSession, error) {
			close(issueEntered)
			<-ctx.Done()
			sourceValidAtCancel <- source.Valid()
			close(issueCanceled)
			<-issueReturn
			return nil, ctx.Err()
		},
	}
	broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, request.Recipient())
	type acquireResult struct {
		lease *Lease
		err   error
	}
	result := make(chan acquireResult, 1)
	go func() {
		lease, err := broker.Acquire(context.Background(), request)
		result <- acquireResult{lease: lease, err: err}
	}()
	waitForSignal(t, issueEntered, "Issue entry")
	materials := resolver.materialSnapshot()
	if len(materials) != 1 || !materials[0].Valid() {
		t.Fatalf("source snapshot = %v, want one valid borrowed source", materials)
	}

	type lifecycleResult struct {
		result ports.RevocationResult
		err    error
	}
	lifecycleOut := make(chan lifecycleResult, 1)
	go func() {
		result, err := broker.RevokeConnection(context.Background(), request)
		lifecycleOut <- lifecycleResult{result: result, err: err}
	}()
	waitForSignal(t, issueCanceled, "Issue cancellation")
	if valid := receiveResult(t, sourceValidAtCancel, "source validity at Issue cancellation"); valid {
		t.Fatal("Issue observed cancellation before connection source destruction")
	}
	assertNoResult(t, lifecycleOut, "RevokeConnection while canceled Issue has not returned")
	close(issueReturn)
	got := receiveResult(t, result, "Acquire after invalidation")
	if got.lease != nil || (!errors.Is(got.err, ErrRevoked) && !errors.Is(got.err, ErrUnavailable)) {
		t.Fatalf("Acquire(after connection invalidation) = %v, %v, want fail closed", got.lease, got.err)
	}
	revoked := receiveResult(t, lifecycleOut, "RevokeConnection after nil late Issue cleanup")
	if revoked.err != nil || revoked.result != ports.RevocationNotRequired {
		t.Fatalf("RevokeConnection(in-flight nil Issue) = %v, %v, want not-required, nil", revoked.result, revoked.err)
	}
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
}

func TestConnectionLifecycleInvalidatesFlightSourceBeforeCancelDuringSettlement(t *testing.T) {
	tests := []struct {
		name       string
		invalidate func(*Broker, credential.Request) (ports.RevocationResult, error)
		wantErr    error
	}{
		{
			name: "revoke connection",
			invalidate: func(broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.RevokeConnection(context.Background(), request)
			},
			wantErr: ErrRevoked,
		},
		{
			name: "close broker",
			invalidate: func(broker *Broker, _ credential.Request) (ports.RevocationResult, error) {
				return broker.Close(context.Background())
			},
			wantErr: ErrClosed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			request := mustTestRequest(t, defaultTestRequestConfig())
			settleEntered := make(chan struct{})
			settleRelease := make(chan struct{})
			claim := &fakeClaim{settleFn: func(context.Context, ports.SecretReadOutcome) error {
				close(settleEntered)
				<-settleRelease
				return nil
			}}
			budget := &fakeBudget{claimFn: func(context.Context, credential.SourceLookup, ports.SecretReadPriority) (ports.SecretReadClaim, error) {
				return claim, nil
			}}
			resolver := &fakeResolver{}
			issuer := &fakeIssuer{clock: clock}
			broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())
			acquired := make(chan acquireOutcome, 1)
			go func() {
				lease, err := broker.Acquire(context.Background(), request)
				acquired <- acquireOutcome{lease: lease, err: err}
			}()
			waitForSignal(t, settleEntered, "blocked source settlement")
			materials := resolver.materialSnapshot()
			if len(materials) != 1 || materials[0] == nil || !materials[0].Valid() {
				t.Fatalf("resolved source = %v, want one live owned material", materials)
			}
			broker.mu.Lock()
			flight := broker.sourceFlights[request.SourceLookup().Digest()]
			broker.mu.Unlock()
			if flight == nil {
				t.Fatal("source flight missing while settlement is blocked")
			}
			validAtCancel := make(chan bool, 1)
			go func() {
				<-flight.ctx.Done()
				validAtCancel <- materials[0].Valid()
			}()
			invalidated := make(chan lifecycleOutcome, 1)
			go func() {
				result, err := test.invalidate(broker, request)
				invalidated <- lifecycleOutcome{result: result, err: err}
			}()
			if valid := receiveResult(t, validAtCancel, "source validity at flight cancellation"); valid {
				t.Fatal("flight cancellation became observable before source destruction")
			}
			if outcomes := claim.outcomes(); len(outcomes) != 1 || outcomes[0] != ports.SecretReadConsumed {
				t.Fatalf("claim settlements = %v, want [consumed]", outcomes)
			}
			broker.mu.Lock()
			flightPresent := broker.sourceFlights[request.SourceLookup().Digest()] == flight
			activeResolves := broker.activeResolves
			broker.mu.Unlock()
			if !flightPresent || activeResolves != 1 {
				t.Fatalf("blocked settlement released capacity early: flight=%v activeResolves=%d", flightPresent, activeResolves)
			}
			assertNoResult(t, invalidated, "lifecycle before blocked settlement returns")
			close(settleRelease)
			got := receiveResult(t, acquired, "Acquire after lifecycle invalidation")
			if got.lease != nil || (!errors.Is(got.err, test.wantErr) && !errors.Is(got.err, ErrUnavailable)) {
				t.Fatalf("Acquire(after lifecycle) = %v, %v, want fail closed", got.lease, got.err)
			}
			lifecycle := receiveResult(t, invalidated, "lifecycle after settlement")
			if lifecycle.err != nil || lifecycle.result != ports.RevocationNotRequired {
				t.Fatalf("lifecycle result = %v, %v, want not-required, nil", lifecycle.result, lifecycle.err)
			}
			broker.mu.Lock()
			flightPresent = broker.sourceFlights[request.SourceLookup().Digest()] != nil
			activeResolves = broker.activeResolves
			broker.mu.Unlock()
			if flightPresent || activeResolves != 0 || materials[0].Valid() {
				t.Fatalf("source cleanup leaked: flight=%v activeResolves=%d valid=%v", flightPresent, activeResolves, materials[0].Valid())
			}
			if test.name != "close broker" {
				_, _ = broker.Close(context.Background())
			}
		})
	}
}

func TestLateResolvePublicationAfterConnectionInvalidationDestroysImmediately(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	resolveEntered := make(chan struct{})
	materialForSettle := make(chan *credential.SourceMaterial, 1)
	materialOut := make(chan *credential.SourceMaterial, 1)
	validAtSettle := make(chan bool, 1)
	claim := &fakeClaim{settleFn: func(context.Context, ports.SecretReadOutcome) error {
		material := <-materialForSettle
		validAtSettle <- material.Valid()
		return nil
	}}
	budget := &fakeBudget{claimFn: func(context.Context, credential.SourceLookup, ports.SecretReadPriority) (ports.SecretReadClaim, error) {
		return claim, nil
	}}
	resolver := &fakeResolver{resolveFn: func(ctx context.Context, _ credential.SourceLookup) (*credential.SourceMaterial, ports.SecretReadOutcome, error) {
		close(resolveEntered)
		<-ctx.Done()
		material, err := credential.NewSourceMaterial([]byte(testSourceCanary))
		materialForSettle <- material
		materialOut <- material
		return material, ports.SecretReadConsumed, err
	}}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())
	acquired := make(chan acquireOutcome, 1)
	go func() {
		lease, err := broker.Acquire(context.Background(), request)
		acquired <- acquireOutcome{lease: lease, err: err}
	}()
	waitForSignal(t, resolveEntered, "blocked Resolve")
	invalidated := make(chan lifecycleOutcome, 1)
	go func() {
		result, err := broker.RevokeConnection(context.Background(), request)
		invalidated <- lifecycleOutcome{result: result, err: err}
	}()
	material := receiveResult(t, materialOut, "late Resolve material")
	if valid := receiveResult(t, validAtSettle, "late material validity at settlement"); valid {
		t.Fatal("late Resolve publication remained valid after holder invalidation")
	}
	got := receiveResult(t, acquired, "Acquire after late Resolve")
	if got.lease != nil || (!errors.Is(got.err, ErrRevoked) && !errors.Is(got.err, ErrUnavailable)) {
		t.Fatalf("Acquire(after late Resolve) = %v, %v, want fail closed", got.lease, got.err)
	}
	lifecycle := receiveResult(t, invalidated, "RevokeConnection after late Resolve")
	if lifecycle.err != nil || lifecycle.result != ports.RevocationNotRequired {
		t.Fatalf("RevokeConnection() = %v, %v, want not-required, nil", lifecycle.result, lifecycle.err)
	}
	if material.Valid() {
		t.Fatal("late Resolve material remains valid after lifecycle completion")
	}
	if outcomes := claim.outcomes(); len(outcomes) != 1 || outcomes[0] != ports.SecretReadConsumed {
		t.Fatalf("claim settlements = %v, want [consumed]", outcomes)
	}
	if got := issuer.issueCount(); got != 0 {
		t.Fatalf("Issue calls after late Resolve = %d, want 0", got)
	}
	_, _ = broker.Close(context.Background())
}

func TestLastSourceWaiterInvalidatesHolderBeforeCancelDuringSettlement(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	settleEntered := make(chan struct{})
	settleRelease := make(chan struct{})
	claim := &fakeClaim{settleFn: func(context.Context, ports.SecretReadOutcome) error {
		close(settleEntered)
		<-settleRelease
		return nil
	}}
	budget := &fakeBudget{claimFn: func(context.Context, credential.SourceLookup, ports.SecretReadPriority) (ports.SecretReadClaim, error) {
		return claim, nil
	}}
	resolver := &fakeResolver{}
	broker := mustTestBroker(t, clock, budget, resolver, &fakeIssuer{clock: clock}, request.Recipient())
	broker.mu.Lock()
	lineage, _, _, err := broker.prepareRequestLocked(request)
	broker.mu.Unlock()
	if err != nil {
		t.Fatalf("prepareRequestLocked() error = %v", err)
	}
	type sourceOutcome struct {
		borrow *sourceBorrow
		err    error
	}
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	resultOut := make(chan sourceOutcome, 1)
	go func() {
		borrow, err := broker.acquireSource(
			callerCtx,
			request,
			ports.SecretReadGeneral,
			lineage.epoch,
		)
		resultOut <- sourceOutcome{borrow: borrow, err: err}
	}()
	waitForSignal(t, settleEntered, "blocked source settlement")
	materials := resolver.materialSnapshot()
	if len(materials) != 1 || materials[0] == nil || !materials[0].Valid() {
		t.Fatalf("resolved source = %v, want one live owned material", materials)
	}
	broker.mu.Lock()
	flight := broker.sourceFlights[request.SourceLookup().Digest()]
	broker.mu.Unlock()
	if flight == nil {
		t.Fatal("source flight missing while settlement is blocked")
	}
	validAtCancel := make(chan bool, 1)
	go func() {
		<-flight.ctx.Done()
		validAtCancel <- materials[0].Valid()
	}()
	cancelCaller()
	if valid := receiveResult(t, validAtCancel, "source validity at abandonment cancellation"); valid {
		t.Fatal("last-waiter cancellation became observable before holder destruction")
	}
	result := receiveResult(t, resultOut, "last source waiter cancellation")
	if result.borrow != nil || !errors.Is(result.err, context.Canceled) {
		t.Fatalf("acquireSource(canceled) = %v, %v, want nil, context.Canceled", result.borrow, result.err)
	}
	if outcomes := claim.outcomes(); len(outcomes) != 1 || outcomes[0] != ports.SecretReadConsumed {
		t.Fatalf("claim settlements = %v, want [consumed]", outcomes)
	}
	broker.mu.Lock()
	flightPresent := broker.sourceFlights[request.SourceLookup().Digest()] == flight
	activeResolves := broker.activeResolves
	broker.mu.Unlock()
	if !flightPresent || activeResolves != 1 {
		t.Fatalf("abandoned blocked flight released capacity early: flight=%v resolves=%d", flightPresent, activeResolves)
	}
	close(settleRelease)
	waitForCondition(t, "abandoned source flight cleanup", func() bool {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		return broker.sourceFlights[request.SourceLookup().Digest()] == nil && broker.activeResolves == 0
	})
	if materials[0].Valid() {
		t.Fatal("abandoned source remains valid after cleanup")
	}
	_, _ = broker.Close(context.Background())
}

func TestConcurrentFlightSourceInvalidatorsJoinDestroyBeforeCancel(t *testing.T) {
	tests := []struct {
		name        string
		invalidator func(*flightSource, context.CancelFunc) func()
	}{
		{
			name: "source flight",
			invalidator: func(source *flightSource, cancel context.CancelFunc) func() {
				flight := &sourceFlight{source: source, cancel: cancel}
				return func() {
					flight.source.invalidate()
					flight.cancel()
				}
			},
		},
		{
			name: "rotation flight",
			invalidator: func(source *flightSource, cancel context.CancelFunc) func() {
				flight := &rotationFlight{source: source, cancel: cancel}
				return func() {
					flight.source.invalidate()
					flight.cancel()
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			material, err := credential.NewSourceMaterial([]byte(testSourceCanary))
			if err != nil {
				t.Fatalf("NewSourceMaterial() error = %v", err)
			}
			destroyDone := make(chan struct{})
			holder := &flightSource{
				invalid:     true,
				destroyDone: destroyDone,
			}
			firstCtx, cancelFirst := context.WithCancel(context.Background())
			secondCtx, cancelSecond := context.WithCancel(context.Background())
			start := make(chan struct{})
			started := make(chan struct{}, 2)
			for _, invalidate := range []func(){
				test.invalidator(holder, cancelFirst),
				test.invalidator(holder, cancelSecond),
			} {
				go func(invalidate func()) {
					started <- struct{}{}
					<-start
					invalidate()
				}(invalidate)
			}
			<-started
			<-started
			close(start)
			select {
			case <-firstCtx.Done():
				t.Fatal("first invalidator published cancellation before destruction completed")
			case <-secondCtx.Done():
				t.Fatal("second invalidator published cancellation before destruction completed")
			case <-time.After(20 * time.Millisecond):
			}
			destroySource(material)
			close(destroyDone)
			waitForSignal(t, firstCtx.Done(), "first joined invalidation cancellation")
			waitForSignal(t, secondCtx.Done(), "second joined invalidation cancellation")
			if material.Valid() {
				t.Fatal("joined invalidators published cancellation before source destruction")
			}
		})
	}
}

func TestResolveSuccessAfterBackendDeadlineIsConsumedButNeverPublished(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	parent := &liveDeadlineContext{Context: context.Background()}
	claim := &fakeClaim{}
	budget := &fakeBudget{claimFn: func(context.Context, credential.SourceLookup, ports.SecretReadPriority) (ports.SecretReadClaim, error) {
		parent.setDeadline(time.Now().Add(time.Millisecond))
		return claim, nil
	}}
	childErr := make(chan error, 1)
	resolver := &fakeResolver{resolveFn: func(ctx context.Context, _ credential.SourceLookup) (*credential.SourceMaterial, ports.SecretReadOutcome, error) {
		<-ctx.Done()
		childErr <- ctx.Err()
		material, err := credential.NewSourceMaterial([]byte(testSourceCanary))
		return material, ports.SecretReadConsumed, err
	}}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())
	holder := &flightSource{}
	material, expiresAt, err := broker.resolveOwned(
		parent,
		request.SourceLookup(),
		ports.SecretReadGeneral,
		holder,
	)
	if material != nil || !expiresAt.IsZero() || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("resolveOwned(late success) = %v, %v, %v, want nil, zero, ErrUnavailable", material, expiresAt, err)
	}
	if got := receiveResult(t, childErr, "resolver child deadline"); !errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("resolver child error = %v, want context.DeadlineExceeded", got)
	}
	if err := parent.Err(); err != nil {
		t.Fatalf("parent context error = %v, want live parent", err)
	}
	materials := resolver.materialSnapshot()
	if len(materials) != 1 || materials[0] == nil || materials[0].Valid() {
		t.Fatalf("late resolved source = %v, want one destroyed material", materials)
	}
	if outcomes := claim.outcomes(); len(outcomes) != 1 || outcomes[0] != ports.SecretReadConsumed {
		t.Fatalf("claim settlements = %v, want [consumed]", outcomes)
	}
	if holder.current() != nil {
		t.Fatal("late source remained published in flight holder")
	}
	if got := issuer.issueCount(); got != 0 {
		t.Fatalf("Issue calls after late Resolve = %d, want 0", got)
	}
	broker.mu.Lock()
	cacheEntries := len(broker.sources)
	broker.mu.Unlock()
	if cacheEntries != 0 {
		t.Fatalf("source cache entries = %d, want 0", cacheEntries)
	}
	_, _ = broker.Close(context.Background())
}

func TestOperationTerminationInvalidatesPendingRotationSourceDuringSettlement(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 2
	next := mustTestRequest(t, nextConfig)
	settleEntered := make(chan struct{})
	settleRelease := make(chan struct{})
	baseClaim := &fakeClaim{}
	rotationClaim := &fakeClaim{settleFn: func(context.Context, ports.SecretReadOutcome) error {
		close(settleEntered)
		<-settleRelease
		return nil
	}}
	var claimMu sync.Mutex
	claimCall := 0
	budget := &fakeBudget{claimFn: func(context.Context, credential.SourceLookup, ports.SecretReadPriority) (ports.SecretReadClaim, error) {
		claimMu.Lock()
		defer claimMu.Unlock()
		claimCall++
		if claimCall == 1 {
			return baseClaim, nil
		}
		return rotationClaim, nil
	}}
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, base.Recipient())
	baseLease, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	type rotateOutcome struct {
		rotation Rotation
		err      error
	}
	rotated := make(chan rotateOutcome, 1)
	go func() {
		rotation, err := broker.Rotate(context.Background(), next)
		rotated <- rotateOutcome{rotation: rotation, err: err}
	}()
	waitForSignal(t, settleEntered, "blocked rotation source settlement")
	materials := resolver.materialSnapshot()
	if len(materials) != 2 || materials[0] == nil || materials[1] == nil ||
		!materials[0].Valid() || !materials[1].Valid() {
		t.Fatalf("rotation sources = %v, want two live materials before termination", materials)
	}
	broker.mu.Lock()
	flight := broker.rotations[keyForConnection(next)]
	broker.mu.Unlock()
	if flight == nil {
		t.Fatal("rotation flight missing while settlement is blocked")
	}
	validAtCancel := make(chan bool, 1)
	go func() {
		<-flight.ctx.Done()
		validAtCancel <- materials[1].Valid()
	}()
	terminated := make(chan lifecycleOutcome, 1)
	go func() {
		result, err := broker.CancelOperation(context.Background(), next)
		terminated <- lifecycleOutcome{result: result, err: err}
	}()
	if valid := receiveResult(t, validAtCancel, "rotation source validity at cancellation"); valid {
		t.Fatal("rotation cancellation became observable before private source destruction")
	}
	lifecycle := receiveResult(t, terminated, "CancelOperation during rotation settlement")
	if lifecycle.err != nil || lifecycle.result != ports.RevocationPending {
		t.Fatalf("CancelOperation() = %v, %v, want pending, nil", lifecycle.result, lifecycle.err)
	}
	if !materials[0].Valid() {
		t.Fatal("operation termination destroyed shared current-lineage source")
	}
	if outcomes := rotationClaim.outcomes(); len(outcomes) != 1 || outcomes[0] != ports.SecretReadConsumed {
		t.Fatalf("rotation claim settlements = %v, want [consumed]", outcomes)
	}
	broker.mu.Lock()
	flightPresent := broker.rotations[keyForConnection(next)] == flight
	activeResolves := broker.activeResolves
	sourceReservations := broker.sourceReservations
	broker.mu.Unlock()
	if !flightPresent || activeResolves != 1 || sourceReservations == 0 {
		t.Fatalf("blocked rotation settlement released capacity: flight=%v resolves=%d reservations=%d", flightPresent, activeResolves, sourceReservations)
	}
	if got := issuer.issueCount(); got != 1 {
		t.Fatalf("Issue calls before settlement release = %d, want base only", got)
	}
	if err := baseLease.Use(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatalf("base Lease.Use(after next-operation termination) error = %v", err)
	}
	assertNoResult(t, rotated, "Rotate before blocked settlement returns")
	close(settleRelease)
	result := receiveResult(t, rotated, "Rotate after operation termination")
	if result.rotation.Valid() || !errors.Is(result.err, ErrOperationTerminated) {
		t.Fatalf("Rotate(after operation termination) = %v, %v, want invalid, ErrOperationTerminated", result.rotation, result.err)
	}
	broker.mu.Lock()
	flightPresent = broker.rotations[keyForConnection(next)] != nil
	activeResolves = broker.activeResolves
	sourceReservations = broker.sourceReservations
	broker.mu.Unlock()
	if flightPresent || activeResolves != 0 || sourceReservations != 0 || materials[1].Valid() {
		t.Fatalf("rotation cleanup leaked: flight=%v resolves=%d reservations=%d sourceValid=%v", flightPresent, activeResolves, sourceReservations, materials[1].Valid())
	}
	_ = baseLease.Close()
	_, _ = broker.Close(context.Background())
}

func TestSourceBorrowReleaseFreesRetiredSlotOnlyAfterSynchronousDestroy(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, request.Recipient())
	broker.mu.Lock()
	lineage, _, _, err := broker.prepareRequestLocked(request)
	if err != nil {
		broker.mu.Unlock()
		t.Fatalf("prepareRequestLocked() error = %v", err)
	}
	epoch := lineage.epoch
	broker.mu.Unlock()
	borrow, err := broker.acquireSource(context.Background(), request, ports.SecretReadGeneral, epoch)
	if err != nil {
		t.Fatalf("acquireSource() error = %v", err)
	}
	materials := resolver.materialSnapshot()
	if len(materials) != 1 || !materials[0].Valid() {
		t.Fatalf("source snapshot = %v, want one live source", materials)
	}
	clock.Add(MaxSourceCacheTTL)
	if err := broker.SweepExpired(); err != nil {
		t.Fatalf("SweepExpired() error = %v", err)
	}
	broker.mu.Lock()
	broker.sourceReservations = MaxSourceEntries - 1
	chargedBefore := len(broker.sources) + len(broker.retiredSources) +
		len(broker.sourceFlights) + int(broker.sourceReservations)
	broker.mu.Unlock()
	if chargedBefore != MaxSourceEntries || !materials[0].Valid() {
		t.Fatalf("retired source charge before release = %d, valid:%v, want %d/true", chargedBefore, materials[0].Valid(), MaxSourceEntries)
	}

	borrow.release()
	if materials[0].Valid() {
		t.Fatal("sourceBorrow.release returned before retired source destruction")
	}
	broker.mu.Lock()
	chargedAfter := len(broker.sources) + len(broker.retiredSources) +
		len(broker.sourceFlights) + int(broker.sourceReservations)
	retiredAfter := len(broker.retiredSources)
	reservationAfter := broker.sourceReservations
	broker.sourceReservations = 0
	broker.mu.Unlock()
	if retiredAfter != 0 || reservationAfter != MaxSourceEntries-1 || chargedAfter != MaxSourceEntries-1 {
		t.Fatalf(
			"source charge after synchronous release = charged:%d retired:%d reservations:%d, want %d/0/%d",
			chargedAfter,
			retiredAfter,
			reservationAfter,
			MaxSourceEntries-1,
			MaxSourceEntries-1,
		)
	}

	replacement, err := broker.acquireSource(context.Background(), request, ports.SecretReadGeneral, epoch)
	if err != nil {
		t.Fatalf("acquireSource(after synchronous Destroy) error = %v", err)
	}
	replacement.release()
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
	assertSourcesInvalid(t, resolver.materialSnapshot()...)
}
