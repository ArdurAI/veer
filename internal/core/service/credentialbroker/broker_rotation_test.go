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

func TestRotateUsesGenerationHighWaterAndTreatsVersionAsOpaque(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	baseConfig := defaultTestRequestConfig()
	baseConfig.version = "zzzz_Opaque"
	base := mustTestRequest(t, baseConfig)
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, base.Recipient())
	baseLease, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	if err := baseLease.Close(); err != nil {
		t.Fatalf("base Lease.Close() error = %v", err)
	}

	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 3
	nextConfig.version = "0000_Opaque"
	nextConfig.operation = 3
	next := mustTestRequest(t, nextConfig)
	rotation, err := broker.Rotate(context.Background(), next)
	if err != nil {
		t.Fatalf("Rotate(generation jump with lexically lower opaque version) error = %v", err)
	}
	if !rotation.Valid() || rotation.Lease() == nil {
		t.Fatalf("Rotate() = %v, want valid committed Rotation", rotation)
	}
	if got := rotation.PriorRevocation(); got != ports.RevocationProviderConfirmed {
		t.Fatalf("PriorRevocation() = %v, want provider-confirmed", got)
	}
	if got := issuer.issueCount(); got != 2 {
		t.Fatalf("Issue calls = %d, want base plus rotation", got)
	}
	if got := issuer.revokeCount(); got != 1 {
		t.Fatalf("Revoke calls = %d, want prior generation only", got)
	}
	materials := resolver.materialSnapshot()
	if len(materials) != 2 || materials[0].Valid() || !materials[1].Valid() {
		t.Fatalf("source validity after cutover = old:%v new:%v, want false/true", materials[0].Valid(), materials[1].Valid())
	}

	staleConfig := defaultTestRequestConfig()
	staleConfig.generation = 2
	staleConfig.version = "newer_Looking_But_Stale"
	staleConfig.operation = 2
	stale := mustTestRequest(t, staleConfig)
	if got, err := broker.Rotate(context.Background(), stale); got.Valid() || !errors.Is(err, ErrStale) {
		t.Fatalf("Rotate(below generation high-water) = %v, %v, want invalid, ErrStale", got, err)
	}
	if lease, err := broker.Acquire(context.Background(), base); lease != nil || !errors.Is(err, ErrStale) {
		t.Fatalf("Acquire(old generation) = %v, %v, want nil, ErrStale", lease, err)
	}
	futureConfig := defaultTestRequestConfig()
	futureConfig.generation = 4
	futureConfig.version = "future"
	futureConfig.operation = 4
	future := mustTestRequest(t, futureConfig)
	if lease, err := broker.Acquire(context.Background(), future); lease != nil || !errors.Is(err, ErrCredentialRotationRequired) {
		t.Fatalf("Acquire(future generation) = %v, %v, want nil, ErrCredentialRotationRequired", lease, err)
	}

	if err := rotation.Lease().Close(); err != nil {
		t.Fatalf("rotation Lease.Close() error = %v", err)
	}
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
	assertSourcesInvalid(t, resolver.materialSnapshot()...)
	assertSessionsInvalid(t, issuer.sessionSnapshot()...)
}

func TestCommittedRotateReturnsReservedLeaseAfterConcurrentLifecycleInvalidation(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 2
	next := mustTestRequest(t, nextConfig)
	revokeRelease := make(chan struct{})
	tracker := &blockingRevocations{release: revokeRelease}
	issuer := &fakeIssuer{
		clock: clock,
		revokeFn: func(ctx context.Context, _ credential.Request, _ *credential.IssuedSession) (ports.RevocationResult, error) {
			return tracker.call(ctx)
		},
	}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, base.Recipient())
	prior, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	_ = prior.Close()

	type rotateResult struct {
		rotation Rotation
		err      error
	}
	rotationResult := make(chan rotateResult, 1)
	go func() {
		rotation, err := broker.Rotate(context.Background(), next)
		rotationResult <- rotateResult{rotation: rotation, err: err}
	}()
	waitForCondition(t, "rotation commit before prior revocation", func() bool {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		lineage := broker.lineages[keyForConnection(next)]
		return lineage != nil && lineage.generation == next.ConnectionGeneration()
	})
	waitForCondition(t, "prior revocation entry", func() bool {
		active, _, calls := tracker.snapshot()
		return active == 1 && calls == 1
	})

	type lifecycleResult struct {
		result ports.RevocationResult
		err    error
	}
	cancelResult := make(chan lifecycleResult, 1)
	go func() {
		result, err := broker.CancelOperation(context.Background(), next)
		cancelResult <- lifecycleResult{result: result, err: err}
	}()
	waitForCondition(t, "new generation revocation entry", func() bool {
		active, _, calls := tracker.snapshot()
		return active == 2 && calls == 2
	})
	close(revokeRelease)

	canceled := receiveResult(t, cancelResult, "CancelOperation completion")
	if canceled.err != nil || canceled.result != ports.RevocationProviderConfirmed {
		t.Fatalf("CancelOperation(next) = %v, %v, want provider-confirmed, nil", canceled.result, canceled.err)
	}
	rotated := receiveResult(t, rotationResult, "Rotate completion")
	if rotated.err != nil || !rotated.rotation.Valid() || rotated.rotation.Lease() == nil {
		t.Fatalf("Rotate(after committed lifecycle race) = %v, %v, want valid Rotation, nil", rotated.rotation, rotated.err)
	}
	if err := rotated.rotation.Lease().Use(context.Background(), func(context.Context, []byte) error { return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatalf("committed reserved Lease.Use() error = %v, want ErrRevoked after lifecycle invalidation", err)
	}
	if err := rotated.rotation.Lease().Close(); err != nil {
		t.Fatalf("committed reserved Lease.Close() error = %v", err)
	}
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
	assertSessionsInvalid(t, issuer.sessionSnapshot()...)
}

func TestCommittedRotateIgnoresLateCallerCancellation(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 2
	next := mustTestRequest(t, nextConfig)
	revokeEntered := make(chan struct{})
	revokeRelease := make(chan struct{})
	var entered sync.Once
	issuer := &fakeIssuer{
		clock: clock,
		revokeFn: func(ctx context.Context, _ credential.Request, _ *credential.IssuedSession) (ports.RevocationResult, error) {
			entered.Do(func() { close(revokeEntered) })
			select {
			case <-revokeRelease:
				return ports.RevocationProviderConfirmed, nil
			case <-ctx.Done():
				return ports.RevocationPending, ctx.Err()
			}
		},
	}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, base.Recipient())
	prior, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	_ = prior.Close()

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		rotation Rotation
		err      error
	}
	resultOut := make(chan result, 1)
	go func() {
		rotation, err := broker.Rotate(ctx, next)
		resultOut <- result{rotation: rotation, err: err}
	}()
	waitForSignal(t, revokeEntered, "post-commit prior Revoke")
	waitForCondition(t, "committed generation", func() bool {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		lineage := broker.lineages[keyForConnection(next)]
		return lineage != nil && lineage.generation == next.ConnectionGeneration()
	})
	cancel()
	close(revokeRelease)
	got := receiveResult(t, resultOut, "Rotate after late caller cancellation")
	if got.err != nil || !got.rotation.Valid() || got.rotation.Lease() == nil {
		t.Fatalf("Rotate(post-commit cancellation) = %v, %v, want valid Rotation, nil", got.rotation, got.err)
	}
	if err := got.rotation.Lease().Use(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatalf("reserved Lease.Use() after caller cancellation error = %v", err)
	}
	_ = got.rotation.Lease().Close()
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
}

func TestRotationAccountsForLatePriorIssueCleanup(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 2
	next := mustTestRequest(t, nextConfig)
	priorIssueEntered := make(chan struct{})
	priorIssueCanceled := make(chan struct{})
	priorIssueReturn := make(chan struct{})
	priorSessionOut := make(chan *credential.IssuedSession, 1)
	revokeEntered := make(chan struct{})
	revokeRelease := make(chan struct{})
	var issueMu sync.Mutex
	issueCalls := 0
	var revokeOnce sync.Once
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(ctx context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			issueMu.Lock()
			issueCalls++
			call := issueCalls
			issueMu.Unlock()
			if call == 1 {
				close(priorIssueEntered)
				<-ctx.Done()
				close(priorIssueCanceled)
				<-priorIssueReturn
				session, err := newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
				if err == nil {
					priorSessionOut <- session
				}
				return session, err
			}
			return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
		},
		revokeFn: func(ctx context.Context, _ credential.Request, session *credential.IssuedSession) (ports.RevocationResult, error) {
			if !session.Valid() {
				t.Error("late prior Issue output was destroyed before upstream Revoke")
			}
			revokeOnce.Do(func() { close(revokeEntered) })
			select {
			case <-revokeRelease:
				return ports.RevocationProviderConfirmed, nil
			case <-ctx.Done():
				return ports.RevocationPending, ctx.Err()
			}
		},
	}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, base.Recipient())
	type acquireResult struct {
		lease *Lease
		err   error
	}
	priorAcquire := make(chan acquireResult, 1)
	go func() {
		lease, err := broker.Acquire(context.Background(), base)
		priorAcquire <- acquireResult{lease: lease, err: err}
	}()
	waitForSignal(t, priorIssueEntered, "prior-generation Issue")

	type rotateResult struct {
		rotation Rotation
		err      error
	}
	rotationOut := make(chan rotateResult, 1)
	go func() {
		rotation, err := broker.Rotate(context.Background(), next)
		rotationOut <- rotateResult{rotation: rotation, err: err}
	}()
	waitForSignal(t, priorIssueCanceled, "prior Issue cancellation at rotation cutover")
	close(priorIssueReturn)
	priorSession := receiveResult(t, priorSessionOut, "late prior Issue output")
	waitForSignal(t, revokeEntered, "late prior Issue cleanup Revoke")
	if !priorSession.Valid() {
		t.Error("late prior Issue output destroyed before Revoke completed")
	}
	assertNoResult(t, priorAcquire, "prior Acquire before late cleanup")

	var returned *rotateResult
	select {
	case result := <-rotationOut:
		returned = &result
		if result.err != nil || !result.rotation.Valid() ||
			result.rotation.PriorRevocation() != ports.RevocationPending {
			t.Errorf("Rotate(before prior cleanup) = %v, %v with prior %v, want valid/nil/pending",
				result.rotation,
				result.err,
				result.rotation.PriorRevocation(),
			)
		}
	default:
	}
	close(revokeRelease)
	prior := receiveResult(t, priorAcquire, "prior Acquire after cleanup")
	if prior.lease != nil || !errors.Is(prior.err, ErrRevoked) {
		t.Fatalf("prior Acquire(after cutover) = %v, %v, want nil, ErrRevoked", prior.lease, prior.err)
	}
	if priorSession.Valid() {
		t.Fatal("late prior Issue output remains valid after cleanup completion")
	}
	if returned == nil {
		result := receiveResult(t, rotationOut, "Rotate after joined prior cleanup")
		returned = &result
		if result.err != nil || !result.rotation.Valid() ||
			result.rotation.PriorRevocation() != ports.RevocationProviderConfirmed {
			t.Fatalf("Rotate(after prior cleanup) = %v, %v with prior %v, want valid/nil/provider-confirmed",
				result.rotation,
				result.err,
				result.rotation.PriorRevocation(),
			)
		}
	}
	if got := issuer.revokeCount(); got != 1 {
		t.Fatalf("late prior cleanup Revoke calls = %d, want exactly 1", got)
	}
	if returned.rotation.Lease() != nil {
		_ = returned.rotation.Lease().Close()
	}
	_, _ = broker.Close(context.Background())
}

func TestRotationLeaseReservationsShareTheGlobalLeaseCapacity(t *testing.T) {
	const rotationWaiters = 3
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 2
	next := mustTestRequest(t, nextConfig)
	issueEntered := make(chan struct{})
	issueRelease := make(chan struct{})
	var issueMu sync.Mutex
	issueCalls := 0
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			issueMu.Lock()
			issueCalls++
			call := issueCalls
			issueMu.Unlock()
			if call == 2 {
				close(issueEntered)
				<-issueRelease
			}
			return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
		},
	}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, base.Recipient())
	seed, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(seed) error = %v", err)
	}
	_ = seed.Close()

	type result struct {
		rotation Rotation
		err      error
	}
	results := make(chan result, rotationWaiters)
	go func() {
		rotation, err := broker.Rotate(context.Background(), next)
		results <- result{rotation: rotation, err: err}
	}()
	waitForSignal(t, issueEntered, "rotation Issue")
	for range rotationWaiters - 1 {
		go func() {
			rotation, err := broker.Rotate(context.Background(), next)
			results <- result{rotation: rotation, err: err}
		}()
	}
	waitForCondition(t, "all rotation waiter lease reservations", func() bool {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		flight := broker.rotations[keyForConnection(next)]
		return flight != nil && flight.waiters == rotationWaiters &&
			flight.leaseReserved == rotationWaiters && broker.leaseReservations == rotationWaiters
	})

	ordinary := make([]*Lease, 0, MaxActiveLeases-rotationWaiters)
	for index := 0; index < MaxActiveLeases-rotationWaiters; index++ {
		lease, acquireErr := broker.Acquire(context.Background(), base)
		if acquireErr != nil {
			t.Fatalf("Acquire(cache hit %d) error = %v", index, acquireErr)
		}
		ordinary = append(ordinary, lease)
	}
	if lease, acquireErr := broker.Acquire(context.Background(), base); lease != nil || !errors.Is(acquireErr, ErrCapacity) {
		t.Fatalf("Acquire(after active+reserved reaches cap) = %v, %v, want nil, ErrCapacity", lease, acquireErr)
	}
	broker.mu.Lock()
	activeBefore := broker.activeLeases
	reservedBefore := broker.leaseReservations
	broker.mu.Unlock()
	if activeBefore != MaxActiveLeases-rotationWaiters || reservedBefore != rotationWaiters ||
		activeBefore+reservedBefore != MaxActiveLeases {
		t.Fatalf("lease capacity before commit = active:%d reserved:%d, want sum %d", activeBefore, reservedBefore, MaxActiveLeases)
	}

	close(issueRelease)
	rotations := make([]Rotation, 0, rotationWaiters)
	for range rotationWaiters {
		got := receiveResult(t, results, "reserved Rotate result")
		if got.err != nil || !got.rotation.Valid() {
			t.Fatalf("Rotate(reserved waiter) = %v, %v, want valid, nil", got.rotation, got.err)
		}
		rotations = append(rotations, got.rotation)
	}
	broker.mu.Lock()
	activeAfter := broker.activeLeases
	reservedAfter := broker.leaseReservations
	broker.mu.Unlock()
	if activeAfter != MaxActiveLeases || reservedAfter != 0 {
		t.Fatalf("lease capacity after commit = active:%d reserved:%d, want %d/0", activeAfter, reservedAfter, MaxActiveLeases)
	}
	for _, lease := range ordinary {
		_ = lease.Close()
	}
	for _, rotation := range rotations {
		_ = rotation.Lease().Close()
	}
	if got := broker.Stats().ActiveLeases; got != 0 {
		t.Fatalf("ActiveLeases after closing all handles = %d, want 0", got)
	}
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
}

func TestRotateAtFullSourceCapacityNeverEvictsCurrentLineageOnPreparationFailure(t *testing.T) {
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
	prior, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	baseSource := resolver.materialSnapshot()[0]
	baseSession := issuer.sessionSnapshot()[0]
	dummies := make([]*sourceEntry, 0, MaxSourceEntries-1)
	broker.mu.Lock()
	for range MaxSourceEntries - 1 {
		dummy := &sourceEntry{retired: true}
		broker.retiredSources[dummy] = struct{}{}
		dummies = append(dummies, dummy)
	}
	broker.mu.Unlock()
	claimsBefore, resolvesBefore, issuesBefore := budget.callCount(), resolver.callCount(), issuer.issueCount()

	rotation, err := broker.Rotate(context.Background(), next)
	if rotation.Valid() || !errors.Is(err, ErrCapacity) {
		t.Fatalf("Rotate(no unrelated source slot) = %v, %v, want invalid, ErrCapacity", rotation, err)
	}
	if budget.callCount() != claimsBefore || resolver.callCount() != resolvesBefore || issuer.issueCount() != issuesBefore {
		t.Fatalf("Rotate(capacity preflight) called backend: claims %d->%d resolves %d->%d issues %d->%d",
			claimsBefore, budget.callCount(), resolvesBefore, resolver.callCount(), issuesBefore, issuer.issueCount())
	}
	if !baseSource.Valid() || !baseSession.Valid() {
		t.Fatal("failed rotation preparation destroyed current-lineage material")
	}
	if err := prior.Use(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatalf("prior Lease.Use() after failed Rotate error = %v", err)
	}
	replayed, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base after failed Rotate) error = %v", err)
	}
	if replayed.state.cell != prior.state.cell {
		t.Fatal("failed Rotate changed prior cached session")
	}
	broker.mu.Lock()
	for _, dummy := range dummies {
		delete(broker.retiredSources, dummy)
	}
	broker.mu.Unlock()
	_ = replayed.Close()
	_ = prior.Close()
	_, _ = broker.Close(context.Background())
}

func TestRotateAtFullSessionCapacityFailsBeforeBackendAndPreservesPriorLease(t *testing.T) {
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
	prior, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	dummies := make([]*sessionCell, 0, MaxSessionEntries-1)
	broker.mu.Lock()
	for range MaxSessionEntries - 1 {
		dummy := &sessionCell{refs: 1}
		broker.cells[dummy] = struct{}{}
		dummies = append(dummies, dummy)
	}
	broker.mu.Unlock()
	claimsBefore, resolvesBefore, issuesBefore := budget.callCount(), resolver.callCount(), issuer.issueCount()
	rotation, err := broker.Rotate(context.Background(), next)
	if rotation.Valid() || !errors.Is(err, ErrCapacity) {
		t.Fatalf("Rotate(no session slot) = %v, %v, want invalid, ErrCapacity", rotation, err)
	}
	if budget.callCount() != claimsBefore || resolver.callCount() != resolvesBefore || issuer.issueCount() != issuesBefore {
		t.Fatal("Rotate(session capacity preflight) called a backend")
	}
	if err := prior.Use(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatalf("prior Lease.Use() after failed Rotate error = %v", err)
	}
	broker.mu.Lock()
	for _, dummy := range dummies {
		delete(broker.cells, dummy)
	}
	broker.mu.Unlock()
	_ = prior.Close()
	_, _ = broker.Close(context.Background())
}

func TestRotateAtFullCachesEvictsOnlyUnrelatedEntriesAndRevokesPriorLineage(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	unrelatedConfig := defaultTestRequestConfig()
	unrelatedConfig.connection = 2
	unrelatedConfig.operation = 2
	unrelated := mustTestRequest(t, unrelatedConfig)
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 3
	next := mustTestRequest(t, nextConfig)
	issueEntered := make(chan struct{})
	issueRelease := make(chan struct{})
	var issueMu sync.Mutex
	issueCalls := 0
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			issueMu.Lock()
			issueCalls++
			call := issueCalls
			issueMu.Unlock()
			if call == 3 {
				close(issueEntered)
				<-issueRelease
			}
			return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
		},
	}
	broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, base.Recipient())
	baseLease, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	_ = baseLease.Close()
	unrelatedLease, err := broker.Acquire(context.Background(), unrelated)
	if err != nil {
		t.Fatalf("Acquire(unrelated) error = %v", err)
	}
	_ = unrelatedLease.Close()
	baseCell := broker.sessions[base.BindingDigest()]
	unrelatedCell := broker.sessions[unrelated.BindingDigest()]
	sourceDummies := make([]*sourceEntry, 0, MaxSourceEntries-2)
	sessionDummies := make([]*sessionCell, 0, MaxSessionEntries-2)
	broker.mu.Lock()
	for range MaxSourceEntries - 2 {
		dummy := &sourceEntry{retired: true}
		broker.retiredSources[dummy] = struct{}{}
		sourceDummies = append(sourceDummies, dummy)
	}
	for range MaxSessionEntries - 2 {
		dummy := &sessionCell{refs: 1, lastUsed: ^uint64(0)}
		broker.cells[dummy] = struct{}{}
		sessionDummies = append(sessionDummies, dummy)
	}
	broker.mu.Unlock()
	type outcome struct {
		rotation Rotation
		err      error
	}
	resultOut := make(chan outcome, 1)
	go func() {
		rotation, err := broker.Rotate(context.Background(), next)
		resultOut <- outcome{rotation: rotation, err: err}
	}()
	waitForSignal(t, issueEntered, "rotation Issue after full-cache preparation")
	materials := resolver.materialSnapshot()
	sessions := issuer.sessionSnapshot()
	if len(materials) != 3 || len(sessions) != 2 {
		t.Fatalf("backend snapshots before commit = sources:%d sessions:%d, want 3/2", len(materials), len(sessions))
	}
	if !materials[0].Valid() || materials[1].Valid() || !materials[2].Valid() {
		t.Errorf("source eviction selected current lineage: base=%v unrelated=%v next=%v",
			materials[0].Valid(), materials[1].Valid(), materials[2].Valid())
	}
	if !sessions[0].Valid() || sessions[1].Valid() {
		t.Errorf("session eviction selected current lineage: base=%v unrelated=%v", sessions[0].Valid(), sessions[1].Valid())
	}
	broker.mu.Lock()
	if _, baseKnown := broker.cells[baseCell]; !baseKnown {
		t.Error("current-lineage session disappeared before cutover")
	}
	if _, unrelatedKnown := broker.cells[unrelatedCell]; unrelatedKnown {
		t.Error("unrelated session was not selected for full-cache eviction")
	}
	broker.mu.Unlock()
	close(issueRelease)
	got := receiveResult(t, resultOut, "full-cache Rotate")
	if got.err != nil || !got.rotation.Valid() {
		t.Fatalf("Rotate(full caches with unrelated slots) = %v, %v, want valid, nil", got.rotation, got.err)
	}
	if got.rotation.PriorRevocation() != ports.RevocationProviderConfirmed || issuer.revokeCount() != 1 {
		t.Fatalf("prior revocation = %v calls=%d, want provider-confirmed/1", got.rotation.PriorRevocation(), issuer.revokeCount())
	}
	broker.mu.Lock()
	for _, dummy := range sourceDummies {
		delete(broker.retiredSources, dummy)
	}
	for _, dummy := range sessionDummies {
		delete(broker.cells, dummy)
	}
	broker.mu.Unlock()
	_ = got.rotation.Lease().Close()
	_, _ = broker.Close(context.Background())
}

func TestRotateCollapsesEveryIssuerErrorToUnavailable(t *testing.T) {
	backendErrors := make([]error, 0, int(ErrSerializationForbidden-ErrInvalid)+2)
	for failure := ErrInvalid; failure <= ErrSerializationForbidden; failure++ {
		backendErrors = append(backendErrors, failure)
	}
	backendErrors = append(backendErrors, fmt.Errorf("%s: wrapped adapter failure", testErrorCanary))
	for index, backendErr := range backendErrors {
		t.Run(fmt.Sprintf("backend-error-%02d", index), func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			base := mustTestRequest(t, defaultTestRequestConfig())
			nextConfig := defaultTestRequestConfig()
			nextConfig.generation = 2
			nextConfig.version = "opaque_B"
			nextConfig.operation = 2
			next := mustTestRequest(t, nextConfig)
			var issueMu sync.Mutex
			calls := 0
			issuer := &fakeIssuer{
				clock: clock,
				issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
					issueMu.Lock()
					calls++
					call := calls
					issueMu.Unlock()
					if call > 1 {
						return nil, backendErr
					}
					return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
				},
			}
			broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, base.Recipient())
			lease, err := broker.Acquire(context.Background(), base)
			if err != nil {
				t.Fatalf("Acquire(base) error = %v", err)
			}
			_ = lease.Close()
			rotation, err := broker.Rotate(context.Background(), next)
			if rotation.Valid() || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Rotate(adapter error %T) = %v, %v, want invalid, ErrUnavailable", backendErr, rotation, err)
			}
			failure, classified := Classify(err)
			if !classified || failure != ErrUnavailable {
				t.Fatalf("Classify(Rotate error) = %v, %v, want ErrUnavailable, true", failure, classified)
			}
			assertNoCanary(t, fmt.Sprint(err))
			_, _ = broker.Close(context.Background())
		})
	}
}

func TestPendingRotationLifecycleFences(t *testing.T) {
	tests := []struct {
		name                       string
		lifecycle                  func(*Broker, credential.Request, credential.Request) (ports.RevocationResult, error)
		want                       error
		differentConnectionBinding bool
	}{
		{
			name: "cancel next operation",
			lifecycle: func(broker *Broker, _ credential.Request, next credential.Request) (ports.RevocationResult, error) {
				return broker.CancelOperation(context.Background(), next)
			},
			want: ErrOperationTerminated,
		},
		{
			name: "close next operation",
			lifecycle: func(broker *Broker, _ credential.Request, next credential.Request) (ports.RevocationResult, error) {
				return broker.CloseOperation(context.Background(), next)
			},
			want: ErrOperationTerminated,
		},
		{
			name: "revoke exact next connection target",
			lifecycle: func(broker *Broker, _ credential.Request, next credential.Request) (ports.RevocationResult, error) {
				return broker.RevokeConnection(context.Background(), next)
			},
			want:                       ErrRevoked,
			differentConnectionBinding: true,
		},
		{
			name: "close broker",
			lifecycle: func(broker *Broker, _ credential.Request, _ credential.Request) (ports.RevocationResult, error) {
				return broker.Close(context.Background())
			},
			want: ErrClosed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			base := mustTestRequest(t, defaultTestRequestConfig())
			nextConfig := defaultTestRequestConfig()
			nextConfig.generation = 2
			nextConfig.version = "opaque_B"
			nextConfig.operation = 2
			next := mustTestRequest(t, nextConfig)
			issueEntered := make(chan struct{})
			issueCanceled := make(chan struct{})
			issueReturn := make(chan struct{})
			var callsMu sync.Mutex
			issueCalls := 0
			issuer := &fakeIssuer{
				clock: clock,
				issueFn: func(ctx context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
					callsMu.Lock()
					issueCalls++
					call := issueCalls
					callsMu.Unlock()
					if call == 1 {
						return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
					}
					close(issueEntered)
					<-ctx.Done()
					close(issueCanceled)
					<-issueReturn
					return nil, ctx.Err()
				},
			}
			broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, base.Recipient())
			prior, err := broker.Acquire(context.Background(), base)
			if err != nil {
				t.Fatalf("Acquire(base) error = %v", err)
			}
			_ = prior.Close()
			type rotateResult struct {
				rotation Rotation
				err      error
			}
			resultOut := make(chan rotateResult, 1)
			go func() {
				rotation, err := broker.Rotate(context.Background(), next)
				resultOut <- rotateResult{rotation: rotation, err: err}
			}()
			waitForSignal(t, issueEntered, "pending rotation Issue")
			lifecycleTarget := next
			if test.differentConnectionBinding {
				revokeConfig := nextConfig
				revokeConfig.operation = 3
				lifecycleTarget = mustTestRequest(t, revokeConfig)
				if lifecycleTarget.BindingDigest().Equal(next.BindingDigest()) {
					t.Fatal("connection-scoped lifecycle fixture unexpectedly reused pending rotation binding")
				}
			}
			_, lifecycleErr := test.lifecycle(broker, base, lifecycleTarget)
			if lifecycleErr != nil {
				t.Fatalf("lifecycle fence error = %v", lifecycleErr)
			}
			waitForSignal(t, issueCanceled, "pending rotation cancellation")
			close(issueReturn)
			got := receiveResult(t, resultOut, "fenced Rotate result")
			if got.rotation.Valid() || !errors.Is(got.err, test.want) {
				t.Fatalf("Rotate(after fence) = %v, %v, want invalid, %v", got.rotation, got.err, test.want)
			}
			if test.want != ErrClosed {
				_, _ = broker.Close(context.Background())
			}
		})
	}
}

func TestPendingRotationLifecycleScopeAndConflictMatrix(t *testing.T) {
	t.Run("arbitrary higher generation remains rotation required", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		base := mustTestRequest(t, defaultTestRequestConfig())
		higherConfig := defaultTestRequestConfig()
		higherConfig.generation = 3
		higherConfig.version = "opaque_C"
		higherConfig.operation = 3
		higher := mustTestRequest(t, higherConfig)
		budget := &fakeBudget{}
		resolver := &fakeResolver{}
		issuer := &fakeIssuer{clock: clock}
		broker := mustTestBroker(t, clock, budget, resolver, issuer, base.Recipient())
		lease, err := broker.Acquire(context.Background(), base)
		if err != nil {
			t.Fatalf("Acquire(base) error = %v", err)
		}
		_ = lease.Close()
		claims, resolves, issues, revokes := budget.callCount(), resolver.callCount(), issuer.issueCount(), issuer.revokeCount()
		for name, lifecycle := range map[string]func() (ports.RevocationResult, error){
			"connection": func() (ports.RevocationResult, error) {
				return broker.RevokeConnection(context.Background(), higher)
			},
			"operation": func() (ports.RevocationResult, error) {
				return broker.CancelOperation(context.Background(), higher)
			},
		} {
			t.Run(name, func(t *testing.T) {
				result, err := lifecycle()
				if result != ports.RevocationNotRequired || !errors.Is(err, ErrCredentialRotationRequired) {
					t.Fatalf("higher-generation lifecycle = %v, %v, want not-required, rotation-required", result, err)
				}
			})
		}
		if budget.callCount() != claims || resolver.callCount() != resolves || issuer.issueCount() != issues || issuer.revokeCount() != revokes {
			t.Fatal("rejected arbitrary higher-generation lifecycle called a backend")
		}
		_, _ = broker.Close(context.Background())
	})

	t.Run("same operation with mismatched binding conflicts without canceling flight", func(t *testing.T) {
		clock := newManualClock(testBrokerNow)
		base := mustTestRequest(t, defaultTestRequestConfig())
		nextConfig := defaultTestRequestConfig()
		nextConfig.generation = 2
		nextConfig.version = "opaque_B"
		nextConfig.operation = 2
		next := mustTestRequest(t, nextConfig)
		mismatchConfig := nextConfig
		mismatchConfig.target = 2
		mismatch := mustTestRequest(t, mismatchConfig)
		if mismatch.OperationID() != next.OperationID() || mismatch.BindingDigest().Equal(next.BindingDigest()) {
			t.Fatal("mismatch fixture does not preserve operation ID with a distinct binding")
		}
		issueEntered := make(chan struct{})
		issueRelease := make(chan struct{})
		var issueMu sync.Mutex
		issueCalls := 0
		issuer := &fakeIssuer{
			clock: clock,
			issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
				issueMu.Lock()
				issueCalls++
				call := issueCalls
				issueMu.Unlock()
				if call == 2 {
					close(issueEntered)
					<-issueRelease
				}
				return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
			},
		}
		broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, base.Recipient())
		prior, err := broker.Acquire(context.Background(), base)
		if err != nil {
			t.Fatalf("Acquire(base) error = %v", err)
		}
		_ = prior.Close()
		type outcome struct {
			rotation Rotation
			err      error
		}
		rotationOut := make(chan outcome, 1)
		go func() {
			rotation, err := broker.Rotate(context.Background(), next)
			rotationOut <- outcome{rotation: rotation, err: err}
		}()
		waitForSignal(t, issueEntered, "pending rotation Issue")
		issuesBefore, revokesBefore := issuer.issueCount(), issuer.revokeCount()
		result, err := broker.CancelOperation(context.Background(), mismatch)
		if result != ports.RevocationNotRequired || !errors.Is(err, ErrConflict) {
			t.Fatalf("CancelOperation(mismatched binding) = %v, %v, want not-required, ErrConflict", result, err)
		}
		if issuer.issueCount() != issuesBefore || issuer.revokeCount() != revokesBefore {
			t.Fatal("mismatched operation lifecycle called a backend")
		}
		close(issueRelease)
		rotated := receiveResult(t, rotationOut, "rotation after rejected mismatch")
		if rotated.err != nil || !rotated.rotation.Valid() {
			t.Fatalf("Rotate(after rejected mismatch) = %v, %v, want valid, nil", rotated.rotation, rotated.err)
		}
		_ = rotated.rotation.Lease().Close()
		_, _ = broker.Close(context.Background())
	})
}

func TestRepeatedLifecycleDuringCanceledPendingRotationCleanupIsNeverNotRequired(t *testing.T) {
	followers := []struct {
		name string
		call func(context.Context, *Broker, credential.Request) (ports.RevocationResult, error)
	}{
		{
			name: "CancelOperation",
			call: func(ctx context.Context, broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.CancelOperation(ctx, request)
			},
		},
		{
			name: "CloseOperation",
			call: func(ctx context.Context, broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.CloseOperation(ctx, request)
			},
		},
		{
			name: "RevokeConnection",
			call: func(ctx context.Context, broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.RevokeConnection(ctx, request)
			},
		},
	}
	for _, follower := range followers {
		t.Run(follower.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			base := mustTestRequest(t, defaultTestRequestConfig())
			nextConfig := defaultTestRequestConfig()
			nextConfig.generation = 2
			nextConfig.version = "opaque_B"
			nextConfig.operation = 2
			next := mustTestRequest(t, nextConfig)
			issueEntered := make(chan struct{})
			issueCanceled := make(chan struct{})
			issueReturn := make(chan struct{})
			lateSessionOut := make(chan *credential.IssuedSession, 1)
			revokeEntered := make(chan struct{})
			revokeRelease := make(chan struct{})
			var issueMu sync.Mutex
			issueCalls := 0
			var revokeOnce sync.Once
			issuer := &fakeIssuer{
				clock: clock,
				issueFn: func(ctx context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
					issueMu.Lock()
					issueCalls++
					call := issueCalls
					issueMu.Unlock()
					if call == 1 {
						return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
					}
					close(issueEntered)
					<-ctx.Done()
					close(issueCanceled)
					<-issueReturn
					session, err := newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
					if err == nil {
						lateSessionOut <- session
					}
					return session, err
				},
				revokeFn: func(ctx context.Context, _ credential.Request, session *credential.IssuedSession) (ports.RevocationResult, error) {
					if !session.Valid() {
						t.Error("late rotation session destroyed before upstream Revoke")
					}
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
			resolver := &fakeResolver{}
			broker := mustTestBroker(t, clock, budget, resolver, issuer, base.Recipient())
			prior, err := broker.Acquire(context.Background(), base)
			if err != nil {
				t.Fatalf("Acquire(base) error = %v", err)
			}
			baseExpiresAt := prior.ExpiresAt()
			_ = prior.Close()
			clock.Set(baseExpiresAt)
			if err := broker.SweepExpired(); err != nil {
				t.Fatalf("SweepExpired(base provider expiry) error = %v", err)
			}

			type rotateResult struct {
				rotation Rotation
				err      error
			}
			rotationOut := make(chan rotateResult, 1)
			go func() {
				rotation, err := broker.Rotate(context.Background(), next)
				rotationOut <- rotateResult{rotation: rotation, err: err}
			}()
			waitForSignal(t, issueEntered, "pending rotation Issue")
			leaderResult, leaderErr := broker.CancelOperation(context.Background(), next)
			if leaderErr != nil || leaderResult != ports.RevocationPending {
				t.Fatalf("initial CancelOperation = %v, %v, want pending, nil", leaderResult, leaderErr)
			}
			waitForSignal(t, issueCanceled, "pending rotation cancellation")

			callWithMidCallCancellation := func(label string) lifecycleOutcome {
				entered := make(chan struct{}, 1)
				release := make(chan struct{})
				broker.mu.Lock()
				broker.clock = &barrierClock{now: clock.Now(), entered: entered, release: release}
				broker.mu.Unlock()
				ctx, cancel := context.WithCancel(context.Background())
				out := make(chan lifecycleOutcome, 1)
				go func() {
					result, err := follower.call(ctx, broker, next)
					out <- lifecycleOutcome{result: result, err: err}
				}()
				receiveResult(t, entered, label+" clock entry")
				cancel()
				close(release)
				got := receiveResult(t, out, label+" result")
				broker.mu.Lock()
				broker.clock = clock
				broker.mu.Unlock()
				return got
			}
			assertPending := func(label string, got lifecycleOutcome) {
				t.Helper()
				if got.result != ports.RevocationPending ||
					(got.err != nil && !errors.Is(got.err, context.Canceled)) {
					t.Errorf("%s = %v, %v, want pending with nil or context.Canceled", label, got.result, got.err)
				}
			}
			assertPending("lifecycle while Issue is outstanding", callWithMidCallCancellation("outstanding Issue lifecycle"))

			close(issueReturn)
			lateSession := receiveResult(t, lateSessionOut, "late rotation Issue output")
			waitForSignal(t, revokeEntered, "late rotation cleanup Revoke")
			assertPending("lifecycle while cleanup Revoke is outstanding", callWithMidCallCancellation("outstanding cleanup lifecycle"))
			assertNoResult(t, rotationOut, "Rotate waiter before unpublished cleanup")
			if !lateSession.Valid() {
				t.Error("late rotation session destroyed before cleanup Revoke completion")
			}
			close(revokeRelease)
			rotated := receiveResult(t, rotationOut, "canceled Rotate after cleanup")
			wantRotationErr := ErrOperationTerminated
			if follower.name == "RevokeConnection" {
				wantRotationErr = ErrRevoked
			}
			if rotated.rotation.Valid() || !errors.Is(rotated.err, wantRotationErr) {
				t.Fatalf("Rotate(after lifecycle cleanup) = %v, %v, want invalid, %v", rotated.rotation, rotated.err, wantRotationErr)
			}
			if lateSession.Valid() {
				t.Fatal("late rotation Issue output remains valid after waiter completion")
			}
			if got := issuer.revokeCount(); got != 1 {
				t.Fatalf("cleanup Revoke calls = %d, want exactly 1", got)
			}
			broker.mu.Lock()
			lineageBefore := *broker.lineages[keyForConnection(next)]
			operationBefore := *broker.operations[keyForOperation(next)]
			nextEpochBefore := broker.nextEpoch
			lineagesBefore := len(broker.lineages)
			operationsBefore := len(broker.operations)
			broker.mu.Unlock()
			claimsBefore, resolvesBefore := budget.callCount(), resolver.callCount()
			issuesBefore, revokesBefore := issuer.issueCount(), issuer.revokeCount()

			result, replayErr := follower.call(context.Background(), broker, next)
			if replayErr != nil ||
				(result != ports.RevocationNotRequired && result != ports.RevocationExpiryBound) {
				t.Fatalf("%s(exact completed pending target) = %v, %v, want idempotent not-required/expiry-bound", follower.name, result, replayErr)
			}
			if follower.name != "RevokeConnection" {
				conflictConfig := nextConfig
				conflictConfig.version = "opaque_conflict"
				conflict := mustTestRequest(t, conflictConfig)
				if result, conflictErr := follower.call(context.Background(), broker, conflict); result != ports.RevocationNotRequired || !errors.Is(conflictErr, ErrConflict) {
					t.Fatalf("%s(conflicting terminal operation) = %v, %v, want not-required, ErrConflict", follower.name, result, conflictErr)
				}

				higherConfig := nextConfig
				higherConfig.operation = 3
				higher := mustTestRequest(t, higherConfig)
				if result, higherErr := follower.call(context.Background(), broker, higher); result != ports.RevocationNotRequired || !errors.Is(higherErr, ErrCredentialRotationRequired) {
					t.Fatalf("%s(unbound higher-generation operation) = %v, %v, want not-required, ErrCredentialRotationRequired", follower.name, result, higherErr)
				}
			}
			if budget.callCount() != claimsBefore || resolver.callCount() != resolvesBefore ||
				issuer.issueCount() != issuesBefore || issuer.revokeCount() != revokesBefore {
				t.Fatalf("idempotent or rejected %s replay called a backend", follower.name)
			}
			broker.mu.Lock()
			lineageAfter := broker.lineages[keyForConnection(next)]
			operationAfter := broker.operations[keyForOperation(next)]
			nextEpochAfter := broker.nextEpoch
			lineagesAfter := len(broker.lineages)
			operationsAfter := len(broker.operations)
			broker.mu.Unlock()
			if lineageAfter == nil || *lineageAfter != lineageBefore ||
				operationAfter == nil || *operationAfter != operationBefore ||
				nextEpochAfter != nextEpochBefore || lineagesAfter != lineagesBefore ||
				operationsAfter != operationsBefore {
				t.Fatalf("%s replay classification mutated broker state", follower.name)
			}
			_, _ = broker.Close(context.Background())
		})
	}
}

func TestRepeatedCurrentGenerationRevokeTracksCanceledNextRotationCleanup(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 2
	next := mustTestRequest(t, nextConfig)
	issueEntered := make(chan struct{})
	issueCanceled := make(chan struct{})
	issueReturn := make(chan struct{})
	lateSessionOut := make(chan *credential.IssuedSession, 1)
	cleanupRevokeEntered := make(chan struct{})
	cleanupRevokeRelease := make(chan struct{})
	var mu sync.Mutex
	issueCalls := 0
	baseRevokes := 0
	cleanupRevokes := 0
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(ctx context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
			mu.Lock()
			issueCalls++
			call := issueCalls
			mu.Unlock()
			if call == 1 {
				return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
			}
			close(issueEntered)
			<-ctx.Done()
			close(issueCanceled)
			<-issueReturn
			session, err := newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
			if err == nil {
				lateSessionOut <- session
			}
			return session, err
		},
		revokeFn: func(ctx context.Context, request credential.Request, session *credential.IssuedSession) (ports.RevocationResult, error) {
			if request.ConnectionGeneration() == base.ConnectionGeneration() {
				mu.Lock()
				baseRevokes++
				mu.Unlock()
				return ports.RevocationProviderConfirmed, nil
			}
			if !session.Valid() {
				t.Error("late rotation output destroyed before cleanup Revoke")
			}
			mu.Lock()
			cleanupRevokes++
			call := cleanupRevokes
			mu.Unlock()
			if call == 1 {
				close(cleanupRevokeEntered)
			}
			select {
			case <-cleanupRevokeRelease:
				return ports.RevocationProviderConfirmed, nil
			case <-ctx.Done():
				return ports.RevocationPending, ctx.Err()
			}
		},
	}
	budget := &fakeBudget{}
	resolver := &fakeResolver{}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, base.Recipient())
	prior, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	_ = prior.Close()
	type rotateResult struct {
		rotation Rotation
		err      error
	}
	rotationOut := make(chan rotateResult, 1)
	go func() {
		rotation, err := broker.Rotate(context.Background(), next)
		rotationOut <- rotateResult{rotation: rotation, err: err}
	}()
	waitForSignal(t, issueEntered, "next-generation Issue")
	result, err := broker.RevokeConnection(context.Background(), base)
	if err != nil || result != ports.RevocationPending {
		t.Fatalf("first RevokeConnection(current generation) = %v, %v, want pending, nil", result, err)
	}
	broker.mu.Lock()
	revokedThrough := broker.lineages[keyForConnection(base)].revokedThrough
	broker.mu.Unlock()
	if revokedThrough != next.ConnectionGeneration() {
		t.Fatalf("revoked-through after canceling pending rotation = %d, want %d", revokedThrough, next.ConnectionGeneration())
	}
	waitForSignal(t, issueCanceled, "next-generation Issue cancellation")
	assertRevokedTargetRejected := func(label string) {
		claims, resolves := budget.callCount(), resolver.callCount()
		issues, revokes := issuer.issueCount(), issuer.revokeCount()
		if lease, acquireErr := broker.Acquire(context.Background(), next); lease != nil || !errors.Is(acquireErr, ErrRevoked) {
			t.Fatalf("Acquire(%s canceled rotation target) = %v, %v, want nil, ErrRevoked", label, lease, acquireErr)
		}
		if rotation, rotateErr := broker.Rotate(context.Background(), next); rotation.Valid() || !errors.Is(rotateErr, ErrRevoked) {
			t.Fatalf("Rotate(%s canceled rotation target) = %v, %v, want invalid, ErrRevoked", label, rotation, rotateErr)
		}
		if budget.callCount() != claims || resolver.callCount() != resolves ||
			issuer.issueCount() != issues || issuer.revokeCount() != revokes {
			t.Fatalf("%s canceled rotation target classification called a backend", label)
		}
	}
	assertRevokedTargetRejected("during Issue cleanup")

	repeatWithMidCallCancellation := func(label string, request credential.Request) lifecycleOutcome {
		mu.Lock()
		beforeBaseRevokes, beforeCleanupRevokes := baseRevokes, cleanupRevokes
		mu.Unlock()
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		broker.mu.Lock()
		broker.clock = &barrierClock{now: clock.Now(), entered: entered, release: release}
		broker.mu.Unlock()
		ctx, cancel := context.WithCancel(context.Background())
		out := make(chan lifecycleOutcome, 1)
		go func() {
			result, err := broker.RevokeConnection(ctx, request)
			out <- lifecycleOutcome{result: result, err: err}
		}()
		receiveResult(t, entered, label+" clock entry")
		cancel()
		close(release)
		got := receiveResult(t, out, label+" result")
		broker.mu.Lock()
		broker.clock = clock
		broker.mu.Unlock()
		if got.result != ports.RevocationPending ||
			(got.err != nil && !errors.Is(got.err, context.Canceled)) {
			t.Errorf("%s = %v, %v, want pending with nil or context.Canceled", label, got.result, got.err)
		}
		mu.Lock()
		afterBaseRevokes, afterCleanupRevokes := baseRevokes, cleanupRevokes
		mu.Unlock()
		if afterBaseRevokes != beforeBaseRevokes || afterCleanupRevokes != beforeCleanupRevokes {
			t.Errorf("%s dispatched duplicate Revoke: before=%d/%d after=%d/%d",
				label,
				beforeBaseRevokes,
				beforeCleanupRevokes,
				afterBaseRevokes,
				afterCleanupRevokes,
			)
		}
		return got
	}
	repeatWithMidCallCancellation("current generation while next Issue is outstanding", base)
	repeatWithMidCallCancellation("target generation while next Issue is outstanding", next)
	close(issueReturn)
	lateSession := receiveResult(t, lateSessionOut, "late next-generation Issue output")
	waitForSignal(t, cleanupRevokeEntered, "late Issue cleanup Revoke")
	assertRevokedTargetRejected("during Revoke cleanup")
	repeatWithMidCallCancellation("current generation while cleanup Revoke is outstanding", base)
	repeatWithMidCallCancellation("target generation while cleanup Revoke is outstanding", next)
	assertNoResult(t, rotationOut, "Rotate before late output cleanup")
	if !lateSession.Valid() {
		t.Error("late next-generation Issue output destroyed before cleanup Revoke completed")
	}
	close(cleanupRevokeRelease)
	rotated := receiveResult(t, rotationOut, "Rotate after current-generation revoke cleanup")
	if rotated.rotation.Valid() || !errors.Is(rotated.err, ErrRevoked) {
		t.Fatalf("Rotate(after current-generation revoke) = %v, %v, want invalid, ErrRevoked", rotated.rotation, rotated.err)
	}
	if lateSession.Valid() {
		t.Fatal("late next-generation Issue output remains valid after Rotate returned")
	}
	mu.Lock()
	gotBaseRevokes, gotCleanupRevokes := baseRevokes, cleanupRevokes
	mu.Unlock()
	if gotBaseRevokes != 1 || gotCleanupRevokes != 1 {
		t.Fatalf("Revoke calls = base:%d cleanup:%d, want 1/1", gotBaseRevokes, gotCleanupRevokes)
	}
	assertRevokedTargetRejected("after cleanup")
	result, err = broker.RevokeConnection(context.Background(), next)
	if err != nil || result != ports.RevocationNotRequired {
		t.Fatalf("RevokeConnection(canceled target after cleanup) = %v, %v, want not-required, nil", result, err)
	}
	mu.Lock()
	gotBaseRevokes, gotCleanupRevokes = baseRevokes, cleanupRevokes
	mu.Unlock()
	if gotBaseRevokes != 1 || gotCleanupRevokes != 1 {
		t.Fatalf("idempotent Revoke calls = base:%d cleanup:%d, want 1/1", gotBaseRevokes, gotCleanupRevokes)
	}
	_, _ = broker.Close(context.Background())
}

func TestRotationSourceTTLIsResolutionBasedAcrossNonCooperativeIssue(t *testing.T) {
	tests := []struct {
		name        string
		advance     time.Duration
		wantSuccess bool
	}{
		{name: "commit before expiry", advance: MaxSourceCacheTTL - time.Minute, wantSuccess: true},
		{name: "reject at exact expiry", advance: MaxSourceCacheTTL},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			base := mustTestRequest(t, defaultTestRequestConfig())
			nextConfig := defaultTestRequestConfig()
			nextConfig.generation = 2
			nextConfig.version = "opaque_B"
			nextConfig.operation = 2
			next := mustTestRequest(t, nextConfig)
			issueEntered := make(chan struct{})
			issueRelease := make(chan struct{})
			var issueMu sync.Mutex
			issueCalls := 0
			issuer := &fakeIssuer{
				clock: clock,
				issueFn: func(_ context.Context, request credential.Request, _ *credential.SourceMaterial) (*credential.IssuedSession, error) {
					issueMu.Lock()
					issueCalls++
					call := issueCalls
					issueMu.Unlock()
					if call == 2 {
						close(issueEntered)
						<-issueRelease
					}
					return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
				},
			}
			resolver := &fakeResolver{}
			broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, base.Recipient())
			prior, err := broker.Acquire(context.Background(), base)
			if err != nil {
				t.Fatalf("Acquire(base) error = %v", err)
			}
			type rotateOutcome struct {
				rotation Rotation
				err      error
			}
			resultOut := make(chan rotateOutcome, 1)
			go func() {
				rotation, err := broker.Rotate(context.Background(), next)
				resultOut <- rotateOutcome{rotation: rotation, err: err}
			}()
			waitForSignal(t, issueEntered, "non-cooperative rotation Issue")
			clock.Add(test.advance)
			close(issueRelease)
			got := receiveResult(t, resultOut, "Rotate after delayed Issue")
			materials := resolver.materialSnapshot()
			sessions := issuer.sessionSnapshot()
			if len(materials) != 2 || len(sessions) != 2 {
				t.Fatalf("owned outputs = sources:%d sessions:%d, want 2/2", len(materials), len(sessions))
			}
			wantExpiresAt := testBrokerNow.Add(MaxSourceCacheTTL)
			broker.mu.Lock()
			entry := broker.sources[next.SourceLookup().Digest()]
			lineage := broker.lineages[keyForConnection(base)]
			generation := lineage.generation
			reservations := broker.sourceReservations + broker.sessionReservations +
				broker.operationReservations + broker.leaseReservations
			_, rotationPresent := broker.rotations[keyForConnection(next)]
			broker.mu.Unlock()
			if test.wantSuccess {
				if got.err != nil || !got.rotation.Valid() {
					t.Fatalf("Rotate(before source expiry) = %v, %v, want committed rotation", got.rotation, got.err)
				}
				if entry == nil || !entry.expiresAt.Equal(wantExpiresAt) {
					t.Fatalf("rotated source expiry present/equal = %v/%v, want true/true", entry != nil, entry != nil && entry.expiresAt.Equal(wantExpiresAt))
				}
				if materials[0].Valid() || !materials[1].Valid() || sessions[0].Valid() || !sessions[1].Valid() {
					t.Fatalf("rotation material validity = sources:%v/%v sessions:%v/%v, want false/true/false/true", materials[0].Valid(), materials[1].Valid(), sessions[0].Valid(), sessions[1].Valid())
				}
				_ = got.rotation.Lease().Close()
			} else {
				if got.rotation.Valid() || !errors.Is(got.err, ErrUnavailable) {
					t.Fatalf("Rotate(at source expiry) = %v, %v, want invalid, ErrUnavailable", got.rotation, got.err)
				}
				if entry != nil || !materials[0].Valid() || materials[1].Valid() ||
					!sessions[0].Valid() || sessions[1].Valid() {
					t.Fatalf("failed rotation retained or destroyed wrong authority: nextEntry=%v sourceValid=%v/%v sessionValid=%v/%v", entry != nil, materials[0].Valid(), materials[1].Valid(), sessions[0].Valid(), sessions[1].Valid())
				}
			}
			if rotationPresent || reservations != 0 {
				t.Fatalf("rotation state after completion = present:%v reservations:%d, want false/0", rotationPresent, reservations)
			}
			if test.wantSuccess && generation != next.ConnectionGeneration() ||
				!test.wantSuccess && generation != base.ConnectionGeneration() {
				t.Fatalf("lineage generation = %d, success=%v", generation, test.wantSuccess)
			}
			wantRevokes := 1
			if test.wantSuccess {
				wantRevokes = 0
			}
			if got := issuer.revokeCount(); got != wantRevokes {
				t.Fatalf("upstream Revoke calls = %d, want %d", got, wantRevokes)
			}
			_ = prior.Close()
			_, _ = broker.Close(context.Background())
		})
	}
}

func TestRotationCommitReservesEpochPairAtomically(t *testing.T) {
	maximum := ^uint64(0)
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 2
	next := mustTestRequest(t, nextConfig)
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, base.Recipient())
	prior, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	broker.mu.Lock()
	baseLineage := broker.lineages[keyForConnection(base)]
	baseEpoch := baseLineage.epoch
	baseCell := broker.sessions[base.BindingDigest()]
	broker.nextEpoch = maximum - 1
	broker.mu.Unlock()

	rotation, err := broker.Rotate(context.Background(), next)
	if rotation.Valid() || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Rotate(with one epoch remaining) = %v, %v, want invalid, ErrUnavailable", rotation, err)
	}
	materials := resolver.materialSnapshot()
	sessions := issuer.sessionSnapshot()
	if len(materials) != 2 || len(sessions) != 2 {
		t.Fatalf("owned outputs = sources:%d sessions:%d, want 2/2", len(materials), len(sessions))
	}
	broker.mu.Lock()
	lineage := broker.lineages[keyForConnection(base)]
	currentCell := broker.sessions[base.BindingDigest()]
	_, nextOperation := broker.operations[keyForOperation(next)]
	_, rotationPresent := broker.rotations[keyForConnection(next)]
	nextEpoch := broker.nextEpoch
	reservations := broker.sourceReservations + broker.sessionReservations +
		broker.operationReservations + broker.leaseReservations
	broker.mu.Unlock()
	if lineage != baseLineage || lineage.generation != base.ConnectionGeneration() ||
		lineage.epoch != baseEpoch || currentCell != baseCell || nextOperation ||
		rotationPresent || nextEpoch != maximum-1 || reservations != 0 {
		t.Fatalf("failed commit mutated state: baseLineage=%v generation=%d epoch=%d baseCell=%v nextOp=%v rotation=%v nextEpoch=%d reservations=%d",
			lineage == baseLineage, lineage.generation, lineage.epoch, currentCell == baseCell,
			nextOperation, rotationPresent, nextEpoch, reservations)
	}
	if !materials[0].Valid() || materials[1].Valid() || !sessions[0].Valid() || sessions[1].Valid() {
		t.Fatalf("failed commit material validity = sources:%v/%v sessions:%v/%v, want true/false/true/false",
			materials[0].Valid(), materials[1].Valid(), sessions[0].Valid(), sessions[1].Valid())
	}
	if got := issuer.revokeCount(); got != 1 {
		t.Fatalf("unpublished next-session Revoke calls = %d, want 1", got)
	}
	if err := prior.Use(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatalf("base Lease.Use() after failed commit error = %v", err)
	}
	_ = prior.Close()
	_, _ = broker.Close(context.Background())
}

func TestLastRotationWaiterInvalidatesSourceBeforeIssueCancelAndRetainsCapacity(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	nextConfig := defaultTestRequestConfig()
	nextConfig.generation = 2
	nextConfig.version = "opaque_B"
	nextConfig.operation = 2
	next := mustTestRequest(t, nextConfig)
	issueEntered := make(chan struct{})
	sourceValidAtCancel := make(chan bool, 1)
	issueRelease := make(chan struct{})
	var issueMu sync.Mutex
	issueCalls := 0
	issuer := &fakeIssuer{
		clock: clock,
		issueFn: func(
			ctx context.Context,
			request credential.Request,
			source *credential.SourceMaterial,
		) (*credential.IssuedSession, error) {
			issueMu.Lock()
			issueCalls++
			call := issueCalls
			issueMu.Unlock()
			if call == 1 {
				return newTestSession(request, clock.Now(), credential.RequestedSessionTTL)
			}
			close(issueEntered)
			<-ctx.Done()
			sourceValidAtCancel <- source.Valid()
			<-issueRelease
			return nil, ctx.Err()
		},
	}
	resolver := &fakeResolver{}
	broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, base.Recipient())
	baseLease, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	type rotateOutcome struct {
		rotation Rotation
		err      error
	}
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	rotated := make(chan rotateOutcome, 1)
	go func() {
		rotation, err := broker.Rotate(callerCtx, next)
		rotated <- rotateOutcome{rotation: rotation, err: err}
	}()
	waitForSignal(t, issueEntered, "blocked rotation Issue")
	materials := resolver.materialSnapshot()
	if len(materials) != 2 || materials[0] == nil || materials[1] == nil ||
		!materials[0].Valid() || !materials[1].Valid() {
		t.Fatalf("rotation sources = %v, want two live materials before abandonment", materials)
	}
	broker.mu.Lock()
	flight := broker.rotations[keyForConnection(next)]
	broker.mu.Unlock()
	if flight == nil {
		t.Fatal("rotation flight missing while Issue is blocked")
	}
	cancelCaller()
	if valid := receiveResult(t, sourceValidAtCancel, "source validity at rotation Issue cancellation"); valid {
		t.Fatal("rotation Issue observed cancellation before private source destruction")
	}
	result := receiveResult(t, rotated, "last rotation waiter cancellation")
	if result.rotation.Valid() || !errors.Is(result.err, context.Canceled) {
		t.Fatalf("Rotate(canceled) = %v, %v, want invalid, context.Canceled", result.rotation, result.err)
	}
	if !materials[0].Valid() {
		t.Fatal("rotation abandonment destroyed current-lineage cached source")
	}
	broker.mu.Lock()
	flightPresent := broker.rotations[keyForConnection(next)] == flight
	sourceReservations := broker.sourceReservations
	sessionReservations := broker.sessionReservations
	operationReservations := broker.operationReservations
	broker.mu.Unlock()
	if !flightPresent || sourceReservations == 0 || sessionReservations == 0 ||
		operationReservations == 0 {
		t.Fatalf(
			"blocked abandoned rotation released capacity: flight=%v source=%d session=%d operation=%d",
			flightPresent,
			sourceReservations,
			sessionReservations,
			operationReservations,
		)
	}
	if err := baseLease.Use(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatalf("base Lease.Use(after rotation abandonment) error = %v", err)
	}
	close(issueRelease)
	waitForCondition(t, "abandoned rotation cleanup", func() bool {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		return broker.rotations[keyForConnection(next)] == nil &&
			broker.sourceReservations == 0 && broker.sessionReservations == 0 &&
			broker.operationReservations == 0
	})
	if materials[1].Valid() {
		t.Fatal("abandoned rotation source remains valid after cleanup")
	}
	if got := issuer.revokeCount(); got != 0 {
		t.Fatalf("upstream Revoke calls for nil abandoned Issue output = %d, want 0", got)
	}
	_ = baseLease.Close()
	_, _ = broker.Close(context.Background())
}
