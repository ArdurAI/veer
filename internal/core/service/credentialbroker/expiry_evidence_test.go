package credentialbroker

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

type expiryEvidenceFixture struct {
	broker     *Broker
	clock      *manualClock
	request    credential.Request
	issuer     *fakeIssuer
	discarded  *credential.IssuedSession
	expiresAt  time.Time
	additional []*Lease
}

func TestDiscardedLiveSessionPreservesExpiryEvidenceAcrossLifecycle(t *testing.T) {
	disposals := []struct {
		name  string
		build func(*testing.T) expiryEvidenceFixture
	}{
		{name: "successful refresh replacement", build: refreshReplacementExpiryFixture},
		{name: "local-use cutoff sweep", build: cutoffSweepExpiryFixture},
		{name: "capacity LRU eviction", build: lruEvictionExpiryFixture},
		{name: "last draining Lease.Close", build: drainingLeaseCloseExpiryFixture},
	}
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
			name: "operation cancel",
			call: func(broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.CancelOperation(context.Background(), request)
			},
		},
		{
			name: "operation close",
			call: func(broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.CloseOperation(context.Background(), request)
			},
		},
		{
			name: "broker close",
			call: func(broker *Broker, _ credential.Request) (ports.RevocationResult, error) {
				return broker.Close(context.Background())
			},
		},
	}

	for _, disposal := range disposals {
		for _, lifecycle := range lifecycles {
			t.Run(disposal.name+"/"+lifecycle.name, func(t *testing.T) {
				fixture := disposal.build(t)
				assertRecordedExpiryEvidence(t, fixture)

				result, err := lifecycle.call(fixture.broker, fixture.request)
				if err != nil || result != ports.RevocationExpiryBound {
					t.Fatalf("lifecycle before provider expiry = %v, %v, want expiry-bound, nil", result, err)
				}
				fixture.clock.Set(fixture.expiresAt)
				result, err = lifecycle.call(fixture.broker, fixture.request)
				if err != nil || result != ports.RevocationNotRequired {
					t.Fatalf("lifecycle at provider expiry = %v, %v, want not-required, nil", result, err)
				}
				closeExpiryFixture(t, fixture)
			})
		}
	}
}

func TestDiscardedLiveSessionContributesToRotationPriorRevocation(t *testing.T) {
	disposals := []struct {
		name  string
		build func(*testing.T) expiryEvidenceFixture
	}{
		{name: "successful refresh replacement", build: refreshReplacementExpiryFixture},
		{name: "local-use cutoff sweep", build: cutoffSweepExpiryFixture},
		{name: "capacity LRU eviction", build: lruEvictionExpiryFixture},
		{name: "last draining Lease.Close", build: drainingLeaseCloseExpiryFixture},
	}
	for _, disposal := range disposals {
		t.Run(disposal.name, func(t *testing.T) {
			fixture := disposal.build(t)
			assertRecordedExpiryEvidence(t, fixture)
			nextConfig := defaultTestRequestConfig()
			nextConfig.generation = 2
			nextConfig.version = "opaque_B"
			nextConfig.operation = 2
			next := mustTestRequest(t, nextConfig)

			rotation, err := fixture.broker.Rotate(context.Background(), next)
			if err != nil || !rotation.Valid() {
				t.Fatalf("Rotate() = %v, %v, want committed rotation", rotation, err)
			}
			if got := rotation.PriorRevocation(); got != ports.RevocationExpiryBound {
				t.Fatalf("Rotation.PriorRevocation() = %v, want expiry-bound", got)
			}
			fixture.additional = append(fixture.additional, rotation.Lease())
			fixture.clock.Set(fixture.expiresAt)
			if err := fixture.broker.SweepExpired(); err != nil {
				t.Fatalf("SweepExpired(at prior provider expiry) error = %v", err)
			}
			fixture.broker.mu.Lock()
			lineageEvidence := fixture.broker.lineages[keyForConnection(next)].expiryBoundUntil
			operationEvidence := fixture.broker.operations[keyForOperation(fixture.request)].expiryBoundUntil
			fixture.broker.mu.Unlock()
			if !lineageEvidence.IsZero() || !operationEvidence.IsZero() {
				t.Fatalf("expiry evidence at provider expiry = connection:%v operation:%v, want zero", lineageEvidence, operationEvidence)
			}
			closeExpiryFixture(t, fixture)
		})
	}
}

func TestExpiryEvidenceIsConnectionWideButOperationScoped(t *testing.T) {
	fixture := cutoffSweepExpiryFixture(t)
	assertRecordedExpiryEvidence(t, fixture)
	otherConfig := defaultTestRequestConfig()
	otherConfig.operation = 2
	otherConfig.target = 2
	otherOperation := mustTestRequest(t, otherConfig)

	result, err := fixture.broker.CancelOperation(context.Background(), otherOperation)
	if err != nil || result != ports.RevocationNotRequired {
		t.Fatalf("CancelOperation(unrelated operation) = %v, %v, want not-required, nil", result, err)
	}
	result, err = fixture.broker.RevokeConnection(context.Background(), otherOperation)
	if err != nil || result != ports.RevocationExpiryBound {
		t.Fatalf("RevokeConnection(same connection, other operation) = %v, %v, want expiry-bound, nil", result, err)
	}
	fixture.clock.Set(fixture.expiresAt)
	result, err = fixture.broker.RevokeConnection(context.Background(), otherOperation)
	if err != nil || result != ports.RevocationNotRequired {
		t.Fatalf("RevokeConnection(at provider expiry) = %v, %v, want not-required, nil", result, err)
	}
	closeExpiryFixture(t, fixture)
}

func TestRepeatedCloseRefreshesAndSweepsExpiryEvidence(t *testing.T) {
	fixture := cutoffSweepExpiryFixture(t)
	assertRecordedExpiryEvidence(t, fixture)

	result, err := fixture.broker.Close(context.Background())
	if err != nil || result != ports.RevocationExpiryBound {
		t.Fatalf("Close(first) = %v, %v, want expiry-bound, nil", result, err)
	}
	fixture.clock.Set(fixture.expiresAt.Add(-time.Nanosecond))
	result, err = fixture.broker.Close(context.Background())
	if err != nil || result != ports.RevocationExpiryBound {
		t.Fatalf("Close(before provider expiry) = %v, %v, want expiry-bound, nil", result, err)
	}
	fixture.clock.Set(fixture.expiresAt)
	result, err = fixture.broker.Close(context.Background())
	if err != nil || result != ports.RevocationNotRequired {
		t.Fatalf("Close(at provider expiry) = %v, %v, want not-required, nil", result, err)
	}
}

func TestRepeatedCloseTimeRegressionFailsClosedWithoutLosingExpiryEvidence(t *testing.T) {
	fixture := cutoffSweepExpiryFixture(t)
	result, err := fixture.broker.Close(context.Background())
	if err != nil || result != ports.RevocationExpiryBound {
		t.Fatalf("Close(first) = %v, %v, want expiry-bound, nil", result, err)
	}
	fixture.clock.Set(fixture.clock.Now().Add(-time.Nanosecond))
	result, err = fixture.broker.Close(context.Background())
	if result != ports.RevocationPending || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Close(regressed clock) = %v, %v, want pending, ErrUnavailable", result, err)
	}
	fixture.clock.Set(fixture.expiresAt)
	result, err = fixture.broker.Close(context.Background())
	if err != nil || result != ports.RevocationNotRequired {
		t.Fatalf("Close(at provider expiry after regression) = %v, %v, want not-required, nil", result, err)
	}
}

func refreshReplacementExpiryFixture(t *testing.T) expiryEvidenceFixture {
	t.Helper()
	fixture, lease := acquireExpiryFixture(t)
	discarded := lease.state.cell.session
	if err := lease.Close(); err != nil {
		t.Fatalf("prior Lease.Close() error = %v", err)
	}
	replacement, err := fixture.broker.Refresh(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	fixture.discarded = discarded
	fixture.additional = append(fixture.additional, replacement)
	return fixture
}

func cutoffSweepExpiryFixture(t *testing.T) expiryEvidenceFixture {
	t.Helper()
	fixture, lease := acquireExpiryFixture(t)
	fixture.discarded = lease.state.cell.session
	if err := lease.Close(); err != nil {
		t.Fatalf("Lease.Close() error = %v", err)
	}
	cutoff := fixture.expiresAt.Add(-credential.SessionExpirySkew - credential.MinNewUseLifetime)
	fixture.clock.Set(cutoff.Add(time.Nanosecond))
	if err := fixture.broker.SweepExpired(); err != nil {
		t.Fatalf("SweepExpired(after local-use cutoff) error = %v", err)
	}
	return fixture
}

func lruEvictionExpiryFixture(t *testing.T) expiryEvidenceFixture {
	t.Helper()
	fixture, lease := acquireExpiryFixture(t)
	targetCell := lease.state.cell
	fixture.discarded = targetCell.session
	if err := lease.Close(); err != nil {
		t.Fatalf("Lease.Close() error = %v", err)
	}

	type dummyCell struct {
		cell   *sessionCell
		cancel context.CancelFunc
	}
	dummies := make([]dummyCell, 0, MaxSessionEntries-1)
	fixture.broker.mu.Lock()
	for index := uint64(0); index < MaxSessionEntries-1; index++ {
		invalidCtx, invalidCancel := context.WithCancel(context.Background())
		cell := &sessionCell{
			lastUsed:      targetCell.lastUsed + index + 1,
			invalidCtx:    invalidCtx,
			invalidCancel: invalidCancel,
		}
		fixture.broker.cells[cell] = struct{}{}
		dummies = append(dummies, dummyCell{cell: cell, cancel: invalidCancel})
	}
	fixture.broker.mu.Unlock()

	otherConfig := defaultTestRequestConfig()
	otherConfig.connection = 2
	otherConfig.operation = 99
	otherConfig.target = 2
	other := mustTestRequest(t, otherConfig)
	otherLease, err := fixture.broker.Acquire(context.Background(), other)
	if err != nil {
		t.Fatalf("Acquire(triggering LRU eviction) error = %v", err)
	}
	fixture.additional = append(fixture.additional, otherLease)
	fixture.broker.mu.Lock()
	for _, dummy := range dummies {
		delete(fixture.broker.cells, dummy.cell)
	}
	fixture.broker.mu.Unlock()
	for _, dummy := range dummies {
		dummy.cancel()
	}
	return fixture
}

func drainingLeaseCloseExpiryFixture(t *testing.T) expiryEvidenceFixture {
	t.Helper()
	fixture, prior := acquireExpiryFixture(t)
	fixture.discarded = prior.state.cell.session
	replacement, err := fixture.broker.Refresh(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !fixture.discarded.Valid() {
		t.Fatal("borrowed draining session destroyed before final Lease.Close")
	}
	if err := prior.Close(); err != nil {
		t.Fatalf("final draining Lease.Close() error = %v", err)
	}
	fixture.additional = append(fixture.additional, replacement)
	return fixture
}

func acquireExpiryFixture(t *testing.T) (expiryEvidenceFixture, *Lease) {
	t.Helper()
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
	lease, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	return expiryEvidenceFixture{
		broker:    broker,
		clock:     clock,
		request:   request,
		issuer:    issuer,
		expiresAt: lease.ExpiresAt(),
	}, lease
}

func assertRecordedExpiryEvidence(t *testing.T, fixture expiryEvidenceFixture) {
	t.Helper()
	if fixture.discarded == nil || fixture.discarded.Valid() {
		t.Fatal("provider-live discarded session was not destroyed locally")
	}
	fixture.broker.mu.Lock()
	lineage := fixture.broker.lineages[keyForConnection(fixture.request)]
	operation := fixture.broker.operations[keyForOperation(fixture.request)]
	lineageEvidence := lineage.expiryBoundUntil
	operationEvidence := operation.expiryBoundUntil
	retainedDiscard := false
	for cell := range fixture.broker.cells {
		if cell.session == fixture.discarded {
			retainedDiscard = true
		}
	}
	fixture.broker.mu.Unlock()
	if retainedDiscard {
		t.Fatal("discarded session remains in broker cells after local destruction")
	}
	if !lineageEvidence.Equal(fixture.expiresAt) || !operationEvidence.Equal(fixture.expiresAt) {
		t.Fatalf("expiry evidence = connection:%v operation:%v, want %v", lineageEvidence, operationEvidence, fixture.expiresAt)
	}
	assertNoCanary(t, fmt.Sprint(fixture.broker, lineageEvidence, operationEvidence))
}

func closeExpiryFixture(t *testing.T, fixture expiryEvidenceFixture) {
	t.Helper()
	for _, lease := range fixture.additional {
		if lease != nil {
			_ = lease.Close()
		}
	}
	if _, err := fixture.broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() cleanup error = %v", err)
	}
	assertSessionsInvalid(t, fixture.issuer.sessionSnapshot()...)
}
