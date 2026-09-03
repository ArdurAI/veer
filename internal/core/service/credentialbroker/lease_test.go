package credentialbroker

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

// gatedAfterFuncContext pauses context.AfterFunc registration without holding
// any broker lock. Tests use the pause to let cancellation or invalidation win
// after Lease.Use's preliminary checks but before its final use admission.
type gatedAfterFuncContext struct {
	parent  context.Context
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGatedAfterFuncContext() (*gatedAfterFuncContext, context.CancelFunc) {
	parent, cancel := context.WithCancel(context.Background())
	return &gatedAfterFuncContext{
		parent:  parent,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}, cancel
}

func (ctx *gatedAfterFuncContext) Deadline() (time.Time, bool) {
	return ctx.parent.Deadline()
}

func (ctx *gatedAfterFuncContext) Done() <-chan struct{} { return ctx.parent.Done() }

func (ctx *gatedAfterFuncContext) Err() error { return ctx.parent.Err() }

// Value deliberately does not expose the parent cancelCtx. That makes the
// standard library use this context's synchronous AfterFunc registration hook.
func (*gatedAfterFuncContext) Value(any) any { return nil }

func (ctx *gatedAfterFuncContext) AfterFunc(callback func()) func() bool {
	ctx.once.Do(func() { close(ctx.entered) })
	<-ctx.release
	return context.AfterFunc(ctx.parent, callback)
}

func TestCopiedLeaseClosesExactlyOnce(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, request.Recipient())
	lease, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	copied := *lease

	start := make(chan struct{})
	errorsOut := make(chan error, 2)
	go func() {
		<-start
		errorsOut <- lease.Close()
	}()
	go func() {
		<-start
		errorsOut <- copied.Close()
	}()
	close(start)
	for range 2 {
		if err := receiveResult(t, errorsOut, "copied Lease.Close result"); err != nil {
			t.Fatalf("Lease.Close() error = %v", err)
		}
	}
	if got := broker.Stats().ActiveLeases; got != 0 {
		t.Fatalf("ActiveLeases = %d, want exactly one handle release", got)
	}
	broker.mu.Lock()
	refs := lease.state.cell.refs
	broker.mu.Unlock()
	if refs != 0 {
		t.Fatalf("session refs = %d, want 0 after copied closes", refs)
	}
	if err := copied.Use(context.Background(), func(context.Context, []byte) error { return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatalf("copied Lease.Use(after Close) error = %v, want ErrRevoked", err)
	}
	if got := issuer.revokeCount(); got != 0 {
		t.Fatalf("Lease.Close() triggered %d upstream revokes, want 0", got)
	}
	if result, err := broker.Close(context.Background()); err != nil || result != ports.RevocationProviderConfirmed {
		t.Fatalf("Broker.Close() = %v, %v, want provider-confirmed, nil", result, err)
	}
	if got := issuer.revokeCount(); got != 1 {
		t.Fatalf("Broker.Close() revoke calls = %d, want 1", got)
	}
	assertSourcesInvalid(t, resolver.materialSnapshot()...)
	assertSessionsInvalid(t, issuer.sessionSnapshot()...)
}

func TestLeaseUseFinalCheckRejectsConcurrentRevokeAndClose(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	revokeEntered := make(chan struct{})
	revokeRelease := make(chan struct{})
	issuer := &fakeIssuer{
		clock: clock,
		revokeFn: func(_ context.Context, _ credential.Request, session *credential.IssuedSession) (ports.RevocationResult, error) {
			if !session.Valid() {
				t.Error("session was destroyed before upstream Revoke entered")
			}
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

	useEntered := make(chan struct{})
	useCanceled := make(chan struct{})
	useReturn := make(chan struct{})
	useResult := make(chan error, 1)
	go func() {
		useResult <- lease.Use(context.Background(), func(ctx context.Context, value []byte) error {
			if string(value) != testSessionCanary {
				t.Errorf("Lease.Use() callback received unexpected material")
			}
			close(useEntered)
			<-ctx.Done()
			close(useCanceled)
			<-useReturn
			return nil
		})
	}()
	waitForSignal(t, useEntered, "Lease.Use callback")

	revokeResult := make(chan lifecycleOutcome, 1)
	closeResult := make(chan error, 1)
	start := make(chan struct{})
	go func() {
		<-start
		result, err := broker.RevokeConnection(context.Background(), request)
		revokeResult <- lifecycleOutcome{result: result, err: err}
	}()
	go func() {
		<-start
		closeResult <- lease.Close()
	}()
	close(start)

	waitForSignal(t, revokeEntered, "concurrent upstream Revoke")
	waitForSignal(t, useCanceled, "Lease.Use invalidation")
	if err := receiveResult(t, closeResult, "concurrent Lease.Close"); err != nil {
		t.Fatalf("Lease.Close() error = %v", err)
	}
	assertNoResult(t, useResult, "Lease.Use before callback returns")
	close(useReturn)
	if err := receiveResult(t, useResult, "Lease.Use final revocation check"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Lease.Use() error = %v, want ErrRevoked", err)
	}
	close(revokeRelease)
	revoked := receiveResult(t, revokeResult, "RevokeConnection after Lease.Close race")
	if revoked.result != ports.RevocationProviderConfirmed || revoked.err != nil {
		t.Fatalf("RevokeConnection() = %v, %v, want provider-confirmed, nil", revoked.result, revoked.err)
	}
	if got := issuer.revokeCount(); got != 1 {
		t.Fatalf("upstream Revoke calls = %d, want exactly 1", got)
	}
	assertSessionsInvalid(t, issuer.sessionSnapshot()...)
	if got := broker.Stats().ActiveLeases; got != 0 {
		t.Fatalf("ActiveLeases = %d, want 0", got)
	}
}

func TestLeaseUseAdmissionRejectsPreCopyCancellationAndClose(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(testing.TB, *Lease, *manualClock, context.CancelFunc)
		wantErr error
	}{
		{
			name: "caller cancellation",
			mutate: func(_ testing.TB, _ *Lease, _ *manualClock, cancel context.CancelFunc) {
				cancel()
			},
			wantErr: context.Canceled,
		},
		{
			name: "original lease close",
			mutate: func(t testing.TB, lease *Lease, _ *manualClock, _ context.CancelFunc) {
				t.Helper()
				if err := lease.Close(); err != nil {
					t.Fatalf("Lease.Close() error = %v", err)
				}
			},
			wantErr: ErrRevoked,
		},
		{
			name: "copied lease close",
			mutate: func(t testing.TB, lease *Lease, _ *manualClock, _ context.CancelFunc) {
				t.Helper()
				copied := *lease
				if err := copied.Close(); err != nil {
					t.Fatalf("copied Lease.Close() error = %v", err)
				}
			},
			wantErr: ErrRevoked,
		},
		{
			name: "new-use lifetime expiration",
			mutate: func(_ testing.TB, lease *Lease, clock *manualClock, _ context.CancelFunc) {
				clock.Set(lease.ExpiresAt().Add(
					-credential.SessionExpirySkew - credential.MinNewUseLifetime + time.Second,
				))
			},
			wantErr: ErrExpired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			request := mustTestRequest(t, defaultTestRequestConfig())
			issuer := &fakeIssuer{clock: clock}
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

			useCtx, cancelUse := newGatedAfterFuncContext()
			releaseUse := sync.OnceFunc(func() { close(useCtx.release) })
			defer func() {
				releaseUse()
				cancelUse()
				_ = lease.Close()
				_, _ = broker.Close(context.Background())
			}()
			callbackEntered := make(chan struct{}, 1)
			useResult := make(chan error, 1)
			go func() {
				useResult <- lease.Use(useCtx, func(context.Context, []byte) error {
					callbackEntered <- struct{}{}
					return nil
				})
			}()
			waitForSignal(t, useCtx.entered, "Lease.Use pre-copy admission pause")

			test.mutate(t, lease, clock, cancelUse)
			releaseUse()
			if err := receiveResult(t, useResult, "Lease.Use after pre-copy invalidation"); !errors.Is(err, test.wantErr) {
				t.Fatalf("Lease.Use() error = %v, want %v", err, test.wantErr)
			}
			assertNoResult(t, callbackEntered, "credential-bearing callback")
		})
	}
}

func TestLeaseUseAdmissionRejectsPreCopyLifecycleInvalidation(t *testing.T) {
	tests := []struct {
		name       string
		invalidate func(*Broker, credential.Request) (ports.RevocationResult, error)
		wantErr    error
	}{
		{
			name: "connection revoke",
			invalidate: func(broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.RevokeConnection(context.Background(), request)
			},
			wantErr: ErrRevoked,
		},
		{
			name: "operation cancel",
			invalidate: func(broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.CancelOperation(context.Background(), request)
			},
			wantErr: ErrRevoked,
		},
		{
			name: "operation close",
			invalidate: func(broker *Broker, request credential.Request) (ports.RevocationResult, error) {
				return broker.CloseOperation(context.Background(), request)
			},
			wantErr: ErrRevoked,
		},
		{
			name: "broker close",
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
			revokeEntered := make(chan struct{})
			revokeRelease := make(chan struct{})
			releaseRevoke := sync.OnceFunc(func() { close(revokeRelease) })
			issuer := &fakeIssuer{
				clock: clock,
				revokeFn: func(context.Context, credential.Request, *credential.IssuedSession) (ports.RevocationResult, error) {
					close(revokeEntered)
					<-revokeRelease
					return ports.RevocationProviderConfirmed, nil
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

			useCtx, cancelUse := newGatedAfterFuncContext()
			releaseUse := sync.OnceFunc(func() { close(useCtx.release) })
			defer func() {
				releaseUse()
				cancelUse()
				_ = lease.Close()
				releaseRevoke()
				_, _ = broker.Close(context.Background())
			}()
			callbackEntered := make(chan struct{}, 1)
			useResult := make(chan error, 1)
			go func() {
				useResult <- lease.Use(useCtx, func(context.Context, []byte) error {
					callbackEntered <- struct{}{}
					return nil
				})
			}()
			waitForSignal(t, useCtx.entered, "Lease.Use pre-copy lifecycle pause")

			lifecycleResult := make(chan lifecycleOutcome, 1)
			go func() {
				result, err := test.invalidate(broker, request)
				lifecycleResult <- lifecycleOutcome{result: result, err: err}
			}()
			waitForSignal(t, revokeEntered, "upstream Revoke after local invalidation")
			releaseUse()
			if err := receiveResult(t, useResult, "Lease.Use after lifecycle invalidation"); !errors.Is(err, test.wantErr) {
				t.Fatalf("Lease.Use() error = %v, want %v", err, test.wantErr)
			}
			assertNoResult(t, callbackEntered, "credential-bearing callback")

			releaseRevoke()
			invalidated := receiveResult(t, lifecycleResult, "lifecycle result")
			if invalidated.result != ports.RevocationProviderConfirmed || invalidated.err != nil {
				t.Fatalf(
					"lifecycle result = %v, %v, want provider-confirmed, nil",
					invalidated.result,
					invalidated.err,
				)
			}
		})
	}
}

func TestLeaseUseAdmissionReleasesLocksBeforeReentrantCallback(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
	lease, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	copied := *lease

	callbackDone := make(chan struct{})
	useResult := make(chan error, 1)
	go func() {
		useResult <- lease.Use(context.Background(), func(_ context.Context, value []byte) error {
			if string(value) != testSessionCanary {
				t.Errorf("Lease.Use() callback received unexpected material")
			}
			if closeErr := copied.Close(); closeErr != nil {
				t.Errorf("reentrant copied Lease.Close() error = %v", closeErr)
			}
			result, revokeErr := broker.RevokeConnection(context.Background(), request)
			if result != ports.RevocationProviderConfirmed || revokeErr != nil {
				t.Errorf(
					"reentrant RevokeConnection() = %v, %v, want provider-confirmed, nil",
					result,
					revokeErr,
				)
			}
			close(callbackDone)
			return nil
		})
	}()

	waitForSignal(t, callbackDone, "reentrant Lease.Use callback")
	if err := receiveResult(t, useResult, "reentrant Lease.Use result"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Lease.Use() error = %v, want ErrRevoked", err)
	}
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
}

func TestLeaseCloseFreesDrainingSessionSlotOnlyAfterSynchronousDestroy(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, &fakeBudget{}, &fakeResolver{}, issuer, request.Recipient())
	lease, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	cell := lease.state.cell
	issued := cell.session
	broker.mu.Lock()
	delete(broker.sessions, cell.binding)
	cell.draining = true
	dummies := make([]*sessionCell, 0, MaxSessionEntries-1)
	for range MaxSessionEntries - 1 {
		dummy := &sessionCell{refs: 1}
		broker.cells[dummy] = struct{}{}
		dummies = append(dummies, dummy)
	}
	chargedBefore := uint64(len(broker.cells)) + broker.sessionReservations
	broker.mu.Unlock()
	if chargedBefore != MaxSessionEntries || !issued.Valid() {
		t.Fatalf("session charge before Close = %d, valid:%v, want %d/true", chargedBefore, issued.Valid(), MaxSessionEntries)
	}

	if err := lease.Close(); err != nil {
		t.Fatalf("Lease.Close() error = %v", err)
	}
	if issued.Valid() {
		t.Fatal("Lease.Close returned before final draining session destruction")
	}
	broker.mu.Lock()
	chargedAfter := uint64(len(broker.cells)) + broker.sessionReservations
	reservationAfter := broker.sessionReservations
	for _, dummy := range dummies {
		delete(broker.cells, dummy)
	}
	broker.mu.Unlock()
	if chargedAfter != MaxSessionEntries-1 || reservationAfter != 0 {
		t.Fatalf("session charge after Close = charged:%d reservations:%d, want %d/0", chargedAfter, reservationAfter, MaxSessionEntries-1)
	}

	replacement, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire(after synchronous Destroy) error = %v", err)
	}
	_ = replacement.Close()
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
}

func TestZeroAndNilBrokerLeaseAPIsNeverPanic(t *testing.T) {
	request := mustTestRequest(t, defaultTestRequestConfig())
	issuer := &fakeIssuer{clock: newManualClock(testBrokerNow)}
	var nilBroker *Broker
	var zeroBroker Broker
	var nilLease *Lease
	var zeroLease Lease
	callback := func(context.Context, []byte) error { return nil }

	tests := []struct {
		name string
		call func()
	}{
		{name: "nil Broker Stats", call: func() { _ = nilBroker.Stats() }},
		{name: "nil Broker RegisterIssuer", call: func() { _ = nilBroker.RegisterIssuer(request.Recipient(), issuer) }},
		{name: "nil Broker Acquire", call: func() { _, _ = nilBroker.Acquire(context.Background(), request) }},
		{name: "nil Broker Refresh", call: func() { _, _ = nilBroker.Refresh(context.Background(), request) }},
		{name: "nil Broker Rotate", call: func() { _, _ = nilBroker.Rotate(context.Background(), request) }},
		{name: "nil Broker RevokeConnection", call: func() { _, _ = nilBroker.RevokeConnection(context.Background(), request) }},
		{name: "nil Broker CancelOperation", call: func() { _, _ = nilBroker.CancelOperation(context.Background(), request) }},
		{name: "nil Broker CloseOperation", call: func() { _, _ = nilBroker.CloseOperation(context.Background(), request) }},
		{name: "nil Broker SweepExpired", call: func() { _ = nilBroker.SweepExpired() }},
		{name: "nil Broker Close", call: func() { _, _ = nilBroker.Close(context.Background()) }},
		{name: "zero Broker Stats", call: func() { _ = zeroBroker.Stats() }},
		{name: "zero Broker Acquire", call: func() { _, _ = zeroBroker.Acquire(context.Background(), request) }},
		{name: "zero Broker Close", call: func() { _, _ = zeroBroker.Close(context.Background()) }},
		{name: "nil Lease ExpiresAt", call: func() { _ = nilLease.ExpiresAt() }},
		{name: "nil Lease Close", call: func() { _ = nilLease.Close() }},
		{name: "nil Lease Use", call: func() { _ = nilLease.Use(context.Background(), callback) }},
		{name: "zero Lease ExpiresAt", call: func() { _ = zeroLease.ExpiresAt() }},
		{name: "zero Lease Close", call: func() { _ = zeroLease.Close() }},
		{name: "zero Lease Use", call: func() { _ = zeroLease.Use(context.Background(), callback) }},
		{name: "nil Broker fmt", call: func() { _ = fmt.Sprintf("%v %#v %+v", nilBroker, nilBroker, nilBroker) }},
		{name: "zero Broker fmt", call: func() { _ = fmt.Sprintf("%v %#v %+v", zeroBroker, zeroBroker, zeroBroker) }},
		{name: "nil Lease fmt", call: func() { _ = fmt.Sprintf("%v %#v %+v", nilLease, nilLease, nilLease) }},
		{name: "zero Lease fmt", call: func() { _ = fmt.Sprintf("%v %#v %+v", zeroLease, zeroLease, zeroLease) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("API panicked: %v", recovered)
				}
			}()
			test.call()
		})
	}

	if _, err := nilBroker.Acquire(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil Broker.Acquire() error = %v, want ErrInvalid", err)
	}
	if _, err := zeroBroker.Close(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero Broker.Close() error = %v, want ErrInvalid", err)
	}
	if err := nilLease.Close(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil Lease.Close() error = %v, want ErrInvalid", err)
	}
	if err := zeroLease.Use(context.Background(), callback); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero Lease.Use() error = %v, want ErrInvalid", err)
	}
}

func TestBrokerLeaseRotationDiagnosticsAndErrorsNeverLeakCanaries(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	resolver := &fakeResolver{
		resolveFn: func(context.Context, credential.SourceLookup) (*credential.SourceMaterial, ports.SecretReadOutcome, error) {
			material, err := credential.NewSourceMaterial([]byte(testSourceCanary))
			if err != nil {
				return nil, ports.SecretReadRetained, err
			}
			return material, ports.SecretReadConsumed, errors.New(testErrorCanary)
		},
	}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, &fakeBudget{}, resolver, issuer, request.Recipient())
	lease, acquireErr := broker.Acquire(context.Background(), request)
	if lease != nil || !errors.Is(acquireErr, ErrUnavailable) {
		t.Fatalf("Acquire() = %v, %v, want nil, ErrUnavailable", lease, acquireErr)
	}

	validResolver := &fakeResolver{}
	validIssuer := &fakeIssuer{clock: clock}
	validBroker := mustTestBroker(t, clock, &fakeBudget{}, validResolver, validIssuer, request.Recipient())
	validLease, err := validBroker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("valid Acquire() error = %v", err)
	}
	values := []any{
		broker,
		Broker{},
		*validBroker,
		validBroker,
		Lease{},
		*validLease,
		validLease,
		Rotation{},
		acquireErr,
		fmt.Errorf("wrapped: %w", acquireErr),
	}
	for _, value := range values {
		for _, formatted := range []string{
			fmt.Sprintf("%v", value),
			fmt.Sprintf("%+v", value),
			fmt.Sprintf("%#v", value),
		} {
			assertNoCanary(t, formatted)
		}
		encoded, err := json.Marshal(value)
		assertNoCanary(t, string(encoded))
		if err != nil {
			assertNoCanary(t, err.Error())
		}
		var gobBytes bytes.Buffer
		gobErr := gob.NewEncoder(&gobBytes).Encode(value)
		assertNoCanary(t, gobBytes.String())
		if gobErr != nil {
			assertNoCanary(t, gobErr.Error())
		}
		var logBytes bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logBytes, nil))
		logger.Info("diagnostic", "value", value)
		assertNoCanary(t, logBytes.String())
	}
	assertSourcesInvalid(t, resolver.materialSnapshot()...)
	if _, err := broker.Close(context.Background()); err != nil {
		t.Fatalf("Broker.Close() error = %v", err)
	}
	_ = validLease.Close()
	if _, err := validBroker.Close(context.Background()); err != nil {
		t.Fatalf("valid Broker.Close() error = %v", err)
	}
	assertSourcesInvalid(t, validResolver.materialSnapshot()...)
	assertSessionsInvalid(t, validIssuer.sessionSnapshot()...)
}

func assertNoCanary(t testing.TB, value string) {
	t.Helper()
	for _, canary := range []string{testSourceCanary, testSessionCanary, testErrorCanary} {
		if strings.Contains(value, canary) {
			t.Errorf("diagnostic leaked canary in %q", value)
		}
	}
}
