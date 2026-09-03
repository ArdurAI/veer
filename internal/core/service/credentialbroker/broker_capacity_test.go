package credentialbroker

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/ports"
)

func TestBrokerFixedCapacityConstants(t *testing.T) {
	wants := map[string]struct {
		got  int
		want int
	}{
		"source entries":         {got: MaxSourceEntries, want: 500},
		"session entries":        {got: MaxSessionEntries, want: 1_000},
		"active leases":          {got: MaxActiveLeases, want: 1_000},
		"tracked connections":    {got: MaxTrackedConnections, want: 500},
		"tracked operations":     {got: MaxTrackedOperations, want: 10_000},
		"concurrent resolves":    {got: MaxConcurrentResolves, want: 32},
		"issuer registrations":   {got: MaxIssuerRegistrations, want: 16},
		"concurrent revocations": {got: MaxConcurrentRevocations, want: 16},
	}
	for name, value := range wants {
		t.Run(name, func(t *testing.T) {
			if value.got != value.want {
				t.Fatalf("bound = %d, want %d", value.got, value.want)
			}
		})
	}
}

func TestRegisterIssuerCapacityRejectsBeforeAnyBackendCall(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	budget := &fakeBudget{}
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker, err := New(resolver, budget, clock)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for index := range MaxIssuerRegistrations {
		recipient, recipientErr := credential.NewRecipient("aws", fmt.Sprintf("issuer-%02d", index))
		if recipientErr != nil {
			t.Fatalf("NewRecipient(%d) error = %v", index, recipientErr)
		}
		if registerErr := broker.RegisterIssuer(recipient, issuer); registerErr != nil {
			t.Fatalf("RegisterIssuer(%d) error = %v", index, registerErr)
		}
	}
	overflow, err := credential.NewRecipient("aws", "issuer-overflow")
	if err != nil {
		t.Fatalf("NewRecipient(overflow) error = %v", err)
	}
	if err := broker.RegisterIssuer(overflow, issuer); !errors.Is(err, ErrCapacity) {
		t.Fatalf("RegisterIssuer(at bound) error = %v, want ErrCapacity", err)
	}
	assertNoBackendCalls(t, budget, resolver, issuer)
}

func TestAcquireCapacityBoundariesDoNotCallBackends(t *testing.T) {
	tests := []struct {
		name  string
		prime func(*Broker)
	}{
		{
			name: "active leases",
			prime: func(broker *Broker) {
				broker.activeLeases = MaxActiveLeases
			},
		},
		{
			name: "tracked connections",
			prime: func(broker *Broker) {
				for index := range MaxTrackedConnections {
					broker.lineages[connectionKey{connectionID: testID("pvc", 10_000+index)}] = &lineageState{}
				}
			},
		},
		{
			name: "tracked operations",
			prime: func(broker *Broker) {
				for index := range MaxTrackedOperations {
					broker.operations[operationKey{operationID: testID("opn", 10_000+index)}] = &operationState{}
				}
			},
		},
		{
			name: "session entries",
			prime: func(broker *Broker) {
				for range MaxSessionEntries {
					broker.cells[&sessionCell{refs: 1}] = struct{}{}
				}
			},
		},
		{
			name: "source entries and reservations",
			prime: func(broker *Broker) {
				broker.sourceReservations = MaxSourceEntries
			},
		},
		{
			name: "concurrent resolves",
			prime: func(broker *Broker) {
				broker.activeResolves = MaxConcurrentResolves
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock(testBrokerNow)
			request := mustTestRequest(t, defaultTestRequestConfig())
			budget := &fakeBudget{}
			resolver := &fakeResolver{}
			issuer := &fakeIssuer{clock: clock}
			broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())
			broker.mu.Lock()
			test.prime(broker)
			broker.mu.Unlock()

			lease, err := broker.Acquire(context.Background(), request)
			if lease != nil || !errors.Is(err, ErrCapacity) {
				t.Fatalf("Acquire(at %s bound) = %v, %v, want nil, ErrCapacity", test.name, lease, err)
			}
			assertNoBackendCalls(t, budget, resolver, issuer)
		})
	}
}

func TestCountersSaturateAndEpochExhaustionFailsClosed(t *testing.T) {
	maximum := ^uint64(0)
	nearMaximum := maximum - 1
	increment(&nearMaximum)
	if nearMaximum != maximum {
		t.Fatalf("increment(MaxUint64-1) = %d, want MaxUint64", nearMaximum)
	}
	increment(&nearMaximum)
	if nearMaximum != maximum {
		t.Fatalf("increment(MaxUint64) wrapped to %d", nearMaximum)
	}

	clock := newManualClock(testBrokerNow)
	request := mustTestRequest(t, defaultTestRequestConfig())
	budget := &fakeBudget{}
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient())
	broker.mu.Lock()
	broker.nextUse = maximum
	if got := broker.touchLocked(); got != maximum || broker.nextUse != maximum {
		broker.mu.Unlock()
		t.Fatalf("touchLocked(at MaxUint64) = %d/state %d, want saturation", got, broker.nextUse)
	}
	broker.stats.SourceHits = maximum
	broker.stats.Revocations = maximum
	broker.nextEpoch = maximum
	broker.mu.Unlock()

	stats := broker.Stats()
	if stats.SourceHits != maximum || stats.Revocations != maximum {
		t.Fatalf("Stats() saturated counters = hits:%d revocations:%d, want MaxUint64", stats.SourceHits, stats.Revocations)
	}
	lease, err := broker.Acquire(context.Background(), request)
	if lease != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Acquire(at epoch exhaustion) = %v, %v, want nil, ErrUnavailable", lease, err)
	}
	assertNoBackendCalls(t, budget, resolver, issuer)
	if got := broker.Stats().TrackedConnections; got != 0 {
		t.Fatalf("TrackedConnections after epoch exhaustion = %d, want 0", got)
	}
	_, _ = broker.Close(context.Background())
}

func TestRejectedOperationProvenanceDoesNotGrowConnectionState(t *testing.T) {
	clock := newManualClock(testBrokerNow)
	base := mustTestRequest(t, defaultTestRequestConfig())
	budget := &fakeBudget{}
	resolver := &fakeResolver{}
	issuer := &fakeIssuer{clock: clock}
	broker := mustTestBroker(t, clock, budget, resolver, issuer, base.Recipient())
	lease, err := broker.Acquire(context.Background(), base)
	if err != nil {
		t.Fatalf("Acquire(base) error = %v", err)
	}
	_ = lease.Close()
	claims, resolves, issues := budget.callCount(), resolver.callCount(), issuer.issueCount()
	for connection := 2; connection <= MaxTrackedConnections+2; connection++ {
		config := defaultTestRequestConfig()
		config.connection = connection
		request := mustTestRequest(t, config)
		if lease, err := broker.Acquire(context.Background(), request); lease != nil || !errors.Is(err, ErrConflict) {
			t.Fatalf("Acquire(conflicting operation, connection %d) = %v, %v, want nil, ErrConflict", connection, lease, err)
		}
		if result, err := broker.CancelOperation(context.Background(), request); result != ports.RevocationNotRequired || !errors.Is(err, ErrConflict) {
			t.Fatalf("CancelOperation(conflicting operation, connection %d) = %v, %v, want not-required, ErrConflict", connection, result, err)
		}
	}
	if got := broker.Stats().TrackedConnections; got != 1 {
		t.Fatalf("TrackedConnections after rejected provenance = %d, want 1", got)
	}
	if budget.callCount() != claims || resolver.callCount() != resolves || issuer.issueCount() != issues {
		t.Fatal("rejected operation provenance called a backend")
	}

	terminalConfig := defaultTestRequestConfig()
	terminalConfig.connection = MaxTrackedConnections + 10
	terminalConfig.operation = 2
	terminal := mustTestRequest(t, terminalConfig)
	broker.mu.Lock()
	broker.operations[keyForOperation(terminal)] = &operationState{
		binding:  terminal.BindingDigest(),
		terminal: true,
	}
	connectionsBefore := len(broker.lineages)
	broker.mu.Unlock()
	if lease, err := broker.Acquire(context.Background(), terminal); lease != nil || !errors.Is(err, ErrOperationTerminated) {
		t.Fatalf("Acquire(terminal operation) = %v, %v, want nil, ErrOperationTerminated", lease, err)
	}
	if result, err := broker.CloseOperation(context.Background(), terminal); result != ports.RevocationNotRequired || err != nil {
		t.Fatalf("CloseOperation(terminal operation) = %v, %v, want not-required, nil", result, err)
	}
	broker.mu.Lock()
	connectionsAfter := len(broker.lineages)
	broker.mu.Unlock()
	if connectionsAfter != connectionsBefore {
		t.Fatalf("terminal operation grew connections from %d to %d", connectionsBefore, connectionsAfter)
	}
	_, _ = broker.Close(context.Background())
}

func TestEpochReservationAndFirstRevokeAreTransactional(t *testing.T) {
	maximum := ^uint64(0)
	newBroker := func(t *testing.T) (*Broker, credential.Request, *fakeBudget, *fakeResolver, *fakeIssuer) {
		t.Helper()
		clock := newManualClock(testBrokerNow)
		request := mustTestRequest(t, defaultTestRequestConfig())
		budget := &fakeBudget{}
		resolver := &fakeResolver{}
		issuer := &fakeIssuer{clock: clock}
		return mustTestBroker(t, clock, budget, resolver, issuer, request.Recipient()), request, budget, resolver, issuer
	}

	for _, test := range []struct {
		name string
		call func(*Broker, credential.Request) error
	}{
		{
			name: "Acquire",
			call: func(broker *Broker, request credential.Request) error {
				lease, err := broker.Acquire(context.Background(), request)
				if lease != nil {
					_ = lease.Close()
					return errors.New("unexpected lease")
				}
				return err
			},
		},
		{
			name: "CancelOperation",
			call: func(broker *Broker, request credential.Request) error {
				result, err := broker.CancelOperation(context.Background(), request)
				if result != ports.RevocationNotRequired {
					return fmt.Errorf("unexpected result %v", result)
				}
				return err
			},
		},
	} {
		t.Run(test.name+" reserves two epochs atomically", func(t *testing.T) {
			broker, request, budget, resolver, issuer := newBroker(t)
			broker.mu.Lock()
			broker.nextEpoch = maximum - 1
			broker.mu.Unlock()
			if err := test.call(broker, request); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("transition error = %v, want ErrUnavailable", err)
			}
			broker.mu.Lock()
			lineages, operations, nextEpoch := len(broker.lineages), len(broker.operations), broker.nextEpoch
			broker.mu.Unlock()
			if lineages != 0 || operations != 0 || nextEpoch != maximum-1 {
				t.Fatalf("partial state = lineages:%d operations:%d epoch:%d, want 0/0/%d", lineages, operations, nextEpoch, maximum-1)
			}
			assertNoBackendCalls(t, budget, resolver, issuer)
			_, _ = broker.Close(context.Background())
		})
	}

	t.Run("first RevokeConnection consumes one remaining epoch", func(t *testing.T) {
		broker, request, budget, resolver, issuer := newBroker(t)
		broker.mu.Lock()
		broker.nextEpoch = maximum - 1
		broker.mu.Unlock()
		result, err := broker.RevokeConnection(context.Background(), request)
		if err != nil || result != ports.RevocationNotRequired {
			t.Fatalf("RevokeConnection() = %v, %v, want not-required, nil", result, err)
		}
		broker.mu.Lock()
		lineage := broker.lineages[keyForConnection(request)]
		nextEpoch := broker.nextEpoch
		broker.mu.Unlock()
		if lineage == nil || lineage.epoch != maximum || lineage.revokedThrough != request.ConnectionGeneration() || nextEpoch != maximum {
			t.Fatalf("first revoke tombstone complete = %v, epoch=%d, want true/%d", lineage != nil && lineage.revokedThrough == request.ConnectionGeneration(), nextEpoch, maximum)
		}
		assertNoBackendCalls(t, budget, resolver, issuer)
		_, _ = broker.Close(context.Background())
	})

	t.Run("first RevokeConnection at exhaustion publishes nothing", func(t *testing.T) {
		broker, request, budget, resolver, issuer := newBroker(t)
		broker.mu.Lock()
		broker.nextEpoch = maximum
		broker.mu.Unlock()
		result, err := broker.RevokeConnection(context.Background(), request)
		if result != ports.RevocationNotRequired || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("RevokeConnection() = %v, %v, want not-required, ErrUnavailable", result, err)
		}
		broker.mu.Lock()
		lineages, nextEpoch := len(broker.lineages), broker.nextEpoch
		broker.mu.Unlock()
		if lineages != 0 || nextEpoch != maximum {
			t.Fatalf("partial revoke state = lineages:%d epoch:%d, want 0/%d", lineages, nextEpoch, maximum)
		}
		assertNoBackendCalls(t, budget, resolver, issuer)
		_, _ = broker.Close(context.Background())
	})
}

func assertNoBackendCalls(
	t testing.TB,
	budget *fakeBudget,
	resolver *fakeResolver,
	issuer *fakeIssuer,
) {
	t.Helper()
	if claims, resolves, issues, revokes := budget.callCount(), resolver.callCount(),
		issuer.issueCount(), issuer.revokeCount(); claims != 0 || resolves != 0 || issues != 0 || revokes != 0 {
		t.Fatalf(
			"backend calls = claims:%d resolves:%d issues:%d revokes:%d, want all zero",
			claims,
			resolves,
			issues,
			revokes,
		)
	}
}

var _ ports.SessionIssuer = (*fakeIssuer)(nil)
