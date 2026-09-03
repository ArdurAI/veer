package credentialbroker

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/credential"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
)

const (
	testSourceCanary  = "VEER_TEST_SOURCE_CANARY_7fa132"
	testSessionCanary = "VEER_TEST_SESSION_CANARY_8cb471"
	testErrorCanary   = "VEER_TEST_ERROR_CANARY_b95e20"
)

var testBrokerNow = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

type clockStep struct {
	now     time.Time
	entered chan<- struct{}
	release <-chan struct{}
}

type scriptedClock struct {
	mu       sync.Mutex
	fallback time.Time
	steps    []clockStep
}

func (clock *scriptedClock) Now() time.Time {
	clock.mu.Lock()
	if len(clock.steps) == 0 {
		fallback := clock.fallback
		clock.mu.Unlock()
		return fallback
	}
	step := clock.steps[0]
	clock.steps = clock.steps[1:]
	clock.mu.Unlock()
	if step.entered != nil {
		step.entered <- struct{}{}
	}
	if step.release != nil {
		<-step.release
	}
	return step.now
}

type doneObservedContext struct {
	context.Context
	once     sync.Once
	observed chan<- struct{}
}

// liveDeadlineContext lets a test impose a deadline on child work while the
// parent itself remains live. It models the broker-owned backend timeout
// independently from caller cancellation without waiting for the production
// timeout duration.
type liveDeadlineContext struct {
	context.Context
	mu       sync.Mutex
	deadline time.Time
	present  bool
}

func (ctx *liveDeadlineContext) Deadline() (time.Time, bool) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.deadline, ctx.present
}

func (ctx *liveDeadlineContext) setDeadline(deadline time.Time) {
	ctx.mu.Lock()
	ctx.deadline = deadline
	ctx.present = true
	ctx.mu.Unlock()
}

func (ctx *doneObservedContext) Done() <-chan struct{} {
	ctx.once.Do(func() { ctx.observed <- struct{}{} })
	return ctx.Context.Done()
}

func newManualClock(now time.Time) *manualClock {
	return &manualClock{now: now}
}

func (clock *manualClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *manualClock) Set(now time.Time) {
	clock.mu.Lock()
	clock.now = now
	clock.mu.Unlock()
}

func (clock *manualClock) Add(delta time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(delta)
	clock.mu.Unlock()
}

type testRequestConfig struct {
	connection int
	operation  int
	target     int
	generation int
	version    string
	action     authorization.Action
	recipient  string
}

func defaultTestRequestConfig() testRequestConfig {
	return testRequestConfig{
		connection: 1,
		operation:  1,
		target:     1,
		generation: 1,
		version:    "opaque_A",
		action:     authorization.ActionProviderApply,
		recipient:  "provider-adapter",
	}
}

type testResourceSpec struct {
	Enabled bool `json:"enabled"`
}

type testResourceStatus struct {
	ObservedGeneration int64 `json:"observedGeneration"`
}

func (status testResourceStatus) ObservedGenerations() []int64 {
	return []int64{status.ObservedGeneration}
}

func testID(prefix string, ordinal int) resource.ID {
	return resource.ID(fmt.Sprintf("%s_%023d", prefix, ordinal))
}

func mustTestRequest(t testing.TB, config testRequestConfig) credential.Request {
	t.Helper()
	if config.connection == 0 {
		config.connection = 1
	}
	if config.operation == 0 {
		config.operation = 1
	}
	if config.target == 0 {
		config.target = 1
	}
	if config.generation == 0 {
		config.generation = 1
	}
	if config.version == "" {
		config.version = "opaque_A"
	}
	if config.action == "" {
		config.action = authorization.ActionProviderApply
	}
	if config.recipient == "" {
		config.recipient = "provider-adapter"
	}

	workspaceID := testID("wsp", 1)
	environmentID := testID("env", 1)
	applicationID := testID("app", config.target)
	componentID := testID("cmp", config.target)
	connectionID := testID("pvc", config.connection)
	referenceID := testID("sec", config.connection)

	workspace := mustTestResource(t, hierarchy.KindWorkspace, workspaceID, nil,
		testResourceSpec{Enabled: true}, testResourceStatus{})
	environment := mustTestResource(t, hierarchy.KindEnvironment, environmentID, idPointer(workspaceID),
		testResourceSpec{Enabled: true}, testResourceStatus{})
	application := mustTestResource(t, hierarchy.KindApplication, applicationID, idPointer(environmentID),
		testResourceSpec{Enabled: true}, testResourceStatus{})
	component := mustTestResource(t, hierarchy.KindComponent, componentID, idPointer(applicationID),
		testResourceSpec{Enabled: true}, testResourceStatus{})

	initialVersion := config.version
	if config.generation > 1 {
		initialVersion = "bootstrap_1"
	}
	connection := mustTestResource(t, hierarchy.KindProviderConnection, connectionID, idPointer(environmentID),
		control.ProviderConnectionSpec{
			Provider: "aws",
			CredentialRef: control.CredentialReference{
				ReferenceID: referenceID.String(),
				Version:     initialVersion,
			},
		},
		control.ProviderConnectionStatus{
			Conditions:   []condition.Condition{},
			Capabilities: []control.ProviderCapability{},
			QuotaChecks:  []control.QuotaCheck{},
		})
	for generation := 2; generation <= config.generation; generation++ {
		version := fmt.Sprintf("bootstrap_%d", generation)
		if generation == config.generation {
			version = config.version
		}
		var err error
		connection, err = connection.ReplaceSpec(
			control.ProviderConnectionSpec{
				Provider: "aws",
				CredentialRef: control.CredentialReference{
					ReferenceID: referenceID.String(),
					Version:     version,
				},
			},
			fmt.Sprintf("resource_%d", generation),
			testBrokerNow.Add(time.Duration(generation)*time.Millisecond),
		)
		if err != nil {
			t.Fatalf("ReplaceSpec(generation %d) error = %v", generation, err)
		}
	}

	records := []hierarchy.Record{
		mustTestRecord(t, workspace),
		mustTestRecord(t, environment),
		mustTestRecord(t, application),
		mustTestRecord(t, component),
		mustTestRecord(t, connection),
	}
	snapshot, err := hierarchy.NewSnapshot(workspaceID, records)
	if err != nil {
		t.Fatalf("hierarchy.NewSnapshot() error = %v", err)
	}
	target, err := credential.NewResourceView(component)
	if err != nil {
		t.Fatalf("credential.NewResourceView() error = %v", err)
	}
	op := mustTestOperation(t, workspaceID, environmentID, connectionID, componentID, config.operation)
	recipient, err := credential.NewRecipient("aws", config.recipient)
	if err != nil {
		t.Fatalf("credential.NewRecipient() error = %v", err)
	}
	request, err := credential.NewRequest(snapshot, connection, target, op, config.action, recipient)
	if err != nil {
		t.Fatalf("credential.NewRequest() error = %v", err)
	}
	return request
}

func mustTestResource[Spec any, Status resource.GenerationObservations](
	t testing.TB,
	kind hierarchy.Kind,
	id resource.ID,
	parent *resource.ID,
	spec Spec,
	status Status,
) resource.Resource[Spec, Status] {
	t.Helper()
	value, err := resource.New(resource.CreateInput[Spec, Status]{
		APIVersion:      hierarchy.APIVersion,
		Kind:            kind.String(),
		ID:              id.String(),
		WorkspaceID:     testID("wsp", 1).String(),
		DisplayName:     "fixture",
		Parent:          parent,
		ResourceVersion: "resource_1",
		CreatedAt:       testBrokerNow,
		Spec:            spec,
		Status:          status,
	})
	if err != nil {
		t.Fatalf("resource.New(%s) error = %v", kind, err)
	}
	return value
}

func mustTestRecord[Spec any, Status resource.GenerationObservations](
	t testing.TB,
	value resource.Resource[Spec, Status],
) hierarchy.Record {
	t.Helper()
	record, err := hierarchy.RecordFrom(value.APIVersion(), value.Kind(), value.Metadata())
	if err != nil {
		t.Fatalf("hierarchy.RecordFrom(%s) error = %v", value.Kind(), err)
	}
	return record
}

func mustTestOperation(
	t testing.TB,
	workspaceID resource.ID,
	environmentID resource.ID,
	connectionID resource.ID,
	targetID resource.ID,
	ordinal int,
) operation.Operation {
	t.Helper()
	op, err := operation.New(operation.Input{
		ID:                   testID("opn", ordinal),
		WorkspaceID:          workspaceID,
		ResourceID:           targetID,
		EnvironmentID:        idPointer(environmentID),
		ProviderConnectionID: idPointer(connectionID),
		Generation:           1,
		ResourceVersion:      "operation_1",
		CreatedAt:            testBrokerNow,
	})
	if err != nil {
		t.Fatalf("operation.New() error = %v", err)
	}
	op, err = operation.Transition(op, operation.TransitionInput{
		Phase:           operation.PhaseRunning,
		ResourceVersion: "operation_2",
		UpdatedAt:       testBrokerNow.Add(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("operation.Transition() error = %v", err)
	}
	return op
}

func idPointer(id resource.ID) *resource.ID {
	copy := id
	return &copy
}

type fakeClaim struct {
	mu       sync.Mutex
	settles  []ports.SecretReadOutcome
	settleFn func(context.Context, ports.SecretReadOutcome) error
}

func (claim *fakeClaim) Settle(ctx context.Context, outcome ports.SecretReadOutcome) error {
	claim.mu.Lock()
	claim.settles = append(claim.settles, outcome)
	fn := claim.settleFn
	claim.mu.Unlock()
	if fn != nil {
		return fn(ctx, outcome)
	}
	return nil
}

func (claim *fakeClaim) outcomes() []ports.SecretReadOutcome {
	claim.mu.Lock()
	defer claim.mu.Unlock()
	return append([]ports.SecretReadOutcome(nil), claim.settles...)
}

type fakeBudget struct {
	mu      sync.Mutex
	calls   int
	claims  []*fakeClaim
	claimFn func(context.Context, credential.SourceLookup, ports.SecretReadPriority) (ports.SecretReadClaim, error)
}

func (budget *fakeBudget) Claim(
	ctx context.Context,
	lookup credential.SourceLookup,
	priority ports.SecretReadPriority,
) (ports.SecretReadClaim, error) {
	budget.mu.Lock()
	budget.calls++
	fn := budget.claimFn
	budget.mu.Unlock()
	if fn != nil {
		return fn(ctx, lookup, priority)
	}
	claim := &fakeClaim{}
	budget.mu.Lock()
	budget.claims = append(budget.claims, claim)
	budget.mu.Unlock()
	return claim, nil
}

func (budget *fakeBudget) callCount() int {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.calls
}

type fakeResolver struct {
	mu        sync.Mutex
	calls     int
	materials []*credential.SourceMaterial
	resolveFn func(context.Context, credential.SourceLookup) (*credential.SourceMaterial, ports.SecretReadOutcome, error)
}

func (resolver *fakeResolver) Resolve(
	ctx context.Context,
	lookup credential.SourceLookup,
) (*credential.SourceMaterial, ports.SecretReadOutcome, error) {
	resolver.mu.Lock()
	resolver.calls++
	fn := resolver.resolveFn
	resolver.mu.Unlock()
	if fn != nil {
		material, outcome, err := fn(ctx, lookup)
		resolver.mu.Lock()
		resolver.materials = append(resolver.materials, material)
		resolver.mu.Unlock()
		return material, outcome, err
	}
	material, err := credential.NewSourceMaterial([]byte(testSourceCanary))
	if err != nil {
		return nil, ports.SecretReadRetained, err
	}
	resolver.mu.Lock()
	resolver.materials = append(resolver.materials, material)
	resolver.mu.Unlock()
	return material, ports.SecretReadConsumed, nil
}

func (resolver *fakeResolver) callCount() int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.calls
}

func (resolver *fakeResolver) materialSnapshot() []*credential.SourceMaterial {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return append([]*credential.SourceMaterial(nil), resolver.materials...)
}

type fakeIssuer struct {
	mu       sync.Mutex
	clock    Clock
	calls    int
	revokes  int
	sessions []*credential.IssuedSession
	issueFn  func(context.Context, credential.Request, *credential.SourceMaterial) (*credential.IssuedSession, error)
	revokeFn func(context.Context, credential.Request, *credential.IssuedSession) (ports.RevocationResult, error)
}

func (issuer *fakeIssuer) Issue(
	ctx context.Context,
	request credential.Request,
	source *credential.SourceMaterial,
) (*credential.IssuedSession, error) {
	issuer.mu.Lock()
	issuer.calls++
	fn := issuer.issueFn
	issuer.mu.Unlock()
	var session *credential.IssuedSession
	var err error
	if fn != nil {
		session, err = fn(ctx, request, source)
	} else {
		now := issuer.clock.Now()
		session, err = newTestSession(request, now, credential.RequestedSessionTTL)
	}
	issuer.mu.Lock()
	issuer.sessions = append(issuer.sessions, session)
	issuer.mu.Unlock()
	return session, err
}

func (issuer *fakeIssuer) Revoke(
	ctx context.Context,
	request credential.Request,
	session *credential.IssuedSession,
) (ports.RevocationResult, error) {
	issuer.mu.Lock()
	issuer.revokes++
	fn := issuer.revokeFn
	issuer.mu.Unlock()
	if fn != nil {
		return fn(ctx, request, session)
	}
	return ports.RevocationProviderConfirmed, nil
}

func (issuer *fakeIssuer) issueCount() int {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return issuer.calls
}

func (issuer *fakeIssuer) revokeCount() int {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return issuer.revokes
}

func (issuer *fakeIssuer) sessionSnapshot() []*credential.IssuedSession {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return append([]*credential.IssuedSession(nil), issuer.sessions...)
}

func newTestSession(
	request credential.Request,
	issuedAt time.Time,
	ttl time.Duration,
) (*credential.IssuedSession, error) {
	material, err := credential.NewSessionMaterial([]byte(testSessionCanary))
	if err != nil {
		return nil, err
	}
	return credential.NewIssuedSession(request, material, issuedAt, issuedAt.Add(ttl))
}

func mustTestBroker(
	t testing.TB,
	clock Clock,
	budget ports.SecretReadBudget,
	resolver ports.SecretResolver,
	issuer ports.SessionIssuer,
	recipient credential.Recipient,
) *Broker {
	t.Helper()
	broker, err := New(resolver, budget, clock)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := broker.RegisterIssuer(recipient, issuer); err != nil {
		t.Fatalf("RegisterIssuer() error = %v", err)
	}
	return broker
}

func waitForSignal(t testing.TB, signal <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func waitForCondition(t testing.TB, label string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", label)
		}
		runtime.Gosched()
	}
}

func receiveResult[T any](t testing.TB, results <-chan T, label string) T {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
		var zero T
		return zero
	}
}

func assertSourcesInvalid(t testing.TB, materials ...*credential.SourceMaterial) {
	t.Helper()
	for index, material := range materials {
		if material != nil && material.Valid() {
			t.Errorf("source material %d remains valid after disposal point", index)
		}
	}
}

func assertSessionsInvalid(t testing.TB, sessions ...*credential.IssuedSession) {
	t.Helper()
	for index, session := range sessions {
		if session != nil && session.Valid() {
			t.Errorf("issued session %d remains valid after disposal point", index)
		}
	}
}
