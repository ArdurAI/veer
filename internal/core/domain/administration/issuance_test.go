package administration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authentication"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

type strongAuthenticationVerifierFunc func(
	context.Context,
	authentication.BearerCredential,
	ElevationRequest,
) (resource.ID, time.Time, error)

func (verify strongAuthenticationVerifierFunc) VerifyStrongAuthentication(
	ctx context.Context,
	credential authentication.BearerCredential,
	request ElevationRequest,
) (resource.ID, time.Time, error) {
	return verify(ctx, credential, request)
}

type blockingStrongAuthenticationVerifier struct {
	entered chan struct{}
}

func (verifier blockingStrongAuthenticationVerifier) VerifyStrongAuthentication(
	ctx context.Context,
	_ authentication.BearerCredential,
	_ ElevationRequest,
) (resource.ID, time.Time, error) {
	close(verifier.entered)
	<-ctx.Done()
	return "", time.Time{}, fmt.Errorf("verifier-private-canary: %w", ctx.Err())
}

type countingClock struct {
	mu    sync.Mutex
	now   time.Time
	calls int
}

type gatedClock struct {
	now       time.Time
	entered   chan struct{}
	release   chan struct{}
	returning chan struct{}
}

func (clock gatedClock) Now() time.Time {
	close(clock.entered)
	<-clock.release
	close(clock.returning)
	return clock.now
}

func (clock *countingClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.calls++
	return clock.now
}

type issuanceClockStep struct {
	now       time.Time
	entered   chan struct{}
	release   chan struct{}
	returning chan struct{}
}

type scriptedIssuanceClock struct {
	mu       sync.Mutex
	steps    []issuanceClockStep
	next     int
	fallback time.Time
}

func (clock *scriptedIssuanceClock) Now() time.Time {
	clock.mu.Lock()
	if clock.next >= len(clock.steps) {
		now := clock.fallback
		clock.mu.Unlock()
		return now
	}
	step := clock.steps[clock.next]
	clock.next++
	clock.mu.Unlock()
	if step.entered != nil {
		close(step.entered)
	}
	if step.release != nil {
		<-step.release
	}
	if step.returning != nil {
		close(step.returning)
	}
	return step.now
}

type issueOutcome struct {
	grant Grant
	err   error
}

func TestLedgerIssueInvokesConfiguredVerifierWithExactInputs(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		ResolvePlatformAuditExportTarget(), time.Minute,
	)
	verifier := &testStrongAuthenticationVerifier{
		proofID:         testProofID,
		authenticatedAt: testNow.Add(-time.Minute),
	}
	clock := &testClock{now: testNow}
	ledger, err := NewLedger([]Administrator{administrator}, verifier, clock)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := authentication.NewBearerCredential(testBearerToken)
	if err != nil {
		t.Fatal(err)
	}

	grant, err := ledger.Issue(context.Background(), credential, request)
	if err != nil {
		t.Fatal(err)
	}
	verifier.mu.Lock()
	calls := verifier.calls
	capturedCredential := verifier.credential
	capturedRequest := cloneElevationRequest(verifier.request)
	verifier.mu.Unlock()
	if calls != 1 || capturedCredential.Token() != credential.Token() ||
		!equalElevationRequestForTest(capturedRequest, request) {
		t.Fatal("ledger did not pass the exact credential and request to its configured verifier once")
	}
	if grant.proofID != testProofID || grant.IssuedAt() != testNow {
		t.Fatal("grant did not bind verifier proof metadata to configured clock time")
	}

	for name, call := range map[string]func() error{
		"invalid credential": func() error {
			_, issueErr := ledger.Issue(context.Background(), authentication.BearerCredential{}, request)
			return issueErr
		},
		"invalid request": func() error {
			_, issueErr := ledger.Issue(context.Background(), credential, ElevationRequest{})
			return issueErr
		},
		"canceled context": func() error {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, issueErr := ledger.Issue(ctx, credential, request)
			return issueErr
		},
	} {
		issueErr := call()
		if name == "canceled context" {
			if !errors.Is(issueErr, context.Canceled) {
				t.Fatalf("%s error = %v", name, issueErr)
			}
		} else if !errors.Is(issueErr, ErrStrongAuthenticationInvalid) {
			t.Fatalf("%s error = %v", name, issueErr)
		}
	}
	verifier.mu.Lock()
	calls = verifier.calls
	verifier.mu.Unlock()
	if calls != 1 {
		t.Fatalf("pre-verification failures invoked verifier %d extra times", calls-1)
	}
}

func TestLedgerIssueClosesVerifierErrorsAndHonorsCancellation(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		ResolvePlatformAuditExportTarget(), time.Minute,
	)
	credential, err := authentication.NewBearerCredential(testBearerToken)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{"invalid", ErrStrongAuthenticationInvalid, ErrStrongAuthenticationInvalid},
		{"wrapped invalid", fmt.Errorf("verifier-private-canary: %w", ErrStrongAuthenticationInvalid), ErrStrongAuthenticationInvalid},
		{"unavailable", ErrStrongAuthenticationUnavailable, ErrStrongAuthenticationUnavailable},
		{"wrapped unavailable", fmt.Errorf("verifier-private-canary: %w", ErrStrongAuthenticationUnavailable), ErrStrongAuthenticationUnavailable},
		{"unknown", errors.New("verifier-private-canary"), ErrStrongAuthenticationUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := &testStrongAuthenticationVerifier{err: test.err}
			ledger, ledgerErr := NewLedger(
				[]Administrator{administrator}, verifier, &testClock{now: testNow},
			)
			if ledgerErr != nil {
				t.Fatal(ledgerErr)
			}
			_, issueErr := ledger.Issue(context.Background(), credential, request)
			if issueErr != test.want || strings.Contains(issueErr.Error(), "private-canary") {
				t.Fatalf("Issue() error = %v, want bare %v", issueErr, test.want)
			}
			if len(ledger.state.proofs) != 0 || len(ledger.state.grants) != 0 {
				t.Fatal("failed verification changed ledger authority")
			}
		})
	}

	entered := make(chan struct{})
	clock := &countingClock{now: testNow}
	ledger, err := NewLedger(
		[]Administrator{administrator},
		blockingStrongAuthenticationVerifier{entered: entered},
		clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, issueErr := ledger.Issue(ctx, credential, request)
		result <- issueErr
	}()
	waitForIssuanceSignal(t, entered, "verifier entry")
	cancel()
	select {
	case issueErr := <-result:
		if issueErr != context.Canceled || strings.Contains(issueErr.Error(), "private-canary") {
			t.Fatalf("Issue(canceled during verification) error = %v", issueErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Issue did not honor context cancellation during verification")
	}
	clock.mu.Lock()
	clockCalls := clock.calls
	clock.mu.Unlock()
	if clockCalls != 0 || len(ledger.state.proofs) != 0 || len(ledger.state.grants) != 0 {
		t.Fatal("canceled verification sampled time or changed ledger authority")
	}
}

func TestLedgerIssueRejectsMalformedVerifierSuccessWithoutAuthority(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		ResolvePlatformAuditExportTarget(), time.Minute,
	)
	credential, err := authentication.NewBearerCredential(testBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name            string
		proofID         resource.ID
		authenticatedAt time.Time
		want            error
	}{
		{"invalid proof ID", "short", testNow, ErrStrongAuthenticationUnavailable},
		{"zero authentication time", testProofID, time.Time{}, ErrStrongAuthenticationUnavailable},
		{"out-of-range authentication time", testProofID, time.Date(10_000, 1, 1, 0, 0, 0, 0, time.UTC), ErrStrongAuthenticationUnavailable},
		{"future authentication", testProofID, testNow.Add(time.Millisecond), ErrStrongAuthenticationInvalid},
		{"stale authentication", testProofID, testNow.Add(-MaxStrongAuthProofAge - time.Millisecond), ErrStrongAuthenticationInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := &testStrongAuthenticationVerifier{
				proofID:         test.proofID,
				authenticatedAt: test.authenticatedAt,
			}
			ledger, ledgerErr := NewLedger(
				[]Administrator{administrator}, verifier, &testClock{now: testNow},
			)
			if ledgerErr != nil {
				t.Fatal(ledgerErr)
			}
			_, issueErr := ledger.Issue(context.Background(), credential, request)
			if issueErr != test.want {
				t.Fatalf("Issue() error = %v, want %v", issueErr, test.want)
			}
			if len(ledger.state.proofs) != 0 || len(ledger.state.grants) != 0 {
				t.Fatal("malformed verifier success changed ledger authority")
			}
		})
	}
}

func TestLedgerIssueCancellationWinsBeforeLockedCommit(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		ResolvePlatformAuditExportTarget(), time.Minute,
	)
	credential, err := authentication.NewBearerCredential(testBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	clock := gatedClock{
		now:       testNow,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
		returning: make(chan struct{}),
	}
	verifier := &testStrongAuthenticationVerifier{
		proofID:         testProofID,
		authenticatedAt: testNow,
	}
	ledger, err := NewLedger([]Administrator{administrator}, verifier, clock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	ledger.state.mu.Lock()
	go func() {
		_, issueErr := ledger.Issue(ctx, credential, request)
		result <- issueErr
	}()
	waitForIssuanceSignal(t, clock.entered, "gated clock entry")
	close(clock.release)
	waitForIssuanceSignal(t, clock.returning, "gated clock return")
	cancel()
	ledger.state.mu.Unlock()
	select {
	case issueErr := <-result:
		if issueErr != context.Canceled {
			t.Fatalf("Issue(canceled before locked commit) error = %v", issueErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Issue remained blocked after ledger lock release")
	}
	if len(ledger.state.proofs) != 0 || len(ledger.state.grants) != 0 {
		t.Fatal("canceled locked issuance changed ledger authority")
	}
}

func TestLedgerCanceledClockSampleIsFencedBeforeContextWins(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	credential, err := authentication.NewBearerCredential(testBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	verifier := strongAuthenticationVerifierFunc(func(
		ctx context.Context,
		_ authentication.BearerCredential,
		request ElevationRequest,
	) (resource.ID, time.Time, error) {
		if err := ctx.Err(); err != nil {
			return "", time.Time{}, err
		}
		return resource.ID(strings.Replace(request.ID().String(), "elv_", "prf_", 1)), testNow, nil
	})

	laterEntered := make(chan struct{})
	laterRelease := make(chan struct{})
	laterReturning := make(chan struct{})
	regressedEntered := make(chan struct{})
	regressedRelease := make(chan struct{})
	regressedReturning := make(chan struct{})
	later := testNow.Add(10 * time.Minute)
	clock := &scriptedIssuanceClock{
		steps: []issuanceClockStep{
			{now: testNow},
			{
				now:       later,
				entered:   laterEntered,
				release:   laterRelease,
				returning: laterReturning,
			},
			{now: testNow},
			{
				now:       testNow,
				entered:   regressedEntered,
				release:   regressedRelease,
				returning: regressedReturning,
			},
		},
		fallback: later,
	}
	ledger, err := NewLedger([]Administrator{administrator}, verifier, clock)
	if err != nil {
		t.Fatal(err)
	}
	newRequest := func(index int) ElevationRequest {
		return mustRequest(
			t, generatedID("elv", index), administrator, principal,
			authorization.ActionAuditExport, target, time.Minute,
		)
	}
	baselineRequest := newRequest(701)
	if _, err := ledger.Issue(context.Background(), credential, baselineRequest); err != nil {
		t.Fatalf("establish high-water mark: %v", err)
	}

	canceledRequest := newRequest(702)
	canceledCtx, cancel := context.WithCancel(context.Background())
	canceledResult := make(chan error, 1)
	ledger.state.mu.Lock()
	go func() {
		_, issueErr := ledger.Issue(canceledCtx, credential, canceledRequest)
		canceledResult <- issueErr
	}()
	waitForIssuanceSignal(t, laterEntered, "later canceled clock sample")
	close(laterRelease)
	waitForIssuanceSignal(t, laterReturning, "later canceled clock return")
	cancel()
	ledger.state.mu.Unlock()
	select {
	case issueErr := <-canceledResult:
		if issueErr != context.Canceled {
			t.Fatalf("later canceled Issue error = %v", issueErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("later canceled Issue did not return after lock release")
	}
	ledger.state.mu.Lock()
	highWater := ledger.state.highWater
	proofCount := len(ledger.state.proofs)
	grantCount := len(ledger.state.grants)
	ledger.state.mu.Unlock()
	if !highWater.Equal(later) || proofCount != 1 || grantCount != 1 {
		t.Fatalf("canceled sample fence/authority = %v proofs:%d grants:%d", highWater, proofCount, grantCount)
	}

	rollbackRequest := newRequest(703)
	if _, err := ledger.Issue(
		context.Background(), credential, rollbackRequest,
	); !errors.Is(err, ErrClockRegressed) {
		t.Fatalf("Issue(after canceled later sample) error = %v, want ErrClockRegressed", err)
	}

	precedenceRequest := newRequest(704)
	precedenceCtx, cancelPrecedence := context.WithCancel(context.Background())
	precedenceResult := make(chan error, 1)
	ledger.state.mu.Lock()
	go func() {
		_, issueErr := ledger.Issue(precedenceCtx, credential, precedenceRequest)
		precedenceResult <- issueErr
	}()
	waitForIssuanceSignal(t, regressedEntered, "regressed canceled clock sample")
	close(regressedRelease)
	waitForIssuanceSignal(t, regressedReturning, "regressed canceled clock return")
	cancelPrecedence()
	ledger.state.mu.Unlock()
	select {
	case issueErr := <-precedenceResult:
		if issueErr != context.Canceled {
			t.Fatalf("context did not take precedence over clock regression: %v", issueErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("regressed canceled Issue did not return after lock release")
	}
	ledger.state.mu.Lock()
	proofCount = len(ledger.state.proofs)
	grantCount = len(ledger.state.grants)
	ledger.state.mu.Unlock()
	if proofCount != 1 || grantCount != 1 {
		t.Fatal("canceled or regressed issuance retained proof or grant authority")
	}
}

func TestBlockedVerifierDoesNotHoldLedgerLifecycleLock(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	credential, err := authentication.NewBearerCredential(testBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	var verifierMu sync.Mutex
	verifierCalls := 0
	blocked := make(chan struct{})
	verifier := strongAuthenticationVerifierFunc(func(
		ctx context.Context,
		_ authentication.BearerCredential,
		request ElevationRequest,
	) (resource.ID, time.Time, error) {
		verifierMu.Lock()
		verifierCalls++
		call := verifierCalls
		verifierMu.Unlock()
		if call == 4 {
			close(blocked)
			<-ctx.Done()
			return "", time.Time{}, ctx.Err()
		}
		return resource.ID(strings.Replace(request.ID().String(), "elv_", "prf_", 1)), testNow, nil
	})
	ledger, err := NewLedger(
		[]Administrator{administrator}, verifier, &testClock{now: testNow},
	)
	if err != nil {
		t.Fatal(err)
	}
	grants := make([]Grant, 0, 3)
	for index := 401; index <= 403; index++ {
		request := mustRequest(
			t, generatedID("elv", index), administrator, principal,
			authorization.ActionAuditExport, target, time.Minute,
		)
		grant, issueErr := ledger.Issue(context.Background(), credential, request)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		grants = append(grants, grant)
	}
	blockedRequest := mustRequest(
		t, generatedID("elv", 404), administrator, principal,
		authorization.ActionAuditExport, target, time.Minute,
	)
	blockedCtx, cancelBlocked := context.WithCancel(context.Background())
	blockedResult := make(chan error, 1)
	go func() {
		_, issueErr := ledger.Issue(blockedCtx, credential, blockedRequest)
		blockedResult <- issueErr
	}()
	waitForIssuanceSignal(t, blocked, "blocked verifier")

	lifecycleResult := make(chan error, 1)
	go func() {
		if state, stateErr := ledger.StateAt(testNow, grants[0]); stateErr != nil || state != GrantStateActive {
			lifecycleResult <- fmt.Errorf("StateAt = %v, %w", state, stateErr)
			return
		}
		if _, consumeErr := ledger.Consume(
			testNow, grants[1], authorization.ActionAuditExport, target,
		); consumeErr != nil {
			lifecycleResult <- fmt.Errorf("Consume: %w", consumeErr)
			return
		}
		if _, revokeErr := ledger.Revoke(testNow, grants[2]); revokeErr != nil {
			lifecycleResult <- fmt.Errorf("Revoke: %w", revokeErr)
			return
		}
		lifecycleResult <- nil
	}()
	select {
	case lifecycleErr := <-lifecycleResult:
		if lifecycleErr != nil {
			t.Fatal(lifecycleErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked verifier held the ledger lifecycle lock")
	}
	cancelBlocked()
	select {
	case issueErr := <-blockedResult:
		if issueErr != context.Canceled {
			t.Fatalf("blocked Issue cancellation error = %v", issueErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked verifier did not return after cancellation")
	}
}

func TestLedgerIssueOrdersClockSamplesAndRejectsInvalidOlderResult(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	credential, err := authentication.NewBearerCredential(testBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	verifier := strongAuthenticationVerifierFunc(func(
		ctx context.Context,
		_ authentication.BearerCredential,
		request ElevationRequest,
	) (resource.ID, time.Time, error) {
		if err := ctx.Err(); err != nil {
			return "", time.Time{}, err
		}
		return resource.ID(strings.Replace(request.ID().String(), "elv_", "prf_", 1)), testNow, nil
	})

	newRequest := func(index int) ElevationRequest {
		return mustRequest(
			t, generatedID("elv", index), administrator, principal,
			authorization.ActionAuditExport, target, time.Minute,
		)
	}

	firstEntered := make(chan struct{})
	firstRelease := make(chan struct{})
	secondEntered := make(chan struct{})
	secondRelease := make(chan struct{})
	clock := &scriptedIssuanceClock{
		steps: []issuanceClockStep{
			{now: testNow, entered: firstEntered, release: firstRelease},
			{now: testNow.Add(time.Second), entered: secondEntered, release: secondRelease},
		},
		fallback: testNow.Add(2 * time.Second),
	}
	ledger, err := NewLedger([]Administrator{administrator}, verifier, clock)
	if err != nil {
		t.Fatal(err)
	}
	firstRequest := newRequest(101)
	secondRequest := newRequest(102)
	firstResult := make(chan issueOutcome, 1)
	go func() {
		grant, issueErr := ledger.Issue(context.Background(), credential, firstRequest)
		firstResult <- issueOutcome{grant: grant, err: issueErr}
	}()
	waitForIssuanceSignal(t, firstEntered, "older valid clock sample")
	secondResult := make(chan issueOutcome, 1)
	go func() {
		grant, issueErr := ledger.Issue(context.Background(), credential, secondRequest)
		secondResult <- issueOutcome{grant: grant, err: issueErr}
	}()
	waitForIssuanceSignal(t, secondEntered, "newer valid clock sample")
	close(secondRelease)
	second := receiveIssueOutcome(t, secondResult, "newer valid clock completion")
	close(firstRelease)
	first := receiveIssueOutcome(t, firstResult, "older valid clock completion")
	if first.err != nil || second.err != nil ||
		first.grant.IssuedAt() != testNow.Add(time.Second) ||
		second.grant.IssuedAt() != testNow.Add(time.Second) {
		t.Fatalf("valid reverse completion = (%v, %v) / (%v, %v)",
			first.grant.IssuedAt(), first.err, second.grant.IssuedAt(), second.err)
	}

	invalidEntered := make(chan struct{})
	invalidRelease := make(chan struct{})
	validEntered := make(chan struct{})
	validRelease := make(chan struct{})
	invalidClock := &scriptedIssuanceClock{
		steps: []issuanceClockStep{
			{now: time.Time{}, entered: invalidEntered, release: invalidRelease},
			{now: testNow.Add(time.Second), entered: validEntered, release: validRelease},
		},
		fallback: testNow.Add(2 * time.Second),
	}
	invalidLedger, err := NewLedger([]Administrator{administrator}, verifier, invalidClock)
	if err != nil {
		t.Fatal(err)
	}
	invalidRequest := newRequest(201)
	validRequest := newRequest(202)
	invalidResult := make(chan issueOutcome, 1)
	go func() {
		grant, issueErr := invalidLedger.Issue(context.Background(), credential, invalidRequest)
		invalidResult <- issueOutcome{grant: grant, err: issueErr}
	}()
	waitForIssuanceSignal(t, invalidEntered, "older invalid clock sample")
	validResult := make(chan issueOutcome, 1)
	go func() {
		grant, issueErr := invalidLedger.Issue(context.Background(), credential, validRequest)
		validResult <- issueOutcome{grant: grant, err: issueErr}
	}()
	waitForIssuanceSignal(t, validEntered, "newer valid clock sample")
	close(validRelease)
	valid := receiveIssueOutcome(t, validResult, "newer valid clock completion")
	close(invalidRelease)
	invalid := receiveIssueOutcome(t, invalidResult, "older invalid clock completion")
	if valid.err != nil || invalid.err != ErrStrongAuthenticationUnavailable {
		t.Fatalf("invalid reverse completion errors = valid:%v invalid:%v", valid.err, invalid.err)
	}
	if _, err := invalidLedger.Issue(context.Background(), credential, invalidRequest); err != nil {
		t.Fatalf("invalid older sample partially retained grant authority: %v", err)
	}

	regressionClock := &testClock{now: testNow.Add(time.Second)}
	regressionLedger, err := NewLedger([]Administrator{administrator}, verifier, regressionClock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := regressionLedger.Issue(context.Background(), credential, newRequest(301)); err != nil {
		t.Fatal(err)
	}
	regressedRequest := newRequest(302)
	regressionClock.set(testNow)
	if _, err := regressionLedger.Issue(
		context.Background(), credential, regressedRequest,
	); !errors.Is(err, ErrClockRegressed) {
		t.Fatalf("fresh clock regression error = %v", err)
	}
	regressionClock.set(testNow.Add(2 * time.Second))
	if _, err := regressionLedger.Issue(context.Background(), credential, regressedRequest); err != nil {
		t.Fatalf("failed clock regression partially retained authority: %v", err)
	}
}

func TestLedgerStaleClockSequenceCannotReduceItsOwnProofAge(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	credential, err := authentication.NewBearerCredential(testBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	verifier := strongAuthenticationVerifierFunc(func(
		ctx context.Context,
		_ authentication.BearerCredential,
		request ElevationRequest,
	) (resource.ID, time.Time, error) {
		if err := ctx.Err(); err != nil {
			return "", time.Time{}, err
		}
		return resource.ID(strings.Replace(request.ID().String(), "elv_", "prf_", 1)), testNow, nil
	})

	for _, test := range []struct {
		name        string
		newerTime   time.Time
		newerError  error
		indexOffset int
	}{
		{
			name:        "newer invalid sample",
			newerTime:   time.Time{},
			newerError:  ErrStrongAuthenticationUnavailable,
			indexOffset: 500,
		},
		{
			name:        "newer regressing sample",
			newerTime:   testNow.Add(-time.Millisecond),
			newerError:  ErrClockRegressed,
			indexOffset: 600,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			olderEntered := make(chan struct{})
			olderRelease := make(chan struct{})
			newerEntered := make(chan struct{})
			newerRelease := make(chan struct{})
			staleMakingTime := testNow.Add(MaxStrongAuthProofAge + time.Minute)
			clock := &scriptedIssuanceClock{
				steps: []issuanceClockStep{
					{now: testNow},
					{now: staleMakingTime, entered: olderEntered, release: olderRelease},
					{now: test.newerTime, entered: newerEntered, release: newerRelease},
				},
				fallback: staleMakingTime.Add(time.Minute),
			}
			ledger, ledgerErr := NewLedger([]Administrator{administrator}, verifier, clock)
			if ledgerErr != nil {
				t.Fatal(ledgerErr)
			}
			baselineRequest := mustRequest(
				t, generatedID("elv", test.indexOffset), administrator, principal,
				authorization.ActionAuditExport, target, time.Minute,
			)
			if _, issueErr := ledger.Issue(context.Background(), credential, baselineRequest); issueErr != nil {
				t.Fatalf("establish high-water mark: %v", issueErr)
			}

			olderRequest := mustRequest(
				t, generatedID("elv", test.indexOffset+1), administrator, principal,
				authorization.ActionAuditExport, target, time.Minute,
			)
			newerRequest := mustRequest(
				t, generatedID("elv", test.indexOffset+2), administrator, principal,
				authorization.ActionAuditExport, target, time.Minute,
			)
			olderResult := make(chan issueOutcome, 1)
			go func() {
				grant, issueErr := ledger.Issue(context.Background(), credential, olderRequest)
				olderResult <- issueOutcome{grant: grant, err: issueErr}
			}()
			waitForIssuanceSignal(t, olderEntered, "older stale-making clock sample")
			newerResult := make(chan issueOutcome, 1)
			go func() {
				grant, issueErr := ledger.Issue(context.Background(), credential, newerRequest)
				newerResult <- issueOutcome{grant: grant, err: issueErr}
			}()
			waitForIssuanceSignal(t, newerEntered, "newer rejected clock sample")
			close(newerRelease)
			newer := receiveIssueOutcome(t, newerResult, "newer rejected clock completion")
			if newer.err != test.newerError {
				t.Fatalf("newer clock error = %v, want %v", newer.err, test.newerError)
			}
			close(olderRelease)
			older := receiveIssueOutcome(t, olderResult, "older stale-making clock completion")
			if older.err != ErrStrongAuthenticationInvalid {
				t.Fatalf("older stale proof error = %v, want %v", older.err, ErrStrongAuthenticationInvalid)
			}

			olderProofID := resource.ID(strings.Replace(olderRequest.ID().String(), "elv_", "prf_", 1))
			newerProofID := resource.ID(strings.Replace(newerRequest.ID().String(), "elv_", "prf_", 1))
			ledger.state.mu.Lock()
			_, olderProofRetained := ledger.state.proofs[olderProofID]
			_, newerProofRetained := ledger.state.proofs[newerProofID]
			_, olderGrantRetained := ledger.state.grants[olderRequest.ID()]
			_, newerGrantRetained := ledger.state.grants[newerRequest.ID()]
			highWater := ledger.state.highWater
			proofCount := len(ledger.state.proofs)
			grantCount := len(ledger.state.grants)
			ledger.state.mu.Unlock()
			if olderProofRetained || newerProofRetained || olderGrantRetained || newerGrantRetained ||
				proofCount != 1 || grantCount != 1 {
				t.Fatal("rejected reverse completions retained proof or grant authority")
			}
			if !highWater.Equal(staleMakingTime) {
				t.Fatalf("high-water time = %v, want conservative %v", highWater, staleMakingTime)
			}
		})
	}
}

func equalElevationRequestForTest(left, right ElevationRequest) bool {
	leftCase, leftHasCase := left.CaseReference()
	rightCase, rightHasCase := right.CaseReference()
	return left.ID() == right.ID() && left.AdministratorID() == right.AdministratorID() &&
		identity.EqualPrincipal(left.Principal(), right.Principal()) && left.Action() == right.Action() &&
		equalTarget(left.Target(), right.Target()) && left.Reason() == right.Reason() &&
		leftCase == rightCase && leftHasCase == rightHasCase &&
		left.RequestedAt().Equal(right.RequestedAt()) && left.Duration() == right.Duration()
}

func waitForIssuanceSignal(t testing.TB, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func receiveIssueOutcome(t testing.TB, result <-chan issueOutcome, name string) issueOutcome {
	t.Helper()
	select {
	case outcome := <-result:
		return outcome
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return issueOutcome{}
	}
}
