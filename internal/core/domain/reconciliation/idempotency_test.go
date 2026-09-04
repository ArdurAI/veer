package reconciliation

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

const fixtureIdempotencyKey = "idem-0123456789ABC"

func TestIdempotencyWindowIsFixedNonSlidingAtExactBoundary(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 30, false)
	scope, err := NewIdempotencyScope(fixture.actor, "PUT", []byte("/api/v1alpha1/workspaces/target"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := mustRequestFingerprint(t, "normalized-request-one")
	result := mustResultDigest(t, "status=202;operation=one")
	ledger, err := NewIdempotencyLedger(2)
	if err != nil {
		t.Fatal(err)
	}
	reservation, disposition, err := ledger.Reserve(fixtureTime, scope, fixtureIdempotencyKey, fingerprint)
	if err != nil || disposition != IdempotencyReserved {
		t.Fatalf("initial Reserve() = %q, %v", disposition, err)
	}
	completed, err := ledger.Complete(reservation, result)
	if err != nil {
		t.Fatal(err)
	}
	wantExpiry := fixtureTime.Add(HTTPIdempotencyWindow)
	if !completed.expiresAt.Equal(wantExpiry) {
		t.Fatalf("expiry = %s, want %s", completed.expiresAt, wantExpiry)
	}

	for index, replayAt := range []time.Time{
		fixtureTime.Add(time.Hour),
		wantExpiry.Add(-time.Millisecond),
	} {
		replay, got, err := ledger.Reserve(replayAt, scope, fixtureIdempotencyKey, fingerprint)
		if err != nil || got != IdempotencyReplay || !replay.expiresAt.Equal(wantExpiry) {
			t.Fatalf("replay %d = %q, expiry %s, %v", index, got, replay.expiresAt, err)
		}
	}

	replacementFingerprint := mustRequestFingerprint(t, "normalized-request-two")
	replacement, got, err := ledger.Reserve(wantExpiry, scope, fixtureIdempotencyKey, replacementFingerprint)
	if err != nil || got != IdempotencyReserved || replacement.epoch != 2 ||
		!replacement.committedAt.Equal(wantExpiry) ||
		!replacement.expiresAt.Equal(wantExpiry.Add(HTTPIdempotencyWindow)) {
		t.Fatalf("exact-boundary replacement = %#v, %q, %v", replacement, got, err)
	}
}

func TestIdempotencyBoundaryMinusEqualAndPlus(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		offset time.Duration
		want   IdempotencyDisposition
	}{
		{name: "minus epsilon", offset: HTTPIdempotencyWindow - time.Millisecond, want: IdempotencyReplay},
		{name: "equality", offset: HTTPIdempotencyWindow, want: IdempotencyReserved},
		{name: "plus epsilon", offset: HTTPIdempotencyWindow + time.Millisecond, want: IdempotencyReserved},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPlanFixture(t, 1, 31, false)
			scope, err := NewIdempotencyScope(fixture.actor, "POST", []byte("/target"))
			if err != nil {
				t.Fatal(err)
			}
			fingerprint := mustRequestFingerprint(t, "request")
			ledger, _ := NewIdempotencyLedger(1)
			reservation, _, err := ledger.Reserve(fixtureTime, scope, fixtureIdempotencyKey, fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ledger.Complete(reservation, mustResultDigest(t, "result")); err != nil {
				t.Fatal(err)
			}
			gotReservation, got, err := ledger.Reserve(fixtureTime.Add(test.offset), scope, fixtureIdempotencyKey, fingerprint)
			if err != nil || got != test.want {
				t.Fatalf("Reserve() = %q, %v", got, err)
			}
			wantEpoch := uint64(1)
			if test.want == IdempotencyReserved {
				wantEpoch = 2
			}
			if gotReservation.epoch != wantEpoch {
				t.Fatalf("epoch = %d, want %d", gotReservation.epoch, wantEpoch)
			}
		})
	}
}

func TestUnresolvedIdempotencyReservationCannotBeRecycledByTime(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 32, false)
	scope, _ := NewIdempotencyScope(fixture.actor, "DELETE", []byte("/target"))
	fingerprint := mustRequestFingerprint(t, "request")
	ledger, _ := NewIdempotencyLedger(1)
	reservation, _, err := ledger.Reserve(fixtureTime, scope, fixtureIdempotencyKey, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	got, disposition, err := ledger.Reserve(
		reservation.expiresAt.Add(365*24*time.Hour),
		scope,
		fixtureIdempotencyKey,
		fingerprint,
	)
	if !errors.Is(err, ErrReservationOutstanding) || disposition != "" || got.epoch != reservation.epoch {
		t.Fatalf("expired unresolved Reserve() = %#v, %q, %v", got, disposition, err)
	}
	if _, _, err := ledger.Reserve(
		reservation.expiresAt.Add(365*24*time.Hour),
		scope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "different"),
	); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("mismatched unresolved error = %v", err)
	}
}

func TestIdempotencyCutoffRacersHaveExactlyOneFreshWinner(t *testing.T) {
	fixture := newPlanFixture(t, 1, 33, false)
	scope, _ := NewIdempotencyScope(fixture.actor, "PATCH", []byte("/target"))
	ledger, _ := NewIdempotencyLedger(1)
	initial, _, err := ledger.Reserve(
		fixtureTime,
		scope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "initial"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Complete(initial, mustResultDigest(t, "initial-result")); err != nil {
		t.Fatal(err)
	}

	type result struct {
		reservation Reservation
		disposition IdempotencyDisposition
		err         error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wait sync.WaitGroup
	requests := []struct {
		name        string
		fingerprint RequestFingerprint
	}{
		{name: "cutoff-left", fingerprint: mustRequestFingerprint(t, "cutoff-left")},
		{name: "cutoff-right", fingerprint: mustRequestFingerprint(t, "cutoff-right")},
	}
	for _, request := range requests {
		request := request
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			reservation, disposition, err := ledger.Reserve(
				initial.expiresAt,
				scope,
				fixtureIdempotencyKey,
				request.fingerprint,
			)
			results <- result{reservation: reservation, disposition: disposition, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	winners := 0
	conflicts := 0
	for result := range results {
		switch {
		case result.err == nil && result.disposition == IdempotencyReserved && result.reservation.epoch == 2:
			winners++
		case errors.Is(result.err, ErrIdempotencyConflict):
			conflicts++
		default:
			t.Fatalf("unexpected racer result: %#v", result)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("winners/conflicts = %d/%d", winners, conflicts)
	}
}

func TestIdempotencyClockAndCapacityFailClosed(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 34, false)
	scope, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/target"))
	ledger, _ := NewIdempotencyLedger(1)
	if _, _, err := ledger.Reserve(fixtureTime, scope, fixtureIdempotencyKey, mustRequestFingerprint(t, "one")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Reserve(
		fixtureTime.Add(-time.Millisecond),
		scope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "one"),
	); !errors.Is(err, ErrClockRegressed) {
		t.Fatalf("clock regression error = %v", err)
	}
	otherScope, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/other"))
	if _, _, err := ledger.Reserve(
		fixtureTime,
		otherScope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "two"),
	); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
}

func TestExpiredCompletedReservationReleasesCapacityAndRejectsStaleCompletion(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 234, false)
	firstScope, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/first"))
	secondScope, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/second"))
	thirdScope, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/third"))
	ledger, _ := NewIdempotencyLedger(2)
	first, _, err := ledger.Reserve(
		fixtureTime,
		firstScope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "first"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Complete(first, mustResultDigest(t, "first-result")); err != nil {
		t.Fatal(err)
	}
	second, _, err := ledger.Reserve(
		fixtureTime,
		secondScope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "second"),
	)
	if err != nil {
		t.Fatal(err)
	}
	third, disposition, err := ledger.Reserve(
		first.expiresAt,
		thirdScope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "third"),
	)
	if err != nil || disposition != IdempotencyReserved || third.epoch != 1 || ledger.Len() != 2 {
		t.Fatalf("capacity reclamation = %#v, %s, len=%d, %v", third, disposition, ledger.Len(), err)
	}
	if _, _, err := ledger.Reserve(
		fixtureTime.Add(-time.Millisecond),
		firstScope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "first"),
	); !errors.Is(err, ErrClockRegressed) {
		t.Fatalf("reclaimed key clock regression error = %v", err)
	}
	if _, err := ledger.Complete(third, mustResultDigest(t, "third-result")); err != nil {
		t.Fatal(err)
	}
	firstAgain, disposition, err := ledger.Reserve(
		third.expiresAt,
		firstScope,
		fixtureIdempotencyKey,
		first.fingerprint,
	)
	if err != nil || disposition != IdempotencyReserved || firstAgain.epoch != 1 {
		t.Fatalf("reclaimed key epoch = %#v, %s, %v", firstAgain, disposition, err)
	}
	if _, err := ledger.Complete(first, mustResultDigest(t, "stale-result")); !errors.Is(err, ErrReservationLost) {
		t.Fatalf("old reservation completed replacement epoch: %v", err)
	}
	if _, _, err := ledger.Reserve(
		first.expiresAt.Add(365*24*time.Hour),
		secondScope,
		fixtureIdempotencyKey,
		second.fingerprint,
	); !errors.Is(err, ErrReservationOutstanding) {
		t.Fatalf("unresolved reservation was reclaimed: %v", err)
	}
}

func TestIdempotencyClockOrderingIsLedgerWide(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 134, false)
	one, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/one"))
	two, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/two"))
	ledger, _ := NewIdempotencyLedger(2)
	if _, _, err := ledger.Reserve(
		fixtureTime.Add(time.Second),
		one,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "one"),
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Reserve(
		fixtureTime,
		two,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "two"),
	); !errors.Is(err, ErrClockRegressed) {
		t.Fatalf("independent key rollback error = %v", err)
	}
	if _, _, err := ledger.Reserve(
		fixtureTime.Add(2*time.Second),
		two,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "two"),
	); err != nil {
		t.Fatalf("forward independent key error = %v", err)
	}
	if _, _, err := ledger.Reserve(
		fixtureTime.Add(time.Second),
		two,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "two"),
	); !errors.Is(err, ErrClockRegressed) {
		t.Fatalf("ledger-wide clock regression error = %v", err)
	}
}

func TestCrossKeyCleanupWaitsForEarlierLiveReservationCall(t *testing.T) {
	fixture := newPlanFixture(t, 1, 334, false)
	protectedScope, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/protected"))
	fillerScope, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/filler"))
	newScope, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/new"))
	protectedFingerprint := mustRequestFingerprint(t, "protected")
	ledger, _ := NewIdempotencyLedger(2)
	protected, _, err := ledger.Reserve(
		fixtureTime,
		protectedScope,
		fixtureIdempotencyKey,
		protectedFingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Complete(protected, mustResultDigest(t, "protected-result")); err != nil {
		t.Fatal(err)
	}
	filler, _, err := ledger.Reserve(
		fixtureTime,
		fillerScope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "filler"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Complete(filler, mustResultDigest(t, "filler-result")); err != nil {
		t.Fatal(err)
	}

	keyDigest := deriveDigest("veer.reconciliation.idempotency-key.v1", []byte(fixtureIdempotencyKey))
	mapKey := formatDigest("", protectedScope.digest) + ":" + formatDigest("", keyDigest)
	earlier, err := ledger.beginIdempotencyCall(mapKey, protected.expiresAt.Add(-time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}

	created, disposition, err := ledger.Reserve(
		protected.expiresAt,
		newScope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "new"),
	)
	if err != nil || disposition != IdempotencyReserved || created.epoch != 1 || ledger.Len() != 2 {
		t.Fatalf("selective reclamation while earlier call is live = %#v, %s, len=%d, %v", created, disposition, ledger.Len(), err)
	}
	replay, disposition, err := ledger.reserveRegistered(
		earlier,
		protectedScope,
		keyDigest,
		mapKey,
		protectedFingerprint,
	)
	ledger.finishIdempotencyCall(mapKey, earlier)
	if err != nil || disposition != IdempotencyReplay || replay.epoch != protected.epoch {
		t.Fatalf("earlier protected call = %#v, %s, %v", replay, disposition, err)
	}

	ledger.activityMu.Lock()
	activeCount := ledger.activeCount
	ledger.activityMu.Unlock()
	if activeCount != 0 {
		t.Fatalf("active calls after completion = %d", activeCount)
	}
}

func TestIdempotencyActiveCallRegistryIsBounded(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 336, false)
	ledger, _ := NewIdempotencyLedger(2)
	keyDigest := deriveDigest("veer.reconciliation.idempotency-key.v1", []byte(fixtureIdempotencyKey))

	type registeredCall struct {
		mapKey string
		call   *idempotencyCall
	}
	var calls []registeredCall
	for index := 0; index < ledger.activeLimit; index++ {
		scope, _ := NewIdempotencyScope(fixture.actor, "POST", []byte(fmt.Sprintf("/active/%d", index)))
		mapKey := formatDigest("", scope.digest) + ":" + formatDigest("", keyDigest)
		call, err := ledger.beginIdempotencyCall(mapKey, fixtureTime)
		if err != nil {
			t.Fatalf("beginIdempotencyCall(%d) = %v", index, err)
		}
		calls = append(calls, registeredCall{mapKey: mapKey, call: call})
	}
	overflowScope, _ := NewIdempotencyScope(fixture.actor, "POST", []byte("/active/overflow"))
	overflowKey := formatDigest("", overflowScope.digest) + ":" + formatDigest("", keyDigest)
	if _, err := ledger.beginIdempotencyCall(overflowKey, fixtureTime); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow active call error = %v", err)
	}

	for _, registered := range calls {
		ledger.finishIdempotencyCall(registered.mapKey, registered.call)
	}
	call, err := ledger.beginIdempotencyCall(overflowKey, fixtureTime)
	if err != nil {
		t.Fatalf("released active capacity was not reusable: %v", err)
	}
	ledger.finishIdempotencyCall(overflowKey, call)
}

func TestIdempotencyReclamationBoundsKeyState(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 335, false)
	ledger, _ := NewIdempotencyLedger(1)
	var stale Reservation
	for index := 0; index < 100; index++ {
		scope, err := NewIdempotencyScope(
			fixture.actor,
			"POST",
			[]byte(fmt.Sprintf("/bounded/%d", index)),
		)
		if err != nil {
			t.Fatal(err)
		}
		at := fixtureTime.Add(time.Duration(index) * (HTTPIdempotencyWindow + time.Millisecond))
		reservation, disposition, err := ledger.Reserve(
			at,
			scope,
			fixtureIdempotencyKey,
			mustRequestFingerprint(t, fmt.Sprintf("request-%d", index)),
		)
		if err != nil || disposition != IdempotencyReserved || reservation.epoch != 1 {
			t.Fatalf("Reserve(%d) = %#v, %s, %v", index, reservation, disposition, err)
		}
		if index == 0 {
			stale = reservation
		}
		if _, err := ledger.Complete(reservation, mustResultDigest(t, fmt.Sprintf("result-%d", index))); err != nil {
			t.Fatal(err)
		}
		if got := len(ledger.keyState); got != 1 {
			t.Fatalf("key-state count after %d = %d", index, got)
		}
	}
	if got := len(ledger.records); got != 1 {
		t.Fatalf("record count = %d", got)
	}
	ledger.activityMu.Lock()
	active := len(ledger.active)
	ledger.activityMu.Unlock()
	if active != 0 {
		t.Fatalf("active-call keys = %d", active)
	}
	if _, err := ledger.Complete(stale, mustResultDigest(t, "stale")); !errors.Is(err, ErrReservationLost) {
		t.Fatalf("reclaimed stale completion = %v", err)
	}
}

func TestIdempotencyRejectsExpiryOutsideCanonicalTimeRange(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 35, false)
	scope, err := NewIdempotencyScope(fixture.actor, "POST", []byte("/target"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := NewIdempotencyLedger(1)
	if err != nil {
		t.Fatal(err)
	}
	nearUpperBound := time.Date(9999, time.December, 31, 23, 59, 59, 999_000_000, time.UTC)
	if _, _, err := ledger.Reserve(
		nearUpperBound,
		scope,
		fixtureIdempotencyKey,
		mustRequestFingerprint(t, "request"),
	); !errors.Is(err, ErrInvalidTime) || !errors.Is(err, ErrInvalidIdempotency) {
		t.Fatalf("Reserve() error = %v", err)
	}
	if ledger.Len() != 0 {
		t.Fatalf("failed reservation retained %d records", ledger.Len())
	}
}
