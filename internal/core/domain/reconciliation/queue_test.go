package reconciliation

import (
	"errors"
	"sync"
	"testing"
)

func TestQueueBudgetPreReservesVisibilityAndFailsAtTargetCap(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 80, false)
	baseline, _ := NewWorkKey(fixture.plan, []byte("baseline-partition"))
	visibility, _ := NewWorkKey(fixture.plan, []byte("visibility-partition"))
	extra, _ := NewWorkKey(fixture.plan, []byte("unreserved-extra"))
	budget, err := NewQueueBudget(TargetMonthlyQueueRequestCap, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := budget.Reserve(baseline, 100_000_000); err != nil {
		t.Fatal(err)
	}
	if _, err := budget.Reserve(visibility, TargetMonthlyVisibilityRequests); err != nil {
		t.Fatal(err)
	}
	used, reserved, available := budget.Usage()
	if used != 0 || reserved != TargetMonthlyQueueRequestCap || available != 0 {
		t.Fatalf("target usage = %d/%d/%d", used, reserved, available)
	}
	if _, err := budget.Reserve(extra, 1); !errors.Is(err, ErrCapacity) {
		t.Fatalf("unreserved request error = %v", err)
	}
}

func TestQueueBudgetCountsRetriesAndPartialBatchAttempts(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 81, false)
	work, _ := NewWorkKey(fixture.plan, []byte("batch"))
	budget, _ := NewQueueBudget(20, 1)
	reservation, err := budget.Reserve(work, 10)
	if err != nil {
		t.Fatal(err)
	}
	// Initial five-entry batch, two retry units after partial failure, and one
	// visibility heartbeat are all billable actions regardless of outcome.
	for _, units := range []int64{5, 2, 1} {
		reservation, err = budget.Consume(reservation, units)
		if err != nil {
			t.Fatal(err)
		}
	}
	completed, err := budget.Complete(reservation)
	if err != nil || completed.consumed != 8 || !completed.completed {
		t.Fatalf("Complete() = %#v, %v", completed, err)
	}
	used, reserved, available := budget.Usage()
	if used != 8 || reserved != 0 || available != 12 {
		t.Fatalf("usage = %d/%d/%d", used, reserved, available)
	}
	if _, err := budget.Reserve(work, 10); !errors.Is(err, ErrReservationLost) {
		t.Fatalf("completed work re-admission error = %v", err)
	}
}

func TestQueueCompletionVersusHeartbeatHasOneAccountingWinner(t *testing.T) {
	for iteration := 0; iteration < 1_000; iteration++ {
		fixture := newPlanFixture(t, 1, 2000+iteration, false)
		work, _ := NewWorkKey(fixture.plan, []byte("race"))
		budget, _ := NewQueueBudget(1, 1)
		reservation, _ := budget.Reserve(work, 1)
		start := make(chan struct{})
		var wait sync.WaitGroup
		var consumeErr, completeErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, consumeErr = budget.Consume(reservation, 1)
		}()
		go func() {
			defer wait.Done()
			<-start
			_, completeErr = budget.Complete(reservation)
		}()
		close(start)
		wait.Wait()
		if completeErr != nil {
			t.Fatalf("iteration %d completion error = %v", iteration, completeErr)
		}
		used, reserved, available := budget.Usage()
		if reserved != 0 || used+available != 1 {
			t.Fatalf("iteration %d usage = %d/%d/%d", iteration, used, reserved, available)
		}
		switch used {
		case 0:
			if !errors.Is(consumeErr, ErrReservationLost) {
				t.Fatalf("iteration %d losing heartbeat error = %v", iteration, consumeErr)
			}
		case 1:
			if consumeErr != nil {
				t.Fatalf("iteration %d winning heartbeat error = %v", iteration, consumeErr)
			}
		default:
			t.Fatalf("iteration %d used = %d", iteration, used)
		}
	}
}
