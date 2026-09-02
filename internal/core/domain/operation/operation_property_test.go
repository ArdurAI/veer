package operation

import (
	"math/rand"
	"testing"
	"testing/quick"
	"time"
)

func TestPropertyTerminalPhasesOnlyReplay(t *testing.T) {
	t.Parallel()

	terminal := []Phase{PhaseSucceeded, PhaseFailed, PhaseCanceled}
	all := []Phase{PhasePending, PhaseWaiting, PhaseRunning, PhaseSucceeded, PhaseFailed, PhaseCanceled}
	property := func(terminalIndex, targetIndex uint8, changeReason bool) bool {
		before := newProviderOperation(t)
		before.Phase = terminal[int(terminalIndex)%len(terminal)]
		target := all[int(targetIndex)%len(all)]
		reason := before.Reason
		if changeReason {
			reason = "Changed"
		}
		after, err := Transition(before, TransitionInput{
			Phase: target, Reason: reason, Message: before.Message,
			CostEstimate: cloneCost(before.CostEstimate), ResourceVersion: "rv_terminal_attempt",
			UpdatedAt: operationFixtureTime.Add(time.Second),
		})
		wantReplay := target == before.Phase && !changeReason
		return (err == nil) == wantReplay && equal(after, before)
	}
	if err := quick.Check(property, &quick.Config{
		MaxCount: 500,
		Rand:     rand.New(rand.NewSource(23)),
	}); err != nil {
		t.Fatal(err)
	}
}
