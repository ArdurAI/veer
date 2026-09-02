package condition

import (
	"errors"
	"testing"
	"time"
)

func FuzzConditionValidation(f *testing.F) {
	f.Add("Ready", "True", "Observed", "safe", int64(1), "2026-09-03T01:01:02.345Z")
	f.Add("", "Maybe", "", "", int64(-1), "")

	f.Fuzz(func(t *testing.T, kind, status, reason, message string, observed int64, timestamp string) {
		if len(kind)+len(status)+len(reason)+len(message)+len(timestamp) > 4_096 {
			t.Skip()
		}
		err := Validate(Condition{
			Type: kind, Status: Status(status), Reason: reason, Message: message,
			ObservedGeneration: observed, LastTransitionAt: timestamp,
		}, 1)
		if err != nil && !errors.Is(err, ErrInvalidCondition) {
			t.Fatalf("Validate() returned unclassified error: %v", err)
		}
	})
}

func FuzzTransition(f *testing.F) {
	f.Add(uint8(0), uint8(2), int64(1), int64(2))
	f.Add(uint8(2), uint8(1), int64(2), int64(1))

	statuses := []Status{StatusTrue, StatusFalse, StatusUnknown, Status("Invalid")}
	f.Fuzz(func(t *testing.T, beforeIndex, afterIndex uint8, beforeObserved, afterObserved int64) {
		beforeObserved %= 10_000
		if beforeObserved < 0 {
			beforeObserved = -beforeObserved
		}
		afterObserved %= 10_000
		before, err := New(Input{
			Type: "Ready", Status: statuses[int(beforeIndex)%3], Reason: "Observed",
			ObservedGeneration: beforeObserved,
		}, max(1, beforeObserved), conditionFixtureTime)
		if err != nil {
			t.Fatalf("seed condition error = %v", err)
		}
		_, err = Transition(before, Update{
			Status: statuses[int(afterIndex)%len(statuses)], Reason: "Refreshed",
			ObservedGeneration: afterObserved,
		}, max(1, max(beforeObserved, afterObserved)), conditionFixtureTime.Add(time.Millisecond))
		if err != nil && !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("Transition() returned unclassified error: %v", err)
		}
	})
}
