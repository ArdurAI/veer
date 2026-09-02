package condition

import (
	"math/rand"
	"testing"
	"testing/quick"
	"time"
)

func TestPropertyTransitionTimestampTracksOnlyStatus(t *testing.T) {
	t.Parallel()

	statuses := []Status{StatusTrue, StatusFalse, StatusUnknown}
	property := func(beforeIndex, afterIndex uint8, generation uint16) bool {
		beforeStatus := statuses[int(beforeIndex)%len(statuses)]
		afterStatus := statuses[int(afterIndex)%len(statuses)]
		observed := int64(generation)%10_000 + 1
		before, err := New(Input{
			Type: "Ready", Status: beforeStatus, Reason: "Observed", ObservedGeneration: observed - 1,
		}, observed, conditionFixtureTime)
		if err != nil {
			return false
		}
		after, err := Transition(before, Update{
			Status: afterStatus, Reason: "Refreshed", ObservedGeneration: observed,
		}, observed, conditionFixtureTime.Add(time.Millisecond))
		if err != nil {
			return false
		}
		return (after.LastTransitionAt != before.LastTransitionAt) == (beforeStatus != afterStatus)
	}
	if err := quick.Check(property, &quick.Config{
		MaxCount: 500,
		Rand:     rand.New(rand.NewSource(19)),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyObservedGenerationNeverRegresses(t *testing.T) {
	t.Parallel()

	property := func(beforeRaw, afterRaw uint16) bool {
		beforeObserved := int64(beforeRaw) + 1
		afterObserved := int64(afterRaw) + 1
		generation := max(beforeObserved, afterObserved)
		before, err := New(Input{
			Type: "Ready", Status: StatusUnknown, Reason: "Observed", ObservedGeneration: beforeObserved,
		}, generation, conditionFixtureTime)
		if err != nil {
			return false
		}
		_, err = Transition(before, Update{
			Status: StatusTrue, Reason: "Observed", ObservedGeneration: afterObserved,
		}, generation, conditionFixtureTime.Add(time.Millisecond))
		return (err == nil) == (afterObserved >= beforeObserved)
	}
	if err := quick.Check(property, &quick.Config{
		MaxCount: 500,
		Rand:     rand.New(rand.NewSource(20)),
	}); err != nil {
		t.Fatal(err)
	}
}
