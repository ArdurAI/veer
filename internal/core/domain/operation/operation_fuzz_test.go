package operation

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"
)

func FuzzTransition(f *testing.F) {
	f.Add(uint8(0), uint8(1), "Waiting", "DependencyPending")
	f.Add(uint8(2), uint8(5), "Canceled", "CancellationAccepted")

	phases := []Phase{PhasePending, PhaseWaiting, PhaseRunning, PhaseSucceeded, PhaseFailed, PhaseCanceled, Phase("Invalid")}
	f.Fuzz(func(t *testing.T, beforeIndex, afterIndex uint8, message, reason string) {
		if len(message)+len(reason) > 4_096 {
			t.Skip()
		}
		before := newProviderOperation(t)
		before.Phase = phases[int(beforeIndex)%6]
		_, err := Transition(before, TransitionInput{
			Phase: phases[int(afterIndex)%len(phases)], Reason: reason, Message: message,
			ResourceVersion: "rv_fuzz_transition", UpdatedAt: operationFixtureTime.Add(time.Millisecond),
		})
		if err != nil && !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("Transition() returned unclassified error: %v", err)
		}
	})
}

func FuzzCanonicalDecode(f *testing.F) {
	valid, err := os.ReadFile("testdata/provider-bound.golden.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bytes.TrimSpace(valid))
	f.Add([]byte{})
	f.Add([]byte(`{"phase":"Running"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxCanonicalBytes+1 {
			t.Skip()
		}
		_, err := UnmarshalCanonical(data)
		if err != nil && !isOperationSentinel(err) {
			t.Fatalf("UnmarshalCanonical() returned unclassified error: %v", err)
		}
	})
}

func isOperationSentinel(err error) bool {
	for _, sentinel := range []error{
		ErrInvalidOperation, ErrInvalidOperationID, ErrInvalidWorkspaceID,
		ErrInvalidResourceID, ErrInvalidGeneration, ErrInvalidResourceVersion,
		ErrInvalidPhase, ErrInvalidReason, ErrInvalidMessage, ErrInvalidTimestamp,
		ErrInvalidProviderBinding, ErrInvalidTransition, ErrPhaseTransition,
		ErrNoMaterialChange, ErrResourceVersionUnchanged,
		ErrCanonicalTooLarge, ErrNonCanonical,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}
