package condition

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var conditionFixtureTime = time.Date(2026, 9, 2, 20, 1, 2, 345_999_999, time.FixedZone("fixture", -5*60*60))

func TestNewNormalizesTimestamp(t *testing.T) {
	t.Parallel()

	got, err := New(Input{
		Type:               "Ready",
		Status:             StatusUnknown,
		Reason:             "PendingObservation",
		Message:            "The controller has not observed this generation.",
		ObservedGeneration: 0,
	}, 1, conditionFixtureTime)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got.LastTransitionAt != "2026-09-03T01:01:02.345Z" {
		t.Fatalf("LastTransitionAt = %q", got.LastTransitionAt)
	}
	if err := Validate(got, 1); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestYearZeroTimestamp(t *testing.T) {
	t.Parallel()

	got, err := New(Input{
		Type: "Ready", Status: StatusUnknown, Reason: "PendingObservation",
		ObservedGeneration: 0,
	}, 1, time.Date(0, time.January, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("New(year zero) error = %v", err)
	}
	if got.LastTransitionAt != "0000-01-01T00:00:00.000Z" {
		t.Fatalf("LastTransitionAt = %q", got.LastTransitionAt)
	}
	if err := Validate(got, 1); err != nil {
		t.Fatalf("Validate(year zero) error = %v", err)
	}
	goZero, err := New(Input{
		Type: "Ready", Status: StatusUnknown, Reason: "PendingObservation",
		ObservedGeneration: 0,
	}, 1, time.Time{})
	if err != nil {
		t.Fatalf("New(Go zero) error = %v", err)
	}
	if goZero.LastTransitionAt != "0001-01-01T00:00:00.000Z" {
		t.Fatalf("Go-zero LastTransitionAt = %q", goZero.LastTransitionAt)
	}

	for _, value := range []time.Time{
		time.Date(0, time.January, 1, 0, 0, 0, 0, time.FixedZone("east", 60*60)),
		time.Date(9999, time.December, 31, 23, 59, 59, 0, time.FixedZone("west", -60*60)),
	} {
		if _, err := New(Input{
			Type: "Ready", Status: StatusUnknown, Reason: "PendingObservation",
			ObservedGeneration: 0,
		}, 1, value); !errors.Is(err, ErrInvalidTimestamp) {
			t.Fatalf("New(UTC year rollover %v) error = %v", value, err)
		}
	}
}

func TestTransitionStatusMatrix(t *testing.T) {
	t.Parallel()

	statuses := []Status{StatusTrue, StatusFalse, StatusUnknown}
	for _, beforeStatus := range statuses {
		beforeStatus := beforeStatus
		for _, afterStatus := range statuses {
			afterStatus := afterStatus
			t.Run(string(beforeStatus)+"_to_"+string(afterStatus), func(t *testing.T) {
				t.Parallel()
				before := mustCondition(t, beforeStatus, 1, conditionFixtureTime)
				after, err := Transition(before, Update{
					Status:             afterStatus,
					Reason:             "ObservationRefreshed",
					Message:            "A bounded safe summary.",
					ObservedGeneration: 2,
				}, 2, conditionFixtureTime.Add(time.Second))
				if err != nil {
					t.Fatalf("Transition() error = %v", err)
				}
				if after.Type != before.Type || after.ObservedGeneration != 2 {
					t.Fatalf("after = %#v", after)
				}
				changed := after.LastTransitionAt != before.LastTransitionAt
				if changed != (afterStatus != beforeStatus) {
					t.Fatalf("timestamp changed = %t, statuses %q -> %q", changed, beforeStatus, afterStatus)
				}
			})
		}
	}
}

func TestSameStatusRefreshPreservesTransitionTime(t *testing.T) {
	t.Parallel()

	before := mustCondition(t, StatusUnknown, 0, conditionFixtureTime)
	after, err := Transition(before, Update{
		Status:             StatusUnknown,
		Reason:             "ProviderUnavailable",
		Message:            "The observation will be retried.",
		ObservedGeneration: 1,
	}, 1, time.Time{})
	if err != nil {
		t.Fatalf("Transition() error = %v", err)
	}
	if after.LastTransitionAt != before.LastTransitionAt {
		t.Fatalf("LastTransitionAt changed: %q -> %q", before.LastTransitionAt, after.LastTransitionAt)
	}
	if before.Reason == after.Reason {
		t.Fatal("reason did not refresh")
	}
}

func TestExactReplayIsNoOp(t *testing.T) {
	t.Parallel()

	before := mustCondition(t, StatusTrue, 1, conditionFixtureTime)
	after, err := Transition(before, Update{
		Status:             before.Status,
		Reason:             before.Reason,
		Message:            before.Message,
		ObservedGeneration: before.ObservedGeneration,
	}, 1, time.Time{})
	if err != nil {
		t.Fatalf("Transition(replay) error = %v", err)
	}
	if after != before {
		t.Fatalf("replay changed value: %#v -> %#v", before, after)
	}
}

func TestInvalidTransitionMatrix(t *testing.T) {
	t.Parallel()

	before := mustCondition(t, StatusUnknown, 1, conditionFixtureTime)
	tests := []struct {
		name       string
		update     Update
		generation int64
		at         time.Time
		want       error
	}{
		{
			name:       "observed generation regresses",
			update:     Update{Status: StatusTrue, Reason: "Ready", ObservedGeneration: 0},
			generation: 2, at: conditionFixtureTime.Add(time.Second), want: ErrObservedGeneration,
		},
		{
			name:       "observed future generation",
			update:     Update{Status: StatusTrue, Reason: "Ready", ObservedGeneration: 3},
			generation: 2, at: conditionFixtureTime.Add(time.Second), want: ErrObservedGeneration,
		},
		{
			name:       "invalid status",
			update:     Update{Status: "Maybe", Reason: "Ready", ObservedGeneration: 1},
			generation: 2, at: conditionFixtureTime.Add(time.Second), want: ErrInvalidStatus,
		},
		{
			name:       "transition time regresses",
			update:     Update{Status: StatusTrue, Reason: "Ready", ObservedGeneration: 1},
			generation: 2, at: conditionFixtureTime.Add(-time.Second), want: ErrInvalidTimestamp,
		},
		{
			name:       "transition time is same normalized millisecond",
			update:     Update{Status: StatusTrue, Reason: "Ready", ObservedGeneration: 1},
			generation: 2, at: conditionFixtureTime.Add(-500 * time.Microsecond), want: ErrInvalidTimestamp,
		},
		{
			name:       "transition time regresses to Go zero instant",
			update:     Update{Status: StatusTrue, Reason: "Ready", ObservedGeneration: 1},
			generation: 2, at: time.Time{}, want: ErrInvalidTimestamp,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			after, err := Transition(before, test.update, test.generation, test.at)
			if !errors.Is(err, ErrInvalidTransition) || !errors.Is(err, test.want) {
				t.Fatalf("Transition() error = %v, want transition and %v", err, test.want)
			}
			if after != before {
				t.Fatalf("failed transition changed value: %#v -> %#v", before, after)
			}
		})
	}
}

func TestValidateConditionMatrix(t *testing.T) {
	t.Parallel()

	valid := mustCondition(t, StatusTrue, 1, conditionFixtureTime)
	tests := []struct {
		name       string
		mutate     func(*Condition)
		generation int64
		want       error
	}{
		{name: "invalid resource generation", mutate: func(*Condition) {}, generation: 0, want: ErrObservedGeneration},
		{name: "empty type", mutate: func(value *Condition) { value.Type = "" }, generation: 1, want: ErrInvalidConditionType},
		{name: "unsafe type", mutate: func(value *Condition) { value.Type = "ready value" }, generation: 1, want: ErrInvalidConditionType},
		{name: "invalid status", mutate: func(value *Condition) { value.Status = "maybe" }, generation: 1, want: ErrInvalidStatus},
		{name: "invalid reason", mutate: func(value *Condition) { value.Reason = "provider.error" }, generation: 1, want: ErrInvalidReason},
		{name: "invalid message utf8", mutate: func(value *Condition) { value.Message = string([]byte{0xff}) }, generation: 1, want: ErrInvalidMessage},
		{name: "message too long", mutate: func(value *Condition) { value.Message = strings.Repeat("界", maxMessageRunes+1) }, generation: 1, want: ErrInvalidMessage},
		{name: "message byte preflight", mutate: func(value *Condition) { value.Message = strings.Repeat("x", 1<<20) }, generation: 1, want: ErrInvalidMessage},
		{name: "negative observation", mutate: func(value *Condition) { value.ObservedGeneration = -1 }, generation: 1, want: ErrObservedGeneration},
		{name: "future observation", mutate: func(value *Condition) { value.ObservedGeneration = 2 }, generation: 1, want: ErrObservedGeneration},
		{name: "timestamp offset", mutate: func(value *Condition) { value.LastTransitionAt = "2026-09-03T01:01:02.345+00:00" }, generation: 1, want: ErrInvalidTimestamp},
		{name: "timestamp precision", mutate: func(value *Condition) { value.LastTransitionAt = "2026-09-03T01:01:02Z" }, generation: 1, want: ErrInvalidTimestamp},
		{name: "timestamp byte preflight", mutate: func(value *Condition) { value.LastTransitionAt = strings.Repeat("0", 1<<20) }, generation: 1, want: ErrInvalidTimestamp},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := valid
			test.mutate(&value)
			err := Validate(value, test.generation)
			if !errors.Is(err, ErrInvalidCondition) || !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want condition and %v", err, test.want)
			}
		})
	}
}

func TestValidateSet(t *testing.T) {
	t.Parallel()

	available := mustNamedCondition(t, "Available")
	ready := mustNamedCondition(t, "Ready")
	if err := ValidateSet([]Condition{available, ready}, 1); err != nil {
		t.Fatalf("ValidateSet(valid) error = %v", err)
	}
	if err := ValidateSet([]Condition{ready, available}, 1); !errors.Is(err, ErrConditionOrder) {
		t.Fatalf("ValidateSet(unsorted) error = %v", err)
	}
	if err := ValidateSet([]Condition{ready, ready}, 1); !errors.Is(err, ErrDuplicateCondition) {
		t.Fatalf("ValidateSet(duplicate) error = %v", err)
	}
	tooMany := make([]Condition, MaxConditions+1)
	if err := ValidateSet(tooMany, 1); !errors.Is(err, ErrTooManyConditions) {
		t.Fatalf("ValidateSet(over limit) error = %v", err)
	}

	clone := CloneSet([]Condition{available, ready})
	clone[0].Reason = "Changed"
	if available.Reason == clone[0].Reason {
		t.Fatal("CloneSet() retained an alias")
	}
}

func TestErrorsDoNotContainValues(t *testing.T) {
	t.Parallel()

	sensitive := "CustomerSecretToken"
	_, err := New(Input{
		Type: sensitive + ".", Status: StatusTrue, Reason: "Ready", ObservedGeneration: 1,
	}, 1, time.Time{})
	if err == nil {
		t.Fatal("New() unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatalf("error contains input value: %q", err)
	}
}

func mustCondition(t *testing.T, status Status, observedGeneration int64, at time.Time) Condition {
	t.Helper()
	value, err := New(Input{
		Type:               "Ready",
		Status:             status,
		Reason:             "ObservationReceived",
		Message:            "A bounded safe summary.",
		ObservedGeneration: observedGeneration,
	}, max(1, observedGeneration), at)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return value
}

func mustNamedCondition(t *testing.T, name string) Condition {
	t.Helper()
	value, err := New(Input{
		Type: name, Status: StatusUnknown, Reason: "PendingObservation", ObservedGeneration: 0,
	}, 1, conditionFixtureTime)
	if err != nil {
		t.Fatalf("New(%q) error = %v", name, err)
	}
	return value
}
