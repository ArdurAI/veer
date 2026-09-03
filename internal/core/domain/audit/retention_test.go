package audit

import (
	"errors"
	"testing"
	"time"
)

func TestRetentionBoundariesAndHolds(t *testing.T) {
	t.Parallel()

	recordedAt := testTime.Add(456 * time.Microsecond)
	normalizedRecordedAt := testTime
	tests := []struct {
		name        string
		evaluatedAt time.Time
		holds       []Hold
		want        RetentionDisposition
		eligible    bool
	}{
		{"before online boundary", normalizedRecordedAt.Add(OnlineRetention - time.Millisecond), nil, RetentionDispositionOnline, false},
		{"at online boundary", normalizedRecordedAt.Add(OnlineRetention), nil, RetentionDispositionArchive, false},
		{"before archive boundary", normalizedRecordedAt.Add(ArchiveRetention - time.Millisecond), nil, RetentionDispositionArchive, false},
		{"at archive boundary", normalizedRecordedAt.Add(ArchiveRetention), nil, RetentionDispositionExpire, true},
	}
	hold, err := NewHold(testHoldID, HoldKindLegal)
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name        string
		evaluatedAt time.Time
		holds       []Hold
		want        RetentionDisposition
		eligible    bool
	}{"hold wins after archive boundary", normalizedRecordedAt.Add(2 * ArchiveRetention), []Hold{hold}, RetentionDispositionHeld, false})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := EvaluateRetention(RetentionInput{
				RecordedAt:          recordedAt,
				EvaluatedAt:         test.evaluatedAt,
				PreviousEvaluatedAt: normalizedRecordedAt,
				ClockState:          ClockStateSynchronized,
				Holds:               test.holds,
			})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Disposition() != test.want || decision.EligibleForDeletion() != test.eligible {
				t.Fatalf("decision = %s/%t, want %s/%t", decision.Disposition(), decision.EligibleForDeletion(), test.want, test.eligible)
			}
			if !decision.OnlineUntil().Equal(normalizedRecordedAt.Add(OnlineRetention)) ||
				!decision.ArchiveUntil().Equal(normalizedRecordedAt.Add(ArchiveRetention)) {
				t.Fatalf("retention boundaries = %s/%s", decision.OnlineUntil(), decision.ArchiveUntil())
			}
		})
	}
}

func TestRetentionInvalidOrRegressedTimeFailsClosed(t *testing.T) {
	t.Parallel()

	valid := RetentionInput{
		RecordedAt:          testTime,
		EvaluatedAt:         testTime.Add(ArchiveRetention),
		PreviousEvaluatedAt: testTime.Add(OnlineRetention),
		ClockState:          ClockStateSynchronized,
	}
	tests := []struct {
		name   string
		mutate func(*RetentionInput)
		want   error
	}{
		{"combined state retains uncertain event", func(input *RetentionInput) { input.ClockState = ClockStateUncertain }, ErrInvalidClockState},
		{"combined state retains regressed event", func(input *RetentionInput) { input.ClockState = ClockStateRegressed }, ErrClockRegressed},
		{"open clock value", func(input *RetentionInput) { input.ClockState = "Other" }, ErrInvalidClockState},
		{"zero event time", func(input *RetentionInput) { input.RecordedAt = time.Time{} }, ErrInvalidClockState},
		{"zero evaluation time", func(input *RetentionInput) { input.EvaluatedAt = time.Time{} }, ErrInvalidClockState},
		{"zero previous time", func(input *RetentionInput) { input.PreviousEvaluatedAt = time.Time{} }, ErrInvalidClockState},
		{"evaluation regression", func(input *RetentionInput) { input.EvaluatedAt = input.PreviousEvaluatedAt.Add(-time.Nanosecond) }, ErrClockRegressed},
		{"future event", func(input *RetentionInput) { input.RecordedAt = input.EvaluatedAt.Add(time.Millisecond) }, ErrInvalidRetention},
		{"year zero event", func(input *RetentionInput) { input.RecordedAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) }, ErrInvalidClockState},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			decision, err := EvaluateRetention(input)
			if !errors.Is(err, test.want) {
				t.Fatalf("EvaluateRetention() = %v, want %v", err, test.want)
			}
			if decision.EligibleForDeletion() {
				t.Fatal("invalid evaluation was deletion eligible")
			}
		})
	}
	if (RetentionDecision{}).EligibleForDeletion() {
		t.Fatal("zero decision was deletion eligible")
	}
}

func TestRetentionHoldValidationAndBounds(t *testing.T) {
	t.Parallel()

	base := RetentionInput{
		RecordedAt:          testTime,
		EvaluatedAt:         testTime.Add(ArchiveRetention),
		PreviousEvaluatedAt: testTime,
		ClockState:          ClockStateSynchronized,
	}
	hold, err := NewHold(testHoldID, HoldKindIncident)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := base
	duplicate.Holds = []Hold{hold, hold}
	if decision, err := EvaluateRetention(duplicate); !errors.Is(err, ErrInvalidRetention) || decision.EligibleForDeletion() {
		t.Fatalf("duplicate hold = %#v, %v", decision, err)
	}

	invalid := base
	invalid.Holds = []Hold{{}}
	if decision, err := EvaluateRetention(invalid); !errors.Is(err, ErrInvalidHold) || decision.EligibleForDeletion() {
		t.Fatalf("invalid hold = %#v, %v", decision, err)
	}

	tooMany := base
	tooMany.Holds = make([]Hold, MaxHolds+1)
	if decision, err := EvaluateRetention(tooMany); !errors.Is(err, ErrTooManyHolds) || decision.EligibleForDeletion() {
		t.Fatalf("too many holds = %#v, %v", decision, err)
	}

	if _, err := NewHold(testHoldID, HoldKind("Other")); !errors.Is(err, ErrInvalidHold) {
		t.Fatalf("open hold kind = %v", err)
	}
}
