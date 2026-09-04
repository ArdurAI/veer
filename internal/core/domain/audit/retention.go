package audit

import (
	"fmt"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// Hold is a bounded reviewed retention blocker. Presence means active; hold
// lifecycle storage and authorization belong outside this pure evaluator.
type Hold struct {
	initialized bool
	id          resource.ID
	kind        HoldKind
}

func NewHold(id resource.ID, kind HoldKind) (Hold, error) {
	hold := Hold{initialized: true, id: id, kind: kind}
	if err := ValidateHold(hold); err != nil {
		return Hold{}, err
	}
	return hold, nil
}

func ValidateHold(hold Hold) error {
	if !hold.initialized {
		return ErrInvalidHold
	}
	if _, err := resource.ParseID(hold.id.String()); err != nil {
		return ErrInvalidHold
	}
	if _, err := ParseHoldKind(hold.kind.String()); err != nil {
		return ErrInvalidHold
	}
	return nil
}

func (hold Hold) ID() resource.ID { return hold.id }
func (hold Hold) Kind() HoldKind  { return hold.kind }

// RetentionInput supplies explicit ordered clock evidence and all active holds
// applicable to one event. ClockState is the caller's conservative combined
// quality for both the retained RecordedAt evidence and the current evaluation
// observation: it must be Uncertain or Regressed if either input has that
// quality, even when the other clock is currently synchronized.
type RetentionInput struct {
	RecordedAt          time.Time
	EvaluatedAt         time.Time
	PreviousEvaluatedAt time.Time
	ClockState          ClockState
	Holds               []Hold
}

// RetentionDecision is an eligibility result, never an instruction to mutate
// storage. The zero value and every error result are fail-closed.
type RetentionDecision struct {
	initialized  bool
	disposition  RetentionDisposition
	onlineUntil  time.Time
	archiveUntil time.Time
}

func (decision RetentionDecision) Disposition() RetentionDisposition {
	return decision.disposition
}
func (decision RetentionDecision) OnlineUntil() time.Time  { return decision.onlineUntil }
func (decision RetentionDecision) ArchiveUntil() time.Time { return decision.archiveUntil }
func (decision RetentionDecision) EligibleForDeletion() bool {
	return decision.initialized && decision.disposition == RetentionDispositionExpire
}

// EvaluateRetention applies the fixed 90-day online and 365-day archive
// windows. Invalid, uncertain, or regressed time can never yield deletion
// eligibility. Any active hold wins over age.
func EvaluateRetention(input RetentionInput) (RetentionDecision, error) {
	if len(input.Holds) > MaxHolds {
		return RetentionDecision{}, fmt.Errorf("%w: %w", ErrInvalidRetention, ErrTooManyHolds)
	}
	if input.ClockState == ClockStateRegressed {
		return RetentionDecision{}, fmt.Errorf("%w: %w", ErrInvalidRetention, ErrClockRegressed)
	}
	if input.ClockState != ClockStateSynchronized {
		return RetentionDecision{}, fmt.Errorf("%w: %w", ErrInvalidRetention, ErrInvalidClockState)
	}
	if input.RecordedAt.IsZero() || input.EvaluatedAt.IsZero() || input.PreviousEvaluatedAt.IsZero() {
		return RetentionDecision{}, fmt.Errorf("%w: %w", ErrInvalidRetention, ErrInvalidClockState)
	}
	if input.EvaluatedAt.Before(input.PreviousEvaluatedAt) {
		return RetentionDecision{}, fmt.Errorf("%w: %w", ErrInvalidRetention, ErrClockRegressed)
	}
	recordedAt, err := normalizeRetentionTime(input.RecordedAt)
	if err != nil {
		return RetentionDecision{}, err
	}
	evaluatedAt, err := normalizeRetentionTime(input.EvaluatedAt)
	if err != nil {
		return RetentionDecision{}, err
	}
	previousEvaluatedAt, err := normalizeRetentionTime(input.PreviousEvaluatedAt)
	if err != nil {
		return RetentionDecision{}, err
	}
	if evaluatedAt.Before(previousEvaluatedAt) {
		return RetentionDecision{}, fmt.Errorf("%w: %w", ErrInvalidRetention, ErrClockRegressed)
	}
	if evaluatedAt.Before(recordedAt) {
		return RetentionDecision{}, fmt.Errorf("%w: event is in the future", ErrInvalidRetention)
	}
	onlineUntil := recordedAt.Add(OnlineRetention)
	archiveUntil := recordedAt.Add(ArchiveRetention)
	if _, err := normalizeTimestamp(onlineUntil); err != nil {
		return RetentionDecision{}, ErrInvalidRetention
	}
	if _, err := normalizeTimestamp(archiveUntil); err != nil {
		return RetentionDecision{}, ErrInvalidRetention
	}
	seen := make(map[resource.ID]struct{}, len(input.Holds))
	for _, hold := range input.Holds {
		if err := ValidateHold(hold); err != nil {
			return RetentionDecision{}, fmt.Errorf("%w: %w", ErrInvalidRetention, ErrInvalidHold)
		}
		if _, exists := seen[hold.id]; exists {
			return RetentionDecision{}, fmt.Errorf("%w: duplicate hold", ErrInvalidRetention)
		}
		seen[hold.id] = struct{}{}
	}

	var disposition RetentionDisposition
	switch {
	case len(input.Holds) > 0:
		disposition = RetentionDispositionHeld
	case evaluatedAt.Before(onlineUntil):
		disposition = RetentionDispositionOnline
	case evaluatedAt.Before(archiveUntil):
		disposition = RetentionDispositionArchive
	default:
		disposition = RetentionDispositionExpire
	}
	return RetentionDecision{
		initialized:  true,
		disposition:  disposition,
		onlineUntil:  onlineUntil,
		archiveUntil: archiveUntil,
	}, nil
}

func normalizeRetentionTime(value time.Time) (time.Time, error) {
	encoded, err := normalizeTimestamp(value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrInvalidRetention, ErrInvalidClockState)
	}
	normalized, _ := parseTimestamp(encoded)
	return normalized, nil
}
