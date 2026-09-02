// Package condition defines provider-independent v1alpha1 status conditions.
package condition

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"
)

const (
	// MaxConditions is the maximum number of conditions retained by one status.
	MaxConditions = 32

	maxMessageRunes = 512
	timestampLayout = "2006-01-02T15:04:05.000Z"
)

var (
	typePattern   = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,63}$`)
	reasonPattern = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,63}$`)

	ErrInvalidCondition     = errors.New("invalid condition")
	ErrInvalidConditionType = errors.New("invalid condition type")
	ErrInvalidStatus        = errors.New("invalid condition status")
	ErrInvalidReason        = errors.New("invalid condition reason")
	ErrInvalidMessage       = errors.New("invalid condition message")
	ErrObservedGeneration   = errors.New("invalid observed generation")
	ErrInvalidTimestamp     = errors.New("invalid condition timestamp")
	ErrInvalidTransition    = errors.New("invalid condition transition")
	ErrInvalidConditionSet  = errors.New("invalid condition set")
	ErrTooManyConditions    = errors.New("condition set exceeds alpha limit")
	ErrDuplicateCondition   = errors.New("duplicate condition type")
	ErrConditionOrder       = errors.New("condition types are not sorted")
)

// Status is the three-valued truth state of a condition.
type Status string

const (
	StatusTrue    Status = "True"
	StatusFalse   Status = "False"
	StatusUnknown Status = "Unknown"
)

// Condition is the canonical JSON shape retained in resource status. Callers
// should create and change values through New and Transition so transition
// timestamps and observed generations cannot drift independently.
type Condition struct {
	Type               string `json:"type"`
	Status             Status `json:"status"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	ObservedGeneration int64  `json:"observedGeneration"`
	LastTransitionAt   string `json:"lastTransitionAt"`
}

// Input supplies the observation fields for a new condition.
type Input struct {
	Type               string
	Status             Status
	Reason             string
	Message            string
	ObservedGeneration int64
}

// Update supplies mutable observation fields. Type is deliberately absent:
// the condition type is its immutable identity inside a status set.
type Update struct {
	Status             Status
	Reason             string
	Message            string
	ObservedGeneration int64
}

// New creates a condition with a normalized, injected transition timestamp.
func New(input Input, resourceGeneration int64, transitionAt time.Time) (Condition, error) {
	timestamp, err := normalizeTimestamp(transitionAt)
	if err != nil {
		return Condition{}, err
	}
	result := Condition{
		Type:               input.Type,
		Status:             input.Status,
		Reason:             input.Reason,
		Message:            input.Message,
		ObservedGeneration: input.ObservedGeneration,
		LastTransitionAt:   timestamp,
	}
	if err := Validate(result, resourceGeneration); err != nil {
		return Condition{}, err
	}
	return result, nil
}

// Transition returns an updated copy without mutating before. A status change
// advances LastTransitionAt; a same-status refresh preserves it. An exact
// replay is a no-op and does not consume or validate the injected timestamp.
func Transition(
	before Condition,
	update Update,
	resourceGeneration int64,
	transitionAt time.Time,
) (Condition, error) {
	if err := Validate(before, resourceGeneration); err != nil {
		return before, fmt.Errorf("%w: %w", ErrInvalidTransition, err)
	}
	if update.ObservedGeneration < before.ObservedGeneration {
		return before, fmt.Errorf("%w: %w", ErrInvalidTransition, ErrObservedGeneration)
	}

	after := Condition{
		Type:               before.Type,
		Status:             update.Status,
		Reason:             update.Reason,
		Message:            update.Message,
		ObservedGeneration: update.ObservedGeneration,
		LastTransitionAt:   before.LastTransitionAt,
	}
	if after == before {
		return before, nil
	}

	if before.Status != after.Status {
		normalized, err := normalizeTimestamp(transitionAt)
		if err != nil {
			return before, fmt.Errorf("%w: %w", ErrInvalidTransition, err)
		}
		beforeTime, _ := time.Parse(timestampLayout, before.LastTransitionAt)
		afterTime, _ := time.Parse(timestampLayout, normalized)
		if !afterTime.After(beforeTime) {
			return before, fmt.Errorf("%w: %w", ErrInvalidTransition, ErrInvalidTimestamp)
		}
		after.LastTransitionAt = normalized
	}

	if err := Validate(after, resourceGeneration); err != nil {
		return before, fmt.Errorf("%w: %w", ErrInvalidTransition, err)
	}
	return after, nil
}

// Validate checks one retained condition against the current resource
// generation. It performs no I/O and never includes field values in errors.
func Validate(value Condition, resourceGeneration int64) error {
	if resourceGeneration < 1 {
		return fmt.Errorf("%w: %w", ErrInvalidCondition, ErrObservedGeneration)
	}
	if !typePattern.MatchString(value.Type) {
		return fmt.Errorf("%w: %w", ErrInvalidCondition, ErrInvalidConditionType)
	}
	if !validStatus(value.Status) {
		return fmt.Errorf("%w: %w", ErrInvalidCondition, ErrInvalidStatus)
	}
	if !reasonPattern.MatchString(value.Reason) {
		return fmt.Errorf("%w: %w", ErrInvalidCondition, ErrInvalidReason)
	}
	if len(value.Message) > maxMessageRunes*utf8.UTFMax ||
		!utf8.ValidString(value.Message) || utf8.RuneCountInString(value.Message) > maxMessageRunes {
		return fmt.Errorf("%w: %w", ErrInvalidCondition, ErrInvalidMessage)
	}
	if value.ObservedGeneration < 0 || value.ObservedGeneration > resourceGeneration {
		return fmt.Errorf("%w: %w", ErrInvalidCondition, ErrObservedGeneration)
	}
	if _, err := parseTimestamp(value.LastTransitionAt); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCondition, err)
	}
	return nil
}

// ValidateSet checks a bounded set in canonical ascending type order. Strict
// ordering also makes condition identity uniqueness deterministic.
func ValidateSet(values []Condition, resourceGeneration int64) error {
	if len(values) > MaxConditions {
		return fmt.Errorf("%w: %w", ErrInvalidConditionSet, ErrTooManyConditions)
	}
	for index, value := range values {
		if err := Validate(value, resourceGeneration); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConditionSet, err)
		}
		if index == 0 {
			continue
		}
		comparison := values[index-1].Type
		if comparison == value.Type {
			return fmt.Errorf("%w: %w", ErrInvalidConditionSet, ErrDuplicateCondition)
		}
		if comparison > value.Type {
			return fmt.Errorf("%w: %w", ErrInvalidConditionSet, ErrConditionOrder)
		}
	}
	return nil
}

// CloneSet returns an independent condition slice for immutable aggregate
// transitions. Conditions contain no maps, slices, or pointers.
func CloneSet(values []Condition) []Condition {
	return slices.Clone(values)
}

func validStatus(status Status) bool {
	switch status {
	case StatusTrue, StatusFalse, StatusUnknown:
		return true
	default:
		return false
	}
}

func normalizeTimestamp(value time.Time) (string, error) {
	if value.IsZero() {
		return "", ErrInvalidTimestamp
	}
	value = value.UTC().Truncate(time.Millisecond)
	if value.Year() < 0 || value.Year() > 9999 {
		return "", ErrInvalidTimestamp
	}
	return value.Format(timestampLayout), nil
}

func parseTimestamp(value string) (time.Time, error) {
	if len(value) != len(timestampLayout) {
		return time.Time{}, ErrInvalidTimestamp
	}
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || parsed.Format(timestampLayout) != value {
		return time.Time{}, ErrInvalidTimestamp
	}
	return parsed, nil
}
