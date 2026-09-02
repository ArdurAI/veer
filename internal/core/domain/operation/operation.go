// Package operation defines provider-independent v1alpha1 asynchronous
// operation state and transition rules.
package operation

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	// MaxCanonicalBytes bounds one standalone operation representation.
	MaxCanonicalBytes = 4_096

	maxMessageRunes = 512
	timestampLayout = "2006-01-02T15:04:05.000Z"
)

var (
	reasonPattern  = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,63}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

	ErrInvalidOperation         = errors.New("invalid operation")
	ErrInvalidOperationID       = errors.New("invalid operation ID")
	ErrInvalidWorkspaceID       = errors.New("invalid operation workspace ID")
	ErrInvalidResourceID        = errors.New("invalid operation resource ID")
	ErrInvalidGeneration        = errors.New("invalid operation generation")
	ErrInvalidResourceVersion   = errors.New("invalid operation resource version")
	ErrInvalidPhase             = errors.New("invalid operation phase")
	ErrInvalidReason            = errors.New("invalid operation reason")
	ErrInvalidMessage           = errors.New("invalid operation message")
	ErrInvalidTimestamp         = errors.New("invalid operation timestamp")
	ErrInvalidProviderBinding   = errors.New("invalid operation provider binding")
	ErrInvalidTransition        = errors.New("invalid operation transition")
	ErrPhaseTransition          = errors.New("operation phase transition is not allowed")
	ErrNoMaterialChange         = errors.New("operation transition has no material change")
	ErrResourceVersionUnchanged = errors.New("next operation resource version must differ")
	ErrImmutableOperationID     = errors.New("operation ID is immutable")
	ErrImmutableWorkspaceID     = errors.New("operation workspace ID is immutable")
	ErrImmutableResourceID      = errors.New("operation resource ID is immutable")
	ErrImmutableProviderBinding = errors.New("operation provider binding is immutable")
	ErrImmutableGeneration      = errors.New("operation generation is immutable")
	ErrImmutableCreatedAt       = errors.New("operation creation timestamp is immutable")
	ErrCanonicalTooLarge        = errors.New("canonical operation exceeds alpha size limit")
	ErrNonCanonical             = errors.New("operation representation is not canonical")
)

// Phase is one durable asynchronous workflow state.
type Phase string

const (
	PhasePending   Phase = "Pending"
	PhaseWaiting   Phase = "Waiting"
	PhaseRunning   Phase = "Running"
	PhaseSucceeded Phase = "Succeeded"
	PhaseFailed    Phase = "Failed"
	// PhaseCanceled preserves the existing v1alpha1 wire spelling.
	PhaseCanceled Phase = "Canceled"
)

// Operation is the complete standalone representation of one accepted
// asynchronous operation. Optional provider binding identifiers are always
// both present or both absent.
type Operation struct {
	ID                   resource.ID           `json:"id"`
	WorkspaceID          resource.ID           `json:"workspaceId"`
	ResourceID           resource.ID           `json:"resourceId"`
	EnvironmentID        *resource.ID          `json:"environmentId,omitempty"`
	ProviderConnectionID *resource.ID          `json:"providerConnectionId,omitempty"`
	Generation           int64                 `json:"generation"`
	ResourceVersion      string                `json:"resourceVersion"`
	Phase                Phase                 `json:"phase"`
	Reason               string                `json:"reason,omitempty"`
	Message              string                `json:"message,omitempty"`
	CostEstimate         *control.CostEstimate `json:"costEstimate,omitempty"`
	CreatedAt            string                `json:"createdAt"`
	UpdatedAt            string                `json:"updatedAt"`
}

// Input supplies immutable target binding and initial safe detail. New always
// creates a Pending operation with equal creation and update timestamps.
type Input struct {
	ID                   resource.ID
	WorkspaceID          resource.ID
	ResourceID           resource.ID
	EnvironmentID        *resource.ID
	ProviderConnectionID *resource.ID
	Generation           int64
	ResourceVersion      string
	Reason               string
	Message              string
	CostEstimate         *control.CostEstimate
	CreatedAt            time.Time
}

// TransitionInput supplies the next workflow state and mutable safe detail.
// UpdatedAt is ignored for an exact replay.
type TransitionInput struct {
	Phase           Phase
	Reason          string
	Message         string
	CostEstimate    *control.CostEstimate
	ResourceVersion string
	UpdatedAt       time.Time
}

// New creates a Pending operation with normalized immutable bindings.
func New(input Input) (Operation, error) {
	createdAt, err := normalizeTimestamp(input.CreatedAt)
	if err != nil {
		return Operation{}, fmt.Errorf("%w: %w", ErrInvalidOperation, err)
	}
	result := Operation{
		ID:                   input.ID,
		WorkspaceID:          input.WorkspaceID,
		ResourceID:           input.ResourceID,
		EnvironmentID:        cloneID(input.EnvironmentID),
		ProviderConnectionID: cloneID(input.ProviderConnectionID),
		Generation:           input.Generation,
		ResourceVersion:      input.ResourceVersion,
		Phase:                PhasePending,
		Reason:               input.Reason,
		Message:              input.Message,
		CostEstimate:         cloneCost(input.CostEstimate),
		CreatedAt:            createdAt,
		UpdatedAt:            createdAt,
	}
	if err := Validate(result); err != nil {
		return Operation{}, err
	}
	return result, nil
}

// Transition returns an updated copy without mutating before. Exact replay is
// a no-op. Nonterminal phases admit versioned evidence refreshes, while all
// non-replay terminal transitions fail closed.
func Transition(before Operation, input TransitionInput) (Operation, error) {
	if err := Validate(before); err != nil {
		return before, fmt.Errorf("%w: %w", ErrInvalidTransition, err)
	}
	after := clone(before)
	after.Phase = input.Phase
	after.Reason = input.Reason
	after.Message = input.Message
	after.CostEstimate = cloneCost(input.CostEstimate)
	if equalSemantic(after, before) {
		return before, nil
	}

	after.ResourceVersion = input.ResourceVersion
	updatedAt, err := normalizeTimestamp(input.UpdatedAt)
	if err != nil {
		return before, fmt.Errorf("%w: %w", ErrInvalidTransition, err)
	}
	after.UpdatedAt = updatedAt
	if err := CheckTransition(before, after); err != nil {
		return before, err
	}
	return after, nil
}

// CheckTransition validates two complete values and enforces immutable fields,
// the phase graph, and non-regressing update time.
func CheckTransition(before, after Operation) error {
	if err := Validate(before); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, err)
	}
	if err := Validate(after); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, err)
	}
	if before.ID != after.ID {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrImmutableOperationID)
	}
	if before.WorkspaceID != after.WorkspaceID {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrImmutableWorkspaceID)
	}
	if before.ResourceID != after.ResourceID {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrImmutableResourceID)
	}
	if !equalIDs(before.EnvironmentID, after.EnvironmentID) ||
		!equalIDs(before.ProviderConnectionID, after.ProviderConnectionID) {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrImmutableProviderBinding)
	}
	if before.Generation != after.Generation {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrImmutableGeneration)
	}
	if before.CreatedAt != after.CreatedAt {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrImmutableCreatedAt)
	}
	if equal(before, after) {
		return nil
	}
	if equalSemantic(before, after) {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrNoMaterialChange)
	}
	if terminal(before.Phase) {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrPhaseTransition)
	}
	if before.Phase != after.Phase && !allowedTransition(before.Phase, after.Phase) {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrPhaseTransition)
	}
	if before.ResourceVersion == after.ResourceVersion {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrResourceVersionUnchanged)
	}
	beforeTime, _ := time.Parse(timestampLayout, before.UpdatedAt)
	afterTime, _ := time.Parse(timestampLayout, after.UpdatedAt)
	if afterTime.Before(beforeTime) {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrInvalidTimestamp)
	}
	return nil
}

// Validate checks one complete operation without performing I/O or including
// field values in errors.
func Validate(value Operation) error {
	if _, err := resource.ParseID(value.ID.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, ErrInvalidOperationID)
	}
	if _, err := resource.ParseID(value.WorkspaceID.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, ErrInvalidWorkspaceID)
	}
	if _, err := resource.ParseID(value.ResourceID.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, ErrInvalidResourceID)
	}
	if err := validateBinding(value.EnvironmentID, value.ProviderConnectionID); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, err)
	}
	if value.Generation < 1 {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, ErrInvalidGeneration)
	}
	if !versionPattern.MatchString(value.ResourceVersion) {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, ErrInvalidResourceVersion)
	}
	if !validPhase(value.Phase) {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, ErrInvalidPhase)
	}
	if value.Reason != "" && !reasonPattern.MatchString(value.Reason) {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, ErrInvalidReason)
	}
	if len(value.Message) > maxMessageRunes*utf8.UTFMax ||
		!utf8.ValidString(value.Message) || utf8.RuneCountInString(value.Message) > maxMessageRunes {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, ErrInvalidMessage)
	}
	if value.CostEstimate != nil {
		if err := control.ValidateCostEstimate(*value.CostEstimate); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidOperation, err)
		}
	}
	createdAt, err := parseTimestamp(value.CreatedAt)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, err)
	}
	updatedAt, err := parseTimestamp(value.UpdatedAt)
	if err != nil || updatedAt.Before(createdAt) {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, ErrInvalidTimestamp)
	}
	if err := validateCanonicalSize(value); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidOperation, err)
	}
	return nil
}

// MarshalCanonical emits the stable compact standalone operation shape.
func MarshalCanonical(value Operation) ([]byte, error) {
	if err := Validate(value); err != nil {
		return nil, err
	}
	data, err := encodeCanonical(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode", ErrInvalidOperation)
	}
	if len(data) > MaxCanonicalBytes {
		return nil, ErrCanonicalTooLarge
	}
	return data, nil
}

// UnmarshalCanonical decodes one bounded, strict, canonical operation.
func UnmarshalCanonical(data []byte) (Operation, error) {
	if len(data) == 0 {
		return Operation{}, ErrNonCanonical
	}
	if len(data) > MaxCanonicalBytes {
		return Operation{}, ErrCanonicalTooLarge
	}
	var result Operation
	if err := jsonv2.Unmarshal(data, &result, jsonv2.RejectUnknownMembers(true)); err != nil {
		return Operation{}, ErrNonCanonical
	}
	if err := Validate(result); err != nil {
		return Operation{}, err
	}
	canonical, err := MarshalCanonical(result)
	if err != nil {
		return Operation{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Operation{}, ErrNonCanonical
	}
	return result, nil
}

func allowedTransition(before, after Phase) bool {
	switch before {
	case PhasePending:
		switch after {
		case PhaseWaiting, PhaseRunning, PhaseSucceeded, PhaseFailed, PhaseCanceled:
			return true
		}
	case PhaseWaiting:
		switch after {
		case PhasePending, PhaseRunning, PhaseSucceeded, PhaseFailed, PhaseCanceled:
			return true
		}
	case PhaseRunning:
		switch after {
		case PhaseWaiting, PhaseSucceeded, PhaseFailed, PhaseCanceled:
			return true
		}
	}
	return false
}

func validPhase(phase Phase) bool {
	switch phase {
	case PhasePending, PhaseWaiting, PhaseRunning, PhaseSucceeded, PhaseFailed, PhaseCanceled:
		return true
	default:
		return false
	}
}

func terminal(phase Phase) bool {
	switch phase {
	case PhaseSucceeded, PhaseFailed, PhaseCanceled:
		return true
	default:
		return false
	}
}

func validateBinding(environmentID, connectionID *resource.ID) error {
	if (environmentID == nil) != (connectionID == nil) {
		return ErrInvalidProviderBinding
	}
	if environmentID == nil {
		return nil
	}
	if _, err := resource.ParseID(environmentID.String()); err != nil {
		return ErrInvalidProviderBinding
	}
	if _, err := resource.ParseID(connectionID.String()); err != nil {
		return ErrInvalidProviderBinding
	}
	return nil
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

func validateCanonicalSize(value Operation) error {
	data, err := encodeCanonical(value)
	if err != nil {
		return errors.New("operation cannot be encoded")
	}
	if len(data) > MaxCanonicalBytes {
		return ErrCanonicalTooLarge
	}
	return nil
}

func encodeCanonical(value Operation) ([]byte, error) {
	return jsonv2.Marshal(
		value,
		json.DefaultOptionsV1(),
		jsontext.AllowInvalidUTF8(false),
	)
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

func clone(value Operation) Operation {
	value.EnvironmentID = cloneID(value.EnvironmentID)
	value.ProviderConnectionID = cloneID(value.ProviderConnectionID)
	value.CostEstimate = cloneCost(value.CostEstimate)
	return value
}

func cloneID(value *resource.ID) *resource.ID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneCost(value *control.CostEstimate) *control.CostEstimate {
	if value == nil {
		return nil
	}
	copy := control.CloneCostEstimate(*value)
	return &copy
}

func equal(left, right Operation) bool {
	return equalSemantic(left, right) && left.ResourceVersion == right.ResourceVersion &&
		left.UpdatedAt == right.UpdatedAt
}

func equalSemantic(left, right Operation) bool {
	if left.ID != right.ID || left.WorkspaceID != right.WorkspaceID || left.ResourceID != right.ResourceID ||
		!equalIDs(left.EnvironmentID, right.EnvironmentID) ||
		!equalIDs(left.ProviderConnectionID, right.ProviderConnectionID) ||
		left.Generation != right.Generation ||
		left.Phase != right.Phase || left.Reason != right.Reason || left.Message != right.Message ||
		left.CreatedAt != right.CreatedAt {
		return false
	}
	if left.CostEstimate == nil || right.CostEstimate == nil {
		return left.CostEstimate == nil && right.CostEstimate == nil
	}
	return control.EqualCostEstimate(*left.CostEstimate, *right.CostEstimate)
}

func equalIDs(left, right *resource.ID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
