package model

import (
	"errors"
	"fmt"
	"slices"

	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/control"
)

var (
	// ErrInvalidCommonStatus marks malformed shared workload observed state.
	ErrInvalidCommonStatus = errors.New("invalid common resource status")
	// ErrObservationCollectionRequired marks an omitted required condition
	// collection.
	ErrObservationCollectionRequired = errors.New("status observation collection is required")
	// ErrInvalidObservedGeneration marks an observation outside the current
	// resource generation fence.
	ErrInvalidObservedGeneration = errors.New("invalid status observed generation")
)

// ValidateCommonStatus validates the shared workload status against the
// current resource generation. A non-nil empty condition set is valid; nil is
// rejected because the wire contract requires an explicit collection.
func ValidateCommonStatus(status CommonStatus, resourceGeneration int64) error {
	if status.Conditions == nil {
		return fmt.Errorf("%w: %w", ErrInvalidCommonStatus, ErrObservationCollectionRequired)
	}
	if resourceGeneration < 1 || status.ObservedGeneration < 0 || status.ObservedGeneration > resourceGeneration {
		return fmt.Errorf("%w: %w", ErrInvalidCommonStatus, ErrInvalidObservedGeneration)
	}
	if err := condition.ValidateSet(status.Conditions, resourceGeneration); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCommonStatus, err)
	}
	return nil
}

// ValidatePolicyStatus preserves the existing control validation contract.
func ValidatePolicyStatus(status PolicyStatus, resourceGeneration int64) error {
	return control.ValidatePolicyStatus(status, resourceGeneration)
}

// ValidatePolicySpec preserves the authorization package's bounded,
// canonical policy contract through the version-independent hub.
func ValidatePolicySpec(spec PolicySpec) error {
	return control.ValidatePolicySpec(spec)
}

// ClonePolicySpec returns an ownership-independent policy value.
func ClonePolicySpec(spec PolicySpec) PolicySpec {
	return control.ClonePolicySpec(spec)
}

// EqualPolicySpec compares policy meaning while preserving required
// collection presence.
func EqualPolicySpec(left, right PolicySpec) bool {
	return control.EqualPolicySpec(left, right)
}

// ValidateProviderConnectionSpec preserves the closed credential-reference
// boundary owned by the control package.
func ValidateProviderConnectionSpec(spec ProviderConnectionSpec) error {
	return control.ValidateProviderConnectionSpec(spec)
}

// CheckProviderConnectionSpecTransition preserves the control package's
// immutable provider and credential-reference identity contract through the
// version-independent hub. Only the credential version may rotate in place.
func CheckProviderConnectionSpecTransition(before, after ProviderConnectionSpec) error {
	return control.CheckProviderConnectionSpecTransition(before, after)
}

// ValidateProviderConnectionStatus preserves all control observation bounds,
// ordering rules, and explicit-known/unknown semantics.
func ValidateProviderConnectionStatus(status ProviderConnectionStatus, resourceGeneration int64) error {
	return control.ValidateProviderConnectionStatus(status, resourceGeneration)
}

// CloneCommonStatus returns an independent condition collection while
// preserving nil versus an explicitly empty collection.
func CloneCommonStatus(status CommonStatus) CommonStatus {
	status.Conditions = condition.CloneSet(status.Conditions)
	return status
}

// EqualCommonStatus compares values and preserves the nil-versus-empty wire
// distinction.
func EqualCommonStatus(left, right CommonStatus) bool {
	return left.ObservedGeneration == right.ObservedGeneration &&
		sameNilness(left.Conditions, right.Conditions) && slices.Equal(left.Conditions, right.Conditions)
}

// ClonePolicyStatus returns an independent condition collection.
func ClonePolicyStatus(status PolicyStatus) PolicyStatus {
	status.Conditions = condition.CloneSet(status.Conditions)
	return status
}

// EqualPolicyStatus compares values and preserves collection presence.
func EqualPolicyStatus(left, right PolicyStatus) bool {
	return left.ObservedGeneration == right.ObservedGeneration &&
		sameNilness(left.Conditions, right.Conditions) && slices.Equal(left.Conditions, right.Conditions)
}

// CloneProviderConnectionSpec documents that the current provider intent is
// value-only. Keeping the helper explicit gives future versions one place to
// add deep-copy behavior if the hub grows reference fields.
func CloneProviderConnectionSpec(spec ProviderConnectionSpec) ProviderConnectionSpec { return spec }

// CloneProviderConnectionStatus delegates to the existing control deep copy.
func CloneProviderConnectionStatus(status ProviderConnectionStatus) ProviderConnectionStatus {
	return control.CloneProviderConnectionStatus(status)
}

// EqualProviderConnectionStatus compares optional decimal values rather than
// pointer identity and preserves required-collection presence.
func EqualProviderConnectionStatus(left, right ProviderConnectionStatus) bool {
	if left.ObservedGeneration != right.ObservedGeneration ||
		!sameNilness(left.Conditions, right.Conditions) ||
		!slices.Equal(left.Conditions, right.Conditions) ||
		!sameNilness(left.Capabilities, right.Capabilities) ||
		!slices.Equal(left.Capabilities, right.Capabilities) ||
		!sameNilness(left.QuotaChecks, right.QuotaChecks) ||
		len(left.QuotaChecks) != len(right.QuotaChecks) {
		return false
	}
	for index := range left.QuotaChecks {
		if !equalQuotaCheck(left.QuotaChecks[index], right.QuotaChecks[index]) {
			return false
		}
	}
	return true
}

func equalQuotaCheck(left, right QuotaCheck) bool {
	return left.Name == right.Name && left.State == right.State &&
		equalStringPointers(left.Requested, right.Requested) &&
		equalStringPointers(left.Available, right.Available) &&
		left.Source == right.Source && left.ObservedAt == right.ObservedAt && left.Reason == right.Reason
}

func equalStringPointers(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameNilness[Value any](left, right []Value) bool {
	return (left == nil) == (right == nil)
}
