// Package control defines Veer's provider-independent v1alpha1 control
// resources and provider observation values.
package control

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	// MaxProviderCapabilities bounds one connection's retained capability view.
	MaxProviderCapabilities = 128
	// MaxQuotaChecks bounds one connection's retained quota view.
	MaxQuotaChecks = 128

	timestampLayout = "2006-01-02T15:04:05.000Z"
)

var (
	providerPattern    = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
	observationPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,127}$`)
	sourcePattern      = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
	reasonPattern      = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,63}$`)
	versionPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	currencyPattern    = regexp.MustCompile(`^[A-Z]{3}$`)
	regionPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

	ErrInvalidPolicyStatus             = errors.New("invalid policy status")
	ErrInvalidProviderConnectionSpec   = errors.New("invalid provider connection spec")
	ErrInvalidProviderConnectionStatus = errors.New("invalid provider connection status")
	ErrInvalidCredentialReference      = errors.New("invalid credential reference")
	ErrInvalidProvider                 = errors.New("invalid provider identifier")
	ErrInvalidProviderCapability       = errors.New("invalid provider capability")
	ErrInvalidCapabilityState          = errors.New("invalid provider capability state")
	ErrInvalidQuotaCheck               = errors.New("invalid quota check")
	ErrInvalidQuotaState               = errors.New("invalid quota state")
	ErrInvalidCostEstimate             = errors.New("invalid cost estimate")
	ErrInvalidCostState                = errors.New("invalid cost state")
	ErrInvalidConfidence               = errors.New("invalid cost confidence")
	ErrInvalidObservationName          = errors.New("invalid observation name")
	ErrInvalidObservationSource        = errors.New("invalid observation source")
	ErrInvalidObservationReason        = errors.New("invalid observation reason")
	ErrInvalidObservationTimestamp     = errors.New("invalid observation timestamp")
	ErrInvalidObservationGeneration    = errors.New("invalid observation generation")
	ErrObservationCollectionRequired   = errors.New("observation collection is required")
	ErrTooManyProviderCapabilities     = errors.New("provider capability set exceeds alpha limit")
	ErrTooManyQuotaChecks              = errors.New("quota check set exceeds alpha limit")
	ErrDuplicateObservation            = errors.New("duplicate observation name")
	ErrObservationOrder                = errors.New("observation names are not sorted")
	ErrInvalidControlPlacement         = errors.New("invalid control resource placement")
)

// PolicySpec is the provider-independent authorization policy contract.
type PolicySpec = authorization.PolicySpec

// PolicyStatus is the provider-free observed state of a Policy resource.
type PolicyStatus struct {
	ObservedGeneration int64                 `json:"observedGeneration"`
	Conditions         []condition.Condition `json:"conditions"`
}

// ObservedGenerations exposes the status and condition observations to the
// common resource generation fence.
func (status PolicyStatus) ObservedGenerations() []int64 {
	return observedGenerations(status.ObservedGeneration, status.Conditions)
}

// CredentialReference identifies one versioned credential held outside Veer
// resources. It intentionally has no URI, path, provider payload, or secret.
type CredentialReference struct {
	ReferenceID string `json:"referenceId"`
	Version     string `json:"version"`
}

// ProviderConnectionSpec binds one provider identifier to one external,
// versioned credential reference.
type ProviderConnectionSpec struct {
	Provider      string              `json:"provider"`
	CredentialRef CredentialReference `json:"credentialRef"`
}

// CapabilityState explicitly distinguishes known support, known lack of
// support, and unavailable knowledge.
type CapabilityState string

const (
	CapabilitySupported   CapabilityState = "Supported"
	CapabilityUnsupported CapabilityState = "Unsupported"
	CapabilityUnknown     CapabilityState = "Unknown"
)

// ProviderCapability is one bounded, attributable capability observation.
type ProviderCapability struct {
	Name       string          `json:"name"`
	State      CapabilityState `json:"state"`
	Source     string          `json:"source"`
	ObservedAt string          `json:"observedAt"`
	Reason     string          `json:"reason"`
}

// QuotaState explicitly represents sufficient, insufficient, or unavailable
// quota knowledge.
type QuotaState string

const (
	QuotaWithinLimit QuotaState = "WithinLimit"
	QuotaExceeded    QuotaState = "Exceeded"
	QuotaUnknown     QuotaState = "Unknown"
)

// QuotaCheck is one bounded, attributable quota observation. Requested and
// Available are canonical non-negative decimals when State is known and are
// omitted when State is Unknown.
type QuotaCheck struct {
	Name       string     `json:"name"`
	State      QuotaState `json:"state"`
	Requested  *string    `json:"requested,omitempty"`
	Available  *string    `json:"available,omitempty"`
	Source     string     `json:"source"`
	ObservedAt string     `json:"observedAt"`
	Reason     string     `json:"reason"`
}

// CostState distinguishes an estimate with an amount from an explicitly
// unavailable estimate.
type CostState string

const (
	CostKnown   CostState = "Known"
	CostUnknown CostState = "Unknown"
)

// Confidence is the bounded evidence quality attached to a cost estimate.
type Confidence string

const (
	ConfidenceLow     Confidence = "Low"
	ConfidenceMedium  Confidence = "Medium"
	ConfidenceHigh    Confidence = "High"
	ConfidenceUnknown Confidence = "Unknown"
)

// CostEstimate is one regional, currency-qualified, attributable estimate.
// Amount is a canonical non-negative decimal only when State is Known.
type CostEstimate struct {
	State      CostState  `json:"state"`
	Amount     *string    `json:"amount,omitempty"`
	Currency   string     `json:"currency"`
	Region     string     `json:"region"`
	Source     string     `json:"source"`
	ObservedAt string     `json:"observedAt"`
	Confidence Confidence `json:"confidence"`
	Reason     string     `json:"reason"`
}

// ProviderConnectionStatus is the complete provider observation view for one
// connection. Capability and quota slices are required, bounded, sorted, and
// unique by name.
type ProviderConnectionStatus struct {
	ObservedGeneration int64                 `json:"observedGeneration"`
	Conditions         []condition.Condition `json:"conditions"`
	Capabilities       []ProviderCapability  `json:"capabilities"`
	QuotaChecks        []QuotaCheck          `json:"quotaChecks"`
}

// ObservedGenerations exposes the status and condition observations to the
// common resource generation fence.
func (status ProviderConnectionStatus) ObservedGenerations() []int64 {
	return observedGenerations(status.ObservedGeneration, status.Conditions)
}

// ValidatePolicyStatus validates the status against its current resource
// generation.
func ValidatePolicyStatus(status PolicyStatus, resourceGeneration int64) error {
	if status.Conditions == nil {
		return fmt.Errorf("%w: %w", ErrInvalidPolicyStatus, ErrObservationCollectionRequired)
	}
	if err := validateObservedGeneration(status.ObservedGeneration, resourceGeneration); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPolicyStatus, err)
	}
	if err := condition.ValidateSet(status.Conditions, resourceGeneration); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPolicyStatus, err)
	}
	return nil
}

// ValidatePolicySpec preserves the authorization package's bounded,
// canonical policy contract at the control-resource boundary.
func ValidatePolicySpec(spec PolicySpec) error {
	return authorization.ValidatePolicySpec(spec)
}

// ClonePolicySpec returns an ownership-independent policy value.
func ClonePolicySpec(spec PolicySpec) PolicySpec {
	return authorization.ClonePolicySpec(spec)
}

// EqualPolicySpec compares policy meaning while preserving required
// collection presence.
func EqualPolicySpec(left, right PolicySpec) bool {
	return authorization.EqualPolicySpec(left, right)
}

// ValidateProviderConnectionSpec enforces the closed provider and credential
// reference boundary.
func ValidateProviderConnectionSpec(spec ProviderConnectionSpec) error {
	if !providerPattern.MatchString(spec.Provider) {
		return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionSpec, ErrInvalidProvider)
	}
	if err := ValidateCredentialReference(spec.CredentialRef); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionSpec, err)
	}
	return nil
}

// ValidateCredentialReference validates an opaque reference and version
// without resolving, reading, or logging credential material.
func ValidateCredentialReference(reference CredentialReference) error {
	if _, err := resource.ParseID(reference.ReferenceID); err != nil {
		return ErrInvalidCredentialReference
	}
	if !versionPattern.MatchString(reference.Version) {
		return ErrInvalidCredentialReference
	}
	return nil
}

// ValidateProviderConnectionStatus validates all retained observations against
// the current resource generation.
func ValidateProviderConnectionStatus(status ProviderConnectionStatus, resourceGeneration int64) error {
	if status.Conditions == nil || status.Capabilities == nil || status.QuotaChecks == nil {
		return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionStatus, ErrObservationCollectionRequired)
	}
	if err := validateObservedGeneration(status.ObservedGeneration, resourceGeneration); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionStatus, err)
	}
	if err := condition.ValidateSet(status.Conditions, resourceGeneration); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionStatus, err)
	}
	if len(status.Capabilities) > MaxProviderCapabilities {
		return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionStatus, ErrTooManyProviderCapabilities)
	}
	for index, capability := range status.Capabilities {
		if err := ValidateProviderCapability(capability); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionStatus, err)
		}
		if err := validateObservationOrder(index, capability.Name, func(index int) string {
			return status.Capabilities[index].Name
		}); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionStatus, err)
		}
	}
	if len(status.QuotaChecks) > MaxQuotaChecks {
		return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionStatus, ErrTooManyQuotaChecks)
	}
	for index, quota := range status.QuotaChecks {
		if err := ValidateQuotaCheck(quota); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionStatus, err)
		}
		if err := validateObservationOrder(index, quota.Name, func(index int) string {
			return status.QuotaChecks[index].Name
		}); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidProviderConnectionStatus, err)
		}
	}
	return nil
}

// ValidateProviderCapability validates one attributable observation.
func ValidateProviderCapability(capability ProviderCapability) error {
	if err := validateObservationMetadata(
		capability.Name,
		capability.Source,
		capability.ObservedAt,
		capability.Reason,
	); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidProviderCapability, err)
	}
	switch capability.State {
	case CapabilitySupported, CapabilityUnsupported, CapabilityUnknown:
		return nil
	default:
		return fmt.Errorf("%w: %w", ErrInvalidProviderCapability, ErrInvalidCapabilityState)
	}
}

// ValidateQuotaCheck validates explicit known/unknown fields and checks the
// numeric relation encoded by the state without using floating point.
func ValidateQuotaCheck(quota QuotaCheck) error {
	if err := validateObservationMetadata(quota.Name, quota.Source, quota.ObservedAt, quota.Reason); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidQuotaCheck, err)
	}
	switch quota.State {
	case QuotaUnknown:
		if quota.Requested != nil || quota.Available != nil {
			return fmt.Errorf("%w: %w", ErrInvalidQuotaCheck, ErrInvalidQuotaState)
		}
		return nil
	case QuotaWithinLimit, QuotaExceeded:
		if quota.Requested == nil || quota.Available == nil {
			return fmt.Errorf("%w: %w", ErrInvalidQuotaCheck, ErrInvalidQuotaState)
		}
	default:
		return fmt.Errorf("%w: %w", ErrInvalidQuotaCheck, ErrInvalidQuotaState)
	}

	comparison, err := compareCanonicalDecimals(*quota.Requested, *quota.Available)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidQuotaCheck, err)
	}
	if quota.State == QuotaWithinLimit && comparison > 0 {
		return fmt.Errorf("%w: %w", ErrInvalidQuotaCheck, ErrInvalidQuotaState)
	}
	if quota.State == QuotaExceeded && comparison <= 0 {
		return fmt.Errorf("%w: %w", ErrInvalidQuotaCheck, ErrInvalidQuotaState)
	}
	return nil
}

// ValidateCostEstimate validates explicit known/unknown fields and all
// attribution metadata.
func ValidateCostEstimate(estimate CostEstimate) error {
	if !currencyPattern.MatchString(estimate.Currency) || !regionPattern.MatchString(estimate.Region) {
		return ErrInvalidCostEstimate
	}
	if err := validateObservationMetadata("cost", estimate.Source, estimate.ObservedAt, estimate.Reason); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCostEstimate, err)
	}
	if !validConfidence(estimate.Confidence) {
		return fmt.Errorf("%w: %w", ErrInvalidCostEstimate, ErrInvalidConfidence)
	}
	switch estimate.State {
	case CostKnown:
		if estimate.Amount == nil || estimate.Confidence == ConfidenceUnknown {
			return fmt.Errorf("%w: %w", ErrInvalidCostEstimate, ErrInvalidCostState)
		}
		if err := validateCanonicalDecimal(*estimate.Amount); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidCostEstimate, err)
		}
	case CostUnknown:
		if estimate.Amount != nil || estimate.Confidence != ConfidenceUnknown {
			return fmt.Errorf("%w: %w", ErrInvalidCostEstimate, ErrInvalidCostState)
		}
	default:
		return fmt.Errorf("%w: %w", ErrInvalidCostEstimate, ErrInvalidCostState)
	}
	return nil
}

// NewPolicyResource validates a Policy and creates its common immutable
// envelope from a server-derived Workspace child placement.
func NewPolicyResource(
	placement hierarchy.Placement,
	input hierarchy.CreateInput[PolicySpec, PolicyStatus],
) (resource.Resource[PolicySpec, PolicyStatus], error) {
	var zero resource.Resource[PolicySpec, PolicyStatus]
	if placement.Kind() != hierarchy.KindPolicy {
		return zero, ErrInvalidControlPlacement
	}
	if err := ValidatePolicySpec(input.Spec); err != nil {
		return zero, err
	}
	if err := ValidatePolicyStatus(input.Status, 1); err != nil {
		return zero, err
	}
	return hierarchy.NewResource(placement, input)
}

// NewProviderConnectionResource validates a ProviderConnection and creates
// its common immutable envelope from a server-derived Environment child
// placement.
func NewProviderConnectionResource(
	placement hierarchy.Placement,
	input hierarchy.CreateInput[ProviderConnectionSpec, ProviderConnectionStatus],
) (resource.Resource[ProviderConnectionSpec, ProviderConnectionStatus], error) {
	var zero resource.Resource[ProviderConnectionSpec, ProviderConnectionStatus]
	if placement.Kind() != hierarchy.KindProviderConnection {
		return zero, ErrInvalidControlPlacement
	}
	if err := ValidateProviderConnectionSpec(input.Spec); err != nil {
		return zero, err
	}
	if err := ValidateProviderConnectionStatus(input.Status, 1); err != nil {
		return zero, err
	}
	return hierarchy.NewResource(placement, input)
}

// CloneProviderConnectionStatus returns a deep-enough independent copy of all
// retained slices and optional decimal pointers.
func CloneProviderConnectionStatus(status ProviderConnectionStatus) ProviderConnectionStatus {
	result := status
	result.Conditions = condition.CloneSet(status.Conditions)
	result.Capabilities = slices.Clone(status.Capabilities)
	result.QuotaChecks = slices.Clone(status.QuotaChecks)
	for index, quota := range status.QuotaChecks {
		result.QuotaChecks[index] = CloneQuotaCheck(quota)
	}
	return result
}

// CloneQuotaCheck copies one quota observation and its optional decimals.
func CloneQuotaCheck(quota QuotaCheck) QuotaCheck {
	result := quota
	result.Requested = cloneString(quota.Requested)
	result.Available = cloneString(quota.Available)
	return result
}

// CloneCostEstimate copies an estimate and its optional amount.
func CloneCostEstimate(estimate CostEstimate) CostEstimate {
	result := estimate
	result.Amount = cloneString(estimate.Amount)
	return result
}

// EqualCostEstimate compares values rather than optional pointer identities.
func EqualCostEstimate(left, right CostEstimate) bool {
	return left.State == right.State && equalStrings(left.Amount, right.Amount) &&
		left.Currency == right.Currency && left.Region == right.Region &&
		left.Source == right.Source && left.ObservedAt == right.ObservedAt &&
		left.Confidence == right.Confidence && left.Reason == right.Reason
}

func observedGenerations(outer int64, conditions []condition.Condition) []int64 {
	result := make([]int64, 1, len(conditions)+1)
	result[0] = outer
	for _, value := range conditions {
		result = append(result, value.ObservedGeneration)
	}
	return result
}

func validateObservedGeneration(observed, resourceGeneration int64) error {
	if resourceGeneration < 1 || observed < 0 || observed > resourceGeneration {
		return ErrInvalidObservationGeneration
	}
	return nil
}

func validateObservationMetadata(name, source, observedAt, reason string) error {
	if !observationPattern.MatchString(name) {
		return ErrInvalidObservationName
	}
	if !sourcePattern.MatchString(source) {
		return ErrInvalidObservationSource
	}
	if len(observedAt) != len(timestampLayout) {
		return ErrInvalidObservationTimestamp
	}
	parsed, err := time.Parse(timestampLayout, observedAt)
	if err != nil || parsed.Format(timestampLayout) != observedAt {
		return ErrInvalidObservationTimestamp
	}
	if !reasonPattern.MatchString(reason) {
		return ErrInvalidObservationReason
	}
	return nil
}

func validateObservationOrder(index int, current string, previous func(int) string) error {
	if index == 0 {
		return nil
	}
	prior := previous(index - 1)
	if prior == current {
		return ErrDuplicateObservation
	}
	if prior > current {
		return ErrObservationOrder
	}
	return nil
}

func validConfidence(confidence Confidence) bool {
	switch confidence {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh, ConfidenceUnknown:
		return true
	default:
		return false
	}
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func equalStrings(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
