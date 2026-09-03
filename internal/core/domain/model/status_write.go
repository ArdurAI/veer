package model

import (
	"errors"
	"fmt"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// ErrInvalidStatusWrite marks an absent, malformed, generation-mismatched, or
// unsupported hub status write.
var ErrInvalidStatusWrite = errors.New("invalid admitted status write")

// StatusWrite is a closed, version-independent sum of the six observed-state
// write variants. It retains the resource generation used for validation;
// resource identity and concurrency remain command and persistence concerns.
type StatusWrite interface {
	// Kind identifies the closed variant.
	Kind() hierarchy.Kind
	// ObservedGenerations returns an ownership-safe observation collection.
	ObservedGenerations() []int64
	// ResourceGeneration returns the generation against which this write was
	// admitted.
	ResourceGeneration() int64
	isStatusWrite()
}

type statusWriteValue[Status resource.GenerationObservations] struct {
	status             Status
	resourceGeneration int64
}

// WorkspaceStatusWrite is immutable admitted Workspace observed state.
type WorkspaceStatusWrite struct {
	value statusWriteValue[WorkspaceStatus]
}

// EnvironmentStatusWrite is immutable admitted Environment observed state.
type EnvironmentStatusWrite struct {
	value statusWriteValue[EnvironmentStatus]
}

// ApplicationStatusWrite is immutable admitted Application observed state.
type ApplicationStatusWrite struct {
	value statusWriteValue[ApplicationStatus]
}

// ComponentStatusWrite is immutable admitted Component observed state.
type ComponentStatusWrite struct {
	value statusWriteValue[ComponentStatus]
}

// PolicyStatusWrite is immutable admitted Policy observed state.
type PolicyStatusWrite struct {
	value statusWriteValue[PolicyStatus]
}

// ProviderConnectionStatusWrite is immutable admitted ProviderConnection
// observed state.
type ProviderConnectionStatusWrite struct {
	value statusWriteValue[ProviderConnectionStatus]
}

// NewWorkspaceStatusWrite validates a Workspace status against the current
// resource generation and takes ownership-safe copies.
func NewWorkspaceStatusWrite(status WorkspaceStatus, resourceGeneration int64) (*WorkspaceStatusWrite, error) {
	if err := ValidateCommonStatus(status, resourceGeneration); err != nil {
		return nil, wrapStatusWriteValidation(err)
	}
	result := &WorkspaceStatusWrite{value: statusWriteValue[WorkspaceStatus]{
		status:             CloneCommonStatus(status),
		resourceGeneration: resourceGeneration,
	}}
	if err := ValidateStatusWrite(result, resourceGeneration); err != nil {
		return nil, err
	}
	return result, nil
}

// NewEnvironmentStatusWrite validates an Environment status against the
// current resource generation and takes ownership-safe copies.
func NewEnvironmentStatusWrite(status EnvironmentStatus, resourceGeneration int64) (*EnvironmentStatusWrite, error) {
	if err := ValidateCommonStatus(status, resourceGeneration); err != nil {
		return nil, wrapStatusWriteValidation(err)
	}
	result := &EnvironmentStatusWrite{value: statusWriteValue[EnvironmentStatus]{
		status:             CloneCommonStatus(status),
		resourceGeneration: resourceGeneration,
	}}
	if err := ValidateStatusWrite(result, resourceGeneration); err != nil {
		return nil, err
	}
	return result, nil
}

// NewApplicationStatusWrite validates an Application status against the
// current resource generation and takes ownership-safe copies.
func NewApplicationStatusWrite(status ApplicationStatus, resourceGeneration int64) (*ApplicationStatusWrite, error) {
	if err := ValidateCommonStatus(status, resourceGeneration); err != nil {
		return nil, wrapStatusWriteValidation(err)
	}
	result := &ApplicationStatusWrite{value: statusWriteValue[ApplicationStatus]{
		status:             CloneCommonStatus(status),
		resourceGeneration: resourceGeneration,
	}}
	if err := ValidateStatusWrite(result, resourceGeneration); err != nil {
		return nil, err
	}
	return result, nil
}

// NewComponentStatusWrite validates a Component status against the current
// resource generation and takes ownership-safe copies.
func NewComponentStatusWrite(status ComponentStatus, resourceGeneration int64) (*ComponentStatusWrite, error) {
	if err := ValidateCommonStatus(status, resourceGeneration); err != nil {
		return nil, wrapStatusWriteValidation(err)
	}
	result := &ComponentStatusWrite{value: statusWriteValue[ComponentStatus]{
		status:             CloneCommonStatus(status),
		resourceGeneration: resourceGeneration,
	}}
	if err := ValidateStatusWrite(result, resourceGeneration); err != nil {
		return nil, err
	}
	return result, nil
}

// NewPolicyStatusWrite validates a Policy status against the current resource
// generation and takes ownership-safe copies.
func NewPolicyStatusWrite(status PolicyStatus, resourceGeneration int64) (*PolicyStatusWrite, error) {
	if err := ValidatePolicyStatus(status, resourceGeneration); err != nil {
		return nil, wrapStatusWriteValidation(err)
	}
	result := &PolicyStatusWrite{value: statusWriteValue[PolicyStatus]{
		status:             ClonePolicyStatus(status),
		resourceGeneration: resourceGeneration,
	}}
	if err := ValidateStatusWrite(result, resourceGeneration); err != nil {
		return nil, err
	}
	return result, nil
}

// NewProviderConnectionStatusWrite validates a ProviderConnection status
// against the current resource generation and takes ownership-safe copies.
func NewProviderConnectionStatusWrite(
	status ProviderConnectionStatus,
	resourceGeneration int64,
) (*ProviderConnectionStatusWrite, error) {
	if err := ValidateProviderConnectionStatus(status, resourceGeneration); err != nil {
		return nil, wrapStatusWriteValidation(err)
	}
	result := &ProviderConnectionStatusWrite{value: statusWriteValue[ProviderConnectionStatus]{
		status:             CloneProviderConnectionStatus(status),
		resourceGeneration: resourceGeneration,
	}}
	if err := ValidateStatusWrite(result, resourceGeneration); err != nil {
		return nil, err
	}
	return result, nil
}

func (*WorkspaceStatusWrite) Kind() hierarchy.Kind   { return hierarchy.KindWorkspace }
func (*EnvironmentStatusWrite) Kind() hierarchy.Kind { return hierarchy.KindEnvironment }
func (*ApplicationStatusWrite) Kind() hierarchy.Kind { return hierarchy.KindApplication }
func (*ComponentStatusWrite) Kind() hierarchy.Kind   { return hierarchy.KindComponent }
func (*PolicyStatusWrite) Kind() hierarchy.Kind      { return hierarchy.KindPolicy }
func (*ProviderConnectionStatusWrite) Kind() hierarchy.Kind {
	return hierarchy.KindProviderConnection
}

func (write *WorkspaceStatusWrite) ObservedGenerations() []int64 {
	if write == nil {
		return nil
	}
	return write.value.status.ObservedGenerations()
}
func (write *EnvironmentStatusWrite) ObservedGenerations() []int64 {
	if write == nil {
		return nil
	}
	return write.value.status.ObservedGenerations()
}
func (write *ApplicationStatusWrite) ObservedGenerations() []int64 {
	if write == nil {
		return nil
	}
	return write.value.status.ObservedGenerations()
}
func (write *ComponentStatusWrite) ObservedGenerations() []int64 {
	if write == nil {
		return nil
	}
	return write.value.status.ObservedGenerations()
}
func (write *PolicyStatusWrite) ObservedGenerations() []int64 {
	if write == nil {
		return nil
	}
	return write.value.status.ObservedGenerations()
}
func (write *ProviderConnectionStatusWrite) ObservedGenerations() []int64 {
	if write == nil {
		return nil
	}
	return write.value.status.ObservedGenerations()
}

func (write *WorkspaceStatusWrite) ResourceGeneration() int64 {
	if write == nil {
		return 0
	}
	return write.value.resourceGeneration
}
func (write *EnvironmentStatusWrite) ResourceGeneration() int64 {
	if write == nil {
		return 0
	}
	return write.value.resourceGeneration
}
func (write *ApplicationStatusWrite) ResourceGeneration() int64 {
	if write == nil {
		return 0
	}
	return write.value.resourceGeneration
}
func (write *ComponentStatusWrite) ResourceGeneration() int64 {
	if write == nil {
		return 0
	}
	return write.value.resourceGeneration
}
func (write *PolicyStatusWrite) ResourceGeneration() int64 {
	if write == nil {
		return 0
	}
	return write.value.resourceGeneration
}
func (write *ProviderConnectionStatusWrite) ResourceGeneration() int64 {
	if write == nil {
		return 0
	}
	return write.value.resourceGeneration
}

func (write *WorkspaceStatusWrite) Status() WorkspaceStatus {
	if write == nil {
		return WorkspaceStatus{}
	}
	return CloneCommonStatus(write.value.status)
}
func (write *EnvironmentStatusWrite) Status() EnvironmentStatus {
	if write == nil {
		return EnvironmentStatus{}
	}
	return CloneCommonStatus(write.value.status)
}
func (write *ApplicationStatusWrite) Status() ApplicationStatus {
	if write == nil {
		return ApplicationStatus{}
	}
	return CloneCommonStatus(write.value.status)
}
func (write *ComponentStatusWrite) Status() ComponentStatus {
	if write == nil {
		return ComponentStatus{}
	}
	return CloneCommonStatus(write.value.status)
}
func (write *PolicyStatusWrite) Status() PolicyStatus {
	if write == nil {
		return PolicyStatus{}
	}
	return ClonePolicyStatus(write.value.status)
}
func (write *ProviderConnectionStatusWrite) Status() ProviderConnectionStatus {
	if write == nil {
		return ProviderConnectionStatus{}
	}
	return CloneProviderConnectionStatus(write.value.status)
}

func (*WorkspaceStatusWrite) isStatusWrite()          {}
func (*EnvironmentStatusWrite) isStatusWrite()        {}
func (*ApplicationStatusWrite) isStatusWrite()        {}
func (*ComponentStatusWrite) isStatusWrite()          {}
func (*PolicyStatusWrite) isStatusWrite()             {}
func (*ProviderConnectionStatusWrite) isStatusWrite() {}

// ValidateStatusWrite validates a value of the closed sum against the current
// resource generation.
func ValidateStatusWrite(write StatusWrite, resourceGeneration int64) error {
	switch value := write.(type) {
	case *WorkspaceStatusWrite:
		if value == nil || value.value.resourceGeneration != resourceGeneration {
			return ErrInvalidStatusWrite
		}
		return wrapStatusWriteValidation(ValidateCommonStatus(value.value.status, resourceGeneration))
	case *EnvironmentStatusWrite:
		if value == nil || value.value.resourceGeneration != resourceGeneration {
			return ErrInvalidStatusWrite
		}
		return wrapStatusWriteValidation(ValidateCommonStatus(value.value.status, resourceGeneration))
	case *ApplicationStatusWrite:
		if value == nil || value.value.resourceGeneration != resourceGeneration {
			return ErrInvalidStatusWrite
		}
		return wrapStatusWriteValidation(ValidateCommonStatus(value.value.status, resourceGeneration))
	case *ComponentStatusWrite:
		if value == nil || value.value.resourceGeneration != resourceGeneration {
			return ErrInvalidStatusWrite
		}
		return wrapStatusWriteValidation(ValidateCommonStatus(value.value.status, resourceGeneration))
	case *PolicyStatusWrite:
		if value == nil || value.value.resourceGeneration != resourceGeneration {
			return ErrInvalidStatusWrite
		}
		return wrapStatusWriteValidation(ValidatePolicyStatus(value.value.status, resourceGeneration))
	case *ProviderConnectionStatusWrite:
		if value == nil || value.value.resourceGeneration != resourceGeneration {
			return ErrInvalidStatusWrite
		}
		return wrapStatusWriteValidation(ValidateProviderConnectionStatus(value.value.status, resourceGeneration))
	default:
		return ErrInvalidStatusWrite
	}
}

// CloneStatusWrite returns an independent value of the same status variant.
func CloneStatusWrite(write StatusWrite) StatusWrite {
	if write == nil || ValidateStatusWrite(write, write.ResourceGeneration()) != nil {
		return nil
	}
	switch value := write.(type) {
	case *WorkspaceStatusWrite:
		if value == nil {
			return nil
		}
		return &WorkspaceStatusWrite{value: statusWriteValue[WorkspaceStatus]{
			status:             CloneCommonStatus(value.value.status),
			resourceGeneration: value.value.resourceGeneration,
		}}
	case *EnvironmentStatusWrite:
		if value == nil {
			return nil
		}
		return &EnvironmentStatusWrite{value: statusWriteValue[EnvironmentStatus]{
			status:             CloneCommonStatus(value.value.status),
			resourceGeneration: value.value.resourceGeneration,
		}}
	case *ApplicationStatusWrite:
		if value == nil {
			return nil
		}
		return &ApplicationStatusWrite{value: statusWriteValue[ApplicationStatus]{
			status:             CloneCommonStatus(value.value.status),
			resourceGeneration: value.value.resourceGeneration,
		}}
	case *ComponentStatusWrite:
		if value == nil {
			return nil
		}
		return &ComponentStatusWrite{value: statusWriteValue[ComponentStatus]{
			status:             CloneCommonStatus(value.value.status),
			resourceGeneration: value.value.resourceGeneration,
		}}
	case *PolicyStatusWrite:
		if value == nil {
			return nil
		}
		return &PolicyStatusWrite{value: statusWriteValue[PolicyStatus]{
			status:             ClonePolicyStatus(value.value.status),
			resourceGeneration: value.value.resourceGeneration,
		}}
	case *ProviderConnectionStatusWrite:
		if value == nil {
			return nil
		}
		return &ProviderConnectionStatusWrite{value: statusWriteValue[ProviderConnectionStatus]{
			status:             CloneProviderConnectionStatus(value.value.status),
			resourceGeneration: value.value.resourceGeneration,
		}}
	default:
		return nil
	}
}

// EqualStatusWrite compares semantic status values across the closed sum.
func EqualStatusWrite(left, right StatusWrite) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if ValidateStatusWrite(left, left.ResourceGeneration()) != nil ||
		ValidateStatusWrite(right, right.ResourceGeneration()) != nil {
		return false
	}
	switch leftValue := left.(type) {
	case *WorkspaceStatusWrite:
		rightValue, ok := right.(*WorkspaceStatusWrite)
		return ok && leftValue != nil && rightValue != nil &&
			EqualCommonStatus(leftValue.value.status, rightValue.value.status) &&
			leftValue.value.resourceGeneration == rightValue.value.resourceGeneration
	case *EnvironmentStatusWrite:
		rightValue, ok := right.(*EnvironmentStatusWrite)
		return ok && leftValue != nil && rightValue != nil &&
			EqualCommonStatus(leftValue.value.status, rightValue.value.status) &&
			leftValue.value.resourceGeneration == rightValue.value.resourceGeneration
	case *ApplicationStatusWrite:
		rightValue, ok := right.(*ApplicationStatusWrite)
		return ok && leftValue != nil && rightValue != nil &&
			EqualCommonStatus(leftValue.value.status, rightValue.value.status) &&
			leftValue.value.resourceGeneration == rightValue.value.resourceGeneration
	case *ComponentStatusWrite:
		rightValue, ok := right.(*ComponentStatusWrite)
		return ok && leftValue != nil && rightValue != nil &&
			EqualCommonStatus(leftValue.value.status, rightValue.value.status) &&
			leftValue.value.resourceGeneration == rightValue.value.resourceGeneration
	case *PolicyStatusWrite:
		rightValue, ok := right.(*PolicyStatusWrite)
		return ok && leftValue != nil && rightValue != nil &&
			EqualPolicyStatus(leftValue.value.status, rightValue.value.status) &&
			leftValue.value.resourceGeneration == rightValue.value.resourceGeneration
	case *ProviderConnectionStatusWrite:
		rightValue, ok := right.(*ProviderConnectionStatusWrite)
		return ok && leftValue != nil && rightValue != nil &&
			EqualProviderConnectionStatus(leftValue.value.status, rightValue.value.status) &&
			leftValue.value.resourceGeneration == rightValue.value.resourceGeneration
	default:
		return false
	}
}

func wrapStatusWriteValidation(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrInvalidStatusWrite, err)
}
