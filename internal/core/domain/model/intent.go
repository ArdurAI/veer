package model

import (
	"errors"
	"fmt"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
)

// ErrInvalidIntent marks an absent, malformed, or unsupported hub intent.
var ErrInvalidIntent = errors.New("invalid admitted intent")

// Intent is a closed, version-independent sum of the six desired-state write
// variants. Each implementation owns private state and returns defensive
// copies, so an admitted value cannot be changed through an alias.
type Intent interface {
	// Kind identifies the closed variant.
	Kind() hierarchy.Kind
	// Metadata returns an ownership-safe copy of caller-owned metadata.
	Metadata() WriteMetadata
	isIntent()
}

type intentValue[Spec any] struct {
	metadata WriteMetadata
	spec     Spec
}

// WorkspaceIntent is immutable admitted Workspace desired state.
type WorkspaceIntent struct{ value intentValue[WorkspaceSpec] }

// EnvironmentIntent is immutable admitted Environment desired state.
type EnvironmentIntent struct{ value intentValue[EnvironmentSpec] }

// ApplicationIntent is immutable admitted Application desired state.
type ApplicationIntent struct{ value intentValue[ApplicationSpec] }

// ComponentIntent is immutable admitted Component desired state.
type ComponentIntent struct{ value intentValue[ComponentSpec] }

// PolicyIntent is immutable admitted Policy desired state.
type PolicyIntent struct{ value intentValue[PolicySpec] }

// ProviderConnectionIntent is immutable admitted ProviderConnection desired
// state.
type ProviderConnectionIntent struct {
	value intentValue[ProviderConnectionSpec]
}

// NewWorkspaceIntent validates and takes ownership-safe copies of Workspace
// desired state.
func NewWorkspaceIntent(metadata WriteMetadata, spec WorkspaceSpec) (*WorkspaceIntent, error) {
	result := &WorkspaceIntent{value: intentValue[WorkspaceSpec]{metadata: CloneWriteMetadata(metadata), spec: spec}}
	if err := ValidateIntent(result); err != nil {
		return nil, err
	}
	return result, nil
}

// NewEnvironmentIntent validates and takes ownership-safe copies of
// Environment desired state.
func NewEnvironmentIntent(metadata WriteMetadata, spec EnvironmentSpec) (*EnvironmentIntent, error) {
	result := &EnvironmentIntent{value: intentValue[EnvironmentSpec]{metadata: CloneWriteMetadata(metadata), spec: spec}}
	if err := ValidateIntent(result); err != nil {
		return nil, err
	}
	return result, nil
}

// NewApplicationIntent validates and takes ownership-safe copies of
// Application desired state.
func NewApplicationIntent(metadata WriteMetadata, spec ApplicationSpec) (*ApplicationIntent, error) {
	result := &ApplicationIntent{value: intentValue[ApplicationSpec]{metadata: CloneWriteMetadata(metadata), spec: spec}}
	if err := ValidateIntent(result); err != nil {
		return nil, err
	}
	return result, nil
}

// NewComponentIntent validates and takes ownership-safe copies of Component
// desired state.
func NewComponentIntent(metadata WriteMetadata, spec ComponentSpec) (*ComponentIntent, error) {
	result := &ComponentIntent{value: intentValue[ComponentSpec]{metadata: CloneWriteMetadata(metadata), spec: spec}}
	if err := ValidateIntent(result); err != nil {
		return nil, err
	}
	return result, nil
}

// NewPolicyIntent validates and takes ownership-safe copies of Policy desired
// state.
func NewPolicyIntent(metadata WriteMetadata, spec PolicySpec) (*PolicyIntent, error) {
	result := &PolicyIntent{value: intentValue[PolicySpec]{
		metadata: CloneWriteMetadata(metadata),
		spec:     ClonePolicySpec(spec),
	}}
	if err := ValidateIntent(result); err != nil {
		return nil, err
	}
	return result, nil
}

// NewProviderConnectionIntent validates and takes ownership-safe copies of
// ProviderConnection desired state.
func NewProviderConnectionIntent(
	metadata WriteMetadata,
	spec ProviderConnectionSpec,
) (*ProviderConnectionIntent, error) {
	result := &ProviderConnectionIntent{value: intentValue[ProviderConnectionSpec]{
		metadata: CloneWriteMetadata(metadata),
		spec:     CloneProviderConnectionSpec(spec),
	}}
	if err := ValidateIntent(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (intent *WorkspaceIntent) Kind() hierarchy.Kind   { return hierarchy.KindWorkspace }
func (intent *EnvironmentIntent) Kind() hierarchy.Kind { return hierarchy.KindEnvironment }
func (intent *ApplicationIntent) Kind() hierarchy.Kind { return hierarchy.KindApplication }
func (intent *ComponentIntent) Kind() hierarchy.Kind   { return hierarchy.KindComponent }
func (intent *PolicyIntent) Kind() hierarchy.Kind      { return hierarchy.KindPolicy }
func (intent *ProviderConnectionIntent) Kind() hierarchy.Kind {
	return hierarchy.KindProviderConnection
}

func (intent *WorkspaceIntent) Metadata() WriteMetadata {
	if intent == nil {
		return WriteMetadata{}
	}
	return CloneWriteMetadata(intent.value.metadata)
}
func (intent *EnvironmentIntent) Metadata() WriteMetadata {
	if intent == nil {
		return WriteMetadata{}
	}
	return CloneWriteMetadata(intent.value.metadata)
}
func (intent *ApplicationIntent) Metadata() WriteMetadata {
	if intent == nil {
		return WriteMetadata{}
	}
	return CloneWriteMetadata(intent.value.metadata)
}
func (intent *ComponentIntent) Metadata() WriteMetadata {
	if intent == nil {
		return WriteMetadata{}
	}
	return CloneWriteMetadata(intent.value.metadata)
}
func (intent *PolicyIntent) Metadata() WriteMetadata {
	if intent == nil {
		return WriteMetadata{}
	}
	return CloneWriteMetadata(intent.value.metadata)
}
func (intent *ProviderConnectionIntent) Metadata() WriteMetadata {
	if intent == nil {
		return WriteMetadata{}
	}
	return CloneWriteMetadata(intent.value.metadata)
}

func (intent *WorkspaceIntent) Spec() WorkspaceSpec {
	if intent == nil {
		return WorkspaceSpec{}
	}
	return intent.value.spec
}
func (intent *EnvironmentIntent) Spec() EnvironmentSpec {
	if intent == nil {
		return EnvironmentSpec{}
	}
	return intent.value.spec
}
func (intent *ApplicationIntent) Spec() ApplicationSpec {
	if intent == nil {
		return ApplicationSpec{}
	}
	return intent.value.spec
}
func (intent *ComponentIntent) Spec() ComponentSpec {
	if intent == nil {
		return ComponentSpec{}
	}
	return intent.value.spec
}
func (intent *PolicyIntent) Spec() PolicySpec {
	if intent == nil {
		return PolicySpec{}
	}
	return ClonePolicySpec(intent.value.spec)
}
func (intent *ProviderConnectionIntent) Spec() ProviderConnectionSpec {
	if intent == nil {
		return ProviderConnectionSpec{}
	}
	return CloneProviderConnectionSpec(intent.value.spec)
}

func (*WorkspaceIntent) isIntent()          {}
func (*EnvironmentIntent) isIntent()        {}
func (*ApplicationIntent) isIntent()        {}
func (*ComponentIntent) isIntent()          {}
func (*PolicyIntent) isIntent()             {}
func (*ProviderConnectionIntent) isIntent() {}

// ValidateIntent defensively validates any value of the closed sum.
func ValidateIntent(intent Intent) error {
	switch value := intent.(type) {
	case *WorkspaceIntent:
		if value == nil {
			return ErrInvalidIntent
		}
		return validateIntentMetadata(value.value.metadata)
	case *EnvironmentIntent:
		if value == nil {
			return ErrInvalidIntent
		}
		return validateIntentMetadata(value.value.metadata)
	case *ApplicationIntent:
		if value == nil {
			return ErrInvalidIntent
		}
		return validateIntentMetadata(value.value.metadata)
	case *ComponentIntent:
		if value == nil {
			return ErrInvalidIntent
		}
		return validateIntentMetadata(value.value.metadata)
	case *PolicyIntent:
		if value == nil {
			return ErrInvalidIntent
		}
		if err := validateIntentMetadata(value.value.metadata); err != nil {
			return err
		}
		if err := ValidatePolicySpec(value.value.spec); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidIntent, err)
		}
		return nil
	case *ProviderConnectionIntent:
		if value == nil {
			return ErrInvalidIntent
		}
		if err := validateIntentMetadata(value.value.metadata); err != nil {
			return err
		}
		if err := ValidateProviderConnectionSpec(value.value.spec); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidIntent, err)
		}
		return nil
	default:
		return ErrInvalidIntent
	}
}

// CloneIntent returns a deep-enough independent value of the same variant.
func CloneIntent(intent Intent) Intent {
	if err := ValidateIntent(intent); err != nil {
		return nil
	}
	switch value := intent.(type) {
	case *WorkspaceIntent:
		if value == nil {
			return nil
		}
		return &WorkspaceIntent{value: intentValue[WorkspaceSpec]{
			metadata: CloneWriteMetadata(value.value.metadata),
			spec:     value.value.spec,
		}}
	case *EnvironmentIntent:
		if value == nil {
			return nil
		}
		return &EnvironmentIntent{value: intentValue[EnvironmentSpec]{
			metadata: CloneWriteMetadata(value.value.metadata),
			spec:     value.value.spec,
		}}
	case *ApplicationIntent:
		if value == nil {
			return nil
		}
		return &ApplicationIntent{value: intentValue[ApplicationSpec]{
			metadata: CloneWriteMetadata(value.value.metadata),
			spec:     value.value.spec,
		}}
	case *ComponentIntent:
		if value == nil {
			return nil
		}
		return &ComponentIntent{value: intentValue[ComponentSpec]{
			metadata: CloneWriteMetadata(value.value.metadata),
			spec:     value.value.spec,
		}}
	case *PolicyIntent:
		if value == nil {
			return nil
		}
		return &PolicyIntent{value: intentValue[PolicySpec]{
			metadata: CloneWriteMetadata(value.value.metadata),
			spec:     ClonePolicySpec(value.value.spec),
		}}
	case *ProviderConnectionIntent:
		if value == nil {
			return nil
		}
		return &ProviderConnectionIntent{value: intentValue[ProviderConnectionSpec]{
			metadata: CloneWriteMetadata(value.value.metadata),
			spec:     CloneProviderConnectionSpec(value.value.spec),
		}}
	default:
		return nil
	}
}

// EqualIntent compares semantic values across the closed sum.
func EqualIntent(left, right Intent) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if ValidateIntent(left) != nil || ValidateIntent(right) != nil {
		return false
	}
	switch leftValue := left.(type) {
	case *WorkspaceIntent:
		rightValue, ok := right.(*WorkspaceIntent)
		return ok && leftValue != nil && rightValue != nil &&
			EqualWriteMetadata(leftValue.value.metadata, rightValue.value.metadata) && leftValue.value.spec == rightValue.value.spec
	case *EnvironmentIntent:
		rightValue, ok := right.(*EnvironmentIntent)
		return ok && leftValue != nil && rightValue != nil && EqualWriteMetadata(leftValue.value.metadata, rightValue.value.metadata)
	case *ApplicationIntent:
		rightValue, ok := right.(*ApplicationIntent)
		return ok && leftValue != nil && rightValue != nil && EqualWriteMetadata(leftValue.value.metadata, rightValue.value.metadata)
	case *ComponentIntent:
		rightValue, ok := right.(*ComponentIntent)
		return ok && leftValue != nil && rightValue != nil && EqualWriteMetadata(leftValue.value.metadata, rightValue.value.metadata)
	case *PolicyIntent:
		rightValue, ok := right.(*PolicyIntent)
		return ok && leftValue != nil && rightValue != nil &&
			EqualWriteMetadata(leftValue.value.metadata, rightValue.value.metadata) &&
			EqualPolicySpec(leftValue.value.spec, rightValue.value.spec)
	case *ProviderConnectionIntent:
		rightValue, ok := right.(*ProviderConnectionIntent)
		return ok && leftValue != nil && rightValue != nil &&
			EqualWriteMetadata(leftValue.value.metadata, rightValue.value.metadata) && leftValue.value.spec == rightValue.value.spec
	default:
		return false
	}
}

func validateIntentMetadata(metadata WriteMetadata) error {
	if err := ValidateWriteMetadata(metadata); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidIntent, err)
	}
	return nil
}
