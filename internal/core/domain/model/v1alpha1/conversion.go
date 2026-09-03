package v1alpha1

import (
	"errors"
	"fmt"

	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/model"
)

var (
	// ErrInvalidSource marks a source value that cannot enter the hub.
	ErrInvalidSource = errors.New("invalid v1alpha1 source model")
	// ErrSourceNotDefaulted marks a source value whose optional fields have not
	// passed through versioned defaulting.
	ErrSourceNotDefaulted = errors.New("v1alpha1 source model is not defaulted")
	// ErrSourceKindMismatch marks a source kind sent to the wrong converter.
	ErrSourceKindMismatch = errors.New("v1alpha1 source kind does not match converter")
	// ErrNilHubValue marks an absent hub value passed to a source converter.
	ErrNilHubValue = errors.New("nil unversioned hub value")
	// ErrInvalidHubValue marks an unversioned value that did not originate from
	// a successful model constructor or no longer satisfies hub invariants.
	ErrInvalidHubValue = errors.New("invalid unversioned hub value")
)

// ToHubWorkspaceIntent converts defaulted Workspace source desired state to
// the immutable unversioned hub.
func ToHubWorkspaceIntent(source WorkspaceWrite) (*model.WorkspaceIntent, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindWorkspace); err != nil {
		return nil, err
	}
	if source.Spec.SuspendReconciliation == nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSource, ErrSourceNotDefaulted)
	}
	metadata, err := toHubMetadata(source.Metadata)
	if err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewWorkspaceIntent(metadata, model.WorkspaceSpec{
		SuspendReconciliation: *source.Spec.SuspendReconciliation,
	}))
}

// ToHubEnvironmentIntent converts Environment source desired state to the
// immutable unversioned hub.
func ToHubEnvironmentIntent(source EnvironmentWrite) (*model.EnvironmentIntent, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindEnvironment); err != nil {
		return nil, err
	}
	metadata, err := toHubMetadata(source.Metadata)
	if err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewEnvironmentIntent(metadata, model.EnvironmentSpec{}))
}

// ToHubApplicationIntent converts Application source desired state to the
// immutable unversioned hub.
func ToHubApplicationIntent(source ApplicationWrite) (*model.ApplicationIntent, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindApplication); err != nil {
		return nil, err
	}
	metadata, err := toHubMetadata(source.Metadata)
	if err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewApplicationIntent(metadata, model.ApplicationSpec{}))
}

// ToHubComponentIntent converts Component source desired state to the
// immutable unversioned hub.
func ToHubComponentIntent(source ComponentWrite) (*model.ComponentIntent, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindComponent); err != nil {
		return nil, err
	}
	metadata, err := toHubMetadata(source.Metadata)
	if err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewComponentIntent(metadata, model.ComponentSpec{}))
}

// ToHubPolicyIntent converts Policy source desired state to the immutable
// unversioned hub.
func ToHubPolicyIntent(source PolicyWrite) (*model.PolicyIntent, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindPolicy); err != nil {
		return nil, err
	}
	metadata, err := toHubMetadata(source.Metadata)
	if err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewPolicyIntent(metadata, source.Spec))
}

// ToHubProviderConnectionIntent converts ProviderConnection source desired
// state to the immutable unversioned hub.
func ToHubProviderConnectionIntent(source ProviderConnectionWrite) (*model.ProviderConnectionIntent, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindProviderConnection); err != nil {
		return nil, err
	}
	metadata, err := toHubMetadata(source.Metadata)
	if err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewProviderConnectionIntent(metadata, source.Spec))
}

// FromHubWorkspaceIntent converts immutable Workspace hub desired state to a
// fully explicit v1alpha1 source value.
func FromHubWorkspaceIntent(hub *model.WorkspaceIntent) (WorkspaceWrite, error) {
	if hub == nil {
		return WorkspaceWrite{}, invalidNilHubError()
	}
	if err := validateHubIntent(hub); err != nil {
		return WorkspaceWrite{}, err
	}
	spec := hub.Spec()
	value := spec.SuspendReconciliation
	return WorkspaceWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindWorkspace.String(),
		Metadata:   fromHubMetadata(hub.Metadata()),
		Spec:       WorkspaceWriteSpec{SuspendReconciliation: &value},
	}, nil
}

// FromHubEnvironmentIntent converts immutable Environment hub desired state
// to v1alpha1.
func FromHubEnvironmentIntent(hub *model.EnvironmentIntent) (EnvironmentWrite, error) {
	if hub == nil {
		return EnvironmentWrite{}, invalidNilHubError()
	}
	if err := validateHubIntent(hub); err != nil {
		return EnvironmentWrite{}, err
	}
	return EnvironmentWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindEnvironment.String(),
		Metadata:   fromHubMetadata(hub.Metadata()),
		Spec:       EnvironmentSpec{},
	}, nil
}

// FromHubApplicationIntent converts immutable Application hub desired state
// to v1alpha1.
func FromHubApplicationIntent(hub *model.ApplicationIntent) (ApplicationWrite, error) {
	if hub == nil {
		return ApplicationWrite{}, invalidNilHubError()
	}
	if err := validateHubIntent(hub); err != nil {
		return ApplicationWrite{}, err
	}
	return ApplicationWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindApplication.String(),
		Metadata:   fromHubMetadata(hub.Metadata()),
		Spec:       ApplicationSpec{},
	}, nil
}

// FromHubComponentIntent converts immutable Component hub desired state to
// v1alpha1.
func FromHubComponentIntent(hub *model.ComponentIntent) (ComponentWrite, error) {
	if hub == nil {
		return ComponentWrite{}, invalidNilHubError()
	}
	if err := validateHubIntent(hub); err != nil {
		return ComponentWrite{}, err
	}
	return ComponentWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindComponent.String(),
		Metadata:   fromHubMetadata(hub.Metadata()),
		Spec:       ComponentSpec{},
	}, nil
}

// FromHubPolicyIntent converts immutable Policy hub desired state to
// v1alpha1.
func FromHubPolicyIntent(hub *model.PolicyIntent) (PolicyWrite, error) {
	if hub == nil {
		return PolicyWrite{}, invalidNilHubError()
	}
	if err := validateHubIntent(hub); err != nil {
		return PolicyWrite{}, err
	}
	return PolicyWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindPolicy.String(),
		Metadata:   fromHubMetadata(hub.Metadata()),
		Spec:       hub.Spec(),
	}, nil
}

// FromHubProviderConnectionIntent converts immutable ProviderConnection hub
// desired state to v1alpha1.
func FromHubProviderConnectionIntent(hub *model.ProviderConnectionIntent) (ProviderConnectionWrite, error) {
	if hub == nil {
		return ProviderConnectionWrite{}, invalidNilHubError()
	}
	if err := validateHubIntent(hub); err != nil {
		return ProviderConnectionWrite{}, err
	}
	return ProviderConnectionWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindProviderConnection.String(),
		Metadata:   fromHubMetadata(hub.Metadata()),
		Spec:       hub.Spec(),
	}, nil
}

// ToHubWorkspaceStatusWrite converts and validates Workspace source observed
// state against the current resource generation.
func ToHubWorkspaceStatusWrite(source WorkspaceStatusWrite, resourceGeneration int64) (*model.WorkspaceStatusWrite, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindWorkspace); err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewWorkspaceStatusWrite(commonStatusToHub(source.Status), resourceGeneration))
}

// ToHubEnvironmentStatusWrite converts and validates Environment source
// observed state against the current resource generation.
func ToHubEnvironmentStatusWrite(source EnvironmentStatusWrite, resourceGeneration int64) (*model.EnvironmentStatusWrite, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindEnvironment); err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewEnvironmentStatusWrite(commonStatusToHub(source.Status), resourceGeneration))
}

// ToHubApplicationStatusWrite converts and validates Application source
// observed state against the current resource generation.
func ToHubApplicationStatusWrite(source ApplicationStatusWrite, resourceGeneration int64) (*model.ApplicationStatusWrite, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindApplication); err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewApplicationStatusWrite(commonStatusToHub(source.Status), resourceGeneration))
}

// ToHubComponentStatusWrite converts and validates Component source observed
// state against the current resource generation.
func ToHubComponentStatusWrite(source ComponentStatusWrite, resourceGeneration int64) (*model.ComponentStatusWrite, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindComponent); err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewComponentStatusWrite(commonStatusToHub(source.Status), resourceGeneration))
}

// ToHubPolicyStatusWrite converts and validates Policy source observed state
// against the current resource generation.
func ToHubPolicyStatusWrite(source PolicyStatusWrite, resourceGeneration int64) (*model.PolicyStatusWrite, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindPolicy); err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewPolicyStatusWrite(source.Status, resourceGeneration))
}

// ToHubProviderConnectionStatusWrite converts and validates
// ProviderConnection source observed state against the current resource
// generation.
func ToHubProviderConnectionStatusWrite(
	source ProviderConnectionStatusWrite,
	resourceGeneration int64,
) (*model.ProviderConnectionStatusWrite, error) {
	if err := validateSourceIdentity(source.APIVersion, source.Kind, hierarchy.KindProviderConnection); err != nil {
		return nil, err
	}
	return wrapSourceResult(model.NewProviderConnectionStatusWrite(source.Status, resourceGeneration))
}

// FromHubWorkspaceStatusWrite converts immutable Workspace hub observed state
// to v1alpha1.
func FromHubWorkspaceStatusWrite(hub *model.WorkspaceStatusWrite) (WorkspaceStatusWrite, error) {
	if hub == nil {
		return WorkspaceStatusWrite{}, invalidNilHubError()
	}
	if err := validateHubStatusWrite(hub); err != nil {
		return WorkspaceStatusWrite{}, err
	}
	return WorkspaceStatusWrite{APIVersion: APIVersion, Kind: hierarchy.KindWorkspace.String(), Status: commonStatusFromHub(hub.Status())}, nil
}

// FromHubEnvironmentStatusWrite converts immutable Environment hub observed
// state to v1alpha1.
func FromHubEnvironmentStatusWrite(hub *model.EnvironmentStatusWrite) (EnvironmentStatusWrite, error) {
	if hub == nil {
		return EnvironmentStatusWrite{}, invalidNilHubError()
	}
	if err := validateHubStatusWrite(hub); err != nil {
		return EnvironmentStatusWrite{}, err
	}
	return EnvironmentStatusWrite{APIVersion: APIVersion, Kind: hierarchy.KindEnvironment.String(), Status: commonStatusFromHub(hub.Status())}, nil
}

// FromHubApplicationStatusWrite converts immutable Application hub observed
// state to v1alpha1.
func FromHubApplicationStatusWrite(hub *model.ApplicationStatusWrite) (ApplicationStatusWrite, error) {
	if hub == nil {
		return ApplicationStatusWrite{}, invalidNilHubError()
	}
	if err := validateHubStatusWrite(hub); err != nil {
		return ApplicationStatusWrite{}, err
	}
	return ApplicationStatusWrite{APIVersion: APIVersion, Kind: hierarchy.KindApplication.String(), Status: commonStatusFromHub(hub.Status())}, nil
}

// FromHubComponentStatusWrite converts immutable Component hub observed state
// to v1alpha1.
func FromHubComponentStatusWrite(hub *model.ComponentStatusWrite) (ComponentStatusWrite, error) {
	if hub == nil {
		return ComponentStatusWrite{}, invalidNilHubError()
	}
	if err := validateHubStatusWrite(hub); err != nil {
		return ComponentStatusWrite{}, err
	}
	return ComponentStatusWrite{APIVersion: APIVersion, Kind: hierarchy.KindComponent.String(), Status: commonStatusFromHub(hub.Status())}, nil
}

// FromHubPolicyStatusWrite converts immutable Policy hub observed state to
// v1alpha1.
func FromHubPolicyStatusWrite(hub *model.PolicyStatusWrite) (PolicyStatusWrite, error) {
	if hub == nil {
		return PolicyStatusWrite{}, invalidNilHubError()
	}
	if err := validateHubStatusWrite(hub); err != nil {
		return PolicyStatusWrite{}, err
	}
	return PolicyStatusWrite{APIVersion: APIVersion, Kind: hierarchy.KindPolicy.String(), Status: hub.Status()}, nil
}

// FromHubProviderConnectionStatusWrite converts immutable
// ProviderConnection hub observed state to v1alpha1.
func FromHubProviderConnectionStatusWrite(
	hub *model.ProviderConnectionStatusWrite,
) (ProviderConnectionStatusWrite, error) {
	if hub == nil {
		return ProviderConnectionStatusWrite{}, invalidNilHubError()
	}
	if err := validateHubStatusWrite(hub); err != nil {
		return ProviderConnectionStatusWrite{}, err
	}
	return ProviderConnectionStatusWrite{
		APIVersion: APIVersion,
		Kind:       hierarchy.KindProviderConnection.String(),
		Status:     hub.Status(),
	}, nil
}

func validateHubIntent(hub model.Intent) error {
	if err := model.ValidateIntent(hub); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidHubValue, err)
	}
	return nil
}

func validateHubStatusWrite(hub model.StatusWrite) error {
	if err := model.ValidateStatusWrite(hub, hub.ResourceGeneration()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidHubValue, err)
	}
	return nil
}

func invalidNilHubError() error {
	return fmt.Errorf("%w: %w", ErrInvalidHubValue, ErrNilHubValue)
}

func wrapSourceResult[Value any](value Value, err error) (Value, error) {
	if err != nil {
		var zero Value
		return zero, fmt.Errorf("%w: %w", ErrInvalidSource, err)
	}
	return value, nil
}

func validateSourceIdentity(apiVersion, kind string, expected hierarchy.Kind) error {
	if apiVersion != APIVersion {
		return fmt.Errorf("%w: %w", ErrInvalidSource, hierarchy.ErrUnsupportedAPIVersion)
	}
	if kind != expected.String() {
		return fmt.Errorf("%w: %w", ErrInvalidSource, ErrSourceKindMismatch)
	}
	return nil
}

func toHubMetadata(source WriteMetadata) (model.WriteMetadata, error) {
	metadata, err := model.NewWriteMetadata(source.DisplayName, source.Labels)
	if err != nil {
		return model.WriteMetadata{}, fmt.Errorf("%w: %w", ErrInvalidSource, err)
	}
	return metadata, nil
}

func fromHubMetadata(hub model.WriteMetadata) WriteMetadata {
	return WriteMetadata{DisplayName: hub.DisplayName(), Labels: hub.Labels()}
}

func commonStatusToHub(source CommonStatus) model.CommonStatus {
	return model.CommonStatus{
		ObservedGeneration: source.ObservedGeneration,
		Conditions:         source.Conditions,
	}
}

func commonStatusFromHub(hub model.CommonStatus) CommonStatus {
	return CommonStatus{
		ObservedGeneration: hub.ObservedGeneration,
		Conditions:         condition.CloneSet(hub.Conditions),
	}
}
