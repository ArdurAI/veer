package reference

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/admission"
	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/model"
	modelv1 "github.com/ArdurAI/veer/internal/core/domain/model/v1alpha1"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func canonicalIntent(intent model.Intent) ([]byte, error) {
	var value any
	var err error
	switch typed := intent.(type) {
	case *model.WorkspaceIntent:
		value, err = modelv1.FromHubWorkspaceIntent(typed)
	case *model.EnvironmentIntent:
		value, err = modelv1.FromHubEnvironmentIntent(typed)
	case *model.ApplicationIntent:
		value, err = modelv1.FromHubApplicationIntent(typed)
	case *model.ComponentIntent:
		value, err = modelv1.FromHubComponentIntent(typed)
	case *model.PolicyIntent:
		value, err = modelv1.FromHubPolicyIntent(typed)
	case *model.ProviderConnectionIntent:
		value, err = modelv1.FromHubProviderConnectionIntent(typed)
	default:
		return nil, ErrInternal
	}
	if err != nil {
		return nil, fmt.Errorf("%w: normalize intent", ErrInternal)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode intent", ErrInternal)
	}
	return encoded, nil
}

func canonicalStatus(write model.StatusWrite) ([]byte, error) {
	var value any
	var err error
	switch typed := write.(type) {
	case *model.WorkspaceStatusWrite:
		value, err = modelv1.FromHubWorkspaceStatusWrite(typed)
	case *model.EnvironmentStatusWrite:
		value, err = modelv1.FromHubEnvironmentStatusWrite(typed)
	case *model.ApplicationStatusWrite:
		value, err = modelv1.FromHubApplicationStatusWrite(typed)
	case *model.ComponentStatusWrite:
		value, err = modelv1.FromHubComponentStatusWrite(typed)
	case *model.PolicyStatusWrite:
		value, err = modelv1.FromHubPolicyStatusWrite(typed)
	case *model.ProviderConnectionStatusWrite:
		value, err = modelv1.FromHubProviderConnectionStatusWrite(typed)
	default:
		return nil, ErrInternal
	}
	if err != nil {
		return nil, fmt.Errorf("%w: normalize status", ErrInternal)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode status", ErrInternal)
	}
	return encoded, nil
}

func newResource(
	admitted admission.CreateResult,
	version string,
	createdAt time.Time,
) (Resource, error) {
	placement := admitted.Placement()
	metadata := admitted.Intent().Metadata()
	inputMetadata := func() (string, map[string]string) {
		return metadata.DisplayName(), metadata.Labels()
	}
	displayName, labels := inputMetadata()

	switch intent := admitted.Intent().(type) {
	case *model.WorkspaceIntent:
		value, err := hierarchy.NewResource(placement, hierarchy.CreateInput[model.WorkspaceSpec, model.WorkspaceStatus]{
			DisplayName: displayName, Labels: labels, ResourceVersion: version, CreatedAt: createdAt,
			Spec: intent.Spec(), Status: model.WorkspaceStatus{Conditions: []condition.Condition{}},
		})
		return resourceView(value, err)
	case *model.EnvironmentIntent:
		value, err := hierarchy.NewResource(placement, hierarchy.CreateInput[model.EnvironmentSpec, model.EnvironmentStatus]{
			DisplayName: displayName, Labels: labels, ResourceVersion: version, CreatedAt: createdAt,
			Spec: intent.Spec(), Status: model.EnvironmentStatus{Conditions: []condition.Condition{}},
		})
		return resourceView(value, err)
	case *model.ApplicationIntent:
		value, err := hierarchy.NewResource(placement, hierarchy.CreateInput[model.ApplicationSpec, model.ApplicationStatus]{
			DisplayName: displayName, Labels: labels, ResourceVersion: version, CreatedAt: createdAt,
			Spec: intent.Spec(), Status: model.ApplicationStatus{Conditions: []condition.Condition{}},
		})
		return resourceView(value, err)
	case *model.ComponentIntent:
		value, err := hierarchy.NewResource(placement, hierarchy.CreateInput[model.ComponentSpec, model.ComponentStatus]{
			DisplayName: displayName, Labels: labels, ResourceVersion: version, CreatedAt: createdAt,
			Spec: intent.Spec(), Status: model.ComponentStatus{Conditions: []condition.Condition{}},
		})
		return resourceView(value, err)
	case *model.PolicyIntent:
		value, err := control.NewPolicyResource(placement, hierarchy.CreateInput[model.PolicySpec, model.PolicyStatus]{
			DisplayName: displayName, Labels: labels, ResourceVersion: version, CreatedAt: createdAt,
			Spec: intent.Spec(), Status: model.PolicyStatus{Conditions: []condition.Condition{}},
		})
		return resourceView(value, err)
	case *model.ProviderConnectionIntent:
		value, err := control.NewProviderConnectionResource(
			placement,
			hierarchy.CreateInput[model.ProviderConnectionSpec, model.ProviderConnectionStatus]{
				DisplayName: displayName, Labels: labels, ResourceVersion: version, CreatedAt: createdAt,
				Spec: intent.Spec(), Status: model.ProviderConnectionStatus{
					Conditions: []condition.Condition{}, Capabilities: []model.ProviderCapability{}, QuotaChecks: []model.QuotaCheck{},
				},
			},
		)
		return resourceView(value, err)
	default:
		return Resource{}, ErrInternal
	}
}

func replaceResource(current Resource, intent model.Intent, version string, updatedAt time.Time) (Resource, error) {
	metadata := intent.Metadata()
	switch typed := intent.(type) {
	case *model.WorkspaceIntent:
		value, err := decodeTyped[model.WorkspaceSpec, model.WorkspaceStatus](current.Canonical, hierarchy.KindWorkspace)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceIntent(metadata.DisplayName(), metadata.Labels(), typed.Spec(), version, updatedAt)
		return resourceView(replaced, err)
	case *model.EnvironmentIntent:
		value, err := decodeTyped[model.EnvironmentSpec, model.EnvironmentStatus](current.Canonical, hierarchy.KindEnvironment)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceIntent(metadata.DisplayName(), metadata.Labels(), typed.Spec(), version, updatedAt)
		return resourceView(replaced, err)
	case *model.ApplicationIntent:
		value, err := decodeTyped[model.ApplicationSpec, model.ApplicationStatus](current.Canonical, hierarchy.KindApplication)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceIntent(metadata.DisplayName(), metadata.Labels(), typed.Spec(), version, updatedAt)
		return resourceView(replaced, err)
	case *model.ComponentIntent:
		value, err := decodeTyped[model.ComponentSpec, model.ComponentStatus](current.Canonical, hierarchy.KindComponent)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceIntent(metadata.DisplayName(), metadata.Labels(), typed.Spec(), version, updatedAt)
		return resourceView(replaced, err)
	case *model.PolicyIntent:
		value, err := decodeTyped[model.PolicySpec, model.PolicyStatus](current.Canonical, hierarchy.KindPolicy)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceIntent(metadata.DisplayName(), metadata.Labels(), typed.Spec(), version, updatedAt)
		return resourceView(replaced, err)
	case *model.ProviderConnectionIntent:
		value, err := decodeTyped[model.ProviderConnectionSpec, model.ProviderConnectionStatus](current.Canonical, hierarchy.KindProviderConnection)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceIntent(metadata.DisplayName(), metadata.Labels(), typed.Spec(), version, updatedAt)
		return resourceView(replaced, err)
	default:
		return Resource{}, ErrInternal
	}
}

func replaceResourceStatus(current Resource, write model.StatusWrite, version string, updatedAt time.Time) (Resource, error) {
	switch typed := write.(type) {
	case *model.WorkspaceStatusWrite:
		value, err := decodeTyped[model.WorkspaceSpec, model.WorkspaceStatus](current.Canonical, hierarchy.KindWorkspace)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceStatus(typed.Status(), version, updatedAt)
		return resourceView(replaced, err)
	case *model.EnvironmentStatusWrite:
		value, err := decodeTyped[model.EnvironmentSpec, model.EnvironmentStatus](current.Canonical, hierarchy.KindEnvironment)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceStatus(typed.Status(), version, updatedAt)
		return resourceView(replaced, err)
	case *model.ApplicationStatusWrite:
		value, err := decodeTyped[model.ApplicationSpec, model.ApplicationStatus](current.Canonical, hierarchy.KindApplication)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceStatus(typed.Status(), version, updatedAt)
		return resourceView(replaced, err)
	case *model.ComponentStatusWrite:
		value, err := decodeTyped[model.ComponentSpec, model.ComponentStatus](current.Canonical, hierarchy.KindComponent)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceStatus(typed.Status(), version, updatedAt)
		return resourceView(replaced, err)
	case *model.PolicyStatusWrite:
		value, err := decodeTyped[model.PolicySpec, model.PolicyStatus](current.Canonical, hierarchy.KindPolicy)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceStatus(typed.Status(), version, updatedAt)
		return resourceView(replaced, err)
	case *model.ProviderConnectionStatusWrite:
		value, err := decodeTyped[model.ProviderConnectionSpec, model.ProviderConnectionStatus](current.Canonical, hierarchy.KindProviderConnection)
		if err != nil {
			return Resource{}, err
		}
		replaced, err := value.ReplaceStatus(typed.Status(), version, updatedAt)
		return resourceView(replaced, err)
	default:
		return Resource{}, ErrInternal
	}
}

func decodeResource(data []byte) (Resource, error) {
	var identity struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(data, &identity); err != nil {
		return Resource{}, fmt.Errorf("%w: decode stored resource", ErrInternal)
	}
	kind, err := hierarchy.ParseKind(identity.Kind)
	if err != nil {
		return Resource{}, fmt.Errorf("%w: stored resource kind", ErrInternal)
	}
	switch kind {
	case hierarchy.KindWorkspace:
		return decodedResourceView[model.WorkspaceSpec, model.WorkspaceStatus](data, kind)
	case hierarchy.KindEnvironment:
		return decodedResourceView[model.EnvironmentSpec, model.EnvironmentStatus](data, kind)
	case hierarchy.KindApplication:
		return decodedResourceView[model.ApplicationSpec, model.ApplicationStatus](data, kind)
	case hierarchy.KindComponent:
		return decodedResourceView[model.ComponentSpec, model.ComponentStatus](data, kind)
	case hierarchy.KindPolicy:
		return decodedResourceView[model.PolicySpec, model.PolicyStatus](data, kind)
	case hierarchy.KindProviderConnection:
		return decodedResourceView[model.ProviderConnectionSpec, model.ProviderConnectionStatus](data, kind)
	default:
		return Resource{}, ErrInternal
	}
}

func decodedResourceView[Spec any, Status resource.GenerationObservations](data []byte, kind hierarchy.Kind) (Resource, error) {
	value, err := decodeTyped[Spec, Status](data, kind)
	if err != nil {
		return Resource{}, err
	}
	canonical, err := resource.MarshalCanonical(value)
	if err != nil || !bytes.Equal(canonical, data) {
		return Resource{}, fmt.Errorf("%w: stored resource is not canonical", ErrInternal)
	}
	return Resource{Canonical: bytes.Clone(canonical), Kind: kind, Metadata: value.Metadata()}, nil
}

func decodeTyped[Spec any, Status resource.GenerationObservations](
	data []byte,
	kind hierarchy.Kind,
) (resource.Resource[Spec, Status], error) {
	value, err := resource.UnmarshalCanonical[Spec, Status](data)
	if err != nil || value.APIVersion() != hierarchy.APIVersion || value.Kind() != kind.String() {
		var zero resource.Resource[Spec, Status]
		return zero, fmt.Errorf("%w: invalid stored %s", ErrInternal, kind)
	}
	return value, nil
}

func resourceView[Spec any, Status resource.GenerationObservations](
	value resource.Resource[Spec, Status],
	err error,
) (Resource, error) {
	if err != nil {
		return Resource{}, err
	}
	canonical, err := resource.MarshalCanonical(value)
	if err != nil {
		return Resource{}, err
	}
	kind, err := hierarchy.ParseKind(value.Kind())
	if err != nil {
		return Resource{}, fmt.Errorf("%w: constructed resource kind", ErrInternal)
	}
	return Resource{Canonical: canonical, Kind: kind, Metadata: value.Metadata()}, nil
}

func hierarchyRecord(value Resource) (hierarchy.Record, error) {
	record, err := hierarchy.RecordFrom(hierarchy.APIVersion, value.Kind.String(), value.Metadata)
	if err != nil {
		return hierarchy.Record{}, fmt.Errorf("%w: project hierarchy", ErrInternal)
	}
	return record, nil
}

func providerSpec(value Resource) (model.ProviderConnectionSpec, error) {
	if value.Kind != hierarchy.KindProviderConnection {
		return model.ProviderConnectionSpec{}, nil
	}
	typed, err := decodeTyped[model.ProviderConnectionSpec, model.ProviderConnectionStatus](
		value.Canonical,
		hierarchy.KindProviderConnection,
	)
	if err != nil {
		return model.ProviderConnectionSpec{}, err
	}
	return typed.Spec()
}

func snapshotFor(resources []Resource, workspaceID resource.ID) (hierarchy.Snapshot, error) {
	records := make([]hierarchy.Record, 0, len(resources))
	for _, value := range resources {
		if value.Metadata.WorkspaceID() != workspaceID {
			continue
		}
		record, err := hierarchyRecord(value)
		if err != nil {
			return hierarchy.Snapshot{}, err
		}
		records = append(records, record)
	}
	snapshot, err := hierarchy.NewSnapshot(workspaceID, records)
	if err != nil {
		if errors.Is(err, hierarchy.ErrWorkspaceRootMissing) {
			return hierarchy.Snapshot{}, ErrNotFound
		}
		return hierarchy.Snapshot{}, fmt.Errorf("%w: hierarchy snapshot", ErrInternal)
	}
	return snapshot, nil
}
