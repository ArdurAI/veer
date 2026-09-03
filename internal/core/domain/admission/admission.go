// Package admission implements Veer's bounded, deterministic, provider-free
// write admission boundary. It performs no I/O and accepts no callback or port
// through which persistence, credentials, queues, or provider APIs could be
// reached.
package admission

import (
	"errors"
	"reflect"

	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/model"
	modelv1 "github.com/ArdurAI/veer/internal/core/domain/model/v1alpha1"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// CreateContext contains only server-issued identity and an immutable
// hierarchy view. ParentID is absent for Workspace and required for every
// child kind. Placement is derived during the reference stage.
type CreateContext struct {
	ID       resource.ID
	ParentID *resource.ID
	Snapshot hierarchy.Snapshot
}

// CreateResult is an immutable admitted create value. Accessors return
// independent values so callers cannot mutate retained admission state.
type CreateResult struct {
	placement hierarchy.Placement
	intent    model.Intent
}

// Placement returns an independent server-derived placement.
func (result CreateResult) Placement() hierarchy.Placement {
	return result.placement.Clone()
}

// Intent returns an independent version-neutral desired-state value.
func (result CreateResult) Intent() model.Intent {
	return model.CloneIntent(result.intent)
}

// AdmitCreate runs schema, semantic, immutable, reference, default, and
// conversion in that exact order and returns no partial result on rejection.
func AdmitCreate(raw []byte, context CreateContext) (CreateResult, error) {
	document, failure := parseRaw(raw)
	if failure != nil {
		return CreateResult{}, failure
	}
	source, failure := schemaIntent(document)
	if failure != nil {
		return CreateResult{}, failure
	}
	if failure := semanticIntent(source); failure != nil {
		return CreateResult{}, failure
	}
	if failure := immutableCreate(source); failure != nil {
		return CreateResult{}, failure
	}
	placement, failure := referenceCreate(source.kind, context)
	if failure != nil {
		return CreateResult{}, failure
	}
	defaulted, failure := defaultIntent(source)
	if failure != nil {
		return CreateResult{}, failure
	}
	intent, failure := convertIntent(defaulted)
	if failure != nil {
		return CreateResult{}, failure
	}
	return CreateResult{placement: placement.Clone(), intent: model.CloneIntent(intent)}, nil
}

// AdmitReplace admits a complete caller-owned metadata and desired-state
// replacement. The supplied current record must be exactly retained by the
// immutable snapshot; existence routing and persistence remain out of scope.
func AdmitReplace(raw []byte, current hierarchy.Record, snapshot hierarchy.Snapshot) (model.Intent, error) {
	document, failure := parseRaw(raw)
	if failure != nil {
		return nil, failure
	}
	source, failure := schemaIntent(document)
	if failure != nil {
		return nil, failure
	}
	if failure := semanticIntent(source); failure != nil {
		return nil, failure
	}
	if failure := immutableCurrent(source.apiVersion, source.kind, current); failure != nil {
		return nil, failure
	}
	if failure := referenceCurrent(current, snapshot); failure != nil {
		return nil, failure
	}
	defaulted, failure := defaultIntent(source)
	if failure != nil {
		return nil, failure
	}
	intent, failure := convertIntent(defaulted)
	if failure != nil {
		return nil, failure
	}
	return model.CloneIntent(intent), nil
}

// AdmitStatus admits a status-only write against the supplied current
// generation and exact immutable hierarchy snapshot.
func AdmitStatus(
	raw []byte,
	current hierarchy.Record,
	generation int64,
	snapshot hierarchy.Snapshot,
) (model.StatusWrite, error) {
	document, failure := parseRaw(raw)
	if failure != nil {
		return nil, failure
	}
	source, failure := schemaStatus(document)
	if failure != nil {
		return nil, failure
	}
	if failure := semanticStatus(source, generation); failure != nil {
		return nil, failure
	}
	if failure := immutableCurrent(source.apiVersion, source.kind, current); failure != nil {
		return nil, failure
	}
	if failure := referenceCurrent(current, snapshot); failure != nil {
		return nil, failure
	}
	defaulted, failure := defaultStatus(source)
	if failure != nil {
		return nil, failure
	}
	status, failure := convertStatus(defaulted, generation)
	if failure != nil {
		return nil, failure
	}
	return model.CloneStatusWrite(status), nil
}

func immutableCreate(source sourceIntent) *Error {
	// The strict create shape contains no server-owned envelope field. Keeping
	// this explicit stage prevents later schema growth from silently bypassing
	// the ordered immutability contract.
	return nil
}

func immutableCurrent(apiVersion string, kind hierarchy.Kind, current hierarchy.Record) *Error {
	if current.APIVersion() != apiVersion {
		return reject(StageImmutable, CodeImmutableField, "/apiVersion")
	}
	if current.Kind() != kind {
		return reject(StageImmutable, CodeImmutableField, "/kind")
	}
	return nil
}

func referenceCreate(kind hierarchy.Kind, context CreateContext) (hierarchy.Placement, *Error) {
	if kind == hierarchy.KindWorkspace {
		if context.ParentID != nil {
			return hierarchy.Placement{}, reject(StageReference, CodeInvalidPlacement, "")
		}
		placement, err := hierarchy.DeriveWorkspace(context.ID)
		if err != nil {
			return hierarchy.Placement{}, mapReferenceError(err)
		}
		return placement, nil
	}
	if context.ParentID == nil {
		return hierarchy.Placement{}, reject(StageReference, CodeInvalidPlacement, "")
	}
	placement, err := context.Snapshot.DeriveChild(kind, context.ID, *context.ParentID)
	if err != nil {
		return hierarchy.Placement{}, mapReferenceError(err)
	}
	return placement, nil
}

func referenceCurrent(current hierarchy.Record, snapshot hierarchy.Snapshot) *Error {
	retained, err := snapshot.Lookup(current.ID())
	if err != nil {
		return mapReferenceError(err)
	}
	if err := hierarchy.CheckTransition(retained, current); err != nil {
		return mapReferenceError(err)
	}
	return nil
}

func mapReferenceError(err error) *Error {
	switch {
	case errors.Is(err, hierarchy.ErrParentNotFound):
		return reject(StageReference, CodeParentNotFound, "")
	case errors.Is(err, hierarchy.ErrParentKindMismatch):
		return reject(StageReference, CodeParentKindMismatch, "")
	case errors.Is(err, hierarchy.ErrWorkspaceMismatch), errors.Is(err, hierarchy.ErrImmutableWorkspaceID):
		return reject(StageReference, CodeWorkspaceMismatch, "")
	default:
		return reject(StageReference, CodeInvalidPlacement, "")
	}
}

type defaultedIntent struct {
	kind  hierarchy.Kind
	value any
}

func defaultIntent(source sourceIntent) (defaultedIntent, *Error) {
	metadata := modelv1.WriteMetadata{
		DisplayName: source.metadata.displayName,
		Labels:      cloneLabels(source.metadata.labels),
	}
	switch source.kind {
	case hierarchy.KindWorkspace:
		return checkedDefaultIntent(defaultedIntent{kind: source.kind, value: modelv1.DefaultWorkspaceWrite(modelv1.WorkspaceWrite{
			APIVersion: source.apiVersion,
			Kind:       source.kind.String(),
			Metadata:   metadata,
			Spec: modelv1.WorkspaceWriteSpec{
				SuspendReconciliation: cloneBool(source.workspace.suspendReconciliation),
			},
		})})
	case hierarchy.KindEnvironment:
		return checkedDefaultIntent(defaultedIntent{kind: source.kind, value: modelv1.DefaultEnvironmentWrite(modelv1.EnvironmentWrite{
			APIVersion: source.apiVersion, Kind: source.kind.String(), Metadata: metadata, Spec: modelv1.EnvironmentSpec{},
		})})
	case hierarchy.KindApplication:
		return checkedDefaultIntent(defaultedIntent{kind: source.kind, value: modelv1.DefaultApplicationWrite(modelv1.ApplicationWrite{
			APIVersion: source.apiVersion, Kind: source.kind.String(), Metadata: metadata, Spec: modelv1.ApplicationSpec{},
		})})
	case hierarchy.KindComponent:
		return checkedDefaultIntent(defaultedIntent{kind: source.kind, value: modelv1.DefaultComponentWrite(modelv1.ComponentWrite{
			APIVersion: source.apiVersion, Kind: source.kind.String(), Metadata: metadata, Spec: modelv1.ComponentSpec{},
		})})
	case hierarchy.KindPolicy:
		return checkedDefaultIntent(defaultedIntent{kind: source.kind, value: modelv1.DefaultPolicyWrite(modelv1.PolicyWrite{
			APIVersion: source.apiVersion, Kind: source.kind.String(), Metadata: metadata, Spec: modelv1.PolicySpec{},
		})})
	case hierarchy.KindProviderConnection:
		return checkedDefaultIntent(defaultedIntent{kind: source.kind, value: modelv1.DefaultProviderConnectionWrite(modelv1.ProviderConnectionWrite{
			APIVersion: source.apiVersion, Kind: source.kind.String(), Metadata: metadata, Spec: source.provider,
		})})
	default:
		return defaultedIntent{}, reject(StageDefault, CodeDefaultFailed, "")
	}
}

func checkedDefaultIntent(result defaultedIntent) (defaultedIntent, *Error) {
	var valid bool
	switch result.kind {
	case hierarchy.KindWorkspace:
		value, ok := result.value.(modelv1.WorkspaceWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String() &&
			value.Spec.SuspendReconciliation != nil && reflect.DeepEqual(value, modelv1.DefaultWorkspaceWrite(value))
	case hierarchy.KindEnvironment:
		value, ok := result.value.(modelv1.EnvironmentWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String() && reflect.DeepEqual(value, modelv1.DefaultEnvironmentWrite(value))
	case hierarchy.KindApplication:
		value, ok := result.value.(modelv1.ApplicationWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String() && reflect.DeepEqual(value, modelv1.DefaultApplicationWrite(value))
	case hierarchy.KindComponent:
		value, ok := result.value.(modelv1.ComponentWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String() && reflect.DeepEqual(value, modelv1.DefaultComponentWrite(value))
	case hierarchy.KindPolicy:
		value, ok := result.value.(modelv1.PolicyWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String() && reflect.DeepEqual(value, modelv1.DefaultPolicyWrite(value))
	case hierarchy.KindProviderConnection:
		value, ok := result.value.(modelv1.ProviderConnectionWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String() && reflect.DeepEqual(value, modelv1.DefaultProviderConnectionWrite(value))
	}
	if !valid {
		return defaultedIntent{}, reject(StageDefault, CodeDefaultFailed, "")
	}
	return result, nil
}

func convertIntent(defaulted defaultedIntent) (model.Intent, *Error) {
	var (
		intent model.Intent
		err    error
	)
	switch defaulted.kind {
	case hierarchy.KindWorkspace:
		value, ok := defaulted.value.(modelv1.WorkspaceWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		intent, err = modelv1.ToHubWorkspaceIntent(value)
	case hierarchy.KindEnvironment:
		value, ok := defaulted.value.(modelv1.EnvironmentWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		intent, err = modelv1.ToHubEnvironmentIntent(value)
	case hierarchy.KindApplication:
		value, ok := defaulted.value.(modelv1.ApplicationWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		intent, err = modelv1.ToHubApplicationIntent(value)
	case hierarchy.KindComponent:
		value, ok := defaulted.value.(modelv1.ComponentWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		intent, err = modelv1.ToHubComponentIntent(value)
	case hierarchy.KindPolicy:
		value, ok := defaulted.value.(modelv1.PolicyWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		intent, err = modelv1.ToHubPolicyIntent(value)
	case hierarchy.KindProviderConnection:
		value, ok := defaulted.value.(modelv1.ProviderConnectionWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		intent, err = modelv1.ToHubProviderConnectionIntent(value)
	default:
		err = modelv1.ErrInvalidSource
	}
	if err != nil || intent == nil {
		return nil, reject(StageConversion, CodeConversionFailed, "")
	}
	return intent, nil
}

type defaultedStatus struct {
	kind  hierarchy.Kind
	value any
}

func defaultStatus(source sourceStatus) (defaultedStatus, *Error) {
	common := modelv1.CommonStatus{
		ObservedGeneration: source.common.ObservedGeneration,
		Conditions:         condition.CloneSet(source.common.Conditions),
	}
	switch source.kind {
	case hierarchy.KindWorkspace:
		return checkedDefaultStatus(defaultedStatus{kind: source.kind, value: modelv1.WorkspaceStatusWrite{APIVersion: source.apiVersion, Kind: source.kind.String(), Status: common}})
	case hierarchy.KindEnvironment:
		return checkedDefaultStatus(defaultedStatus{kind: source.kind, value: modelv1.EnvironmentStatusWrite{APIVersion: source.apiVersion, Kind: source.kind.String(), Status: common}})
	case hierarchy.KindApplication:
		return checkedDefaultStatus(defaultedStatus{kind: source.kind, value: modelv1.ApplicationStatusWrite{APIVersion: source.apiVersion, Kind: source.kind.String(), Status: common}})
	case hierarchy.KindComponent:
		return checkedDefaultStatus(defaultedStatus{kind: source.kind, value: modelv1.ComponentStatusWrite{APIVersion: source.apiVersion, Kind: source.kind.String(), Status: common}})
	case hierarchy.KindPolicy:
		return checkedDefaultStatus(defaultedStatus{kind: source.kind, value: modelv1.PolicyStatusWrite{
			APIVersion: source.apiVersion, Kind: source.kind.String(),
			Status: modelv1.PolicyStatus{ObservedGeneration: source.common.ObservedGeneration, Conditions: condition.CloneSet(source.common.Conditions)},
		}})
	case hierarchy.KindProviderConnection:
		return checkedDefaultStatus(defaultedStatus{kind: source.kind, value: modelv1.ProviderConnectionStatusWrite{
			APIVersion: source.apiVersion, Kind: source.kind.String(),
			Status: model.CloneProviderConnectionStatus(source.provider),
		}})
	default:
		return defaultedStatus{}, reject(StageDefault, CodeDefaultFailed, "")
	}
}

func checkedDefaultStatus(result defaultedStatus) (defaultedStatus, *Error) {
	valid := false
	switch result.kind {
	case hierarchy.KindWorkspace:
		value, ok := result.value.(modelv1.WorkspaceStatusWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String()
	case hierarchy.KindEnvironment:
		value, ok := result.value.(modelv1.EnvironmentStatusWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String()
	case hierarchy.KindApplication:
		value, ok := result.value.(modelv1.ApplicationStatusWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String()
	case hierarchy.KindComponent:
		value, ok := result.value.(modelv1.ComponentStatusWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String()
	case hierarchy.KindPolicy:
		value, ok := result.value.(modelv1.PolicyStatusWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String()
	case hierarchy.KindProviderConnection:
		value, ok := result.value.(modelv1.ProviderConnectionStatusWrite)
		valid = ok && value.APIVersion == modelv1.APIVersion && value.Kind == result.kind.String()
	}
	if !valid {
		return defaultedStatus{}, reject(StageDefault, CodeDefaultFailed, "")
	}
	return result, nil
}

func convertStatus(defaulted defaultedStatus, generation int64) (model.StatusWrite, *Error) {
	var (
		status model.StatusWrite
		err    error
	)
	switch defaulted.kind {
	case hierarchy.KindWorkspace:
		value, ok := defaulted.value.(modelv1.WorkspaceStatusWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		status, err = modelv1.ToHubWorkspaceStatusWrite(value, generation)
	case hierarchy.KindEnvironment:
		value, ok := defaulted.value.(modelv1.EnvironmentStatusWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		status, err = modelv1.ToHubEnvironmentStatusWrite(value, generation)
	case hierarchy.KindApplication:
		value, ok := defaulted.value.(modelv1.ApplicationStatusWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		status, err = modelv1.ToHubApplicationStatusWrite(value, generation)
	case hierarchy.KindComponent:
		value, ok := defaulted.value.(modelv1.ComponentStatusWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		status, err = modelv1.ToHubComponentStatusWrite(value, generation)
	case hierarchy.KindPolicy:
		value, ok := defaulted.value.(modelv1.PolicyStatusWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		status, err = modelv1.ToHubPolicyStatusWrite(value, generation)
	case hierarchy.KindProviderConnection:
		value, ok := defaulted.value.(modelv1.ProviderConnectionStatusWrite)
		if !ok {
			return nil, reject(StageConversion, CodeConversionFailed, "")
		}
		status, err = modelv1.ToHubProviderConnectionStatusWrite(value, generation)
	default:
		err = modelv1.ErrInvalidSource
	}
	if err != nil || status == nil {
		return nil, reject(StageConversion, CodeConversionFailed, "")
	}
	return status, nil
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
