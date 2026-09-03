// Package v1alpha1 defines Veer's first versioned admission source models and
// their conversion boundary to the unversioned domain hub.
package v1alpha1

import (
	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
)

// APIVersion is the only source representation served by this package.
const APIVersion = hierarchy.APIVersion

// WriteMetadata contains only caller-owned metadata fields.
type WriteMetadata struct {
	DisplayName string            `json:"displayName"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// DesiredWrite is the versioned source envelope shared by create and complete
// desired-state replacement. The schema stage establishes exact field names;
// conversion still checks version and kind defensively.
type DesiredWrite[Spec any] struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Metadata   WriteMetadata `json:"metadata"`
	Spec       Spec          `json:"spec"`
}

// ObservedWrite is the versioned source envelope for status replacement.
type ObservedWrite[Status any] struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     Status `json:"status"`
}

// WorkspaceWriteSpec preserves source presence so admission can distinguish
// omission (default false) from an explicit value. Schema validation must
// reject JSON null before typed decoding because both null and omission decode
// to nil through an ordinary pointer.
type WorkspaceWriteSpec struct {
	SuspendReconciliation *bool `json:"suspendReconciliation,omitempty"`
}

// EnvironmentSpec is the closed v1alpha1 Environment desired-state shape.
type EnvironmentSpec struct{}

// ApplicationSpec is the closed v1alpha1 Application desired-state shape.
type ApplicationSpec struct{}

// ComponentSpec is the closed v1alpha1 Component desired-state shape.
type ComponentSpec struct{}

// CommonStatus is the v1alpha1 wire form shared by four workload resources.
type CommonStatus struct {
	ObservedGeneration int64                 `json:"observedGeneration"`
	Conditions         []condition.Condition `json:"conditions"`
}

type (
	WorkspaceStatus   = CommonStatus
	EnvironmentStatus = CommonStatus
	ApplicationStatus = CommonStatus
	ComponentStatus   = CommonStatus

	// Existing control types are themselves the reviewed v1alpha1 contract.
	PolicySpec               = control.PolicySpec
	PolicyStatus             = control.PolicyStatus
	ProviderConnectionSpec   = control.ProviderConnectionSpec
	ProviderConnectionStatus = control.ProviderConnectionStatus
	CredentialReference      = control.CredentialReference
	CapabilityState          = control.CapabilityState
	ProviderCapability       = control.ProviderCapability
	QuotaState               = control.QuotaState
	QuotaCheck               = control.QuotaCheck

	WorkspaceWrite          = DesiredWrite[WorkspaceWriteSpec]
	EnvironmentWrite        = DesiredWrite[EnvironmentSpec]
	ApplicationWrite        = DesiredWrite[ApplicationSpec]
	ComponentWrite          = DesiredWrite[ComponentSpec]
	PolicyWrite             = DesiredWrite[PolicySpec]
	ProviderConnectionWrite = DesiredWrite[ProviderConnectionSpec]

	WorkspaceStatusWrite          = ObservedWrite[WorkspaceStatus]
	EnvironmentStatusWrite        = ObservedWrite[EnvironmentStatus]
	ApplicationStatusWrite        = ObservedWrite[ApplicationStatus]
	ComponentStatusWrite          = ObservedWrite[ComponentStatus]
	PolicyStatusWrite             = ObservedWrite[PolicyStatus]
	ProviderConnectionStatusWrite = ObservedWrite[ProviderConnectionStatus]
)

const (
	// MaxProviderCapabilities is the retained per-connection capability limit.
	MaxProviderCapabilities = control.MaxProviderCapabilities
	// MaxQuotaChecks is the retained per-connection quota-check limit.
	MaxQuotaChecks = control.MaxQuotaChecks

	CapabilitySupported   = control.CapabilitySupported
	CapabilityUnsupported = control.CapabilityUnsupported
	CapabilityUnknown     = control.CapabilityUnknown

	QuotaWithinLimit = control.QuotaWithinLimit
	QuotaExceeded    = control.QuotaExceeded
	QuotaUnknown     = control.QuotaUnknown
)
