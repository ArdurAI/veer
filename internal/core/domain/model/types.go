// Package model defines Veer's version-independent admitted resource models.
// Transport versions convert into these values before a service constructs or
// changes a resource envelope.
package model

import (
	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// WorkspaceSpec is the canonical admitted Workspace intent. Source versions
// may make fields optional, but the hub always contains explicit defaults.
type WorkspaceSpec struct {
	SuspendReconciliation bool `json:"suspendReconciliation"`
}

// EnvironmentSpec remains closed until its owning roadmap issue adopts fields.
type EnvironmentSpec struct{}

// ApplicationSpec remains closed until its owning roadmap issue adopts fields.
type ApplicationSpec struct{}

// ComponentSpec remains closed until its owning roadmap issue adopts fields.
type ComponentSpec struct{}

// CommonStatus is the shared observed-state shape for Workspace, Environment,
// Application, and Component resources.
type CommonStatus struct {
	ObservedGeneration int64                 `json:"observedGeneration"`
	Conditions         []condition.Condition `json:"conditions"`
}

// ObservedGenerations returns an independent collection containing the outer
// observation followed by every condition observation.
func (status CommonStatus) ObservedGenerations() []int64 {
	result := make([]int64, 1, len(status.Conditions)+1)
	result[0] = status.ObservedGeneration
	for _, value := range status.Conditions {
		result = append(result, value.ObservedGeneration)
	}
	return result
}

type (
	// The four workload resource statuses intentionally share one hub shape.
	WorkspaceStatus   = CommonStatus
	EnvironmentStatus = CommonStatus
	ApplicationStatus = CommonStatus
	ComponentStatus   = CommonStatus

	// Control-resource aliases preserve the contracts implemented by the
	// control package while presenting one complete six-kind model package.
	PolicySpec               = control.PolicySpec
	PolicyStatus             = control.PolicyStatus
	ProviderConnectionSpec   = control.ProviderConnectionSpec
	ProviderConnectionStatus = control.ProviderConnectionStatus
	CredentialReference      = control.CredentialReference
	CapabilityState          = control.CapabilityState
	ProviderCapability       = control.ProviderCapability
	QuotaState               = control.QuotaState
	QuotaCheck               = control.QuotaCheck
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

var (
	_ resource.GenerationObservations = CommonStatus{}
	_ resource.GenerationObservations = PolicyStatus{}
	_ resource.GenerationObservations = ProviderConnectionStatus{}
)
