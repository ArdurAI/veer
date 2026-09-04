package reconciliation

import (
	"fmt"
	"log/slog"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// ProviderBinding is the exact versioned ProviderConnection and credential
// reference basis used by one plan. It contains no secret material.
type ProviderBinding struct {
	initialized               bool
	connectionID              resource.ID
	connectionGeneration      int64
	connectionResourceVersion string
	connectionEvidence        Evidence
	credentialReferenceID     resource.ID
	credentialGeneration      int64
	credentialResourceVersion string
	credentialEvidence        Evidence
}

// ProviderBindingInput supplies the retained provider and credential revisions.
type ProviderBindingInput struct {
	ConnectionID              resource.ID
	ConnectionGeneration      int64
	ConnectionResourceVersion string
	ConnectionEvidence        Evidence
	CredentialReferenceID     resource.ID
	CredentialGeneration      int64
	CredentialResourceVersion string
	CredentialEvidence        Evidence
}

// NewProviderBinding validates and seals one non-secret provider basis.
func NewProviderBinding(input ProviderBindingInput) (ProviderBinding, error) {
	value := ProviderBinding{
		initialized:               true,
		connectionID:              input.ConnectionID,
		connectionGeneration:      input.ConnectionGeneration,
		connectionResourceVersion: input.ConnectionResourceVersion,
		connectionEvidence:        input.ConnectionEvidence,
		credentialReferenceID:     input.CredentialReferenceID,
		credentialGeneration:      input.CredentialGeneration,
		credentialResourceVersion: input.CredentialResourceVersion,
		credentialEvidence:        input.CredentialEvidence,
	}
	if err := ValidateProviderBinding(value); err != nil {
		return ProviderBinding{}, err
	}
	return value, nil
}

// ValidateProviderBinding checks exact IDs, generations, versions, and evidence kinds.
func ValidateProviderBinding(value ProviderBinding) error {
	if !value.initialized || !validID(value.connectionID) || !validID(value.credentialReferenceID) ||
		value.connectionGeneration < 1 || value.credentialGeneration < 1 ||
		!validVersion(value.connectionResourceVersion) || !validVersion(value.credentialResourceVersion) {
		return ErrPlanMismatch
	}
	if ValidateEvidence(value.connectionEvidence) != nil ||
		value.connectionEvidence.kind != EvidenceProviderConnection ||
		value.connectionEvidence.version != value.connectionResourceVersion {
		return ErrPlanMismatch
	}
	if ValidateEvidence(value.credentialEvidence) != nil ||
		value.credentialEvidence.kind != EvidenceCredentialReference ||
		value.credentialEvidence.version != value.credentialResourceVersion {
		return ErrPlanMismatch
	}
	return nil
}

func (value ProviderBinding) ConnectionID() resource.ID   { return value.connectionID }
func (value ProviderBinding) ConnectionGeneration() int64 { return value.connectionGeneration }
func (value ProviderBinding) ConnectionResourceVersion() string {
	return value.connectionResourceVersion
}
func (value ProviderBinding) ConnectionEvidence() Evidence { return value.connectionEvidence }
func (value ProviderBinding) CredentialReferenceID() resource.ID {
	return value.credentialReferenceID
}
func (value ProviderBinding) CredentialGeneration() int64 { return value.credentialGeneration }
func (value ProviderBinding) CredentialResourceVersion() string {
	return value.credentialResourceVersion
}
func (value ProviderBinding) CredentialEvidence() Evidence { return value.credentialEvidence }

// Equal compares the exact non-secret provider and credential basis.
func (value ProviderBinding) Equal(other ProviderBinding) bool {
	return ValidateProviderBinding(value) == nil && ValidateProviderBinding(other) == nil &&
		value.connectionID == other.connectionID &&
		value.connectionGeneration == other.connectionGeneration &&
		value.connectionResourceVersion == other.connectionResourceVersion &&
		value.connectionEvidence.Equal(other.connectionEvidence) &&
		value.credentialReferenceID == other.credentialReferenceID &&
		value.credentialGeneration == other.credentialGeneration &&
		value.credentialResourceVersion == other.credentialResourceVersion &&
		value.credentialEvidence.Equal(other.credentialEvidence)
}

func (value ProviderBinding) String() string {
	if ValidateProviderBinding(value) != nil {
		return "reconciliation-provider-binding(invalid)"
	}
	return "reconciliation-provider-binding(ids=redacted,versions=redacted,evidence=redacted)"
}
func (value ProviderBinding) GoString() string { return value.String() }
func (value ProviderBinding) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value ProviderBinding) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (ProviderBinding) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ProviderBinding) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ProviderBinding) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (ProviderBinding) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
