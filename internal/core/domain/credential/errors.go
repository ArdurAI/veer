// Package credential defines Veer's provider-credential request and material
// safety contract. It performs no secret-store or provider I/O.
package credential

import "errors"

var (
	// ErrInvalidRecipient marks an adapter recipient outside the bounded,
	// provider-specific registration vocabulary.
	ErrInvalidRecipient = errors.New("invalid credential recipient")
	// ErrInvalidResourceView marks a target projection that was not derived
	// from a valid immutable resource envelope.
	ErrInvalidResourceView = errors.New("invalid credential resource view")
	// ErrInvalidRequest marks a forged, stale, or incomplete credential request.
	ErrInvalidRequest = errors.New("invalid credential request")
	// ErrConnectionNotRetained means the supplied ProviderConnection envelope
	// is not the exact connection retained by the hierarchy snapshot.
	ErrConnectionNotRetained = errors.New("provider connection is not retained")
	// ErrTargetNotRetained means the supplied target view is not the exact
	// resource retained by the hierarchy snapshot.
	ErrTargetNotRetained = errors.New("credential target is not retained")
	// ErrScopeMismatch marks any Workspace, Environment, connection, target, or
	// recipient disagreement at the credential boundary.
	ErrScopeMismatch = errors.New("credential request scope does not match")
	// ErrTargetGenerationMismatch prevents an Operation from authorizing a
	// different desired-state generation of its target.
	ErrTargetGenerationMismatch = errors.New("credential target generation does not match")
	// ErrOperationNotRunning prevents authority from being minted before or
	// after the exact provider-effect phase.
	ErrOperationNotRunning = errors.New("credential operation is not running")
	// ErrUnsupportedProviderAction rejects non-provider and broker-internal
	// authorization actions as provider-session purposes.
	ErrUnsupportedProviderAction = errors.New("unsupported credential provider action")
	// ErrInvalidDigest marks a zero, forged, or inconsistent binding digest.
	ErrInvalidDigest = errors.New("invalid credential binding digest")
	// ErrInvalidMaterial marks empty or over-limit credential material.
	ErrInvalidMaterial = errors.New("invalid credential material")
	// ErrInvalidMaterialCallback rejects a nil raw-material consumer.
	ErrInvalidMaterialCallback = errors.New("invalid credential material callback")
	// ErrMaterialDestroyed marks access after best-effort material destruction.
	ErrMaterialDestroyed = errors.New("credential material is destroyed")
	// ErrInvalidIssuedSession marks a malformed or unbound provider session.
	ErrInvalidIssuedSession = errors.New("invalid issued credential session")
	// ErrInvalidSessionLifetime marks a provider session outside the alpha
	// issuance bounds.
	ErrInvalidSessionLifetime = errors.New("invalid issued credential session lifetime")
	// ErrSerializationForbidden prevents capability-bearing values and raw
	// material from entering resources, queues, fixtures, or telemetry.
	ErrSerializationForbidden = errors.New("credential serialization forbidden")
)
