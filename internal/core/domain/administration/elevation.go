package administration

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// ElevationRequest is one immutable, strong-authentication challenge. It
// binds the exact configured administrator identity, one eligible action, one
// sealed target, the required reason, optional case reference, and requested
// lifetime before verification occurs.
type ElevationRequest struct {
	initialized   bool
	grantID       resource.ID
	administrator Administrator
	principal     identity.Principal
	action        authorization.Action
	target        Target
	reason        string
	caseReference string
	requestedAt   time.Time
	duration      time.Duration
}

// NewElevationRequest constructs a single-action elevation challenge. The
// supplied time is normalized to UTC millisecond precision.
func NewElevationRequest(
	grantID resource.ID,
	administrator Administrator,
	principal identity.Principal,
	action authorization.Action,
	target Target,
	reason string,
	caseReference string,
	requestedAt time.Time,
	duration time.Duration,
) (ElevationRequest, error) {
	normalized, err := normalizeContractTime(requestedAt)
	if err != nil {
		return ElevationRequest{}, fmt.Errorf("%w: %w", ErrInvalidElevationRequest, err)
	}
	request := ElevationRequest{
		initialized:   true,
		grantID:       grantID,
		administrator: administrator,
		principal:     identity.ClonePrincipal(principal),
		action:        action,
		target:        cloneTarget(target),
		reason:        reason,
		caseReference: caseReference,
		requestedAt:   normalized,
		duration:      duration,
	}
	if err := ValidateElevationRequest(request); err != nil {
		return ElevationRequest{}, err
	}
	return request, nil
}

// ValidateElevationRequest checks a complete challenge without exposing its
// identity claims, IDs, reason, or case reference in the error chain.
func ValidateElevationRequest(request ElevationRequest) error {
	if !request.initialized {
		return ErrInvalidElevationRequest
	}
	if _, err := resource.ParseID(request.grantID.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidElevationRequest, ErrInvalidGrantID)
	}
	if ValidateAdministrator(request.administrator) != nil {
		return fmt.Errorf("%w: %w", ErrInvalidElevationRequest, ErrInvalidAdministrator)
	}
	if identity.ValidatePrincipal(request.principal) != nil ||
		!request.administrator.MatchesPrincipal(request.principal) {
		return fmt.Errorf("%w: %w", ErrInvalidElevationRequest, ErrIdentityMismatch)
	}
	if !validAction(request.action) {
		return fmt.Errorf("%w: %w", ErrInvalidElevationRequest, ErrInvalidAction)
	}
	if ValidateTarget(request.target) != nil {
		return fmt.Errorf("%w: %w", ErrInvalidElevationRequest, ErrInvalidTarget)
	}
	if !validActionTarget(request.action, request.target) {
		return fmt.Errorf("%w: %w", ErrInvalidElevationRequest, ErrActionTargetMismatch)
	}
	if !validBoundedText(request.reason, 1, MaxReasonRunes) {
		return fmt.Errorf("%w: %w", ErrInvalidElevationRequest, ErrInvalidReason)
	}
	if request.caseReference != "" &&
		!validBoundedText(request.caseReference, 1, MaxCaseReferenceRunes) {
		return fmt.Errorf("%w: %w", ErrInvalidElevationRequest, ErrInvalidCaseReference)
	}
	if !canonicalContractTime(request.requestedAt) {
		return fmt.Errorf("%w: %w", ErrInvalidElevationRequest, ErrInvalidClock)
	}
	if request.duration <= 0 || request.duration > MaxElevationDuration ||
		request.duration%timestampResolution != 0 {
		return fmt.Errorf("%w: %w", ErrInvalidElevationRequest, ErrInvalidElevationDuration)
	}
	return nil
}

func cloneElevationRequest(request ElevationRequest) ElevationRequest {
	request.principal = identity.ClonePrincipal(request.principal)
	request.target = cloneTarget(request.target)
	return request
}

func (request ElevationRequest) ID() resource.ID              { return request.grantID }
func (request ElevationRequest) AdministratorID() resource.ID { return request.administrator.ID() }
func (request ElevationRequest) Principal() identity.Principal {
	return identity.ClonePrincipal(request.principal)
}
func (request ElevationRequest) Action() authorization.Action { return request.action }
func (request ElevationRequest) Target() Target               { return cloneTarget(request.target) }
func (request ElevationRequest) Reason() string               { return request.reason }
func (request ElevationRequest) RequestedAt() time.Time       { return request.requestedAt }
func (request ElevationRequest) Duration() time.Duration      { return request.duration }
func (request ElevationRequest) CaseReference() (string, bool) {
	return request.caseReference, request.caseReference != ""
}

func (request ElevationRequest) String() string {
	if ValidateElevationRequest(request) != nil {
		return "elevation-request(invalid)"
	}
	return "elevation-request(identity=redacted,scope=redacted,reason=redacted)"
}

func (request ElevationRequest) GoString() string { return request.String() }
func (request ElevationRequest) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, request.String())
}
func (request ElevationRequest) LogValue() slog.Value   { return redactedLogValue(request.String()) }
func (ElevationRequest) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ElevationRequest) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ElevationRequest) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (ElevationRequest) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

// StrongAuthReceipt is immutable evidence produced only after an external
// StrongAuthenticationVerifier has validated the exact principal and its
// configured auth_time/acr/amr policy. Principal alone cannot establish this
// result.
type StrongAuthReceipt struct {
	initialized     bool
	proofID         resource.ID
	request         ElevationRequest
	authenticatedAt time.Time
	verifiedAt      time.Time
}

// NewStrongAuthReceipt constructs verifier output. Both times normalize to
// UTC milliseconds; verification cannot precede the request or authentication
// instant, and the proof age cannot exceed MaxStrongAuthProofAge.
func NewStrongAuthReceipt(
	proofID resource.ID,
	request ElevationRequest,
	authenticatedAt time.Time,
	verifiedAt time.Time,
) (StrongAuthReceipt, error) {
	if ValidateElevationRequest(request) != nil {
		return StrongAuthReceipt{}, fmt.Errorf("%w: request", ErrInvalidStrongAuthReceipt)
	}
	if _, err := resource.ParseID(proofID.String()); err != nil {
		return StrongAuthReceipt{}, fmt.Errorf("%w: %w", ErrInvalidStrongAuthReceipt, ErrInvalidStrongAuthProofID)
	}
	normalizedAuthenticated, err := normalizeContractTime(authenticatedAt)
	if err != nil {
		return StrongAuthReceipt{}, fmt.Errorf("%w: %w", ErrInvalidStrongAuthReceipt, ErrInvalidClock)
	}
	normalizedVerified, err := normalizeContractTime(verifiedAt)
	if err != nil {
		return StrongAuthReceipt{}, fmt.Errorf("%w: %w", ErrInvalidStrongAuthReceipt, ErrInvalidClock)
	}
	if normalizedVerified.Before(request.requestedAt) || normalizedVerified.Before(normalizedAuthenticated) {
		return StrongAuthReceipt{}, fmt.Errorf("%w: %w", ErrInvalidStrongAuthReceipt, ErrClockRegressed)
	}
	if normalizedVerified.Sub(normalizedAuthenticated) > MaxStrongAuthProofAge {
		return StrongAuthReceipt{}, fmt.Errorf("%w: %w", ErrInvalidStrongAuthReceipt, ErrStrongAuthProofStale)
	}
	receipt := StrongAuthReceipt{
		initialized:     true,
		proofID:         proofID,
		request:         cloneElevationRequest(request),
		authenticatedAt: normalizedAuthenticated,
		verifiedAt:      normalizedVerified,
	}
	if !validStrongAuthReceipt(receipt) {
		return StrongAuthReceipt{}, ErrInvalidStrongAuthReceipt
	}
	return receipt, nil
}

func validStrongAuthReceipt(receipt StrongAuthReceipt) bool {
	return receipt.initialized &&
		resourceIDValid(receipt.proofID) &&
		ValidateElevationRequest(receipt.request) == nil &&
		canonicalContractTime(receipt.authenticatedAt) && canonicalContractTime(receipt.verifiedAt) &&
		!receipt.verifiedAt.Before(receipt.request.requestedAt) &&
		!receipt.verifiedAt.Before(receipt.authenticatedAt) &&
		receipt.verifiedAt.Sub(receipt.authenticatedAt) <= MaxStrongAuthProofAge
}

func (receipt StrongAuthReceipt) ProofID() resource.ID { return receipt.proofID }
func (receipt StrongAuthReceipt) Request() ElevationRequest {
	return cloneElevationRequest(receipt.request)
}
func (receipt StrongAuthReceipt) AuthenticatedAt() time.Time { return receipt.authenticatedAt }
func (receipt StrongAuthReceipt) VerifiedAt() time.Time      { return receipt.verifiedAt }

func (receipt StrongAuthReceipt) String() string {
	if !validStrongAuthReceipt(receipt) {
		return "strong-authentication-receipt(invalid)"
	}
	return "strong-authentication-receipt(identity=redacted,proof=redacted)"
}

func (receipt StrongAuthReceipt) GoString() string { return receipt.String() }
func (receipt StrongAuthReceipt) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, receipt.String())
}
func (receipt StrongAuthReceipt) LogValue() slog.Value   { return redactedLogValue(receipt.String()) }
func (StrongAuthReceipt) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (StrongAuthReceipt) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (StrongAuthReceipt) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (StrongAuthReceipt) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

func resourceIDValid(id resource.ID) bool {
	_, err := resource.ParseID(id.String())
	return err == nil
}
