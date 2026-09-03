package administration

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// Grant is an immutable opaque handle to ledger-owned one-use elevation state.
// Copying this value cannot copy authority: every transition is resolved by ID
// against the originating Ledger's retained record.
type Grant struct {
	initialized     bool
	id              resource.ID
	administratorID resource.ID
	proofID         resource.ID
	action          authorization.Action
	target          Target
	reason          string
	caseReference   string
	issuedAt        time.Time
	expiresAt       time.Time
}

func validGrant(grant Grant) bool {
	if !grant.initialized || !resourceIDValid(grant.id) ||
		!resourceIDValid(grant.administratorID) || !resourceIDValid(grant.proofID) ||
		!validActionTarget(grant.action, grant.target) ||
		!validBoundedText(grant.reason, 1, MaxReasonRunes) ||
		(grant.caseReference != "" &&
			!validBoundedText(grant.caseReference, 1, MaxCaseReferenceRunes)) ||
		!canonicalContractTime(grant.issuedAt) || !canonicalContractTime(grant.expiresAt) ||
		!grant.expiresAt.After(grant.issuedAt) {
		return false
	}
	duration := grant.expiresAt.Sub(grant.issuedAt)
	return duration <= MaxElevationDuration && duration%timestampResolution == 0
}

func equalGrant(left, right Grant) bool {
	return validGrant(left) && validGrant(right) && left.id == right.id &&
		left.administratorID == right.administratorID && left.proofID == right.proofID &&
		left.action == right.action && equalTarget(left.target, right.target) &&
		left.reason == right.reason && left.caseReference == right.caseReference &&
		left.issuedAt.Equal(right.issuedAt) && left.expiresAt.Equal(right.expiresAt)
}

func cloneGrant(grant Grant) Grant {
	grant.target = cloneTarget(grant.target)
	return grant
}

func (grant Grant) ID() resource.ID              { return grant.id }
func (grant Grant) AdministratorID() resource.ID { return grant.administratorID }
func (grant Grant) Action() authorization.Action { return grant.action }
func (grant Grant) Target() Target               { return cloneTarget(grant.target) }
func (grant Grant) Reason() string               { return grant.reason }
func (grant Grant) IssuedAt() time.Time          { return grant.issuedAt }
func (grant Grant) ExpiresAt() time.Time         { return grant.expiresAt }
func (grant Grant) CaseReference() (string, bool) {
	return grant.caseReference, grant.caseReference != ""
}

func (grant Grant) String() string {
	if !validGrant(grant) {
		return "elevation-grant(invalid)"
	}
	return "elevation-grant(identity=redacted,scope=redacted,reason=redacted)"
}

func (grant Grant) GoString() string { return grant.String() }
func (grant Grant) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, grant.String())
}
func (grant Grant) LogValue() slog.Value     { return redactedLogValue(grant.String()) }
func (Grant) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Grant) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Grant) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Grant) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

// ConsumptionReceipt is immutable evidence of the one successful use of a
// grant. Audit owns any durable representation derived from these accessors.
type ConsumptionReceipt struct {
	initialized bool
	grant       Grant
	consumedAt  time.Time
}

func validConsumptionReceipt(receipt ConsumptionReceipt) bool {
	return receipt.initialized && validGrant(receipt.grant) &&
		canonicalContractTime(receipt.consumedAt) &&
		!receipt.consumedAt.Before(receipt.grant.issuedAt) &&
		receipt.consumedAt.Before(receipt.grant.expiresAt)
}

func (receipt ConsumptionReceipt) GrantID() resource.ID         { return receipt.grant.id }
func (receipt ConsumptionReceipt) AdministratorID() resource.ID { return receipt.grant.administratorID }
func (receipt ConsumptionReceipt) Action() authorization.Action { return receipt.grant.action }
func (receipt ConsumptionReceipt) Target() Target               { return cloneTarget(receipt.grant.target) }
func (receipt ConsumptionReceipt) Reason() string               { return receipt.grant.reason }
func (receipt ConsumptionReceipt) IssuedAt() time.Time          { return receipt.grant.issuedAt }
func (receipt ConsumptionReceipt) ExpiresAt() time.Time         { return receipt.grant.expiresAt }
func (receipt ConsumptionReceipt) ConsumedAt() time.Time        { return receipt.consumedAt }
func (receipt ConsumptionReceipt) CaseReference() (string, bool) {
	return receipt.grant.caseReference, receipt.grant.caseReference != ""
}

func (receipt ConsumptionReceipt) String() string {
	if !validConsumptionReceipt(receipt) {
		return "elevation-consumption-receipt(invalid)"
	}
	return "elevation-consumption-receipt(identity=redacted,scope=redacted)"
}

func (receipt ConsumptionReceipt) GoString() string { return receipt.String() }
func (receipt ConsumptionReceipt) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, receipt.String())
}
func (receipt ConsumptionReceipt) LogValue() slog.Value   { return redactedLogValue(receipt.String()) }
func (ConsumptionReceipt) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ConsumptionReceipt) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ConsumptionReceipt) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (ConsumptionReceipt) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

// RevocationReceipt is immutable evidence that an active grant was made
// permanently unusable before its expiry.
type RevocationReceipt struct {
	initialized bool
	grant       Grant
	revokedAt   time.Time
}

func validRevocationReceipt(receipt RevocationReceipt) bool {
	return receipt.initialized && validGrant(receipt.grant) &&
		canonicalContractTime(receipt.revokedAt) &&
		!receipt.revokedAt.Before(receipt.grant.issuedAt) &&
		receipt.revokedAt.Before(receipt.grant.expiresAt)
}

func (receipt RevocationReceipt) GrantID() resource.ID         { return receipt.grant.id }
func (receipt RevocationReceipt) AdministratorID() resource.ID { return receipt.grant.administratorID }
func (receipt RevocationReceipt) Action() authorization.Action { return receipt.grant.action }
func (receipt RevocationReceipt) Target() Target               { return cloneTarget(receipt.grant.target) }
func (receipt RevocationReceipt) Reason() string               { return receipt.grant.reason }
func (receipt RevocationReceipt) IssuedAt() time.Time          { return receipt.grant.issuedAt }
func (receipt RevocationReceipt) ExpiresAt() time.Time         { return receipt.grant.expiresAt }
func (receipt RevocationReceipt) RevokedAt() time.Time         { return receipt.revokedAt }
func (receipt RevocationReceipt) CaseReference() (string, bool) {
	return receipt.grant.caseReference, receipt.grant.caseReference != ""
}

func (receipt RevocationReceipt) String() string {
	if !validRevocationReceipt(receipt) {
		return "elevation-revocation-receipt(invalid)"
	}
	return "elevation-revocation-receipt(identity=redacted,scope=redacted)"
}

func (receipt RevocationReceipt) GoString() string { return receipt.String() }
func (receipt RevocationReceipt) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, receipt.String())
}
func (receipt RevocationReceipt) LogValue() slog.Value   { return redactedLogValue(receipt.String()) }
func (RevocationReceipt) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (RevocationReceipt) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (RevocationReceipt) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (RevocationReceipt) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
