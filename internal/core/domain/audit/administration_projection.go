package audit

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/domain/administration"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// ElevationRefFromGrant projects either the issuance or natural expiry of an
// immutable administration grant. Consumed and Revoked require their receipts.
func ElevationRefFromGrant(grant administration.Grant, state ElevationState) (ElevationRef, error) {
	var recordedAt time.Time
	switch state {
	case ElevationStateIssued:
		recordedAt = grant.IssuedAt()
	case ElevationStateExpired:
		recordedAt = grant.ExpiresAt()
	default:
		return ElevationRef{}, fmt.Errorf("%w: grant state requires receipt", ErrInvalidReference)
	}
	caseReference, _ := grant.CaseReference()
	return newElevationRef(
		grant.ID(),
		grant.AdministratorID(),
		grant.Action(),
		grant.Target(),
		grant.Reason(),
		caseReference,
		grant.IssuedAt(),
		grant.ExpiresAt(),
		state,
		recordedAt,
	)
}

func ElevationRefFromConsumption(receipt administration.ConsumptionReceipt) (ElevationRef, error) {
	caseReference, _ := receipt.CaseReference()
	return newElevationRef(
		receipt.GrantID(),
		receipt.AdministratorID(),
		receipt.Action(),
		receipt.Target(),
		receipt.Reason(),
		caseReference,
		receipt.IssuedAt(),
		receipt.ExpiresAt(),
		ElevationStateConsumed,
		receipt.ConsumedAt(),
	)
}

func ElevationRefFromRevocation(receipt administration.RevocationReceipt) (ElevationRef, error) {
	caseReference, _ := receipt.CaseReference()
	return newElevationRef(
		receipt.GrantID(),
		receipt.AdministratorID(),
		receipt.Action(),
		receipt.Target(),
		receipt.Reason(),
		caseReference,
		receipt.IssuedAt(),
		receipt.ExpiresAt(),
		ElevationStateRevoked,
		receipt.RevokedAt(),
	)
}

func (reference ElevationRef) String() string {
	if validateElevationRef(reference) != nil {
		return "audit-elevation(invalid)"
	}
	return "audit-elevation(state=" + reference.state.String() + ",identity=redacted,scope=redacted,reason=redacted)"
}

func (reference ElevationRef) GoString() string { return reference.String() }
func (reference ElevationRef) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, reference.String())
}
func (reference ElevationRef) LogValue() slog.Value { return slog.StringValue(reference.String()) }

func newElevationRef(
	grantID resource.ID,
	administratorID resource.ID,
	action authorization.Action,
	target administration.Target,
	reason string,
	caseReference string,
	issuedAt time.Time,
	expiresAt time.Time,
	state ElevationState,
	recordedAt time.Time,
) (ElevationRef, error) {
	if administration.ValidateTarget(target) != nil || !validElevationAction(action, target.Kind()) ||
		!validElevationText(reason, 1, administration.MaxReasonRunes) ||
		(caseReference != "" && !validElevationText(caseReference, 1, administration.MaxCaseReferenceRunes)) {
		return ElevationRef{}, ErrInvalidReference
	}
	issued, err := normalizeTimestamp(issuedAt)
	if err != nil {
		return ElevationRef{}, ErrInvalidReference
	}
	expires, err := normalizeTimestamp(expiresAt)
	if err != nil {
		return ElevationRef{}, ErrInvalidReference
	}
	recorded, err := normalizeTimestamp(recordedAt)
	if err != nil {
		return ElevationRef{}, ErrInvalidReference
	}
	reference := ElevationRef{
		initialized:     true,
		grantID:         grantID,
		administratorID: administratorID,
		action:          action,
		targetKind:      target.Kind().String(),
		reason:          reason,
		caseReference:   caseReference,
		issuedAt:        issued,
		expiresAt:       expires,
		state:           state,
		recordedAt:      recorded,
	}
	if id, present := target.WorkspaceID(); present {
		reference.workspaceID = idPointer(id)
	}
	if id, present := target.ObjectID(); present {
		reference.objectID = idPointer(id)
	}
	if id, present := target.ResourceID(); present {
		reference.resourceID = idPointer(id)
	}
	if id, present := target.EnvironmentID(); present {
		reference.environmentID = idPointer(id)
	}
	if id, present := target.ProviderConnectionID(); present {
		reference.providerConnectionID = idPointer(id)
	}
	if err := validateElevationRef(reference); err != nil {
		return ElevationRef{}, err
	}
	return reference, nil
}

func validElevationAction(action authorization.Action, kind administration.TargetKind) bool {
	valid := false
	for _, candidate := range administration.EligibleActions() {
		valid = valid || action == candidate
	}
	if !valid {
		return false
	}
	switch action {
	case authorization.ActionAuditExport:
		return kind == administration.TargetKindPlatformAudit || kind == administration.TargetKindWorkspaceAudit
	case authorization.ActionOperationQuarantine, authorization.ActionWorkRedrive:
		return kind == administration.TargetKindOperation
	default:
		return false
	}
}

func validElevationActionReference(reference ElevationRef) bool {
	switch reference.action {
	case authorization.ActionAuditExport:
		return reference.targetKind == administration.TargetKindPlatformAudit.String() ||
			reference.targetKind == administration.TargetKindWorkspaceAudit.String()
	case authorization.ActionOperationQuarantine, authorization.ActionWorkRedrive:
		return reference.targetKind == administration.TargetKindOperation.String()
	default:
		return false
	}
}

func validElevationTargetShape(reference ElevationRef) bool {
	switch reference.targetKind {
	case "PlatformAudit":
		return reference.objectID == nil && reference.workspaceID == nil && reference.resourceID == nil &&
			reference.environmentID == nil && reference.providerConnectionID == nil
	case "WorkspaceAudit":
		return reference.objectID != nil && reference.workspaceID != nil && reference.resourceID != nil &&
			reference.environmentID == nil && reference.providerConnectionID == nil &&
			*reference.objectID == *reference.workspaceID && *reference.resourceID == *reference.workspaceID
	case "Operation":
		return reference.objectID != nil && reference.workspaceID != nil && reference.resourceID != nil &&
			(reference.environmentID == nil) == (reference.providerConnectionID == nil)
	default:
		return false
	}
}

func validElevationReason(value string) bool {
	return validElevationText(value, 1, administration.MaxReasonRunes)
}

func validElevationCaseReference(value string) bool {
	return validElevationText(value, 1, administration.MaxCaseReferenceRunes)
}

func validElevationPeriod(issuedAt, expiresAt time.Time) bool {
	return expiresAt.After(issuedAt) && expiresAt.Sub(issuedAt) <= administration.MaxElevationDuration &&
		expiresAt.Sub(issuedAt)%time.Millisecond == 0
}

func validElevationText(value string, minimum, maximum int) bool {
	if len(value) > maximum*utf8.UTFMax || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return false
	}
	for _, current := range value {
		if unicode.IsControl(current) {
			return false
		}
	}
	return true
}
