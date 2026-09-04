package administration

import (
	"slices"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
)

const (
	// ContractVersion binds the administrator identity, eligible action,
	// sealed target, strong-authentication, clock, and one-use grant rules.
	ContractVersion = "veer.administration.v1alpha1"

	// MaxAdministrators bounds the process-local configured administrator set.
	MaxAdministrators = 64
	// MaxTrackedElevations bounds active grants and retained terminal tombstones.
	MaxTrackedElevations = 1_000
	// MaxReasonRunes bounds the required human explanation.
	MaxReasonRunes = 256
	// MaxCaseReferenceRunes bounds the optional external incident or change key.
	MaxCaseReferenceRunes = 128

	// MaxStrongAuthProofAge is the oldest authentication instant accepted at
	// verification and rechecked when a grant is issued.
	MaxStrongAuthProofAge = 5 * time.Minute
	// MaxElevationDuration is the absolute requested lifetime ceiling. Grants
	// cannot be renewed.
	MaxElevationDuration = 15 * time.Minute
)

var eligibleActions = []authorization.Action{
	authorization.ActionAuditExport,
	authorization.ActionOperationQuarantine,
	authorization.ActionWorkRedrive,
}

// EligibleActions returns the complete initial human-elevatable action set in
// canonical order. Workspace roles and PolicySpec cannot add to this set.
func EligibleActions() []authorization.Action { return slices.Clone(eligibleActions) }

func validAction(action authorization.Action) bool {
	for _, candidate := range eligibleActions {
		if action == candidate {
			return true
		}
	}
	return false
}

// TargetKind is one closed privileged target classification.
type TargetKind string

const (
	TargetKindPlatformAudit  TargetKind = "PlatformAudit"
	TargetKindWorkspaceAudit TargetKind = "WorkspaceAudit"
	TargetKindOperation      TargetKind = "Operation"
)

// String returns the closed target-kind spelling.
func (kind TargetKind) String() string {
	if !validTargetKind(kind) {
		return "Invalid"
	}
	return string(kind)
}

// GoString prevents invalid underlying values from entering diagnostics.
func (kind TargetKind) GoString() string {
	return "administration.TargetKind(" + kind.String() + ")"
}

func validTargetKind(kind TargetKind) bool {
	return kind == TargetKindPlatformAudit || kind == TargetKindWorkspaceAudit || kind == TargetKindOperation
}

// GrantState is one irreversible ledger-owned lifecycle state.
type GrantState uint8

const (
	GrantStateActive GrantState = iota + 1
	GrantStateConsumed
	GrantStateRevoked
	GrantStateExpired
)

// String returns a closed, non-sensitive lifecycle spelling.
func (state GrantState) String() string {
	switch state {
	case GrantStateActive:
		return "Active"
	case GrantStateConsumed:
		return "Consumed"
	case GrantStateRevoked:
		return "Revoked"
	case GrantStateExpired:
		return "Expired"
	default:
		return "Invalid"
	}
}

// GoString avoids exposing invalid numeric values in diagnostics.
func (state GrantState) GoString() string {
	return "administration.GrantState(" + state.String() + ")"
}
