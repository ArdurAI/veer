// Package administration defines Veer's process-local privileged-elevation
// reference contract. It performs no authentication, persistence, audit, or
// provider I/O.
package administration

import "errors"

var (
	ErrInvalidAdministrator       = errors.New("invalid platform administrator")
	ErrAdministratorNotHuman      = errors.New("platform administrator must be human")
	ErrAdministratorNotRegistered = errors.New("platform administrator is not registered")
	ErrDuplicateAdministratorID   = errors.New("duplicate platform administrator ID")
	ErrDuplicateAdministrator     = errors.New("duplicate platform administrator identity")
	ErrTooManyAdministrators      = errors.New("platform administrator limit exceeded")

	ErrInvalidAction        = errors.New("invalid privileged administration action")
	ErrInvalidTarget        = errors.New("invalid privileged administration target")
	ErrActionTargetMismatch = errors.New("privileged administration action and target do not match")

	ErrInvalidElevationRequest  = errors.New("invalid privileged elevation request")
	ErrInvalidGrantID           = errors.New("invalid privileged elevation grant ID")
	ErrInvalidReason            = errors.New("invalid privileged elevation reason")
	ErrInvalidCaseReference     = errors.New("invalid privileged elevation case reference")
	ErrInvalidElevationDuration = errors.New("invalid privileged elevation duration")
	ErrIdentityMismatch         = errors.New("privileged administrator identity does not match")

	ErrInvalidStrongAuthReceipt = errors.New("invalid strong-authentication receipt")
	ErrInvalidStrongAuthProofID = errors.New("invalid strong-authentication proof ID")
	ErrStrongAuthProofStale     = errors.New("strong-authentication proof is stale")
	ErrStrongAuthProofReplayed  = errors.New("strong-authentication proof was already used")

	ErrInvalidLedger       = errors.New("invalid privileged elevation ledger")
	ErrElevationLedgerFull = errors.New("privileged elevation ledger is full")
	ErrDuplicateGrantID    = errors.New("privileged elevation grant ID was already used")
	ErrGrantNotFound       = errors.New("privileged elevation grant was not found")
	ErrGrantMismatch       = errors.New("privileged elevation grant does not match ledger")
	ErrGrantConsumed       = errors.New("privileged elevation grant was already consumed")
	ErrGrantRevoked        = errors.New("privileged elevation grant was revoked")
	ErrGrantExpired        = errors.New("privileged elevation grant expired")
	ErrGrantScopeMismatch  = errors.New("privileged elevation grant action or target does not match")

	ErrInvalidClock           = errors.New("invalid privileged administration clock")
	ErrClockRegressed         = errors.New("privileged administration clock regressed")
	ErrSerializationForbidden = errors.New("privileged administration serialization forbidden")
)
