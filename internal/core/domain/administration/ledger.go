package administration

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// Ledger is the sole owner of process-local elevation issuance and lifecycle
// state. Its proof and grant indexes make aliases and reconstructed receipts
// unable to replay within one process, and terminal tombstones remain retained
// until the fixed capacity is exhausted.
//
// This reference boundary is deliberately not durable or cross-node. Issues
// #30, #31, and #24 own authoritative persistence/CAS and runtime integration;
// callers must not claim this Ledger alone provides those guarantees.
type Ledger struct {
	state *ledgerState
}

type ledgerState struct {
	mu             sync.Mutex
	administrators map[resource.ID]Administrator
	proofs         map[resource.ID]struct{}
	grants         map[resource.ID]*grantRecord
	highWater      time.Time
}

type grantRecord struct {
	grant      Grant
	state      GrantState
	terminalAt time.Time
}

// NewLedger validates and takes an immutable copy of the configured human
// platform-administrator directory. An empty directory is valid and denies all
// issuance.
func NewLedger(administrators []Administrator) (Ledger, error) {
	if len(administrators) > MaxAdministrators {
		return Ledger{}, fmt.Errorf("%w: %w", ErrInvalidLedger, ErrTooManyAdministrators)
	}
	byID := make(map[resource.ID]Administrator, len(administrators))
	byIdentity := make(map[administratorIdentityKey]resource.ID, len(administrators))
	for _, administrator := range administrators {
		if ValidateAdministrator(administrator) != nil {
			return Ledger{}, fmt.Errorf("%w: %w", ErrInvalidLedger, ErrInvalidAdministrator)
		}
		if _, exists := byID[administrator.id]; exists {
			return Ledger{}, fmt.Errorf("%w: %w", ErrInvalidLedger, ErrDuplicateAdministratorID)
		}
		key := administratorKey(administrator)
		if _, exists := byIdentity[key]; exists {
			return Ledger{}, fmt.Errorf("%w: %w", ErrInvalidLedger, ErrDuplicateAdministrator)
		}
		byID[administrator.id] = administrator
		byIdentity[key] = administrator.id
	}
	return Ledger{state: &ledgerState{
		administrators: byID,
		proofs:         make(map[resource.ID]struct{}),
		grants:         make(map[resource.ID]*grantRecord),
	}}, nil
}

// Issue atomically records one proof tombstone and one active grant. All
// validation is staged before either map changes. A valid forward clock sample
// advances the ledger high-water mark even when later semantic validation
// fails, preventing a caller from retrying failed work with an earlier clock.
func (ledger Ledger) Issue(now time.Time, receipt StrongAuthReceipt) (Grant, error) {
	if ledger.state == nil {
		return Grant{}, ErrInvalidLedger
	}
	if !validStrongAuthReceipt(receipt) {
		return Grant{}, ErrInvalidStrongAuthReceipt
	}
	normalized, err := normalizeContractTime(now)
	if err != nil {
		return Grant{}, err
	}

	state := ledger.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.observeClockAtLeast(normalized, receipt.verifiedAt); err != nil {
		return Grant{}, err
	}
	if normalized.Sub(receipt.authenticatedAt) > MaxStrongAuthProofAge {
		return Grant{}, ErrStrongAuthProofStale
	}

	configured, exists := state.administrators[receipt.request.administrator.id]
	if !exists {
		return Grant{}, ErrAdministratorNotRegistered
	}
	if !equalAdministrator(configured, receipt.request.administrator) ||
		!configured.MatchesPrincipal(receipt.request.principal) {
		return Grant{}, ErrIdentityMismatch
	}
	if _, exists := state.proofs[receipt.proofID]; exists {
		return Grant{}, ErrStrongAuthProofReplayed
	}
	if _, exists := state.grants[receipt.request.grantID]; exists {
		return Grant{}, ErrDuplicateGrantID
	}
	if len(state.grants) >= MaxTrackedElevations {
		return Grant{}, ErrElevationLedgerFull
	}

	expiresAt, err := normalizeContractTime(normalized.Add(receipt.request.duration))
	if err != nil {
		return Grant{}, fmt.Errorf("%w: expiration", ErrInvalidElevationDuration)
	}
	grant := Grant{
		initialized:     true,
		id:              receipt.request.grantID,
		administratorID: configured.id,
		proofID:         receipt.proofID,
		action:          receipt.request.action,
		target:          cloneTarget(receipt.request.target),
		reason:          receipt.request.reason,
		caseReference:   receipt.request.caseReference,
		issuedAt:        normalized,
		expiresAt:       expiresAt,
	}
	if !validGrant(grant) {
		return Grant{}, ErrInvalidElevationRequest
	}

	// No operation below this point can fail: the proof tombstone and grant
	// become visible together while the single ledger lock is held.
	state.proofs[receipt.proofID] = struct{}{}
	state.grants[grant.id] = &grantRecord{grant: cloneGrant(grant), state: GrantStateActive}
	return cloneGrant(grant), nil
}

// StateAt returns ledger truth for a grant. At the exact expiry instant an
// active record irreversibly becomes an Expired tombstone.
func (ledger Ledger) StateAt(now time.Time, grant Grant) (GrantState, error) {
	if ledger.state == nil {
		return 0, ErrInvalidLedger
	}
	if !validGrant(grant) {
		return 0, ErrGrantMismatch
	}
	normalized, err := normalizeContractTime(now)
	if err != nil {
		return 0, err
	}
	state := ledger.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.observeClock(normalized); err != nil {
		return 0, err
	}
	record, err := state.lookupGrant(grant)
	if err != nil {
		return 0, err
	}
	record.expireAt(normalized)
	return record.state, nil
}

// Consume atomically spends an active grant once, only for its exact bound
// action and target. Copies, aliases, and concurrent attempts all resolve to
// the same retained ledger record.
func (ledger Ledger) Consume(
	now time.Time,
	grant Grant,
	expectedAction authorization.Action,
	expectedTarget Target,
) (ConsumptionReceipt, error) {
	if ledger.state == nil {
		return ConsumptionReceipt{}, ErrInvalidLedger
	}
	if !validGrant(grant) {
		return ConsumptionReceipt{}, ErrGrantMismatch
	}
	normalized, err := normalizeContractTime(now)
	if err != nil {
		return ConsumptionReceipt{}, err
	}
	state := ledger.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.observeClock(normalized); err != nil {
		return ConsumptionReceipt{}, err
	}
	record, err := state.lookupGrant(grant)
	if err != nil {
		return ConsumptionReceipt{}, err
	}
	record.expireAt(normalized)
	if err := terminalGrantError(record.state); err != nil {
		return ConsumptionReceipt{}, err
	}
	if record.grant.action != expectedAction || !equalTarget(record.grant.target, expectedTarget) {
		return ConsumptionReceipt{}, ErrGrantScopeMismatch
	}
	receipt := ConsumptionReceipt{
		initialized: true,
		grant:       cloneGrant(record.grant),
		consumedAt:  normalized,
	}
	if !validConsumptionReceipt(receipt) {
		return ConsumptionReceipt{}, ErrGrantMismatch
	}
	record.state = GrantStateConsumed
	record.terminalAt = normalized
	return receipt, nil
}

// Revoke atomically makes an active grant permanently unusable. Consumed,
// revoked, and expired grants cannot transition again.
func (ledger Ledger) Revoke(now time.Time, grant Grant) (RevocationReceipt, error) {
	if ledger.state == nil {
		return RevocationReceipt{}, ErrInvalidLedger
	}
	if !validGrant(grant) {
		return RevocationReceipt{}, ErrGrantMismatch
	}
	normalized, err := normalizeContractTime(now)
	if err != nil {
		return RevocationReceipt{}, err
	}
	state := ledger.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.observeClock(normalized); err != nil {
		return RevocationReceipt{}, err
	}
	record, err := state.lookupGrant(grant)
	if err != nil {
		return RevocationReceipt{}, err
	}
	record.expireAt(normalized)
	if err := terminalGrantError(record.state); err != nil {
		return RevocationReceipt{}, err
	}
	receipt := RevocationReceipt{
		initialized: true,
		grant:       cloneGrant(record.grant),
		revokedAt:   normalized,
	}
	if !validRevocationReceipt(receipt) {
		return RevocationReceipt{}, ErrGrantMismatch
	}
	record.state = GrantStateRevoked
	record.terminalAt = normalized
	return receipt, nil
}

func (state *ledgerState) observeClock(value time.Time) error {
	if !state.highWater.IsZero() && value.Before(state.highWater) {
		return ErrClockRegressed
	}
	if state.highWater.IsZero() || value.After(state.highWater) {
		state.highWater = value
	}
	return nil
}

func (state *ledgerState) observeClockAtLeast(value, minimum time.Time) error {
	if value.Before(minimum) || (!state.highWater.IsZero() && value.Before(state.highWater)) {
		return ErrClockRegressed
	}
	if state.highWater.IsZero() || value.After(state.highWater) {
		state.highWater = value
	}
	return nil
}

func (state *ledgerState) lookupGrant(grant Grant) (*grantRecord, error) {
	record, exists := state.grants[grant.id]
	if !exists {
		return nil, ErrGrantNotFound
	}
	if record == nil || !equalGrant(record.grant, grant) {
		return nil, ErrGrantMismatch
	}
	return record, nil
}

func (record *grantRecord) expireAt(now time.Time) {
	if record.state == GrantStateActive && !now.Before(record.grant.expiresAt) {
		record.state = GrantStateExpired
		record.terminalAt = record.grant.expiresAt
	}
}

func terminalGrantError(state GrantState) error {
	switch state {
	case GrantStateActive:
		return nil
	case GrantStateConsumed:
		return ErrGrantConsumed
	case GrantStateRevoked:
		return ErrGrantRevoked
	case GrantStateExpired:
		return ErrGrantExpired
	default:
		return ErrGrantMismatch
	}
}

func (ledger Ledger) String() string {
	if ledger.state == nil {
		return "elevation-ledger(invalid)"
	}
	return "elevation-ledger(identity=redacted,state=redacted)"
}

func (ledger Ledger) GoString() string { return ledger.String() }
func (ledger Ledger) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, ledger.String())
}
func (ledger Ledger) LogValue() slog.Value    { return redactedLogValue(ledger.String()) }
func (Ledger) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Ledger) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Ledger) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Ledger) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
