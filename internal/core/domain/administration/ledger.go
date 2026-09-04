package administration

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authentication"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// Ledger is the sole owner of process-local elevation issuance and lifecycle
// state. Its proof and grant indexes make aliases and reconstructed values
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
	mu              sync.Mutex
	clockSamples    atomic.Uint64
	lastClockSample uint64
	verifier        StrongAuthenticationVerifier
	clock           Clock
	administrators  map[resource.ID]Administrator
	proofs          map[resource.ID]struct{}
	grants          map[resource.ID]*grantRecord
	highWater       time.Time
}

type grantRecord struct {
	grant      Grant
	state      GrantState
	terminalAt time.Time
}

type issuanceClockSample struct {
	sequence uint64
	observed time.Time
	err      error
}

// NewLedger validates and takes an immutable copy of the configured human
// platform-administrator directory and the required verification authorities.
// An empty directory is valid and denies all issuance. The verifier and clock
// are shared by every Ledger copy and cannot be replaced through public APIs.
func NewLedger(
	administrators []Administrator,
	verifier StrongAuthenticationVerifier,
	clock Clock,
) (Ledger, error) {
	if isNilInterface(verifier) || isNilInterface(clock) {
		return Ledger{}, ErrInvalidLedger
	}
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
		verifier:       verifier,
		clock:          clock,
		administrators: byID,
		proofs:         make(map[resource.ID]struct{}),
		grants:         make(map[resource.ID]*grantRecord),
	}}, nil
}

// Issue invokes the configured verifier with the exact credential and request,
// samples the configured clock, and atomically records one proof tombstone and
// one active grant. Callers cannot supply verifier output or issuance time.
// All validation is staged before either map changes. A valid forward clock
// sample advances the ledger high-water mark even when later semantic
// validation fails, preventing retries of failed work with an earlier clock.
func (ledger Ledger) Issue(
	ctx context.Context,
	credential authentication.BearerCredential,
	request ElevationRequest,
) (Grant, error) {
	if ledger.state == nil || isNilInterface(ledger.state.verifier) || isNilInterface(ledger.state.clock) {
		return Grant{}, ErrInvalidLedger
	}
	if isNilInterface(ctx) {
		return Grant{}, ErrStrongAuthenticationUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	if !credential.Valid() || ValidateElevationRequest(request) != nil {
		return Grant{}, ErrStrongAuthenticationInvalid
	}

	state := ledger.state
	proofID, authenticatedAt, verificationErr := state.verifier.VerifyStrongAuthentication(
		ctx,
		credential,
		cloneElevationRequest(request),
	)
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	if verificationErr != nil {
		if failure, classified := ClassifyStrongAuthenticationError(verificationErr); classified {
			return Grant{}, failure
		}
		return Grant{}, ErrStrongAuthenticationUnavailable
	}
	if !resourceIDValid(proofID) {
		return Grant{}, ErrStrongAuthenticationUnavailable
	}
	normalizedAuthenticated, err := normalizeContractTime(authenticatedAt)
	if err != nil {
		return Grant{}, ErrStrongAuthenticationUnavailable
	}
	clockSample := state.sampleIssuanceClock()

	state.mu.Lock()
	defer state.mu.Unlock()
	normalized, err := state.observeIssuanceClockLocked(clockSample)
	// Once sampled, time must be fenced even when cancellation wins. Otherwise
	// a strategically canceled later observation could let a subsequent clock
	// rollback appear fresh. Context still takes precedence over clock errors.
	if contextErr := ctx.Err(); contextErr != nil {
		return Grant{}, contextErr
	}
	if err != nil {
		return Grant{}, err
	}
	if normalized.Before(request.requestedAt) || normalized.Before(normalizedAuthenticated) ||
		normalized.Sub(normalizedAuthenticated) > MaxStrongAuthProofAge {
		return Grant{}, ErrStrongAuthenticationInvalid
	}

	configured, exists := state.administrators[request.administrator.id]
	if !exists {
		return Grant{}, ErrAdministratorNotRegistered
	}
	if !equalAdministrator(configured, request.administrator) ||
		!configured.MatchesPrincipal(request.principal) {
		return Grant{}, ErrIdentityMismatch
	}
	if _, exists := state.proofs[proofID]; exists {
		return Grant{}, ErrStrongAuthProofReplayed
	}
	if _, exists := state.grants[request.grantID]; exists {
		return Grant{}, ErrDuplicateGrantID
	}
	if len(state.grants) >= MaxTrackedElevations {
		return Grant{}, ErrElevationLedgerFull
	}

	expiresAt, err := normalizeContractTime(normalized.Add(request.duration))
	if err != nil {
		return Grant{}, fmt.Errorf("%w: expiration", ErrInvalidElevationDuration)
	}
	grant := Grant{
		initialized:     true,
		id:              request.grantID,
		administratorID: configured.id,
		proofID:         proofID,
		action:          request.action,
		target:          cloneTarget(request.target),
		reason:          request.reason,
		caseReference:   request.caseReference,
		issuedAt:        normalized,
		expiresAt:       expiresAt,
	}
	if !validGrant(grant) {
		return Grant{}, ErrInvalidElevationRequest
	}
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}

	// No operation below this point can fail: the proof tombstone and grant
	// become visible together while the single ledger lock is held.
	state.proofs[proofID] = struct{}{}
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

func (state *ledgerState) sampleIssuanceClock() issuanceClockSample {
	if state == nil || isNilInterface(state.clock) {
		return issuanceClockSample{err: ErrStrongAuthenticationUnavailable}
	}
	var sequence uint64
	for {
		current := state.clockSamples.Load()
		if current == ^uint64(0) {
			return issuanceClockSample{err: ErrStrongAuthenticationUnavailable}
		}
		if state.clockSamples.CompareAndSwap(current, current+1) {
			sequence = current + 1
			break
		}
	}
	return issuanceClockSample{sequence: sequence, observed: state.clock.Now()}
}

// observeIssuanceClockLocked orders Clock.Now completions by call start. An
// older overlapping call uses the latest already-observed time instead of
// manufacturing a rollback; a fresh sequential rollback still fails closed.
func (state *ledgerState) observeIssuanceClockLocked(sample issuanceClockSample) (time.Time, error) {
	if sample.sequence == 0 {
		return time.Time{}, ErrStrongAuthenticationUnavailable
	}
	if sample.err != nil {
		if sample.sequence > state.lastClockSample {
			state.lastClockSample = sample.sequence
		}
		return time.Time{}, ErrStrongAuthenticationUnavailable
	}
	normalized, err := normalizeContractTime(sample.observed)
	if err != nil {
		if sample.sequence > state.lastClockSample {
			state.lastClockSample = sample.sequence
		}
		return time.Time{}, ErrStrongAuthenticationUnavailable
	}
	if sample.sequence <= state.lastClockSample {
		// A stale sequence still carries a valid time observation. Clamp it
		// forward against the accepted high-water mark; never replace its own
		// later observation with an earlier time for freshness decisions.
		if state.highWater.IsZero() || normalized.After(state.highWater) {
			state.highWater = normalized
		}
		return state.highWater, nil
	}

	// Advance the sequence fence even when this fresh sample is rejected, so
	// an older overlapping sample cannot later appear fresh.
	state.lastClockSample = sample.sequence
	if !state.highWater.IsZero() && normalized.Before(state.highWater) {
		return time.Time{}, ErrClockRegressed
	}
	if state.highWater.IsZero() || normalized.After(state.highWater) {
		state.highWater = normalized
	}
	return normalized, nil
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
