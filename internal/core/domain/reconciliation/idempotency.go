package reconciliation

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~:+/-]{15,127}$`)

// IdempotencyScope is the exact logical principal, HTTP method, and canonical
// target scope reduced to a non-reversible digest.
type IdempotencyScope struct {
	initialized bool
	digest      digestValue
}

// NewIdempotencyScope derives one mutation scope without retaining identity claims.
func NewIdempotencyScope(
	principal identity.Principal,
	method string,
	canonicalTarget []byte,
) (IdempotencyScope, error) {
	if identity.ValidatePrincipal(principal) != nil || !validMutationMethod(method) ||
		len(canonicalTarget) == 0 || len(canonicalTarget) > MaxEvidenceBytes {
		return IdempotencyScope{}, ErrInvalidIdempotency
	}
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.idempotency-scope.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashFrame(hasher, principal.Kind().String())
	writeHashFrame(hasher, principal.Issuer())
	writeHashFrame(hasher, principal.Subject())
	writeHashFrame(hasher, method)
	writeHashBytes(hasher, canonicalTarget)
	return IdempotencyScope{initialized: true, digest: digestFromHasher(hasher)}, nil
}

// Equal compares complete scope digests.
func (value IdempotencyScope) Equal(other IdempotencyScope) bool {
	return value.initialized && other.initialized && equalDigest(value.digest, other.digest)
}

func (value IdempotencyScope) String() string {
	if !value.initialized || !value.digest.initialized {
		return "idempotency-scope(invalid)"
	}
	return "idempotency-scope(redacted)"
}
func (value IdempotencyScope) GoString() string { return value.String() }
func (value IdempotencyScope) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value IdempotencyScope) LogValue() slog.Value { return redactedLogValue(value.String()) }

// Reservation is one fixed-window key epoch. A completed reservation carries
// only a semantic result digest, never the response body.
type Reservation struct {
	initialized bool
	scope       IdempotencyScope
	keyDigest   digestValue
	fingerprint RequestFingerprint
	epoch       uint64
	committedAt time.Time
	expiresAt   time.Time
	completed   bool
	result      ResultDigest
}

func (value Reservation) Epoch() uint64                   { return value.epoch }
func (value Reservation) CommittedAt() time.Time          { return value.committedAt }
func (value Reservation) ExpiresAt() time.Time            { return value.expiresAt }
func (value Reservation) Completed() bool                 { return value.completed }
func (value Reservation) Fingerprint() RequestFingerprint { return value.fingerprint }
func (value Reservation) Result() (ResultDigest, bool) {
	if !value.completed {
		return ResultDigest{}, false
	}
	return value.result, true
}

func (value Reservation) String() string {
	if validateReservation(value) != nil {
		return "idempotency-reservation(invalid)"
	}
	return fmt.Sprintf("idempotency-reservation(epoch=%d,completed=%t,identity=redacted)", value.epoch, value.completed)
}
func (value Reservation) GoString() string { return value.String() }
func (value Reservation) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value Reservation) LogValue() slog.Value { return redactedLogValue(value.String()) }

// IdempotencyLedger is a bounded process-local oracle for the adopted atomic
// reservation rules. PostgreSQL remains authoritative in production issue #30.
type IdempotencyLedger struct {
	mu          sync.Mutex
	activityMu  sync.Mutex
	initialized bool
	maximum     int
	activeLimit int
	nextCall    atomic.Uint64
	lastCall    uint64
	highWater   time.Time
	keyState    map[string]idempotencyKeyState
	records     map[string]Reservation
	active      map[string]map[*idempotencyCall]struct{}
	activeCount int
}

type idempotencyKeyState struct {
	epoch uint64
}

type idempotencyCall struct {
	sequence   uint64
	observedAt time.Time
}

// NewIdempotencyLedger creates a bounded reference ledger.
func NewIdempotencyLedger(maximum int) (*IdempotencyLedger, error) {
	if maximum < 1 {
		return nil, ErrInvalidIdempotency
	}
	activeLimit := maximum
	if maximum < math.MaxInt {
		activeLimit++
	}
	return &IdempotencyLedger{
		initialized: true,
		maximum:     maximum,
		activeLimit: activeLimit,
		keyState:    make(map[string]idempotencyKeyState, maximum),
		records:     make(map[string]Reservation, maximum),
		active:      make(map[string]map[*idempotencyCall]struct{}, maximum),
	}, nil
}

// Reserve atomically creates, replays, conflicts, or replaces one key epoch.
// databaseTime represents PostgreSQL time sampled after the durable key lock.
func (ledger *IdempotencyLedger) Reserve(
	databaseTime time.Time,
	scope IdempotencyScope,
	key string,
	fingerprint RequestFingerprint,
) (Reservation, IdempotencyDisposition, error) {
	if ledger == nil || !ledger.initialized || !scope.initialized || !scope.digest.initialized ||
		!validIdempotencyKey(key) || !fingerprint.initialized {
		return Reservation{}, "", ErrInvalidIdempotency
	}
	now, err := normalizeTime(databaseTime)
	if err != nil {
		return Reservation{}, "", fmt.Errorf("%w: %w", ErrInvalidIdempotency, err)
	}
	keyDigest := deriveDigest("veer.reconciliation.idempotency-key.v1", []byte(key))
	mapKey := formatDigest("", scope.digest) + ":" + formatDigest("", keyDigest)
	call, err := ledger.beginIdempotencyCall(mapKey, now)
	if err != nil {
		return Reservation{}, "", ErrCapacity
	}
	defer ledger.finishIdempotencyCall(mapKey, call)
	return ledger.reserveRegistered(call, scope, keyDigest, mapKey, fingerprint)
}

func (ledger *IdempotencyLedger) reserveRegistered(
	call *idempotencyCall,
	scope IdempotencyScope,
	keyDigest digestValue,
	mapKey string,
	fingerprint RequestFingerprint,
) (Reservation, IdempotencyDisposition, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.observeIdempotencyTimeLocked(call); err != nil {
		return Reservation{}, "", err
	}
	now := call.observedAt

	state, guarded := ledger.keyState[mapKey]
	current, exists := ledger.records[mapKey]
	if exists {
		if !current.completed {
			if !current.fingerprint.Equal(fingerprint) {
				return Reservation{}, "", ErrIdempotencyConflict
			}
			return current, "", ErrReservationOutstanding
		}
		if now.Before(current.expiresAt) {
			if !current.fingerprint.Equal(fingerprint) {
				return Reservation{}, "", ErrIdempotencyConflict
			}
			return current, IdempotencyReplay, nil
		}
		if ledger.hasEarlierLiveCall(mapKey, call, current.expiresAt) {
			return Reservation{}, "", ErrReservationOutstanding
		}
		if state.epoch == ^uint64(0) {
			return Reservation{}, "", ErrCapacity
		}
		current, err := newReservation(scope, keyDigest, fingerprint, state.epoch+1, now)
		if err != nil {
			return Reservation{}, "", fmt.Errorf("%w: %w", ErrInvalidIdempotency, err)
		}
		state.epoch = current.epoch
		ledger.keyState[mapKey] = state
		ledger.records[mapKey] = current
		return current, IdempotencyReserved, nil
	}
	if len(ledger.records) >= ledger.maximum {
		ledger.reclaimExpiredCompletedLocked(now, call)
		if len(ledger.records) >= ledger.maximum {
			return Reservation{}, "", ErrCapacity
		}
	}
	epoch := uint64(1)
	if guarded {
		if state.epoch == ^uint64(0) {
			return Reservation{}, "", ErrCapacity
		}
		epoch = state.epoch + 1
	}
	created, err := newReservation(scope, keyDigest, fingerprint, epoch, now)
	if err != nil {
		return Reservation{}, "", fmt.Errorf("%w: %w", ErrInvalidIdempotency, err)
	}
	ledger.keyState[mapKey] = idempotencyKeyState{epoch: epoch}
	ledger.records[mapKey] = created
	return created, IdempotencyReserved, nil
}

// Complete binds a semantic result exactly once without moving expiry.
func (ledger *IdempotencyLedger) Complete(reservation Reservation, result ResultDigest) (Reservation, error) {
	if ledger == nil || !ledger.initialized || validateReservation(reservation) != nil || !result.initialized {
		return Reservation{}, ErrInvalidIdempotency
	}
	mapKey := formatDigest("", reservation.scope.digest) + ":" + formatDigest("", reservation.keyDigest)
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	current, exists := ledger.records[mapKey]
	if !exists || current.epoch != reservation.epoch ||
		!current.fingerprint.Equal(reservation.fingerprint) || !current.scope.Equal(reservation.scope) ||
		!current.committedAt.Equal(reservation.committedAt) || !current.expiresAt.Equal(reservation.expiresAt) {
		return Reservation{}, ErrReservationLost
	}
	if current.completed {
		if current.result.Equal(result) {
			return current, nil
		}
		return Reservation{}, ErrReservationLost
	}
	current.completed = true
	current.result = result
	ledger.records[mapKey] = current
	return current, nil
}

// Len returns the bounded count of retained scoped key records.
func (ledger *IdempotencyLedger) Len() int {
	if ledger == nil {
		return 0
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return len(ledger.records)
}

func (ledger *IdempotencyLedger) reclaimExpiredCompletedLocked(now time.Time, current *idempotencyCall) {
	for key, reservation := range ledger.records {
		if reservation.completed && !now.Before(reservation.expiresAt) &&
			!ledger.hasEarlierLiveCall(key, current, reservation.expiresAt) {
			delete(ledger.records, key)
			delete(ledger.keyState, key)
		}
	}
}

func (ledger *IdempotencyLedger) beginIdempotencyCall(
	mapKey string,
	now time.Time,
) (*idempotencyCall, error) {
	ledger.activityMu.Lock()
	defer ledger.activityMu.Unlock()
	if ledger.activeCount >= ledger.activeLimit {
		return nil, ErrCapacity
	}
	sequence, err := ledger.nextIdempotencyCall()
	if err != nil {
		return nil, err
	}
	call := &idempotencyCall{sequence: sequence, observedAt: now}
	if ledger.active[mapKey] == nil {
		ledger.active[mapKey] = make(map[*idempotencyCall]struct{})
	}
	ledger.active[mapKey][call] = struct{}{}
	ledger.activeCount++
	return call, nil
}

func (ledger *IdempotencyLedger) observeIdempotencyTimeLocked(call *idempotencyCall) error {
	if call.sequence <= ledger.lastCall {
		if call.observedAt.After(ledger.highWater) {
			ledger.highWater = call.observedAt
		}
		return nil
	}
	ledger.lastCall = call.sequence
	if !ledger.highWater.IsZero() && call.observedAt.Before(ledger.highWater) {
		return fmt.Errorf("%w: %w", ErrInvalidIdempotency, ErrClockRegressed)
	}
	if call.observedAt.After(ledger.highWater) {
		ledger.highWater = call.observedAt
	}
	return nil
}

func (ledger *IdempotencyLedger) nextIdempotencyCall() (uint64, error) {
	for {
		current := ledger.nextCall.Load()
		if current == ^uint64(0) {
			return 0, ErrCapacity
		}
		if ledger.nextCall.CompareAndSwap(current, current+1) {
			return current + 1, nil
		}
	}
}

func (ledger *IdempotencyLedger) finishIdempotencyCall(mapKey string, call *idempotencyCall) {
	ledger.activityMu.Lock()
	if _, exists := ledger.active[mapKey][call]; exists {
		delete(ledger.active[mapKey], call)
		ledger.activeCount--
	}
	if len(ledger.active[mapKey]) == 0 {
		delete(ledger.active, mapKey)
	}
	ledger.activityMu.Unlock()
}

func (ledger *IdempotencyLedger) hasEarlierLiveCall(
	mapKey string,
	current *idempotencyCall,
	expiresAt time.Time,
) bool {
	ledger.activityMu.Lock()
	defer ledger.activityMu.Unlock()
	for call := range ledger.active[mapKey] {
		if call != current && call.observedAt.Before(expiresAt) {
			return true
		}
	}
	return false
}

func (ledger *IdempotencyLedger) String() string {
	if ledger == nil || !ledger.initialized {
		return "idempotency-ledger(invalid)"
	}
	return "idempotency-ledger(state=redacted)"
}
func (ledger *IdempotencyLedger) GoString() string { return ledger.String() }
func (ledger *IdempotencyLedger) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, ledger.String())
}
func (ledger *IdempotencyLedger) LogValue() slog.Value { return redactedLogValue(ledger.String()) }

func (Reservation) MarshalJSON() ([]byte, error)          { return nil, ErrSerializationForbidden }
func (Reservation) MarshalText() ([]byte, error)          { return nil, ErrSerializationForbidden }
func (Reservation) MarshalBinary() ([]byte, error)        { return nil, ErrSerializationForbidden }
func (Reservation) GobEncode() ([]byte, error)            { return nil, ErrSerializationForbidden }
func (IdempotencyScope) MarshalJSON() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (IdempotencyScope) MarshalText() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (IdempotencyScope) MarshalBinary() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (IdempotencyScope) GobEncode() ([]byte, error)       { return nil, ErrSerializationForbidden }
func (*IdempotencyLedger) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (*IdempotencyLedger) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (*IdempotencyLedger) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (*IdempotencyLedger) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

func newReservation(
	scope IdempotencyScope,
	keyDigest digestValue,
	fingerprint RequestFingerprint,
	epoch uint64,
	now time.Time,
) (Reservation, error) {
	expiresAt, err := addNormalizedDuration(now, HTTPIdempotencyWindow)
	if err != nil {
		return Reservation{}, err
	}
	return Reservation{
		initialized: true,
		scope:       scope,
		keyDigest:   keyDigest,
		fingerprint: fingerprint,
		epoch:       epoch,
		committedAt: now,
		expiresAt:   expiresAt,
	}, nil
}

func validateReservation(value Reservation) error {
	if !value.initialized || !value.scope.initialized || !value.keyDigest.initialized ||
		!value.fingerprint.initialized || value.epoch == 0 || value.committedAt.IsZero() ||
		value.expiresAt.IsZero() || value.expiresAt.Sub(value.committedAt) != HTTPIdempotencyWindow ||
		(value.completed != value.result.initialized) {
		return ErrInvalidIdempotency
	}
	return nil
}

func validIdempotencyKey(value string) bool {
	return len(value) >= MinIdempotencyKeyBytes && len(value) <= MaxIdempotencyKeyBytes &&
		!strings.ContainsAny(value, "\r\n") && idempotencyKeyPattern.MatchString(value)
}

func validMutationMethod(value string) bool {
	switch value {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}
