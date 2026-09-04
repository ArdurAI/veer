package reconciliation

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// LeaseBinding is one stable Workspace/resource-lineage row with the current
// generation, Operation, and plan bound as columns rather than alternate keys.
type LeaseBinding struct {
	initialized  bool
	workspaceID  resource.ID
	resourceID   resource.ID
	generation   int64
	operationID  resource.ID
	planRevision uint32
	planDigest   PlanDigest
}

// LeaseBindingFromPlan projects the exact authoritative binding for a plan.
func LeaseBindingFromPlan(plan Plan) (LeaseBinding, error) {
	if ValidatePlan(plan) != nil {
		return LeaseBinding{}, ErrInvalidLease
	}
	return LeaseBinding{
		initialized:  true,
		workspaceID:  plan.workspaceID,
		resourceID:   plan.resourceID,
		generation:   plan.generation,
		operationID:  plan.operationID,
		planRevision: plan.revision,
		planDigest:   plan.digest,
	}, nil
}

func (value LeaseBinding) WorkspaceID() resource.ID { return value.workspaceID }
func (value LeaseBinding) ResourceID() resource.ID  { return value.resourceID }
func (value LeaseBinding) Generation() int64        { return value.generation }
func (value LeaseBinding) OperationID() resource.ID { return value.operationID }
func (value LeaseBinding) PlanRevision() uint32     { return value.planRevision }
func (value LeaseBinding) PlanDigest() PlanDigest   { return value.planDigest }

func (value LeaseBinding) Equal(other LeaseBinding) bool {
	return validateLeaseBinding(value) == nil && validateLeaseBinding(other) == nil &&
		value.workspaceID == other.workspaceID && value.resourceID == other.resourceID &&
		value.generation == other.generation && value.operationID == other.operationID &&
		value.planRevision == other.planRevision &&
		value.planDigest.Equal(other.planDigest)
}

// LeaseToken is one acquired or renewed authoritative ownership receipt.
type LeaseToken struct {
	initialized bool
	table       *leaseTableIdentity
	binding     LeaseBinding
	ownerID     resource.ID
	fence       int64
	acquiredAt  time.Time
	expiresAt   time.Time
}

func (value LeaseToken) Binding() LeaseBinding { return value.binding }
func (value LeaseToken) OwnerID() resource.ID  { return value.ownerID }
func (value LeaseToken) Fence() int64          { return value.fence }
func (value LeaseToken) AcquiredAt() time.Time { return value.acquiredAt }
func (value LeaseToken) ExpiresAt() time.Time  { return value.expiresAt }

func (value LeaseToken) String() string {
	if validateLeaseToken(value) != nil {
		return "reconciliation-lease-token(invalid)"
	}
	return fmt.Sprintf("reconciliation-lease-token(fence=%d,identity=redacted)", value.fence)
}
func (value LeaseToken) GoString() string { return value.String() }
func (value LeaseToken) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value LeaseToken) LogValue() slog.Value { return redactedLogValue(value.String()) }

type leaseRow struct {
	binding    LeaseBinding
	ownerID    resource.ID
	fence      int64
	acquiredAt time.Time
	expiresAt  time.Time
	observedAt time.Time
}

// leaseTableIdentity is deliberately non-zero-sized so distinct tables always
// receive distinct comparable marker addresses.
type leaseTableIdentity [1]byte

// LeaseTable is a bounded process-local oracle for signed monotonic fencing.
// PostgreSQL row locks and database time remain issue #30 responsibilities.
type LeaseTable struct {
	mu          sync.Mutex
	initialized bool
	identity    *leaseTableIdentity
	maximum     int
	rows        map[string]leaseRow
}

// NewLeaseTable creates a bounded reference table retaining stable lineage rows.
func NewLeaseTable(maximum int) (*LeaseTable, error) {
	if maximum < 1 {
		return nil, ErrInvalidLease
	}
	return &LeaseTable{
		initialized: true,
		identity:    &leaseTableIdentity{},
		maximum:     maximum,
		rows:        make(map[string]leaseRow, maximum),
	}, nil
}

// NextFence returns the next positive signed bigint fence without wrap or reuse.
func NextFence(previous int64) (int64, error) {
	if previous < 0 || previous == MaxFence {
		return 0, ErrFenceExhausted
	}
	return previous + 1, nil
}

// Acquire creates or takes over a stable lineage row. Equality with expiry loses.
// databaseTime represents PostgreSQL time sampled after the row lock.
func (table *LeaseTable) Acquire(
	databaseTime time.Time,
	binding LeaseBinding,
	ownerID resource.ID,
) (LeaseToken, error) {
	if table == nil || !table.initialized || validateLeaseBinding(binding) != nil || !validID(ownerID) {
		return LeaseToken{}, ErrInvalidLease
	}
	now, err := normalizeTime(databaseTime)
	if err != nil {
		return LeaseToken{}, fmt.Errorf("%w: %w", ErrInvalidLease, err)
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	key := leaseRowKey(binding)
	row, exists := table.rows[key]
	if exists {
		if err := table.observeNowLocked(key, now); err != nil {
			return LeaseToken{}, err
		}
		row = table.rows[key]
		if !row.binding.Equal(binding) {
			return LeaseToken{}, ErrLeaseLost
		}
	}
	if exists && row.ownerID != "" && now.Before(row.expiresAt) {
		return LeaseToken{}, ErrLeaseHeld
	}
	if !exists && len(table.rows) >= table.maximum {
		return LeaseToken{}, ErrCapacity
	}
	previousFence := int64(0)
	if exists {
		previousFence = row.fence
	}
	fence, err := NextFence(previousFence)
	if err != nil {
		return LeaseToken{}, err
	}
	expiresAt, err := addNormalizedDuration(now, StoreLeaseDuration)
	if err != nil {
		return LeaseToken{}, fmt.Errorf("%w: %w", ErrInvalidLease, err)
	}
	row = leaseRow{
		binding:    binding,
		ownerID:    ownerID,
		fence:      fence,
		acquiredAt: now,
		expiresAt:  expiresAt,
		observedAt: now,
	}
	table.rows[key] = row
	return tokenFromRow(row, table.identity), nil
}

// AcquireReplacement atomically replaces an expired or surrendered lineage
// binding only when expected still exactly matches the stable row. Generation
// may move forward at revision one; a same-generation replan must be the exact
// next revision.
func (table *LeaseTable) AcquireReplacement(
	databaseTime time.Time,
	authority LeaseReplacementAuthority,
	ownerID resource.ID,
) (LeaseToken, error) {
	if table == nil || !table.initialized || validateLeaseReplacementAuthority(authority) != nil ||
		!validID(ownerID) {
		return LeaseToken{}, ErrInvalidLease
	}
	now, err := normalizeTime(databaseTime)
	if err != nil {
		return LeaseToken{}, fmt.Errorf("%w: %w", ErrInvalidLease, err)
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	key := leaseRowKey(authority.expected)
	if err := table.observeNowLocked(key, now); err != nil {
		return LeaseToken{}, err
	}
	row := table.rows[key]
	if !row.binding.Equal(authority.expected) {
		return LeaseToken{}, ErrLeaseLost
	}
	if row.ownerID != "" && now.Before(row.expiresAt) {
		return LeaseToken{}, ErrLeaseHeld
	}
	fence, err := NextFence(row.fence)
	if err != nil {
		return LeaseToken{}, err
	}
	expiresAt, err := addNormalizedDuration(now, StoreLeaseDuration)
	if err != nil {
		return LeaseToken{}, fmt.Errorf("%w: %w", ErrInvalidLease, err)
	}
	if !authority.use.CompareAndSwap(false, true) {
		return LeaseToken{}, ErrInvalidLease
	}
	if authority.transition != nil && authority.transition.Load() != 0 {
		return LeaseToken{}, ErrInvalidLease
	}
	replaced := leaseRow{
		binding:    authority.replacement,
		ownerID:    ownerID,
		fence:      fence,
		acquiredAt: now,
		expiresAt:  expiresAt,
		observedAt: now,
	}
	table.rows[key] = replaced
	if authority.transition != nil {
		// Publish the paired admission only after the replacement row is live.
		// Atomic publication lets NewPreparedAttempt observe the preceding row
		// write without taking the lease-table lock.
		authority.transition.Store(1)
	}
	return tokenFromRow(replaced, table.identity), nil
}

// Renew extends a live exact token from databaseTime while preserving its fence.
func (table *LeaseTable) Renew(databaseTime time.Time, token LeaseToken) (LeaseToken, error) {
	if table == nil || !table.initialized || validateLeaseToken(token) != nil {
		return LeaseToken{}, ErrInvalidLease
	}
	if token.table != table.identity {
		return LeaseToken{}, ErrLeaseLost
	}
	now, err := normalizeTime(databaseTime)
	if err != nil {
		return LeaseToken{}, fmt.Errorf("%w: %w", ErrInvalidLease, err)
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	key := leaseRowKey(token.binding)
	if err := table.observeNowLocked(key, now); err != nil {
		return LeaseToken{}, err
	}
	row, ok := table.currentRowLocked(now, token)
	if !ok {
		return LeaseToken{}, ErrLeaseLost
	}
	expiresAt, err := addNormalizedDuration(now, StoreLeaseDuration)
	if err != nil {
		return LeaseToken{}, fmt.Errorf("%w: %w", ErrInvalidLease, err)
	}
	row.expiresAt = expiresAt
	row.observedAt = now
	table.rows[key] = row
	return tokenFromRow(row, table.identity), nil
}

// Surrender removes ownership without deleting the stable fence row.
func (table *LeaseTable) Surrender(databaseTime time.Time, token LeaseToken) error {
	if table == nil || !table.initialized || validateLeaseToken(token) != nil {
		return ErrInvalidLease
	}
	if token.table != table.identity {
		return ErrLeaseLost
	}
	now, err := normalizeTime(databaseTime)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidLease, err)
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	key := leaseRowKey(token.binding)
	if err := table.observeNowLocked(key, now); err != nil {
		return err
	}
	row, ok := table.currentRowLocked(now, token)
	if !ok {
		return ErrLeaseLost
	}
	row.ownerID = ""
	row.expiresAt = now
	row.observedAt = now
	table.rows[key] = row
	return nil
}

// DispatchAuthority is a fail-closed projection of all execution-time checks.
type DispatchAuthority struct {
	initialized        bool
	planDigest         PlanDigest
	attemptBinding     digestValue
	authorizationInput string
	policyVersion      string
	observedAt         time.Time
	use                *atomic.Bool
}

// NewDispatchAuthority revalidates the current Operation, authorization,
// provider/credential binding, capability, quota, and cost evidence at the
// exact PostgreSQL-time sample later used to authorize dispatch.
func NewDispatchAuthority(
	databaseTime time.Time,
	plan Plan,
	attempt Attempt,
	current operation.Operation,
	decision authorization.Decision,
	providerBinding *ProviderBinding,
	capability Evidence,
	quota Evidence,
	cost Evidence,
) (DispatchAuthority, error) {
	now, err := normalizeTime(databaseTime)
	if err != nil {
		return DispatchAuthority{}, fmt.Errorf("%w: %w", ErrDispatchAuthority, err)
	}
	if ValidatePlan(plan) != nil || ValidateAttempt(attempt) != nil || attempt.state != AttemptStatePrepared ||
		now.Before(attempt.preparedAt) ||
		(!attempt.retryValidUntil.IsZero() && !now.Before(attempt.retryValidUntil)) ||
		(!attempt.observationDeadline.IsZero() && !now.Before(attempt.observationDeadline)) ||
		!attempt.planDigest.Equal(plan.digest) || attempt.planKind != plan.kind || !effectMatchesPlan(attempt.effect, plan) ||
		operation.Validate(current) != nil || !operationPhaseAllowsPurpose(current.Phase, attempt.purpose) ||
		current.ID != plan.operationID || current.WorkspaceID != plan.workspaceID ||
		current.ResourceID != plan.resourceID || current.Generation != plan.generation ||
		!optionalIDsEqual(current.EnvironmentID, plan.environmentID) ||
		!optionalIDsEqual(current.ProviderConnectionID, plan.connectionID) ||
		authorization.ValidateDecision(decision) != nil || !decision.Allowed() ||
		decision.PolicyVersion().String() != plan.policyVersion ||
		decision.InputDigest().String() != plan.authorizationInput ||
		!providerBindingsEqual(providerBinding, plan.providerBinding) ||
		!capability.Equal(plan.capability) || !quota.Equal(plan.quota) || !cost.Equal(plan.cost) {
		return DispatchAuthority{}, ErrDispatchAuthority
	}
	return DispatchAuthority{
		initialized:        true,
		planDigest:         plan.digest,
		attemptBinding:     deriveAttemptDispatchBinding(attempt),
		authorizationInput: decision.InputDigest().String(),
		policyVersion:      decision.PolicyVersion().String(),
		observedAt:         now,
		use:                &atomic.Bool{},
	}, nil
}

// ObservedAt returns the exact authoritative-time sample bound to the checks.
func (value DispatchAuthority) ObservedAt() time.Time { return value.observedAt }

// DispatchPermit binds one exact live fence to an authorized RPC window.
type DispatchPermit struct {
	initialized    bool
	token          LeaseToken
	attemptBinding digestValue
	authorizedAt   time.Time
	deadline       time.Time
	use            *atomic.Bool
}

func (value DispatchPermit) Token() LeaseToken       { return value.token }
func (value DispatchPermit) AuthorizedAt() time.Time { return value.authorizedAt }
func (value DispatchPermit) Deadline() time.Time     { return value.deadline }

// AuthorizeDispatch atomically rechecks lease authority and the strict
// RPC-deadline-plus-margin rule immediately before mutation.
func (table *LeaseTable) AuthorizeDispatch(
	databaseTime time.Time,
	token LeaseToken,
	rpcTimeout time.Duration,
	authority DispatchAuthority,
) (DispatchPermit, error) {
	if table == nil || !table.initialized || validateLeaseToken(token) != nil ||
		validateDispatchAuthority(authority) != nil ||
		!authority.planDigest.Equal(token.binding.planDigest) || rpcTimeout <= 0 {
		return DispatchPermit{}, ErrDispatchAuthority
	}
	if token.table != table.identity {
		return DispatchPermit{}, ErrLeaseLost
	}
	now, err := normalizeTime(databaseTime)
	if err != nil {
		return DispatchPermit{}, fmt.Errorf("%w: %w", ErrDispatchAuthority, err)
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	key := leaseRowKey(token.binding)
	if err := table.observeNowLocked(key, now); err != nil {
		return DispatchPermit{}, err
	}
	if !authority.observedAt.Equal(now) {
		return DispatchPermit{}, ErrDispatchAuthority
	}
	row, ok := table.currentRowLocked(now, token)
	if !ok {
		return DispatchPermit{}, ErrLeaseLost
	}
	deadline, err := addNormalizedDuration(now, rpcTimeout)
	if err != nil || !deadline.After(now) || !deadline.Before(row.expiresAt.Add(-DispatchSafetyMargin)) {
		return DispatchPermit{}, ErrDispatchWindow
	}
	if !authority.use.CompareAndSwap(false, true) {
		return DispatchPermit{}, ErrDispatchAuthority
	}
	return DispatchPermit{
		initialized:    true,
		token:          tokenFromRow(row, table.identity),
		attemptBinding: authority.attemptBinding,
		authorizedAt:   now,
		deadline:       deadline,
		use:            &atomic.Bool{},
	}, nil
}

// StableRenewalInterval deterministically spreads work between 15 and 20 seconds.
func StableRenewalInterval(work WorkKey) (time.Duration, error) {
	if !validWorkKey(work) {
		return 0, ErrInvalidLease
	}
	spanMilliseconds := uint64((RenewalDeadline-RenewalJitterMinimum)/time.Millisecond) + 1
	offset := binary.BigEndian.Uint64(work.digest[:8]) % spanMilliseconds
	return RenewalJitterMinimum + time.Duration(offset)*time.Millisecond, nil
}

// VisibilityDeadline models ChangeMessageVisibility resetting, not extending,
// the interval from the successful call time.
func VisibilityDeadline(changedAt time.Time) (time.Time, error) {
	value, err := normalizeTime(changedAt)
	if err != nil {
		return time.Time{}, err
	}
	return addNormalizedDuration(value, QueueVisibilityDuration)
}

// Len returns the number of retained stable lineage rows.
func (table *LeaseTable) Len() int {
	if table == nil {
		return 0
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	return len(table.rows)
}

func (table *LeaseTable) observeNowLocked(key string, now time.Time) error {
	row, exists := table.rows[key]
	if !exists {
		return ErrLeaseLost
	}
	if !row.observedAt.IsZero() && now.Before(row.observedAt) {
		return ErrClockRegressed
	}
	if now.After(row.observedAt) {
		row.observedAt = now
		table.rows[key] = row
	}
	return nil
}

func (table *LeaseTable) currentRowLocked(now time.Time, token LeaseToken) (leaseRow, bool) {
	if token.table != table.identity {
		return leaseRow{}, false
	}
	row, exists := table.rows[leaseRowKey(token.binding)]
	if !exists || row.ownerID == "" || !now.Before(row.expiresAt) ||
		row.ownerID != token.ownerID || row.fence != token.fence || !row.binding.Equal(token.binding) {
		return leaseRow{}, false
	}
	return row, true
}

func validateLeaseBinding(value LeaseBinding) error {
	if !value.initialized || !validID(value.workspaceID) || !validID(value.resourceID) ||
		!validID(value.operationID) || value.generation < 1 || value.planRevision == 0 ||
		!value.planDigest.initialized {
		return ErrInvalidLease
	}
	return nil
}

func leaseBindingMovesForward(current, candidate LeaseBinding) bool {
	if candidate.generation < current.generation {
		return false
	}
	if candidate.generation == current.generation {
		return candidate.operationID == current.operationID &&
			current.planRevision < ^uint32(0) &&
			candidate.planRevision == current.planRevision+1
	}
	return candidate.operationID != current.operationID && candidate.planRevision == 1
}

func validateLeaseToken(value LeaseToken) error {
	if !value.initialized || value.table == nil || validateLeaseBinding(value.binding) != nil || !validID(value.ownerID) ||
		value.fence < 1 || value.acquiredAt.IsZero() || value.expiresAt.IsZero() ||
		value.expiresAt.Sub(value.acquiredAt) < StoreLeaseDuration {
		return ErrInvalidLease
	}
	return nil
}

func validateDispatchPermit(value DispatchPermit) error {
	if !value.initialized || validateLeaseToken(value.token) != nil || value.authorizedAt.IsZero() ||
		!value.attemptBinding.initialized || value.use == nil ||
		value.deadline.IsZero() || !value.deadline.After(value.authorizedAt) ||
		!value.deadline.Before(value.token.expiresAt.Add(-DispatchSafetyMargin)) {
		return ErrDispatchAuthority
	}
	return nil
}

func validateDispatchAuthority(value DispatchAuthority) error {
	observedAt, err := normalizeTime(value.observedAt)
	if !value.initialized || !value.planDigest.initialized || value.authorizationInput == "" ||
		!value.attemptBinding.initialized || value.policyVersion == "" || value.use == nil ||
		err != nil || !observedAt.Equal(value.observedAt) {
		return ErrDispatchAuthority
	}
	return nil
}

func leaseRowKey(value LeaseBinding) string {
	return value.workspaceID.String() + ":" + value.resourceID.String()
}

func tokenFromRow(row leaseRow, table *leaseTableIdentity) LeaseToken {
	return LeaseToken{
		initialized: true,
		table:       table,
		binding:     row.binding,
		ownerID:     row.ownerID,
		fence:       row.fence,
		acquiredAt:  row.acquiredAt,
		expiresAt:   row.expiresAt,
	}
}

func providerBindingsEqual(left, right *ProviderBinding) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func optionalIDsEqual(left, right *resource.ID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func operationPhaseAllowsPurpose(phase operation.Phase, purpose AttemptPurpose) bool {
	switch purpose {
	case AttemptPurposeForward, AttemptPurposeCompensation:
		return phase == operation.PhaseRunning
	case AttemptPurposeObservation, AttemptPurposeProviderCancel:
		return phase == operation.PhaseRunning || phase == operation.PhaseWaiting
	default:
		return false
	}
}

func (LeaseBinding) MarshalJSON() ([]byte, error)        { return nil, ErrSerializationForbidden }
func (LeaseBinding) MarshalText() ([]byte, error)        { return nil, ErrSerializationForbidden }
func (LeaseBinding) MarshalBinary() ([]byte, error)      { return nil, ErrSerializationForbidden }
func (LeaseBinding) GobEncode() ([]byte, error)          { return nil, ErrSerializationForbidden }
func (LeaseToken) MarshalJSON() ([]byte, error)          { return nil, ErrSerializationForbidden }
func (LeaseToken) MarshalText() ([]byte, error)          { return nil, ErrSerializationForbidden }
func (LeaseToken) MarshalBinary() ([]byte, error)        { return nil, ErrSerializationForbidden }
func (LeaseToken) GobEncode() ([]byte, error)            { return nil, ErrSerializationForbidden }
func (DispatchAuthority) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (DispatchAuthority) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (DispatchAuthority) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (DispatchAuthority) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (DispatchPermit) MarshalJSON() ([]byte, error)      { return nil, ErrSerializationForbidden }
func (DispatchPermit) MarshalText() ([]byte, error)      { return nil, ErrSerializationForbidden }
func (DispatchPermit) MarshalBinary() ([]byte, error)    { return nil, ErrSerializationForbidden }
func (DispatchPermit) GobEncode() ([]byte, error)        { return nil, ErrSerializationForbidden }
func (*LeaseTable) MarshalJSON() ([]byte, error)         { return nil, ErrSerializationForbidden }
func (*LeaseTable) MarshalText() ([]byte, error)         { return nil, ErrSerializationForbidden }
func (*LeaseTable) MarshalBinary() ([]byte, error)       { return nil, ErrSerializationForbidden }
func (*LeaseTable) GobEncode() ([]byte, error)           { return nil, ErrSerializationForbidden }
