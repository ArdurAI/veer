package reference

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/admission"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/model"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/reconciliation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
)

var resourceVersionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type replayKind uint8

const (
	replayMutation replayKind = iota + 1
	replayStatus
)

type replayRecord struct {
	kind        replayKind
	fingerprint reconciliation.RequestFingerprint
	epoch       uint64
	expiresAt   time.Time
	mutation    MutationReceipt
	status      StatusReceipt
}

// Service serializes the process-local idempotency oracle with reference-store
// transactions. It makes no durable recovery or provider execution claim.
type Service struct {
	mu sync.Mutex

	store      ports.ReferenceStore
	clock      Clock
	issuer     Issuer
	tokenKey   []byte
	tokenLimit int
	ledger     *reconciliation.IdempotencyLedger
	replays    map[string]replayRecord
	tokens     map[string]pageTokenRecord
}

// New validates and owns all configuration inputs.
func New(config Config) (*Service, error) {
	if config.Store == nil || config.Clock == nil || config.Issuer == nil || len(config.PageTokenKey) < 32 {
		return nil, ErrInvalidConfiguration
	}
	tokenLimit := config.MaximumPageTokens
	if tokenLimit == 0 {
		tokenLimit = defaultTokenLimit
	}
	replayLimit := config.MaximumReplays
	if replayLimit == 0 {
		replayLimit = defaultReplayLimit
	}
	if tokenLimit < 1 || replayLimit < 1 {
		return nil, ErrInvalidConfiguration
	}
	ledger, err := reconciliation.NewIdempotencyLedger(replayLimit)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return &Service{
		store: config.Store, clock: config.Clock, issuer: config.Issuer,
		tokenKey: append([]byte(nil), config.PageTokenKey...), tokenLimit: tokenLimit,
		ledger: ledger, replays: make(map[string]replayRecord, replayLimit),
		tokens: make(map[string]pageTokenRecord, tokenLimit),
	}, nil
}

// Create admits and atomically stores one desired-state resource and Pending
// operation, or returns the original logical receipt for a live keyed replay.
func (service *Service) Create(ctx context.Context, command CreateCommand) (MutationReceipt, error) {
	if service == nil {
		return MutationReceipt{}, ErrInvalidConfiguration
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.validateMutation(ctx, command.Principal, command.CanonicalTarget, command.IdempotencyKey); err != nil {
		return MutationReceipt{}, err
	}
	if _, err := hierarchy.ParseKind(command.Kind.String()); err != nil || len(command.Body) == 0 {
		return MutationReceipt{}, ErrInvalidCommand
	}
	normalized, err := admission.NormalizeIntent(command.Body)
	if err != nil {
		return MutationReceipt{}, err
	}
	if normalized.Kind() != command.Kind {
		return MutationReceipt{}, ErrInvalidCommand
	}
	canonical, err := canonicalIntent(normalized)
	if err != nil {
		return MutationReceipt{}, err
	}
	now := service.clock.Now()
	fingerprint, scope, key, err := service.idempotencyIdentity(
		command.Principal, "POST", command.CanonicalTarget, command.IdempotencyKey, canonical,
	)
	if err != nil {
		return MutationReceipt{}, err
	}
	if replay, found, err := service.liveReplay(now, scope, command.IdempotencyKey, key, fingerprint, replayMutation); found || err != nil {
		return replay.mutation, err
	}

	id, err := service.issuer.ResourceID(command.Kind)
	if err != nil {
		return MutationReceipt{}, fmt.Errorf("%w: issue resource identity", ErrInternal)
	}
	var receipt MutationReceipt
	var completed replayRecord
	err = service.store.Update(context.WithoutCancel(ctx), func(tx ports.ReferenceTransaction) error {
		resources, err := loadResources(tx)
		if err != nil {
			return err
		}
		if _, exists := findResource(resources, id); exists {
			return fmt.Errorf("%w: issued identity collision", ErrInternal)
		}

		createContext := admission.CreateContext{ID: id, ParentID: cloneID(command.ParentID), Members: command.Members}
		if command.Kind == hierarchy.KindWorkspace {
			if command.WorkspaceID != "" || command.ParentID != nil {
				return ErrInvalidCommand
			}
		} else {
			if _, err := resource.ParseID(command.WorkspaceID.String()); err != nil || command.ParentID == nil {
				return ErrInvalidCommand
			}
			snapshot, err := snapshotFor(resources, command.WorkspaceID)
			if err != nil {
				return err
			}
			createContext.Snapshot = snapshot
		}
		admitted, err := admission.AdmitCreate(command.Body, createContext)
		if err != nil {
			return err
		}
		if !model.EqualIntent(normalized, admitted.Intent()) {
			return fmt.Errorf("%w: normalized create drift", ErrInternal)
		}
		version, err := service.issuer.ResourceVersion()
		if err != nil {
			return fmt.Errorf("%w: issue resource version", ErrInternal)
		}
		created, err := newResource(admitted, version, now)
		if err != nil {
			return err
		}
		operationValue, operationBytes, err := service.newOperation(created.Metadata, now)
		if err != nil {
			return err
		}
		receipt = MutationReceipt{
			ResourceID: id, OperationID: operationValue.ID,
			Generation: created.Metadata.Generation().Int64(), ResourceVersion: created.Metadata.ResourceVersion().String(),
			AcceptedAt: formatTimestamp(now),
		}
		reservation, err := service.reserveFresh(now, scope, command.IdempotencyKey, fingerprint)
		if err != nil {
			return err
		}
		completed, err = service.completeReplay(reservation, key, replayRecord{kind: replayMutation, mutation: receipt})
		if err != nil {
			return err
		}
		tx.PutResource(id, created.Canonical)
		tx.PutOperation(operationValue.ID, operationBytes)
		return nil
	})
	if err != nil {
		return MutationReceipt{}, err
	}
	service.saveReplay(now, key, completed)
	return receipt, nil
}

// Replace applies one full caller-owned desired-state replacement.
func (service *Service) Replace(ctx context.Context, command ReplaceCommand) (MutationReceipt, error) {
	if service == nil {
		return MutationReceipt{}, ErrInvalidConfiguration
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.validateAddressedMutation(
		ctx, command.Principal, command.Kind, command.ResourceID, command.ExpectedResourceVersion,
		command.CanonicalTarget, command.IdempotencyKey,
	); err != nil {
		return MutationReceipt{}, err
	}
	normalized, err := admission.NormalizeIntent(command.Body)
	if err != nil {
		return MutationReceipt{}, err
	}
	if normalized.Kind() != command.Kind {
		return MutationReceipt{}, ErrInvalidCommand
	}
	canonical, err := canonicalIntent(normalized)
	if err != nil {
		return MutationReceipt{}, err
	}
	now := service.clock.Now()
	fingerprint, scope, key, err := service.idempotencyIdentity(
		command.Principal, "PUT", command.CanonicalTarget, command.IdempotencyKey, canonical,
	)
	if err != nil {
		return MutationReceipt{}, err
	}
	if replay, found, err := service.liveReplay(now, scope, command.IdempotencyKey, key, fingerprint, replayMutation); found || err != nil {
		return replay.mutation, err
	}

	var receipt MutationReceipt
	var completed replayRecord
	err = service.store.Update(context.WithoutCancel(ctx), func(tx ports.ReferenceTransaction) error {
		resources, err := loadResources(tx)
		if err != nil {
			return err
		}
		current, exists := findResource(resources, command.ResourceID)
		if !exists {
			return ErrNotFound
		}
		if current.Kind != command.Kind {
			return ErrNotFound
		}
		if current.Metadata.ResourceVersion().String() != command.ExpectedResourceVersion {
			return &PreconditionError{CurrentResourceVersion: current.Metadata.ResourceVersion().String()}
		}
		snapshot, err := snapshotFor(resources, current.Metadata.WorkspaceID())
		if err != nil {
			return err
		}
		record, err := hierarchyRecord(current)
		if err != nil {
			return err
		}
		provider, err := providerSpec(current)
		if err != nil {
			return err
		}
		admitted, err := admission.AdmitReplace(command.Body, record, admission.ReplaceContext{
			Snapshot: snapshot, Members: command.Members, CurrentProviderConnectionSpec: provider,
		})
		if err != nil {
			return err
		}
		if !model.EqualIntent(normalized, admitted) {
			return fmt.Errorf("%w: normalized replacement drift", ErrInternal)
		}
		version, err := service.issuer.ResourceVersion()
		if err != nil {
			return fmt.Errorf("%w: issue resource version", ErrInternal)
		}
		replaced, err := replaceResource(current, admitted, version, now)
		if err != nil {
			return err
		}
		operationValue, operationBytes, err := service.newOperation(replaced.Metadata, now)
		if err != nil {
			return err
		}
		receipt = MutationReceipt{
			ResourceID: command.ResourceID, OperationID: operationValue.ID,
			Generation: replaced.Metadata.Generation().Int64(), ResourceVersion: replaced.Metadata.ResourceVersion().String(),
			AcceptedAt: formatTimestamp(now),
		}
		reservation, err := service.reserveFresh(now, scope, command.IdempotencyKey, fingerprint)
		if err != nil {
			return err
		}
		completed, err = service.completeReplay(reservation, key, replayRecord{kind: replayMutation, mutation: receipt})
		if err != nil {
			return err
		}
		tx.PutResource(command.ResourceID, replaced.Canonical)
		tx.PutOperation(operationValue.ID, operationBytes)
		return nil
	})
	if err != nil {
		return MutationReceipt{}, err
	}
	service.saveReplay(now, key, completed)
	return receipt, nil
}

// Delete enforces the hierarchy's RESTRICT rule and removes one resource from
// the reference store while retaining its accepted Pending operation.
func (service *Service) Delete(ctx context.Context, command DeleteCommand) (MutationReceipt, error) {
	if service == nil {
		return MutationReceipt{}, ErrInvalidConfiguration
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.validateAddressedMutation(
		ctx, command.Principal, command.Kind, command.ResourceID, command.ExpectedResourceVersion,
		command.CanonicalTarget, command.IdempotencyKey,
	); err != nil {
		return MutationReceipt{}, err
	}
	canonical := []byte(`{"delete":true}`)
	now := service.clock.Now()
	fingerprint, scope, key, err := service.idempotencyIdentity(
		command.Principal, "DELETE", command.CanonicalTarget, command.IdempotencyKey, canonical,
	)
	if err != nil {
		return MutationReceipt{}, err
	}
	if replay, found, err := service.liveReplay(now, scope, command.IdempotencyKey, key, fingerprint, replayMutation); found || err != nil {
		return replay.mutation, err
	}

	var receipt MutationReceipt
	var completed replayRecord
	err = service.store.Update(context.WithoutCancel(ctx), func(tx ports.ReferenceTransaction) error {
		resources, err := loadResources(tx)
		if err != nil {
			return err
		}
		current, exists := findResource(resources, command.ResourceID)
		if !exists {
			return ErrNotFound
		}
		if current.Kind != command.Kind {
			return ErrNotFound
		}
		if current.Metadata.ResourceVersion().String() != command.ExpectedResourceVersion {
			return &PreconditionError{CurrentResourceVersion: current.Metadata.ResourceVersion().String()}
		}
		snapshot, err := snapshotFor(resources, current.Metadata.WorkspaceID())
		if err != nil {
			return err
		}
		if err := snapshot.CheckDelete(command.ResourceID); err != nil {
			if errors.Is(err, hierarchy.ErrDeleteRestricted) {
				return ErrLifecycleConflict
			}
			return fmt.Errorf("%w: delete precondition", ErrInternal)
		}
		deletedVersion, err := service.issuer.ResourceVersion()
		if err != nil {
			return fmt.Errorf("%w: issue deletion version", ErrInternal)
		}
		operationValue, operationBytes, err := service.newOperation(current.Metadata, now)
		if err != nil {
			return err
		}
		receipt = MutationReceipt{
			ResourceID: command.ResourceID, OperationID: operationValue.ID,
			Generation: current.Metadata.Generation().Int64(), ResourceVersion: deletedVersion,
			AcceptedAt: formatTimestamp(now),
		}
		reservation, err := service.reserveFresh(now, scope, command.IdempotencyKey, fingerprint)
		if err != nil {
			return err
		}
		completed, err = service.completeReplay(reservation, key, replayRecord{kind: replayMutation, mutation: receipt})
		if err != nil {
			return err
		}
		tx.DeleteResource(command.ResourceID)
		tx.PutOperation(operationValue.ID, operationBytes)
		return nil
	})
	if err != nil {
		return MutationReceipt{}, err
	}
	service.saveReplay(now, key, completed)
	return receipt, nil
}

// ReplaceStatus applies one generation-bounded status-only write.
func (service *Service) ReplaceStatus(ctx context.Context, command StatusCommand) (StatusReceipt, error) {
	if service == nil {
		return StatusReceipt{}, ErrInvalidConfiguration
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.validateAddressedMutation(
		ctx, command.Principal, command.Kind, command.ResourceID, command.ExpectedResourceVersion,
		command.CanonicalTarget, command.IdempotencyKey,
	); err != nil {
		return StatusReceipt{}, err
	}
	normalized, err := admission.NormalizeStatus(command.Body)
	if err != nil {
		return StatusReceipt{}, err
	}
	if normalized.Kind() != command.Kind {
		return StatusReceipt{}, ErrInvalidCommand
	}
	canonical, err := canonicalStatus(normalized)
	if err != nil {
		return StatusReceipt{}, err
	}
	now := service.clock.Now()
	fingerprint, scope, key, err := service.idempotencyIdentity(
		command.Principal, "PUT", command.CanonicalTarget, command.IdempotencyKey, canonical,
	)
	if err != nil {
		return StatusReceipt{}, err
	}
	if replay, found, err := service.liveReplay(now, scope, command.IdempotencyKey, key, fingerprint, replayStatus); found || err != nil {
		return replay.status, err
	}

	var receipt StatusReceipt
	var completed replayRecord
	err = service.store.Update(context.WithoutCancel(ctx), func(tx ports.ReferenceTransaction) error {
		resources, err := loadResources(tx)
		if err != nil {
			return err
		}
		current, exists := findResource(resources, command.ResourceID)
		if !exists {
			return ErrNotFound
		}
		if current.Kind != command.Kind {
			return ErrNotFound
		}
		if current.Metadata.ResourceVersion().String() != command.ExpectedResourceVersion {
			return &PreconditionError{CurrentResourceVersion: current.Metadata.ResourceVersion().String()}
		}
		snapshot, err := snapshotFor(resources, current.Metadata.WorkspaceID())
		if err != nil {
			return err
		}
		record, err := hierarchyRecord(current)
		if err != nil {
			return err
		}
		admitted, err := admission.AdmitStatus(
			command.Body, record, current.Metadata.Generation().Int64(), snapshot,
		)
		if err != nil {
			return err
		}
		actualCanonical, err := canonicalStatus(admitted)
		if err != nil || !bytes.Equal(canonical, actualCanonical) {
			return fmt.Errorf("%w: normalized status drift", ErrInternal)
		}
		version, err := service.issuer.ResourceVersion()
		if err != nil {
			return fmt.Errorf("%w: issue status version", ErrInternal)
		}
		replaced, err := replaceResourceStatus(current, admitted, version, now)
		if err != nil {
			return err
		}
		observations := admitted.ObservedGenerations()
		if len(observations) == 0 {
			return fmt.Errorf("%w: missing status observation", ErrInternal)
		}
		receipt = StatusReceipt{
			ResourceID: command.ResourceID, ObservedGeneration: observations[0],
			ResourceVersion: replaced.Metadata.ResourceVersion().String(),
			UpdatedAt:       formatTimestamp(replaced.Metadata.UpdatedAt()),
		}
		reservation, err := service.reserveFresh(now, scope, command.IdempotencyKey, fingerprint)
		if err != nil {
			return err
		}
		completed, err = service.completeReplay(reservation, key, replayRecord{kind: replayStatus, status: receipt})
		if err != nil {
			return err
		}
		tx.PutResource(command.ResourceID, replaced.Canonical)
		return nil
	})
	if err != nil {
		return StatusReceipt{}, err
	}
	service.saveReplay(now, key, completed)
	return receipt, nil
}

// Get returns one ownership-safe canonical resource snapshot.
func (service *Service) Get(ctx context.Context, principal identity.Principal, id resource.ID) (Resource, error) {
	if service == nil {
		return Resource{}, ErrInvalidConfiguration
	}
	if ctx == nil || identity.ValidatePrincipal(principal) != nil || resourceIDInvalid(id) {
		return Resource{}, ErrInvalidCommand
	}
	var result Resource
	err := service.store.View(ctx, func(reader ports.ReferenceReader) error {
		data, exists := reader.GetResource(id)
		if !exists {
			return ErrNotFound
		}
		value, err := decodeResource(data)
		if err != nil {
			return err
		}
		result = cloneResource(value)
		return nil
	})
	return result, err
}

// GetOperation returns one validated canonical operation snapshot.
func (service *Service) GetOperation(ctx context.Context, principal identity.Principal, id resource.ID) (Operation, error) {
	if service == nil {
		return Operation{}, ErrInvalidConfiguration
	}
	if ctx == nil || identity.ValidatePrincipal(principal) != nil || resourceIDInvalid(id) {
		return Operation{}, ErrInvalidCommand
	}
	var result Operation
	err := service.store.View(ctx, func(reader ports.ReferenceReader) error {
		data, exists := reader.GetOperation(id)
		if !exists {
			return ErrNotFound
		}
		value, err := operation.UnmarshalCanonical(data)
		if err != nil {
			return fmt.Errorf("%w: invalid stored operation", ErrInternal)
		}
		canonical, err := operation.MarshalCanonical(value)
		if err != nil || !bytes.Equal(canonical, data) {
			return fmt.Errorf("%w: noncanonical stored operation", ErrInternal)
		}
		result = Operation{Canonical: canonical, Value: value}
		return nil
	})
	return result, err
}

func (service *Service) newOperation(metadata resource.Metadata, now time.Time) (operation.Operation, []byte, error) {
	id, err := service.issuer.OperationID()
	if err != nil {
		return operation.Operation{}, nil, fmt.Errorf("%w: issue operation identity", ErrInternal)
	}
	version, err := service.issuer.ResourceVersion()
	if err != nil {
		return operation.Operation{}, nil, fmt.Errorf("%w: issue operation version", ErrInternal)
	}
	value, err := operation.New(operation.Input{
		ID: id, WorkspaceID: metadata.WorkspaceID(), ResourceID: metadata.ID(),
		Generation: metadata.Generation().Int64(), ResourceVersion: version, CreatedAt: now,
	})
	if err != nil {
		return operation.Operation{}, nil, err
	}
	canonical, err := operation.MarshalCanonical(value)
	if err != nil {
		return operation.Operation{}, nil, err
	}
	return value, canonical, nil
}

func (service *Service) validateMutation(
	ctx context.Context,
	principal identity.Principal,
	target, key string,
) error {
	if service == nil || ctx == nil || ctx.Err() != nil || identity.ValidatePrincipal(principal) != nil ||
		len(target) == 0 || len(target) > reconciliation.MaxEvidenceBytes || len(key) == 0 {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrInvalidCommand
	}
	return nil
}

func (service *Service) validateAddressedMutation(
	ctx context.Context,
	principal identity.Principal,
	kind hierarchy.Kind,
	id resource.ID,
	version, target, key string,
) error {
	if err := service.validateMutation(ctx, principal, target, key); err != nil {
		return err
	}
	if _, err := hierarchy.ParseKind(kind.String()); err != nil {
		return ErrInvalidCommand
	}
	if resourceIDInvalid(id) || !resourceVersionPattern.MatchString(version) {
		return ErrInvalidCommand
	}
	return nil
}

func (service *Service) idempotencyIdentity(
	principal identity.Principal,
	method, target, key string,
	canonical []byte,
) (reconciliation.RequestFingerprint, reconciliation.IdempotencyScope, string, error) {
	fingerprint, err := reconciliation.NewRequestFingerprint(canonical)
	if err != nil {
		return reconciliation.RequestFingerprint{}, reconciliation.IdempotencyScope{}, "", ErrInvalidCommand
	}
	scope, err := reconciliation.NewIdempotencyScope(principal, method, []byte(target))
	if err != nil {
		return reconciliation.RequestFingerprint{}, reconciliation.IdempotencyScope{}, "", ErrInvalidCommand
	}
	return fingerprint, scope, service.replayMapKey(principal, method, target, key), nil
}

func (service *Service) liveReplay(
	now time.Time,
	scope reconciliation.IdempotencyScope,
	rawKey, mapKey string,
	fingerprint reconciliation.RequestFingerprint,
	kind replayKind,
) (replayRecord, bool, error) {
	current, exists := service.replays[mapKey]
	if !exists || !now.Before(current.expiresAt) {
		return replayRecord{}, false, nil
	}
	if current.kind != kind || !current.fingerprint.Equal(fingerprint) {
		return replayRecord{}, true, ErrIdempotencyConflict
	}
	reservation, disposition, err := service.ledger.Reserve(now, scope, rawKey, fingerprint)
	if err != nil {
		if errors.Is(err, reconciliation.ErrIdempotencyConflict) {
			return replayRecord{}, true, ErrIdempotencyConflict
		}
		return replayRecord{}, true, fmt.Errorf("%w: replay reservation", ErrInternal)
	}
	if disposition != reconciliation.IdempotencyReplay || !reservation.Completed() || reservation.Epoch() != current.epoch {
		return replayRecord{}, true, ErrReplayUnavailable
	}
	return current, true, nil
}

func (service *Service) reserveFresh(
	now time.Time,
	scope reconciliation.IdempotencyScope,
	key string,
	fingerprint reconciliation.RequestFingerprint,
) (reconciliation.Reservation, error) {
	reservation, disposition, err := service.ledger.Reserve(now, scope, key, fingerprint)
	if errors.Is(err, reconciliation.ErrIdempotencyConflict) {
		return reconciliation.Reservation{}, ErrIdempotencyConflict
	}
	if errors.Is(err, reconciliation.ErrInvalidIdempotency) {
		return reconciliation.Reservation{}, ErrInvalidCommand
	}
	if errors.Is(err, reconciliation.ErrCapacity) {
		return reconciliation.Reservation{}, ErrCapacity
	}
	if err != nil {
		return reconciliation.Reservation{}, fmt.Errorf("%w: reserve idempotency", ErrInternal)
	}
	if disposition != reconciliation.IdempotencyReserved {
		return reconciliation.Reservation{}, ErrReplayUnavailable
	}
	return reservation, nil
}

func (service *Service) completeReplay(
	reservation reconciliation.Reservation,
	mapKey string,
	result replayRecord,
) (replayRecord, error) {
	canonical, err := json.Marshal(result.semanticValue())
	if err != nil {
		return replayRecord{}, fmt.Errorf("%w: encode replay result", ErrInternal)
	}
	digest, err := reconciliation.NewResultDigest(canonical)
	if err != nil {
		return replayRecord{}, fmt.Errorf("%w: digest replay result", ErrInternal)
	}
	completed, err := service.ledger.Complete(reservation, digest)
	if err != nil {
		return replayRecord{}, fmt.Errorf("%w: complete idempotency", ErrInternal)
	}
	result.fingerprint = reservation.Fingerprint()
	result.epoch = completed.Epoch()
	result.expiresAt = completed.ExpiresAt()
	_ = mapKey
	return result, nil
}

func (record replayRecord) semanticValue() any {
	if record.kind == replayStatus {
		return record.status
	}
	return record.mutation
}

func (service *Service) saveReplay(now time.Time, key string, record replayRecord) {
	for existing, value := range service.replays {
		if !now.Before(value.expiresAt) {
			delete(service.replays, existing)
		}
	}
	service.replays[key] = record
}

func (service *Service) replayMapKey(principal identity.Principal, method, target, key string) string {
	hasher := hmac.New(sha256.New, service.tokenKey)
	writeFrame := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hasher.Write(size[:])
		_, _ = hasher.Write([]byte(value))
	}
	writeFrame("veer.reference.replay.v1")
	writeFrame(principal.Fingerprint().String())
	writeFrame(method)
	writeFrame(target)
	writeFrame(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

func loadResources(reader ports.ReferenceReader) ([]Resource, error) {
	canonical := reader.ListResources()
	result := make([]Resource, 0, len(canonical))
	for _, data := range canonical {
		value, err := decodeResource(data)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func findResource(resources []Resource, id resource.ID) (Resource, bool) {
	for _, value := range resources {
		if value.Metadata.ID() == id {
			return cloneResource(value), true
		}
	}
	return Resource{}, false
}

func cloneResource(value Resource) Resource {
	value.Canonical = bytes.Clone(value.Canonical)
	return value
}

func cloneID(value *resource.ID) *resource.ID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func resourceIDInvalid(id resource.ID) bool {
	_, err := resource.ParseID(id.String())
	return err != nil
}

func formatTimestamp(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format(timestampLayout)
}
