// Package referenceauthorization binds the process-local reference lifecycle
// service to Veer's hierarchy-sealed PolicySet evaluator. It is an executable
// authorization harness, not a production identity, persistence, or worker
// implementation.
package referenceauthorization

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/isolation"
	"github.com/ArdurAI/veer/internal/core/domain/reconciliation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/service/reference"
)

const (
	defaultMaximumAdmissions = 4_096
	maximumWorkspaces        = isolation.MaxWorkspaceScopes
)

var (
	ErrInvalidConfiguration = errors.New("invalid reference authorization configuration")
	ErrDenied               = errors.New("reference authorization denied")
	ErrUnavailable          = errors.New("reference authorization unavailable")
	ErrStaleAuthorization   = errors.New("reference authorization is stale")
)

// Config provides the exclusively owned lifecycle service, private Workspace
// member directories, and the process-local admission bound.
type Config struct {
	Reference         *reference.Service
	MemberDirectories []authorization.MemberDirectory
	MaximumAdmissions int
}

type admission struct {
	principal       identity.Principal
	action          authorization.Action
	decision        authorization.Decision
	resourceTarget  authorization.Target
	operationTarget authorization.Target
}

type requestAdmission struct {
	operationID resource.ID
	resourceID  resource.ID
}

// Service serializes membership changes, policy evaluation, lifecycle
// mutations, and execution callbacks. Callers must not retain and separately
// mutate Config.Reference after successful construction.
type Service struct {
	mu          sync.Mutex
	reference   *reference.Service
	directories map[resource.ID]authorization.MemberDirectory
	admissions  map[resource.ID]admission
	requests    map[[sha256.Size]byte]requestAdmission
	maximum     int

	beforeReplaceMembersLock func()
}

// New validates and takes ownership of the supplied runtime configuration.
func New(config Config) (*Service, error) {
	if config.Reference == nil || len(config.MemberDirectories) == 0 ||
		len(config.MemberDirectories) > maximumWorkspaces {
		return nil, ErrInvalidConfiguration
	}
	maximum := config.MaximumAdmissions
	if maximum == 0 {
		maximum = defaultMaximumAdmissions
	}
	if maximum < 1 {
		return nil, ErrInvalidConfiguration
	}
	directories := make(map[resource.ID]authorization.MemberDirectory, len(config.MemberDirectories))
	for _, directory := range config.MemberDirectories {
		if authorization.ValidateMemberDirectory(directory) != nil {
			return nil, ErrInvalidConfiguration
		}
		workspaceID := directory.WorkspaceID()
		if _, exists := directories[workspaceID]; exists {
			return nil, ErrInvalidConfiguration
		}
		directories[workspaceID] = directory
	}
	return &Service{
		reference: config.Reference, directories: directories,
		admissions: make(map[resource.ID]admission, maximum),
		requests:   make(map[[sha256.Size]byte]requestAdmission, maximum), maximum: maximum,
	}, nil
}

// ReplaceMembers installs one complete private directory for an already-known
// Workspace. The same lock is held by execution callbacks, making revocation
// and process-local effects race-safe in this harness.
func (service *Service) ReplaceMembers(directory authorization.MemberDirectory) error {
	if service == nil || authorization.ValidateMemberDirectory(directory) != nil {
		return ErrInvalidConfiguration
	}
	if service.beforeReplaceMembersLock != nil {
		service.beforeReplaceMembersLock()
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	workspaceID := directory.WorkspaceID()
	if _, exists := service.directories[workspaceID]; !exists {
		return ErrInvalidConfiguration
	}
	service.directories[workspaceID] = directory
	return nil
}

// List evaluates resource.list independently for every retained row before
// that row can affect the returned page or cursor.
func (service *Service) List(ctx context.Context, query reference.ListQuery) (reference.Page, error) {
	if err := validateRequest(service, ctx, query.Principal); err != nil {
		return reference.Page{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if query.Kind == hierarchy.KindWorkspace {
		query.WorkspaceIDs = service.workspaceIDs()
	} else {
		query.WorkspaceIDs = nil
		if _, exists := service.directories[query.WorkspaceID]; !exists {
			return reference.Page{}, ErrDenied
		}
	}
	states := make(map[resource.ID]reference.AuthorizationState)
	return service.reference.ListWhere(ctx, query, func(
		value reference.Resource,
		resolve reference.AuthorizationStateResolver,
	) (bool, error) {
		workspaceID := value.Metadata.WorkspaceID()
		directory, exists := service.directories[workspaceID]
		if !exists {
			return false, nil
		}
		state, exists := states[workspaceID]
		if !exists {
			var err error
			state, err = resolve(workspaceID, directory)
			if err != nil {
				return false, classifyStateError(err)
			}
			states[workspaceID] = state
		}
		target, err := authorization.ResolveResourceTarget(state.Snapshot, value.Metadata.ID())
		if err != nil {
			return false, fmt.Errorf("%w: resolve list target", ErrUnavailable)
		}
		decision, err := evaluate(state, query.Principal, authorization.ActionResourceList, target)
		if err != nil {
			return false, err
		}
		return decision.Allowed(), nil
	})
}

// Get returns a resource only after resolving its retained hierarchy target
// and evaluating the current Workspace PolicySet.
func (service *Service) Get(
	ctx context.Context,
	principal identity.Principal,
	workspaceID resource.ID,
	id resource.ID,
) (reference.Resource, error) {
	if err := validateRequest(service, ctx, principal); err != nil {
		return reference.Resource{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	value, _, _, _, err := service.authorizeResource(
		ctx, principal, authorization.ActionResourceGet, workspaceID, id,
	)
	return value, err
}

// Create fails closed because the published reference server exposes only
// Workspace creation, which is reserved by the authorization matrix.
func (service *Service) Create(
	ctx context.Context,
	command reference.CreateCommand,
) (reference.MutationReceipt, error) {
	if err := validateRequest(service, ctx, command.Principal); err != nil {
		return reference.MutationReceipt{}, err
	}
	return reference.MutationReceipt{}, ErrDenied
}

// Replace authorizes the retained resource before persistence and records the
// exact admitted actor and decision for subsequent Plan binding.
func (service *Service) Replace(
	ctx context.Context,
	command reference.ReplaceCommand,
) (reference.MutationReceipt, error) {
	if err := validateRequest(service, ctx, command.Principal); err != nil {
		return reference.MutationReceipt{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	value, state, target, decision, err := service.authorizeResource(
		ctx, command.Principal, authorization.ActionResourceReplace, command.WorkspaceID, command.ResourceID,
	)
	if err != nil {
		return reference.MutationReceipt{}, err
	}
	command.Members = service.directories[value.Metadata.WorkspaceID()]
	return service.mutate(ctx, command.Principal, authorization.ActionResourceReplace,
		command.CanonicalTarget, command.IdempotencyKey, state, target, decision,
		func() (reference.MutationReceipt, error) { return service.reference.Replace(ctx, command) })
}

// Delete authorizes the retained resource before persistence and records the
// exact admitted actor and decision for subsequent Plan binding.
func (service *Service) Delete(
	ctx context.Context,
	command reference.DeleteCommand,
) (reference.MutationReceipt, error) {
	if err := validateRequest(service, ctx, command.Principal); err != nil {
		return reference.MutationReceipt{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if receipt, replay, err := service.replayDelete(ctx, command); replay {
		return receipt, err
	}
	_, state, target, decision, err := service.authorizeResource(
		ctx, command.Principal, authorization.ActionResourceDelete, command.WorkspaceID, command.ResourceID,
	)
	if err != nil {
		return reference.MutationReceipt{}, err
	}
	return service.mutate(ctx, command.Principal, authorization.ActionResourceDelete,
		command.CanonicalTarget, command.IdempotencyKey, state, target, decision,
		func() (reference.MutationReceipt, error) { return service.reference.Delete(ctx, command) })
}

// ReplaceStatus fails closed because status replacement is service-reserved.
func (service *Service) ReplaceStatus(
	ctx context.Context,
	command reference.StatusCommand,
) (reference.StatusReceipt, error) {
	if err := validateRequest(service, ctx, command.Principal); err != nil {
		return reference.StatusReceipt{}, err
	}
	return reference.StatusReceipt{}, ErrDenied
}

// GetOperation independently validates the Operation's retained bindings and
// evaluates operation.get against the current Workspace PolicySet.
func (service *Service) GetOperation(
	ctx context.Context,
	principal identity.Principal,
	id resource.ID,
) (reference.Operation, error) {
	if err := validateRequest(service, ctx, principal); err != nil {
		return reference.Operation{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	var value reference.Operation
	found := false
	for _, workspaceID := range service.workspaceIDs() {
		candidate, err := service.reference.GetOperation(ctx, principal, workspaceID, id)
		if errors.Is(err, reference.ErrNotFound) {
			continue
		}
		if err != nil {
			return reference.Operation{}, err
		}
		if found {
			return reference.Operation{}, fmt.Errorf("%w: duplicate Operation identity across Workspaces", ErrUnavailable)
		}
		value = candidate
		found = true
	}
	if !found {
		return reference.Operation{}, ErrDenied
	}
	state, err := service.authorizationState(ctx, value.Value.WorkspaceID)
	if err != nil {
		return reference.Operation{}, err
	}
	target, err := authorization.ResolveOperationTarget(
		state.Snapshot, value.Value.ID, value.Value.ResourceID, value.Value.WorkspaceID,
		value.Value.EnvironmentID, value.Value.ProviderConnectionID,
	)
	if err != nil {
		if _, lookupErr := state.Snapshot.Lookup(value.Value.ResourceID); lookupErr == nil {
			return reference.Operation{}, fmt.Errorf("%w: resolve Operation target", ErrUnavailable)
		}
		record, exists := service.admissions[id]
		if !exists || !operationTargetMatches(record.operationTarget, value) {
			return reference.Operation{}, fmt.Errorf("%w: resolve deleted Operation target", ErrUnavailable)
		}
		target = record.operationTarget
	}
	decision, err := evaluate(state, principal, authorization.ActionOperationGet, target)
	if err != nil {
		return reference.Operation{}, err
	}
	if !decision.Allowed() {
		return reference.Operation{}, ErrDenied
	}
	return value, nil
}

// NewPlan replaces caller-supplied Operation, Actor, and Authorization fields
// with the exact retained Operation and admission record before constructing
// the immutable Plan.
func (service *Service) NewPlan(
	ctx context.Context,
	operationID resource.ID,
	input reconciliation.PlanInput,
) (reconciliation.Plan, error) {
	if service == nil || ctx == nil || ctx.Err() != nil {
		if ctx != nil && ctx.Err() != nil {
			return reconciliation.Plan{}, ctx.Err()
		}
		return reconciliation.Plan{}, ErrInvalidConfiguration
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	record, exists := service.admissions[operationID]
	if !exists {
		return reconciliation.Plan{}, ErrDenied
	}
	current, err := service.reference.GetOperation(
		ctx, record.principal, record.operationTarget.WorkspaceID(), operationID,
	)
	if err != nil {
		return reconciliation.Plan{}, err
	}
	input.Operation = current.Value
	input.Actor = identity.ClonePrincipal(record.principal)
	input.Authorization = record.decision
	return reconciliation.NewPlan(input)
}

// WithExecutionAuthorization reloads current retained state, re-evaluates the
// admission action, validates its exact Plan bindings, and invokes effect only
// while membership/policy mutation remains excluded by this runtime.
//
// effect runs while the Service mutex is held and must not call back into this
// Service because the mutex is deliberately non-reentrant.
func (service *Service) WithExecutionAuthorization(
	ctx context.Context,
	plan reconciliation.Plan,
	effect func() error,
) error {
	if service == nil || ctx == nil || effect == nil || reconciliation.ValidatePlan(plan) != nil {
		return ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	record, exists := service.admissions[plan.OperationID()]
	if !exists || record.principal.Kind() != plan.ActorKind() ||
		record.principal.Fingerprint().String() != plan.ActorFingerprint() ||
		record.decision.PolicyVersion().String() != plan.PolicyVersion() ||
		record.decision.InputDigest().String() != plan.AuthorizationInput() {
		return ErrStaleAuthorization
	}
	currentOperation, err := service.reference.GetOperation(
		ctx, record.principal, plan.WorkspaceID(), plan.OperationID(),
	)
	if err != nil {
		return err
	}
	if currentOperation.Value.WorkspaceID != plan.WorkspaceID() ||
		currentOperation.Value.ResourceID != plan.ResourceID() ||
		currentOperation.Value.Generation != plan.Generation() {
		return ErrStaleAuthorization
	}
	state, err := service.authorizationState(ctx, plan.WorkspaceID())
	if err != nil {
		return err
	}
	target := record.resourceTarget
	if record.action != authorization.ActionResourceDelete {
		currentResource, err := service.reference.Get(
			ctx, record.principal, plan.WorkspaceID(), plan.ResourceID(),
		)
		if err != nil || currentResource.Metadata.Generation().Int64() != plan.Generation() {
			return ErrStaleAuthorization
		}
		target, err = authorization.ResolveResourceTarget(state.Snapshot, plan.ResourceID())
		if err != nil {
			return ErrStaleAuthorization
		}
	} else if authorization.ValidateTarget(target) != nil ||
		target.ObjectKind() != authorization.ObjectKindResource ||
		target.ResourceID() != plan.ResourceID() || target.WorkspaceID() != plan.WorkspaceID() {
		return ErrStaleAuthorization
	}
	decision, err := evaluate(state, record.principal, record.action, target)
	if err != nil {
		return err
	}
	if !decision.Allowed() {
		return ErrDenied
	}
	if decision.PolicyVersion().String() != plan.PolicyVersion() ||
		decision.InputDigest().String() != plan.AuthorizationInput() {
		return ErrStaleAuthorization
	}
	return effect()
}

func (service *Service) authorizeResource(
	ctx context.Context,
	principal identity.Principal,
	action authorization.Action,
	workspaceID resource.ID,
	id resource.ID,
) (reference.Resource, reference.AuthorizationState, authorization.Target, authorization.Decision, error) {
	value, err := service.reference.Get(ctx, principal, workspaceID, id)
	if err != nil {
		if errors.Is(err, reference.ErrNotFound) {
			return reference.Resource{}, reference.AuthorizationState{}, authorization.Target{}, authorization.Decision{}, ErrDenied
		}
		return reference.Resource{}, reference.AuthorizationState{}, authorization.Target{}, authorization.Decision{}, err
	}
	state, err := service.authorizationState(ctx, value.Metadata.WorkspaceID())
	if err != nil {
		return reference.Resource{}, reference.AuthorizationState{}, authorization.Target{}, authorization.Decision{}, err
	}
	target, err := authorization.ResolveResourceTarget(state.Snapshot, value.Metadata.ID())
	if err != nil {
		return reference.Resource{}, reference.AuthorizationState{}, authorization.Target{}, authorization.Decision{}, fmt.Errorf("%w: resolve resource target", ErrUnavailable)
	}
	decision, err := evaluate(state, principal, action, target)
	if err != nil {
		return reference.Resource{}, reference.AuthorizationState{}, authorization.Target{}, authorization.Decision{}, err
	}
	if !decision.Allowed() {
		return reference.Resource{}, reference.AuthorizationState{}, authorization.Target{}, authorization.Decision{}, ErrDenied
	}
	return value, state, target, decision, nil
}

func (service *Service) authorizationState(
	ctx context.Context,
	workspaceID resource.ID,
) (reference.AuthorizationState, error) {
	directory, exists := service.directories[workspaceID]
	if !exists {
		return reference.AuthorizationState{}, ErrDenied
	}
	state, err := service.reference.LoadAuthorizationState(ctx, workspaceID, directory)
	if err != nil {
		return reference.AuthorizationState{}, classifyStateError(err)
	}
	return state, nil
}

func evaluate(
	state reference.AuthorizationState,
	principal identity.Principal,
	action authorization.Action,
	target authorization.Target,
) (authorization.Decision, error) {
	decision, err := state.Policies.Evaluate(authorization.Input{
		Principal: principal, Action: action, Target: target,
	})
	if err != nil {
		return authorization.Decision{}, fmt.Errorf("%w: evaluate policy", ErrUnavailable)
	}
	return decision, nil
}

func (service *Service) mutate(
	ctx context.Context,
	principal identity.Principal,
	action authorization.Action,
	target string,
	idempotencyKey string,
	state reference.AuthorizationState,
	resourceTarget authorization.Target,
	decision authorization.Decision,
	mutation func() (reference.MutationReceipt, error),
) (reference.MutationReceipt, error) {
	key := admissionRequestKey(
		principal, resourceTarget.WorkspaceID(), action, target, idempotencyKey,
	)
	existing, replay := service.requests[key]
	if replay {
		if existing.resourceID != resourceTarget.ResourceID() {
			return reference.MutationReceipt{}, fmt.Errorf("%w: admission replay target mismatch", ErrUnavailable)
		}
		if _, exists := service.admissions[existing.operationID]; !exists {
			return reference.MutationReceipt{}, fmt.Errorf("%w: admission replay record missing", ErrUnavailable)
		}
	}
	if !replay && len(service.admissions) >= service.maximum {
		return reference.MutationReceipt{}, reference.ErrCapacity
	}
	receipt, err := mutation()
	if err != nil {
		return reference.MutationReceipt{}, err
	}
	if receipt.ResourceID != resourceTarget.ResourceID() {
		return reference.MutationReceipt{}, fmt.Errorf("%w: admission result target mismatch", ErrUnavailable)
	}
	if replay && existing.operationID == receipt.OperationID {
		return receipt, nil
	}
	operationValue, err := service.reference.GetOperation(
		ctx, principal, resourceTarget.WorkspaceID(), receipt.OperationID,
	)
	if err != nil {
		return reference.MutationReceipt{}, fmt.Errorf("%w: load admitted Operation", ErrUnavailable)
	}
	operationTarget, err := authorization.ResolveOperationTarget(
		state.Snapshot, operationValue.Value.ID, operationValue.Value.ResourceID,
		operationValue.Value.WorkspaceID, operationValue.Value.EnvironmentID,
		operationValue.Value.ProviderConnectionID,
	)
	if err != nil {
		return reference.MutationReceipt{}, fmt.Errorf("%w: seal admitted Operation", ErrUnavailable)
	}
	if replay {
		delete(service.admissions, existing.operationID)
	}
	service.admissions[receipt.OperationID] = admission{
		principal: identity.ClonePrincipal(principal), action: action, decision: decision,
		resourceTarget: resourceTarget, operationTarget: operationTarget,
	}
	service.requests[key] = requestAdmission{operationID: receipt.OperationID, resourceID: receipt.ResourceID}
	return receipt, nil
}

func (service *Service) replayDelete(
	ctx context.Context,
	command reference.DeleteCommand,
) (reference.MutationReceipt, bool, error) {
	key := admissionRequestKey(
		command.Principal, command.WorkspaceID, authorization.ActionResourceDelete,
		command.CanonicalTarget, command.IdempotencyKey,
	)
	existing, replay := service.requests[key]
	if !replay {
		return reference.MutationReceipt{}, false, nil
	}
	record, exists := service.admissions[existing.operationID]
	if !exists || record.action != authorization.ActionResourceDelete ||
		existing.resourceID != command.ResourceID || record.resourceTarget.ResourceID() != command.ResourceID {
		return reference.MutationReceipt{}, true, fmt.Errorf("%w: invalid delete replay", ErrUnavailable)
	}
	receipt, err := service.reference.Delete(ctx, command)
	if errors.Is(err, reference.ErrNotFound) {
		return reference.MutationReceipt{}, true, ErrDenied
	}
	if err != nil {
		return reference.MutationReceipt{}, true, err
	}
	if receipt.OperationID != existing.operationID || receipt.ResourceID != existing.resourceID {
		return reference.MutationReceipt{}, true, fmt.Errorf("%w: delete replay mismatch", ErrUnavailable)
	}
	return receipt, true, nil
}

func operationTargetMatches(target authorization.Target, value reference.Operation) bool {
	if authorization.ValidateTarget(target) != nil || target.ObjectKind() != authorization.ObjectKindOperation ||
		target.ObjectID() != value.Value.ID || target.ResourceID() != value.Value.ResourceID ||
		target.WorkspaceID() != value.Value.WorkspaceID {
		return false
	}
	providerID, providerPresent := target.ProviderConnectionID()
	if value.Value.EnvironmentID == nil && value.Value.ProviderConnectionID == nil {
		return !providerPresent
	}
	environmentID, environmentPresent := target.EnvironmentID()
	return optionalIDEqual(environmentID, environmentPresent, value.Value.EnvironmentID) &&
		optionalIDEqual(providerID, providerPresent, value.Value.ProviderConnectionID)
}

// workspaceIDs returns the configured stable scopes in deterministic order.
// The caller holds service.mu.
func (service *Service) workspaceIDs() []resource.ID {
	result := make([]resource.ID, 0, len(service.directories))
	for workspaceID := range service.directories {
		result = append(result, workspaceID)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].String() < result[right].String()
	})
	return result
}

func optionalIDEqual(value resource.ID, present bool, expected *resource.ID) bool {
	if expected == nil {
		return !present
	}
	return present && value == *expected
}

func admissionRequestKey(
	principal identity.Principal,
	workspaceID resource.ID,
	action authorization.Action,
	target string,
	idempotencyKey string,
) [sha256.Size]byte {
	hasher := sha256.New()
	var size [8]byte
	writeFrame := func(value string) {
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hasher.Write(size[:])
		_, _ = hasher.Write([]byte(value))
	}
	writeFrame("veer.reference.authorization-request.v1")
	writeFrame(principal.Fingerprint().String())
	writeFrame(workspaceID.String())
	writeFrame(action.String())
	writeFrame(target)
	writeFrame(idempotencyKey)
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func classifyStateError(err error) error {
	if errors.Is(err, authorization.ErrMemberNotFound) {
		return ErrDenied
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, reference.ErrNotFound) {
		return err
	}
	return fmt.Errorf("%w: load authorization state", ErrUnavailable)
}

func validateRequest(service *Service, ctx context.Context, principal identity.Principal) error {
	if service == nil || ctx == nil || identity.ValidatePrincipal(principal) != nil {
		return ErrInvalidConfiguration
	}
	return ctx.Err()
}
