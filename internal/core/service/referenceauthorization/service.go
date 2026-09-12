// Package referenceauthorization binds the process-local reference lifecycle
// service to Veer's hierarchy-sealed PolicySet evaluator. It is an executable
// authorization harness, not a production identity, persistence, or worker
// implementation.
package referenceauthorization

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/reconciliation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/service/reference"
)

const (
	defaultMaximumAdmissions = 4_096
	maximumWorkspaces        = 4_096
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
	principal identity.Principal
	action    authorization.Action
	decision  authorization.Decision
}

// Service serializes membership changes, policy evaluation, lifecycle
// mutations, and execution callbacks. Callers must not retain and separately
// mutate Config.Reference after successful construction.
type Service struct {
	mu          sync.Mutex
	reference   *reference.Service
	directories map[resource.ID]authorization.MemberDirectory
	admissions  map[resource.ID]admission
	requests    map[[sha256.Size]byte]resource.ID
	maximum     int
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
		requests:   make(map[[sha256.Size]byte]resource.ID, maximum), maximum: maximum,
	}, nil
}

// ReplaceMembers installs one complete private directory for an already-known
// Workspace. The same lock is held by execution callbacks, making revocation
// and process-local effects race-safe in this harness.
func (service *Service) ReplaceMembers(directory authorization.MemberDirectory) error {
	if service == nil || authorization.ValidateMemberDirectory(directory) != nil {
		return ErrInvalidConfiguration
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
	id resource.ID,
) (reference.Resource, error) {
	if err := validateRequest(service, ctx, principal); err != nil {
		return reference.Resource{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	value, _, err := service.authorizeResource(ctx, principal, authorization.ActionResourceGet, id)
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
	value, decision, err := service.authorizeResource(
		ctx, command.Principal, authorization.ActionResourceReplace, command.ResourceID,
	)
	if err != nil {
		return reference.MutationReceipt{}, err
	}
	command.Members = service.directories[value.Metadata.WorkspaceID()]
	return service.mutate(ctx, command.Principal, authorization.ActionResourceReplace,
		command.CanonicalTarget, command.IdempotencyKey, decision,
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
	_, decision, err := service.authorizeResource(
		ctx, command.Principal, authorization.ActionResourceDelete, command.ResourceID,
	)
	if err != nil {
		return reference.MutationReceipt{}, err
	}
	return service.mutate(ctx, command.Principal, authorization.ActionResourceDelete,
		command.CanonicalTarget, command.IdempotencyKey, decision,
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
	value, err := service.reference.GetOperation(ctx, principal, id)
	if err != nil {
		return reference.Operation{}, err
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
		return reference.Operation{}, fmt.Errorf("%w: resolve Operation target", ErrUnavailable)
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
	current, err := service.reference.GetOperation(ctx, record.principal, operationID)
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
	currentOperation, err := service.reference.GetOperation(ctx, record.principal, plan.OperationID())
	if err != nil {
		return err
	}
	if currentOperation.Value.WorkspaceID != plan.WorkspaceID() ||
		currentOperation.Value.ResourceID != plan.ResourceID() ||
		currentOperation.Value.Generation != plan.Generation() {
		return ErrStaleAuthorization
	}
	currentResource, err := service.reference.Get(ctx, record.principal, plan.ResourceID())
	if err != nil || currentResource.Metadata.Generation().Int64() != plan.Generation() {
		return ErrStaleAuthorization
	}
	state, err := service.authorizationState(ctx, plan.WorkspaceID())
	if err != nil {
		return err
	}
	target, err := authorization.ResolveResourceTarget(state.Snapshot, plan.ResourceID())
	if err != nil {
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
	id resource.ID,
) (reference.Resource, authorization.Decision, error) {
	value, err := service.reference.Get(ctx, principal, id)
	if err != nil {
		return reference.Resource{}, authorization.Decision{}, err
	}
	state, err := service.authorizationState(ctx, value.Metadata.WorkspaceID())
	if err != nil {
		return reference.Resource{}, authorization.Decision{}, err
	}
	target, err := authorization.ResolveResourceTarget(state.Snapshot, value.Metadata.ID())
	if err != nil {
		return reference.Resource{}, authorization.Decision{}, fmt.Errorf("%w: resolve resource target", ErrUnavailable)
	}
	decision, err := evaluate(state, principal, action, target)
	if err != nil {
		return reference.Resource{}, authorization.Decision{}, err
	}
	if !decision.Allowed() {
		return reference.Resource{}, authorization.Decision{}, ErrDenied
	}
	return value, decision, nil
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
	decision authorization.Decision,
	mutation func() (reference.MutationReceipt, error),
) (reference.MutationReceipt, error) {
	key := admissionRequestKey(principal, action, target, idempotencyKey)
	existingOperationID, replay := service.requests[key]
	if !replay && len(service.admissions) >= service.maximum {
		return reference.MutationReceipt{}, reference.ErrCapacity
	}
	receipt, err := mutation()
	if err != nil {
		return reference.MutationReceipt{}, err
	}
	if replay {
		if existingOperationID != receipt.OperationID {
			return reference.MutationReceipt{}, fmt.Errorf("%w: admission replay mismatch", ErrUnavailable)
		}
		return receipt, nil
	}
	service.admissions[receipt.OperationID] = admission{
		principal: identity.ClonePrincipal(principal), action: action, decision: decision,
	}
	service.requests[key] = receipt.OperationID
	return receipt, nil
}

func admissionRequestKey(
	principal identity.Principal,
	action authorization.Action,
	target string,
	idempotencyKey string,
) [sha256.Size]byte {
	return sha256.Sum256([]byte(principal.Fingerprint().String() + "\x00" +
		action.String() + "\x00" + target + "\x00" + idempotencyKey))
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
