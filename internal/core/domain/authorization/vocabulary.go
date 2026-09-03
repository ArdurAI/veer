// Package authorization defines Veer's deterministic, provider-independent
// Workspace and Environment authorization contract.
package authorization

import "slices"

const (
	// ContractVersion binds the action registry, role matrix, scope semantics,
	// version framing, and decision reasons implemented by this package.
	ContractVersion = "veer.authorization.v1alpha1"
	// ListEvaluationMode requires every retained result row to receive its own
	// sealed target and decision; no parent or synthetic collection target may
	// stand in for the row.
	ListEvaluationMode = "per-retained-row"

	// MaxMembers is ADR 0001's target-scale Workspace principal ceiling.
	MaxMembers = 500
	// MaxPolicies is ADR 0001's target-scale Workspace Policy ceiling.
	MaxPolicies = 2_500
	// MaxBindingsPerPolicy bounds canonical policy work independently of the
	// common resource byte and admission node ceilings.
	MaxBindingsPerPolicy = 128
	// MaxDecisionBytes matches Veer's bounded receipt/problem profile.
	MaxDecisionBytes = 1_024
)

// Action is one closed semantic authorization operation. Resource actions are
// paired with the hierarchy kind carried by a sealed Target.
type Action string

const (
	ActionResourceList          Action = "resource.list"
	ActionResourceGet           Action = "resource.get"
	ActionResourceCreate        Action = "resource.create"
	ActionResourceReplace       Action = "resource.replace"
	ActionResourceDelete        Action = "resource.delete"
	ActionResourceStatusReplace Action = "resource.status.replace"

	ActionPlanList    Action = "plan.list"
	ActionPlanGet     Action = "plan.get"
	ActionPlanPreview Action = "plan.preview"

	ActionOperationList       Action = "operation.list"
	ActionOperationGet        Action = "operation.get"
	ActionOperationCancel     Action = "operation.cancel"
	ActionOperationRetry      Action = "operation.retry"
	ActionOperationQuarantine Action = "operation.quarantine"

	ActionMembershipList    Action = "membership.list"
	ActionMembershipGet     Action = "membership.get"
	ActionMembershipCreate  Action = "membership.create"
	ActionMembershipReplace Action = "membership.replace"
	ActionMembershipDelete  Action = "membership.delete"

	ActionAuditList   Action = "audit.list"
	ActionAuditExport Action = "audit.export"

	ActionApprovalApprove  Action = "approval.approve"
	ActionApprovalReject   Action = "approval.reject"
	ActionApprovalOverride Action = "approval.override"

	ActionWorkPublish         Action = "work.publish"
	ActionWorkConsume         Action = "work.consume"
	ActionWorkRedrive         Action = "work.redrive"
	ActionReconcilePlan       Action = "reconcile.plan"
	ActionReconcileExecute    Action = "reconcile.execute"
	ActionOperationTransition Action = "operation.transition"
	ActionCredentialResolve   Action = "credential.resolve"
	ActionProviderDiscover    Action = "provider.discover"
	ActionProviderApply       Action = "provider.apply"
	ActionProviderObserve     Action = "provider.observe"
	ActionProviderDelete      Action = "provider.delete"
	ActionAuditAppend         Action = "audit.append"
)

var allActions = []Action{
	ActionResourceList,
	ActionResourceGet,
	ActionResourceCreate,
	ActionResourceReplace,
	ActionResourceDelete,
	ActionResourceStatusReplace,
	ActionPlanList,
	ActionPlanGet,
	ActionPlanPreview,
	ActionOperationList,
	ActionOperationGet,
	ActionOperationCancel,
	ActionOperationRetry,
	ActionOperationQuarantine,
	ActionMembershipList,
	ActionMembershipGet,
	ActionMembershipCreate,
	ActionMembershipReplace,
	ActionMembershipDelete,
	ActionAuditList,
	ActionAuditExport,
	ActionApprovalApprove,
	ActionApprovalReject,
	ActionApprovalOverride,
	ActionWorkPublish,
	ActionWorkConsume,
	ActionWorkRedrive,
	ActionReconcilePlan,
	ActionReconcileExecute,
	ActionOperationTransition,
	ActionCredentialResolve,
	ActionProviderDiscover,
	ActionProviderApply,
	ActionProviderObserve,
	ActionProviderDelete,
	ActionAuditAppend,
}

// String returns the exact versioned action spelling.
func (action Action) String() string { return string(action) }

// ParseAction admits only the closed action registry.
func ParseAction(value string) (Action, error) {
	action := Action(value)
	for _, candidate := range allActions {
		if action == candidate {
			return action, nil
		}
	}
	return "", ErrInvalidAction
}

// Actions returns an independent action registry in canonical order.
func Actions() []Action { return slices.Clone(allActions) }

// Role is one of Veer's four initial Workspace roles.
type Role string

const (
	RoleViewer                 Role = "Viewer"
	RoleDeveloper              Role = "Developer"
	RoleOperator               Role = "Operator"
	RoleWorkspaceAdministrator Role = "WorkspaceAdministrator"
)

var allRoles = []Role{RoleViewer, RoleDeveloper, RoleOperator, RoleWorkspaceAdministrator}

// String returns the exact versioned role spelling.
func (role Role) String() string { return string(role) }

// ParseRole admits only the closed role registry.
func ParseRole(value string) (Role, error) {
	role := Role(value)
	for _, candidate := range allRoles {
		if role == candidate {
			return role, nil
		}
	}
	return "", ErrInvalidRole
}

// Roles returns an independent role registry in canonical order.
func Roles() []Role { return slices.Clone(allRoles) }

// InheritedRoles returns the intentionally non-transitive job-role expansion.
// Developer, Operator, and WorkspaceAdministrator inherit Viewer only.
func InheritedRoles(role Role) []Role {
	switch role {
	case RoleViewer:
		return []Role{RoleViewer}
	case RoleDeveloper:
		return []Role{RoleViewer, RoleDeveloper}
	case RoleOperator:
		return []Role{RoleViewer, RoleOperator}
	case RoleWorkspaceAdministrator:
		return []Role{RoleViewer, RoleWorkspaceAdministrator}
	default:
		return nil
	}
}

// ScopeKind selects one exact policy inheritance root.
type ScopeKind string

const (
	ScopeKindWorkspace   ScopeKind = "Workspace"
	ScopeKindEnvironment ScopeKind = "Environment"
)

func (kind ScopeKind) String() string { return string(kind) }

// ParseScopeKind admits only Workspace and Environment.
func ParseScopeKind(value string) (ScopeKind, error) {
	kind := ScopeKind(value)
	switch kind {
	case ScopeKindWorkspace, ScopeKindEnvironment:
		return kind, nil
	default:
		return "", ErrInvalidScope
	}
}

// ScopeKinds returns the closed scope registry in canonical order.
func ScopeKinds() []ScopeKind { return []ScopeKind{ScopeKindWorkspace, ScopeKindEnvironment} }

// ScopeDescendants returns the exact scope-kind descent relation. Workspace
// grants cover the Workspace and its Environment subtrees; Environment grants
// never cross into another Environment or back to the Workspace root.
func ScopeDescendants(kind ScopeKind) []ScopeKind {
	switch kind {
	case ScopeKindWorkspace:
		return []ScopeKind{ScopeKindWorkspace, ScopeKindEnvironment}
	case ScopeKindEnvironment:
		return []ScopeKind{ScopeKindEnvironment}
	default:
		return nil
	}
}

// ObjectKind distinguishes the authorization object from its hierarchy anchor.
type ObjectKind string

const (
	ObjectKindResource   ObjectKind = "Resource"
	ObjectKindOperation  ObjectKind = "Operation"
	ObjectKindPlan       ObjectKind = "Plan"
	ObjectKindMembership ObjectKind = "Membership"
	ObjectKindAudit      ObjectKind = "Audit"
)

func (kind ObjectKind) String() string { return string(kind) }

// ParseObjectKind admits only the closed object registry.
func ParseObjectKind(value string) (ObjectKind, error) {
	kind := ObjectKind(value)
	switch kind {
	case ObjectKindResource, ObjectKindOperation, ObjectKindPlan,
		ObjectKindMembership, ObjectKindAudit:
		return kind, nil
	default:
		return "", ErrInvalidObjectKind
	}
}

// ObjectKinds returns the closed object registry in canonical order.
func ObjectKinds() []ObjectKind {
	return []ObjectKind{
		ObjectKindResource,
		ObjectKindOperation,
		ObjectKindPlan,
		ObjectKindMembership,
		ObjectKindAudit,
	}
}

// Effect is the closed authorization outcome.
type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
	// DefaultEffect is returned whenever no exact grant applies.
	DefaultEffect Effect = EffectDeny
)

func (effect Effect) String() string { return string(effect) }

// Effects returns the closed effect registry in canonical order.
func Effects() []Effect { return []Effect{EffectAllow, EffectDeny} }

// Reason is the stable internal explanation for one valid decision.
type Reason string

const (
	ReasonCrossWorkspace   Reason = "CrossWorkspace"
	ReasonReservedAction   Reason = "ReservedAction"
	ReasonNoMembership     Reason = "NoMembership"
	ReasonNoRoleBinding    Reason = "NoRoleBinding"
	ReasonScopeNotGranted  Reason = "ScopeNotGranted"
	ReasonActionNotGranted Reason = "ActionNotGranted"
	ReasonRoleGranted      Reason = "RoleGranted"
)

func (reason Reason) String() string { return string(reason) }

// Reasons returns the stable decision precedence order.
func Reasons() []Reason {
	return []Reason{
		ReasonCrossWorkspace,
		ReasonReservedAction,
		ReasonNoMembership,
		ReasonNoRoleBinding,
		ReasonScopeNotGranted,
		ReasonActionNotGranted,
		ReasonRoleGranted,
	}
}
