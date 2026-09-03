package authorization

import (
	"slices"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
)

// Grant is one direct role grant. ResourceKinds are hierarchy anchors, not
// caller-provided names. Role inheritance is reported separately.
type Grant struct {
	Action        Action
	ObjectKind    ObjectKind
	ResourceKinds []hierarchy.Kind
}

// ReservedResourceAction is a target-kind-specific reservation. Global
// reservations are returned by ReservedActions.
type ReservedResourceAction struct {
	Action       Action
	ResourceKind hierarchy.Kind
}

var globallyReservedActions = []Action{
	ActionResourceStatusReplace,
	ActionOperationQuarantine,
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

var targetReservedActions = []ReservedResourceAction{{
	Action:       ActionResourceCreate,
	ResourceKind: hierarchy.KindWorkspace,
}}

var viewerResourceKinds = []hierarchy.Kind{
	hierarchy.KindApplication,
	hierarchy.KindComponent,
	hierarchy.KindEnvironment,
	hierarchy.KindProviderConnection,
	hierarchy.KindWorkspace,
}

var directRoleGrants = map[Role][]Grant{
	RoleViewer: {
		grant(ActionResourceList, ObjectKindResource, viewerResourceKinds...),
		grant(ActionResourceGet, ObjectKindResource, viewerResourceKinds...),
		grant(ActionPlanList, ObjectKindPlan, viewerResourceKinds...),
		grant(ActionPlanGet, ObjectKindPlan, viewerResourceKinds...),
		grant(ActionOperationList, ObjectKindOperation, viewerResourceKinds...),
		grant(ActionOperationGet, ObjectKindOperation, viewerResourceKinds...),
		grant(ActionAuditList, ObjectKindAudit, viewerResourceKinds...),
	},
	RoleDeveloper: {
		grant(ActionResourceCreate, ObjectKindResource, hierarchy.KindApplication, hierarchy.KindComponent),
		grant(ActionResourceReplace, ObjectKindResource, hierarchy.KindApplication, hierarchy.KindComponent),
		grant(ActionResourceDelete, ObjectKindResource, hierarchy.KindApplication, hierarchy.KindComponent),
		grant(ActionPlanPreview, ObjectKindPlan, hierarchy.KindApplication, hierarchy.KindComponent),
		grant(ActionOperationCancel, ObjectKindOperation, hierarchy.KindApplication, hierarchy.KindComponent),
	},
	RoleOperator: {
		grant(ActionResourceCreate, ObjectKindResource, hierarchy.KindEnvironment, hierarchy.KindProviderConnection),
		grant(ActionResourceReplace, ObjectKindResource, hierarchy.KindEnvironment, hierarchy.KindProviderConnection),
		grant(ActionResourceDelete, ObjectKindResource, hierarchy.KindEnvironment, hierarchy.KindProviderConnection),
		grant(ActionPlanPreview, ObjectKindPlan, hierarchy.KindEnvironment, hierarchy.KindProviderConnection),
		grant(
			ActionOperationCancel,
			ObjectKindOperation,
			hierarchy.KindApplication,
			hierarchy.KindComponent,
			hierarchy.KindEnvironment,
			hierarchy.KindProviderConnection,
		),
		grant(
			ActionOperationRetry,
			ObjectKindOperation,
			hierarchy.KindApplication,
			hierarchy.KindComponent,
			hierarchy.KindEnvironment,
			hierarchy.KindProviderConnection,
		),
	},
	RoleWorkspaceAdministrator: {
		grant(ActionResourceList, ObjectKindResource, hierarchy.KindPolicy),
		grant(ActionResourceGet, ObjectKindResource, hierarchy.KindPolicy),
		grant(ActionResourceCreate, ObjectKindResource, hierarchy.KindPolicy),
		grant(ActionResourceReplace, ObjectKindResource, hierarchy.KindPolicy, hierarchy.KindWorkspace),
		grant(ActionResourceDelete, ObjectKindResource, hierarchy.KindPolicy, hierarchy.KindWorkspace),
		grant(ActionPlanList, ObjectKindPlan, hierarchy.KindPolicy, hierarchy.KindWorkspace),
		grant(ActionPlanGet, ObjectKindPlan, hierarchy.KindPolicy, hierarchy.KindWorkspace),
		grant(ActionPlanPreview, ObjectKindPlan, hierarchy.KindPolicy, hierarchy.KindWorkspace),
		grant(ActionOperationList, ObjectKindOperation, hierarchy.KindPolicy, hierarchy.KindWorkspace),
		grant(ActionOperationGet, ObjectKindOperation, hierarchy.KindPolicy, hierarchy.KindWorkspace),
		grant(ActionOperationCancel, ObjectKindOperation, hierarchy.KindPolicy, hierarchy.KindWorkspace),
		grant(ActionMembershipList, ObjectKindMembership),
		grant(ActionMembershipGet, ObjectKindMembership),
		grant(ActionMembershipCreate, ObjectKindMembership),
		grant(ActionMembershipReplace, ObjectKindMembership),
		grant(ActionMembershipDelete, ObjectKindMembership),
	},
}

// RoleGrants returns independent direct grants in canonical matrix order.
// Callers expand star inheritance with InheritedRoles. Viewer self-membership
// access is conditional and therefore intentionally not reported as an
// unrestricted grant.
func RoleGrants(role Role) []Grant {
	grants, exists := directRoleGrants[role]
	if !exists {
		return nil
	}
	result := make([]Grant, len(grants))
	for index, item := range grants {
		result[index] = cloneGrant(item)
	}
	return result
}

// ReservedActions returns actions never granted to tenant roles.
func ReservedActions() []Action { return slices.Clone(globallyReservedActions) }

// ReservedResourceActions returns target-specific tenant reservations.
func ReservedResourceActions() []ReservedResourceAction {
	return slices.Clone(targetReservedActions)
}

func roleAllows(role Role, action Action, target Target) bool {
	for _, inherited := range InheritedRoles(role) {
		for _, item := range directRoleGrants[inherited] {
			if item.Action != action || item.ObjectKind != target.objectKind {
				continue
			}
			if len(item.ResourceKinds) == 0 || slices.Contains(item.ResourceKinds, target.resourceKind) {
				return true
			}
		}
	}
	return false
}

func actionReserved(action Action, target Target) bool {
	if slices.Contains(globallyReservedActions, action) {
		return true
	}
	for _, item := range targetReservedActions {
		if item.Action == action && item.ResourceKind == target.resourceKind &&
			target.objectKind == ObjectKindResource {
			return true
		}
	}
	return false
}

func grant(action Action, objectKind ObjectKind, resourceKinds ...hierarchy.Kind) Grant {
	return Grant{Action: action, ObjectKind: objectKind, ResourceKinds: slices.Clone(resourceKinds)}
}

func cloneGrant(item Grant) Grant {
	item.ResourceKinds = slices.Clone(item.ResourceKinds)
	return item
}
