package reference

import (
	"context"
	"fmt"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/model"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
)

// AuthorizationState is one immutable, same-view hierarchy and policy
// projection. Callers can resolve a target and evaluate it without combining
// independently observed store revisions.
type AuthorizationState struct {
	Snapshot hierarchy.Snapshot
	Policies authorization.PolicySet
}

// AuthorizationStateResolver derives a sealed authorization view from the
// exact resource revision already retained by a ListWhere call.
type AuthorizationStateResolver func(
	resource.ID,
	authorization.MemberDirectory,
) (AuthorizationState, error)

// LoadAuthorizationState constructs the current authorization state for one
// Workspace from a single retained store view and a private member directory.
func (service *Service) LoadAuthorizationState(
	ctx context.Context,
	workspaceID resource.ID,
	members authorization.MemberDirectory,
) (AuthorizationState, error) {
	if service == nil {
		return AuthorizationState{}, ErrInvalidConfiguration
	}
	if ctx == nil || ctx.Err() != nil {
		if ctx != nil && ctx.Err() != nil {
			return AuthorizationState{}, ctx.Err()
		}
		return AuthorizationState{}, ErrInvalidCommand
	}
	if resourceIDInvalid(workspaceID) || authorization.ValidateMemberDirectory(members) != nil ||
		members.WorkspaceID() != workspaceID {
		return AuthorizationState{}, ErrInvalidCommand
	}

	var result AuthorizationState
	err := service.store.View(ctx, func(reader ports.ReferenceReader) error {
		resources, err := loadResources(reader)
		if err != nil {
			return err
		}
		result, err = authorizationStateFor(resources, workspaceID, members)
		return err
	})
	if err != nil {
		return AuthorizationState{}, err
	}
	return result, nil
}

func authorizationStateFor(
	resources []Resource,
	workspaceID resource.ID,
	members authorization.MemberDirectory,
) (AuthorizationState, error) {
	snapshot, err := snapshotFor(resources, workspaceID)
	if err != nil {
		return AuthorizationState{}, err
	}
	policies := make([]authorization.PolicyRevision, 0)
	for _, value := range resources {
		if value.Kind != hierarchy.KindPolicy || value.Metadata.WorkspaceID() != workspaceID {
			continue
		}
		typed, err := decodeTyped[model.PolicySpec, model.PolicyStatus](value.Canonical, hierarchy.KindPolicy)
		if err != nil {
			return AuthorizationState{}, err
		}
		spec, err := typed.Spec()
		if err != nil {
			return AuthorizationState{}, fmt.Errorf("%w: decode Policy spec", ErrInternal)
		}
		record, err := hierarchyRecord(value)
		if err != nil {
			return AuthorizationState{}, err
		}
		policies = append(policies, authorization.PolicyRevision{
			Record: record, Generation: value.Metadata.Generation(), Spec: spec,
		})
	}
	set, err := authorization.NewPolicySet(snapshot, members, policies)
	if err != nil {
		return AuthorizationState{}, fmt.Errorf("%w: compile authorization state: %w", ErrInternal, err)
	}
	return AuthorizationState{Snapshot: snapshot, Policies: set}, nil
}
