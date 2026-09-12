package httptransport

import (
	"context"
	"errors"
	"slices"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
)

var referenceActions = []authorization.Action{
	authorization.ActionResourceList,
	authorization.ActionResourceGet,
	authorization.ActionResourceCreate,
	authorization.ActionResourceReplace,
	authorization.ActionResourceDelete,
	authorization.ActionResourceStatusReplace,
	authorization.ActionOperationGet,
}

var (
	// ErrReferenceAuthorizationDenied is the only caller-visible denial class
	// accepted from a reference authorization dependency.
	ErrReferenceAuthorizationDenied = errors.New("reference authorization denied")
	// ErrReferenceAuthorizationUnavailable reports a retry-safe failure of the
	// injected authorization dependency.
	ErrReferenceAuthorizationUnavailable = errors.New("reference authorization unavailable")
)

// ReferenceAuthorizer gates one published operation after authentication. It
// is intentionally narrower than Veer's policy evaluator: issue #24 owns
// authoritative hierarchy resolution and per-retained-row policy enforcement.
type ReferenceAuthorizer interface {
	Authorize(context.Context, identity.Principal, authorization.Action) error
}

// ReferenceActions returns an independent copy of the exact published action
// surface accepted by the reference handler.
func ReferenceActions() []authorization.Action { return slices.Clone(referenceActions) }
