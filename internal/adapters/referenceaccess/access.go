// Package referenceaccess implements the deliberately narrow credential and
// action gate used by the loopback-only reference server.
package referenceaccess

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
	httptransport "github.com/ArdurAI/veer/internal/transport/http"
)

var ErrInvalidConfiguration = errors.New("invalid reference-access configuration")

// Access authenticates one preconfigured bearer credential and allows only a
// closed set of reference-harness actions for the corresponding principal. It
// is not an OIDC verifier or tenant-policy evaluator.
type Access struct {
	digest    [sha256.Size]byte
	principal identity.Principal
	actions   map[authorization.Action]struct{}
}

// New hashes the credential immediately and owns all configured values.
func New(
	credential ports.BearerCredential,
	principal identity.Principal,
	actions []authorization.Action,
) (*Access, error) {
	if !credential.Valid() || identity.ValidatePrincipal(principal) != nil || len(actions) == 0 {
		return nil, ErrInvalidConfiguration
	}
	allowed := make(map[authorization.Action]struct{}, len(actions))
	for _, action := range actions {
		if _, err := authorization.ParseAction(action.String()); err != nil {
			return nil, ErrInvalidConfiguration
		}
		allowed[action] = struct{}{}
	}
	return &Access{
		digest:    sha256.Sum256([]byte(credential.Token())),
		principal: identity.ClonePrincipal(principal),
		actions:   allowed,
	}, nil
}

// Authenticate compares only fixed-size digests and never retains or reports
// the presented credential.
func (access *Access) Authenticate(
	ctx context.Context,
	credential ports.BearerCredential,
) (identity.Principal, error) {
	if err := ctx.Err(); err != nil {
		return identity.Principal{}, err
	}
	if access == nil || !credential.Valid() {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	digest := sha256.Sum256([]byte(credential.Token()))
	if subtle.ConstantTimeCompare(access.digest[:], digest[:]) != 1 {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	return identity.ClonePrincipal(access.principal), nil
}

// Authorize enforces the configured principal and closed action allow-list.
func (access *Access) Authorize(
	ctx context.Context,
	principal identity.Principal,
	action authorization.Action,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if access == nil || !identity.EqualPrincipal(access.principal, principal) {
		return httptransport.ErrReferenceAuthorizationDenied
	}
	if _, allowed := access.actions[action]; !allowed {
		return httptransport.ErrReferenceAuthorizationDenied
	}
	return nil
}

var (
	_ ports.Authenticator               = (*Access)(nil)
	_ httptransport.ReferenceAuthorizer = (*Access)(nil)
)
