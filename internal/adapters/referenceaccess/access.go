// Package referenceaccess implements the deliberately narrow credential and
// action gate used by the loopback-only reference server.
package referenceaccess

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	digestKey [sha256.Size]byte
	digest    [sha256.Size]byte
	principal identity.Principal
	actions   map[authorization.Action]struct{}
}

// New reduces the credential to a per-process keyed digest immediately and
// owns all configured values.
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
	var digestKey [sha256.Size]byte
	if _, err := rand.Read(digestKey[:]); err != nil {
		return nil, ErrInvalidConfiguration
	}
	return &Access{
		digestKey: digestKey,
		digest:    credentialDigest(digestKey, credential),
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
	digest := credentialDigest(access.digestKey, credential)
	if !hmac.Equal(access.digest[:], digest[:]) {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	return identity.ClonePrincipal(access.principal), nil
}

func credentialDigest(key [sha256.Size]byte, credential ports.BearerCredential) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(credential.Token()))
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest
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
