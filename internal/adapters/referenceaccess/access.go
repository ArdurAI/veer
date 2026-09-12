// Package referenceaccess implements the deliberately narrow credential and
// action gate used by the loopback-only reference server.
package referenceaccess

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
)

var ErrInvalidConfiguration = errors.New("invalid reference-access configuration")

// Access authenticates one preconfigured bearer credential for the
// corresponding principal. It is not an OIDC verifier.
type Access struct {
	digestKey [sha256.Size]byte
	digest    [sha256.Size]byte
	principal identity.Principal
}

// New reduces the credential to a per-process keyed digest immediately and
// owns all configured values.
func New(
	credential ports.BearerCredential,
	principal identity.Principal,
) (*Access, error) {
	if !credential.Valid() || identity.ValidatePrincipal(principal) != nil {
		return nil, ErrInvalidConfiguration
	}
	var digestKey [sha256.Size]byte
	if _, err := rand.Read(digestKey[:]); err != nil {
		return nil, ErrInvalidConfiguration
	}
	return &Access{
		digestKey: digestKey,
		digest:    credentialDigest(digestKey, credential),
		principal: identity.ClonePrincipal(principal),
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

var _ ports.Authenticator = (*Access)(nil)
