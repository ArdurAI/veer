package oidc

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
	jose "github.com/go-jose/go-jose/v4"
)

// Verifier implements the core authentication port for one immutable trust
// anchor. It performs no discovery, login, introspection, routing, or policy.
type Verifier struct {
	anchor validatedTrustAnchor
	cache  *keyCache
	clock  Clock
}

// NewVerifier validates and copies the trust anchor and hardens a private copy
// of client. A nil client uses the standard transport; a nil clock uses wall
// time. Neither input is mutated.
func NewVerifier(anchor TrustAnchor, client *http.Client, clock Clock) (*Verifier, error) {
	validated, err := validateTrustAnchor(anchor)
	if err != nil {
		return nil, err
	}
	clock = clockOrWall(clock)
	return &Verifier{
		anchor: validated,
		cache:  newKeyCache(validated, client, clock),
		clock:  clock,
	}, nil
}

// Authenticate verifies one bounded bearer credential and normalizes its
// signed claims. Every credential failure is deliberately indistinguishable.
func (verifier *Verifier) Authenticate(
	ctx context.Context,
	credential ports.BearerCredential,
) (identity.Principal, error) {
	if err := ctx.Err(); err != nil {
		return identity.Principal{}, err
	}
	if verifier == nil || verifier.cache == nil || !credential.Valid() {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	compact := credential.Token()
	inspected, ok := inspectCompactToken(compact)
	if !ok || !verifier.acceptsHeader(inspected.header) {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	algorithm := jose.SignatureAlgorithm(inspected.header.algorithm)
	signed, err := jose.ParseSignedCompact(compact, verifier.anchor.algorithms)
	if err != nil || len(signed.Signatures) != 1 || !matchesParsedHeader(signed.Signatures[0], inspected.header) {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}

	verificationKey, err := verifier.cache.resolve(ctx, inspected.header.keyID, algorithm)
	if err != nil {
		return identity.Principal{}, classifyResolutionError(ctx, err)
	}
	payload, verifyErr := signed.Verify(verificationKey.key)
	if verifyErr != nil {
		var refreshed bool
		verificationKey, refreshed, err = verifier.cache.resolveAfterSignatureFailure(
			ctx,
			inspected.header.keyID,
			algorithm,
			verificationKey.generation,
		)
		if err != nil {
			return identity.Principal{}, classifyResolutionError(ctx, err)
		}
		if !refreshed {
			return identity.Principal{}, ports.ErrAuthenticationInvalid
		}
		payload, verifyErr = signed.Verify(verificationKey.key)
		if verifyErr != nil {
			return identity.Principal{}, ports.ErrAuthenticationInvalid
		}
	}
	if !bytes.Equal(payload, inspected.payload) {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	if err := ctx.Err(); err != nil {
		return identity.Principal{}, err
	}
	principal, ok := verifier.principalFromClaims(payload)
	if !ok {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	if err := ctx.Err(); err != nil {
		return identity.Principal{}, err
	}
	return principal, nil
}

func (verifier *Verifier) acceptsHeader(header protectedHeader) bool {
	algorithm := jose.SignatureAlgorithm(header.algorithm)
	if _, accepted := verifier.anchor.algorithmSet[algorithm]; !accepted {
		return false
	}
	if !validOpaqueValue(header.keyID, maxKeyIDBytes) ||
		!validOpaqueValue(header.typeName, maxTypeBytes) {
		return false
	}
	for _, acceptedType := range verifier.anchor.acceptedTypes {
		if strings.EqualFold(header.typeName, acceptedType) {
			return true
		}
	}
	return false
}

func matchesParsedHeader(signature jose.Signature, expected protectedHeader) bool {
	parsedType, ok := signature.Protected.ExtraHeaders[jose.HeaderType].(string)
	return ok &&
		signature.Protected.Algorithm == expected.algorithm &&
		signature.Protected.KeyID == expected.keyID &&
		parsedType == expected.typeName &&
		signature.Protected.JSONWebKey == nil
}

func classifyResolutionError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, errNoMatchingKey) {
		return ports.ErrAuthenticationInvalid
	}
	return ports.ErrAuthenticationUnavailable
}

var _ ports.Authenticator = (*Verifier)(nil)
