package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
	jose "github.com/go-jose/go-jose/v4"
)

// Authenticator dispatches a bounded set of explicit token-class trust
// anchors. Unverified claims are used only to select exactly one verifier;
// that verifier still performs the complete signature and claim validation.
type Authenticator struct {
	verifiers []*Verifier
}

// NewAuthenticator validates and copies every trust anchor. Anchors whose
// exact issuer, audience, accepted type, and algorithm can all overlap are
// rejected because no token could be routed between them unambiguously.
func NewAuthenticator(
	anchors []TrustAnchor,
	client *http.Client,
	clock Clock,
) (*Authenticator, error) {
	if len(anchors) == 0 || len(anchors) > MaxTrustAnchors {
		return nil, configError("authenticator must contain between one and 16 trust anchors")
	}
	clock = clockOrWall(clock)

	validated := make([]validatedTrustAnchor, 0, len(anchors))
	for _, anchor := range anchors {
		candidate, err := validateTrustAnchor(anchor)
		if err != nil {
			return nil, err
		}
		for _, existing := range validated {
			if trustAnchorsOverlap(existing, candidate) {
				return nil, configError("trust anchors have an ambiguous token-class overlap")
			}
		}
		validated = append(validated, candidate)
	}

	result := &Authenticator{verifiers: make([]*Verifier, 0, len(validated))}
	for _, anchor := range validated {
		result.verifiers = append(result.verifiers, &Verifier{
			anchor: anchor,
			cache:  newKeyCache(anchor, client, clock),
			clock:  clock,
		})
	}
	return result, nil
}

// Authenticate strictly inspects the bounded compact token, selects one
// configured class without network access, then delegates full verification.
func (authenticator *Authenticator) Authenticate(
	ctx context.Context,
	credential ports.BearerCredential,
) (identity.Principal, error) {
	if err := ctx.Err(); err != nil {
		return identity.Principal{}, err
	}
	if authenticator == nil || !credential.Valid() {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}

	inspected, ok := inspectCompactToken(credential.Token())
	if !ok {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	issuer, audiences, ok := routingClaims(inspected.payload)
	if !ok {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}

	var selected *Verifier
	for _, verifier := range authenticator.verifiers {
		if verifier.anchor.issuer != issuer ||
			!containsExact(audiences, verifier.anchor.audience) ||
			!verifier.acceptsHeader(inspected.header) {
			continue
		}
		if selected != nil {
			return identity.Principal{}, ports.ErrAuthenticationInvalid
		}
		selected = verifier
	}
	if selected == nil {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	return selected.Authenticate(ctx, credential)
}

func routingClaims(payload []byte) (string, []string, bool) {
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", nil, false
	}
	issuer, ok := requiredJSONString(claims, "iss")
	if !ok {
		return "", nil, false
	}
	audiences, ok := parseAudiences(claims["aud"])
	if !ok {
		return "", nil, false
	}
	for _, audience := range audiences {
		if !validOpaqueValue(audience, identity.MaxAudienceBytes) {
			return "", nil, false
		}
	}
	return issuer, audiences, true
}

func trustAnchorsOverlap(left, right validatedTrustAnchor) bool {
	return left.issuer == right.issuer &&
		left.audience == right.audience &&
		algorithmsOverlap(left.algorithmSet, right.algorithmSet) &&
		stringsOverlap(left.acceptedTypes, right.acceptedTypes)
}

func algorithmsOverlap(
	left, right map[jose.SignatureAlgorithm]struct{},
) bool {
	for value := range left {
		if _, present := right[value]; present {
			return true
		}
	}
	return false
}

func stringsOverlap(left, right []string) bool {
	for _, leftValue := range left {
		for _, rightValue := range right {
			if strings.EqualFold(leftValue, rightValue) {
				return true
			}
		}
	}
	return false
}

var _ ports.Authenticator = (*Authenticator)(nil)
