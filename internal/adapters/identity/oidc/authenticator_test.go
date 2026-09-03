package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
	jose "github.com/go-jose/go-jose/v4"
)

func TestAuthenticatorRoutesAcrossExactIssuers(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	firstKey := generateECDSAKey(t)
	secondKey := generateECDSAKey(t)
	fixture.setKeys(t,
		publicJWK(firstKey, "first-key", jose.ES256),
		publicJWK(secondKey, "second-key", jose.ES256),
	)
	first := testTrustAnchor(fixture, identity.KindHuman)
	second := testTrustAnchor(fixture, identity.KindHuman)
	second.Issuer = fixture.server.URL + "/second-issuer"
	authenticator, err := NewAuthenticator(
		[]TrustAnchor{first, second},
		fixture.server.Client(),
		clock,
	)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	secondClaims := validClaims(second, clock.Now())
	secondToken := signClaims(t, secondKey, jose.ES256, "second-key", "at+jwt", secondClaims)
	principal, err := authenticateWith(t, authenticator, secondToken)
	if err != nil {
		t.Fatalf("authenticate second issuer: %v", err)
	}
	if principal.Issuer() != second.Issuer {
		t.Fatal("authenticator selected the wrong issuer trust anchor")
	}
	if got := fixture.hits.Load(); got != 1 {
		t.Fatalf("selected issuer caused %d JWKS fetches, want 1", got)
	}

	firstClaims := validClaims(first, clock.Now())
	firstToken := signClaims(t, firstKey, jose.ES256, "first-key", "at+jwt", firstClaims)
	principal, err = authenticateWith(t, authenticator, firstToken)
	if err != nil {
		t.Fatalf("authenticate first issuer: %v", err)
	}
	if principal.Issuer() != first.Issuer {
		t.Fatal("authenticator selected the wrong issuer trust anchor")
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("two selected issuer caches caused %d JWKS fetches, want 2", got)
	}
}

func TestAuthenticatorRoutesSameIssuerByExactAudience(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	firstKey := generateECDSAKey(t)
	secondKey := generateECDSAKey(t)
	fixture.setKeys(t,
		publicJWK(firstKey, "first-audience-key", jose.ES256),
		publicJWK(secondKey, "second-audience-key", jose.ES256),
	)
	first := testTrustAnchor(fixture, identity.KindHuman)
	first.Audience = "first-api"
	second := testTrustAnchor(fixture, identity.KindHuman)
	second.Audience = "second-api"
	authenticator, err := NewAuthenticator(
		[]TrustAnchor{first, second},
		fixture.server.Client(),
		clock,
	)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	claims := validClaims(second, clock.Now())
	claims["aud"] = second.Audience
	token := signClaims(t, secondKey, jose.ES256, "second-audience-key", "at+jwt", claims)
	principal, err := authenticateWith(t, authenticator, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got, want := principal.Audiences(), []string{second.Audience}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("principal audiences = %v, want %v", got, want)
	}
	if got := fixture.hits.Load(); got != 1 {
		t.Fatalf("audience dispatch caused %d JWKS fetches, want 1", got)
	}
}

func TestAuthenticatorRejectsAmbiguousOrUnknownRoutingWithoutNetwork(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(key, "routing-key", jose.ES256))
	first := testTrustAnchor(fixture, identity.KindHuman)
	first.Audience = "first-api"
	second := testTrustAnchor(fixture, identity.KindHuman)
	second.Audience = "second-api"
	authenticator, err := NewAuthenticator(
		[]TrustAnchor{first, second},
		fixture.server.Client(),
		clock,
	)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	tests := []struct {
		name   string
		claims map[string]any
	}{
		{
			name: "multi-audience ambiguity",
			claims: map[string]any{
				"iss": first.Issuer,
				"sub": "subject-123",
				"aud": []string{first.Audience, second.Audience},
				"iat": clock.Now().Unix(),
				"exp": clock.Now().Add(first.MaxTokenLifetime).Unix(),
			},
		},
		{
			name: "unknown issuer",
			claims: map[string]any{
				"iss": "https://unknown.invalid",
				"sub": "subject-123",
				"aud": first.Audience,
				"iat": clock.Now().Unix(),
				"exp": clock.Now().Add(first.MaxTokenLifetime).Unix(),
			},
		},
		{
			name: "unknown audience",
			claims: map[string]any{
				"iss": first.Issuer,
				"sub": "subject-123",
				"aud": "unknown-api",
				"iat": clock.Now().Unix(),
				"exp": clock.Now().Add(first.MaxTokenLifetime).Unix(),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signClaims(t, key, jose.ES256, "routing-key", "at+jwt", test.claims)
			_, err := authenticateWith(t, authenticator, token)
			requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
		})
	}
	if got := fixture.hits.Load(); got != 0 {
		t.Fatalf("rejected routing caused %d JWKS fetches, want zero", got)
	}
}

func TestNewAuthenticatorRejectsUnboundedOrOverlappingAnchors(t *testing.T) {
	fixture := newKeyServer(t)
	base := testTrustAnchor(fixture, identity.KindHuman)

	for _, anchors := range [][]TrustAnchor{
		nil,
		make([]TrustAnchor, MaxTrustAnchors+1),
		{base, base},
	} {
		_, err := NewAuthenticator(anchors, fixture.server.Client(), newFakeClock(testNow))
		if !errors.Is(err, ErrInvalidTrustAnchor) {
			t.Fatalf("NewAuthenticator error = %v, want ErrInvalidTrustAnchor", err)
		}
		if err != nil && (strings.Contains(err.Error(), base.Issuer) ||
			strings.Contains(err.Error(), base.Audience)) {
			t.Fatalf("NewAuthenticator error exposed trust-anchor values: %q", err)
		}
	}

	disjointType := base
	disjointType.AcceptedTypes = []string{"JWT"}
	if _, err := NewAuthenticator(
		[]TrustAnchor{base, disjointType},
		fixture.server.Client(),
		newFakeClock(testNow),
	); err != nil {
		t.Fatalf("disjoint protected types should be routable: %v", err)
	}

	disjointAlgorithm := base
	disjointAlgorithm.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA}
	if _, err := NewAuthenticator(
		[]TrustAnchor{base, disjointAlgorithm},
		fixture.server.Client(),
		newFakeClock(testNow),
	); err != nil {
		t.Fatalf("disjoint algorithms should be routable: %v", err)
	}

	foldLeft := base
	foldLeft.AcceptedTypes = []string{"S"}
	foldRight := base
	foldRight.AcceptedTypes = []string{"ſ"}
	_, err := NewAuthenticator(
		[]TrustAnchor{foldLeft, foldRight},
		fixture.server.Client(),
		newFakeClock(testNow),
	)
	if !errors.Is(err, ErrInvalidTrustAnchor) {
		t.Fatalf("Unicode-fold type overlap error = %v, want ErrInvalidTrustAnchor", err)
	}
}

func TestAuthenticatorsHandleTypedNilDependenciesAndReceivers(t *testing.T) {
	fixture := newKeyServer(t)
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	var typedNilClock *fakeClock

	verifier, err := NewVerifier(anchor, fixture.server.Client(), typedNilClock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, ok := verifier.clock.(wallClock); !ok {
		t.Fatal("NewVerifier did not normalize a typed-nil clock")
	}
	authenticator, err := NewAuthenticator(
		[]TrustAnchor{anchor},
		fixture.server.Client(),
		typedNilClock,
	)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if _, ok := authenticator.verifiers[0].clock.(wallClock); !ok {
		t.Fatal("NewAuthenticator did not normalize a typed-nil clock")
	}

	credential, err := ports.NewBearerCredential("a.b.c")
	if err != nil {
		t.Fatalf("NewBearerCredential: %v", err)
	}
	var nilVerifier *Verifier
	var nilAuthenticator *Authenticator
	for _, implementation := range []ports.Authenticator{nilVerifier, nilAuthenticator} {
		_, err := implementation.Authenticate(context.Background(), credential)
		requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = implementation.Authenticate(ctx, credential)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled context error = %v, want context.Canceled", err)
		}
	}
}

func authenticateWith(
	t *testing.T,
	authenticator ports.Authenticator,
	compact string,
) (identity.Principal, error) {
	t.Helper()
	credential, err := ports.NewBearerCredential(compact)
	if err != nil {
		t.Fatalf("NewBearerCredential for generated token: %v", err)
	}
	return authenticator.Authenticate(t.Context(), credential)
}
