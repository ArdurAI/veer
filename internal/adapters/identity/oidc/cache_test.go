package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
	jose "github.com/go-jose/go-jose/v4"
)

func TestJWKSUnknownKeyRefreshIsBoundedAndSupportsRotation(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	firstKey := generateECDSAKey(t)
	rotatedKey := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(firstKey, "key-1", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := cacheClaims(anchor, clock.Now())
	firstToken := signClaims(t, firstKey, jose.ES256, "key-1", "at+jwt", claims)
	if _, err := authenticate(t, verifier, firstToken); err != nil {
		t.Fatalf("authenticate first key: %v", err)
	}

	unknownToken := signClaims(t, rotatedKey, jose.ES256, "key-2", "at+jwt", claims)
	_, err := authenticate(t, verifier, unknownToken)
	requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("initial plus unknown-kid fetches = %d, want 2", got)
	}

	for index := range 32 {
		kid := "attacker-key-" + string(rune('a'+index%26))
		token := signClaims(t, rotatedKey, jose.ES256, kid, "at+jwt", claims)
		_, err := authenticate(t, verifier, token)
		requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("unknown-kid burst caused %d fetches, want 2 total", got)
	}

	clock.Advance(anchor.Cache.RefreshCooldown)
	fixture.setKeys(t,
		publicJWK(firstKey, "key-1", jose.ES256),
		publicJWK(rotatedKey, "key-2", jose.ES256),
	)
	if _, err := authenticate(t, verifier, unknownToken); err != nil {
		t.Fatalf("authenticate rotated key: %v", err)
	}
	if got := fixture.hits.Load(); got != 3 {
		t.Fatalf("rotation fetches = %d, want 3", got)
	}
}

func TestJWKSSameKeyIDRotationRefreshesAfterSignatureFailure(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	firstKey := generateECDSAKey(t)
	rotatedKey := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(firstKey, "stable-kid", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := cacheClaims(anchor, clock.Now())
	if _, err := authenticate(t, verifier,
		signClaims(t, firstKey, jose.ES256, "stable-kid", "at+jwt", claims)); err != nil {
		t.Fatalf("authenticate first key: %v", err)
	}

	fixture.setKeys(t, publicJWK(rotatedKey, "stable-kid", jose.ES256))
	rotatedToken := signClaims(t, rotatedKey, jose.ES256, "stable-kid", "at+jwt", claims)
	if _, err := authenticate(t, verifier, rotatedToken); err != nil {
		t.Fatalf("authenticate same-kid rotation: %v", err)
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("same-kid rotation fetches = %d, want 2", got)
	}

	badKey := generateECDSAKey(t)
	badToken := signClaims(t, badKey, jose.ES256, "stable-kid", "at+jwt", claims)
	for range 16 {
		_, err := authenticate(t, verifier, badToken)
		requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("bad-signature burst caused %d fetches, want 2 total", got)
	}
}

func TestJWKSProactiveRefreshAndFreshKeyFallback(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	firstKey := generateECDSAKey(t)
	secondKey := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(firstKey, "key-1", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := cacheClaims(anchor, clock.Now())
	firstToken := signClaims(t, firstKey, jose.ES256, "key-1", "at+jwt", claims)
	secondToken := signClaims(t, secondKey, jose.ES256, "key-2", "at+jwt", claims)
	if _, err := authenticate(t, verifier, firstToken); err != nil {
		t.Fatalf("warm cache: %v", err)
	}

	clock.Advance(anchor.Cache.Freshness - anchor.Cache.RefreshAhead)
	fixture.setKeys(t,
		publicJWK(firstKey, "key-1", jose.ES256),
		publicJWK(secondKey, "key-2", jose.ES256),
	)
	if _, err := authenticate(t, verifier, firstToken); err != nil {
		t.Fatalf("authenticate during proactive refresh: %v", err)
	}
	if _, err := authenticate(t, verifier, secondToken); err != nil {
		t.Fatalf("authenticate proactively loaded key: %v", err)
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("proactive refresh fetches = %d, want 2", got)
	}

	clock.Advance(anchor.Cache.Freshness - anchor.Cache.RefreshAhead)
	fixture.setResponse(http.StatusServiceUnavailable, []byte(`{"error":"CANARY-PROVIDER-BODY"}`))
	if _, err := authenticate(t, verifier, secondToken); err != nil {
		t.Fatalf("fresh key was not used after proactive outage: %v", err)
	}
	if _, err := authenticate(t, verifier, secondToken); err != nil {
		t.Fatalf("fresh key was not reused during refresh cooldown: %v", err)
	}
	if got := fixture.hits.Load(); got != 3 {
		t.Fatalf("proactive outage caused %d fetches, want 3 total", got)
	}

	clock.Advance(anchor.Cache.RefreshAhead + time.Second)
	_, err := authenticate(t, verifier, secondToken)
	requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
	if strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), anchor.JWKSURI) {
		t.Fatalf("outage error disclosed endpoint or provider body: %q", err)
	}
}

func TestJWKSStaleCacheRefreshesAfterSuccessfulFetchDespiteLongCooldown(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(key, "short-cache-key", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	anchor.Cache.Freshness = 2 * time.Second
	anchor.Cache.RefreshAhead = time.Second
	anchor.Cache.RefreshCooldown = time.Minute
	verifier := newTestVerifier(t, fixture, anchor, clock)
	token := signClaims(t, key, jose.ES256, "short-cache-key", "at+jwt", cacheClaims(anchor, clock.Now()))

	if _, err := authenticate(t, verifier, token); err != nil {
		t.Fatalf("warm cache: %v", err)
	}
	clock.Advance(anchor.Cache.Freshness)
	if _, err := authenticate(t, verifier, token); err != nil {
		t.Fatalf("refresh stale cache: %v", err)
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("stale cache fetches = %d, want 2", got)
	}
}

func TestJWKSInitialRefreshIsCoalesced(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(key, "coalesced-key", jose.ES256))
	gate := make(chan struct{})
	fixture.setGate(gate)
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	token := signClaims(t, key, jose.ES256, "coalesced-key", "at+jwt", cacheClaims(anchor, clock.Now()))
	credential, err := ports.NewBearerCredential(token)
	if err != nil {
		t.Fatalf("NewBearerCredential: %v", err)
	}

	const callers = 24
	start := make(chan struct{})
	errorsByCaller := make(chan error, callers)
	var callersReady sync.WaitGroup
	callersReady.Add(callers)
	for range callers {
		go func() {
			callersReady.Done()
			<-start
			_, authenticateErr := verifier.Authenticate(context.Background(), credential)
			errorsByCaller <- authenticateErr
		}()
	}
	callersReady.Wait()
	close(start)
	requireEventually(t, time.Second, func() bool { return fixture.hits.Load() == 1 })
	close(gate)
	for range callers {
		if err := <-errorsByCaller; err != nil {
			t.Fatalf("coalesced Authenticate: %v", err)
		}
	}
	if got := fixture.hits.Load(); got != 1 {
		t.Fatalf("concurrent initial fetches = %d, want 1", got)
	}
}

func TestJWKSOutageClassificationAndCooldown(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	fixture.setResponse(http.StatusServiceUnavailable, []byte(`{"detail":"CANARY"}`))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	token := signClaims(t, key, jose.ES256, "missing-key", "at+jwt", cacheClaims(anchor, clock.Now()))

	for range 8 {
		_, err := authenticate(t, verifier, token)
		requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
		if strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), token) {
			t.Fatalf("outage error disclosed input: %q", err)
		}
	}
	if got := fixture.hits.Load(); got != 1 {
		t.Fatalf("outage burst caused %d fetches, want 1", got)
	}
	clock.Advance(anchor.Cache.RefreshCooldown)
	_, err := authenticate(t, verifier, token)
	requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("post-cooldown fetches = %d, want 2", got)
	}
}

func TestJWKSContextCancellationAndInternalTimeout(t *testing.T) {
	t.Run("caller cancellation", func(t *testing.T) {
		fixture := newKeyServer(t)
		clock := newFakeClock(testNow)
		key := generateECDSAKey(t)
		fixture.setKeys(t, publicJWK(key, "context-key", jose.ES256))
		gate := make(chan struct{})
		fixture.setGate(gate)
		anchor := testTrustAnchor(fixture, identity.KindHuman)
		verifier := newTestVerifier(t, fixture, anchor, clock)
		token := signClaims(t, key, jose.ES256, "context-key", "at+jwt", cacheClaims(anchor, clock.Now()))
		credential, err := ports.NewBearerCredential(token)
		if err != nil {
			t.Fatalf("NewBearerCredential: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, authenticateErr := verifier.Authenticate(ctx, credential)
			result <- authenticateErr
		}()
		requireEventually(t, time.Second, func() bool { return fixture.hits.Load() == 1 })
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	})

	t.Run("adapter fetch timeout", func(t *testing.T) {
		fixture := newKeyServer(t)
		clock := newFakeClock(testNow)
		key := generateECDSAKey(t)
		fixture.setKeys(t, publicJWK(key, "timeout-key", jose.ES256))
		fixture.setGate(make(chan struct{}))
		anchor := testTrustAnchor(fixture, identity.KindHuman)
		anchor.Cache.FetchTimeout = 10 * time.Millisecond
		verifier := newTestVerifier(t, fixture, anchor, clock)
		token := signClaims(t, key, jose.ES256, "timeout-key", "at+jwt", cacheClaims(anchor, clock.Now()))
		_, err := authenticate(t, verifier, token)
		requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
	})
}

func TestJWKSCallerCancellationCannotBypassRefreshCooldown(t *testing.T) {
	t.Run("cold cache", func(t *testing.T) {
		fixture := newKeyServer(t)
		clock := newFakeClock(testNow)
		key := generateECDSAKey(t)
		fixture.setKeys(t, publicJWK(key, "cancel-key", jose.ES256))
		anchor := testTrustAnchor(fixture, identity.KindHuman)
		verifier := newTestVerifier(t, fixture, anchor, clock)
		token := signClaims(t, key, jose.ES256, "cancel-key", "at+jwt", cacheClaims(anchor, clock.Now()))
		credential, err := ports.NewBearerCredential(token)
		if err != nil {
			t.Fatalf("NewBearerCredential: %v", err)
		}

		for cycle := int64(1); cycle <= 3; cycle++ {
			gate := make(chan struct{})
			fixture.setGate(gate)
			ctx, cancel := context.WithCancel(t.Context())
			result := make(chan error, 1)
			go func() {
				_, authenticateErr := verifier.Authenticate(ctx, credential)
				result <- authenticateErr
			}()
			requireEventually(t, time.Second, func() bool { return fixture.hits.Load() == cycle })
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled refresh error = %v, want context.Canceled", err)
			}

			for range 8 {
				retryCtx, retryCancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				_, retryErr := verifier.Authenticate(retryCtx, credential)
				retryCancel()
				requireAuthenticationError(t, retryErr, ports.ErrAuthenticationUnavailable)
			}
			if got := fixture.hits.Load(); got != cycle {
				t.Fatalf("cycle %d cancellation burst caused %d fetches", cycle, got)
			}
			clock.Advance(anchor.Cache.RefreshCooldown)
		}
	})

	t.Run("reactive unknown key", func(t *testing.T) {
		fixture := newKeyServer(t)
		clock := newFakeClock(testNow)
		trustedKey := generateECDSAKey(t)
		unknownKey := generateECDSAKey(t)
		fixture.setKeys(t, publicJWK(trustedKey, "trusted-key", jose.ES256))
		anchor := testTrustAnchor(fixture, identity.KindHuman)
		verifier := newTestVerifier(t, fixture, anchor, clock)
		claims := cacheClaims(anchor, clock.Now())
		if _, err := authenticate(t, verifier,
			signClaims(t, trustedKey, jose.ES256, "trusted-key", "at+jwt", claims)); err != nil {
			t.Fatalf("warm cache: %v", err)
		}
		unknownToken := signClaims(t, unknownKey, jose.ES256, "unknown-key", "at+jwt", claims)
		credential, err := ports.NewBearerCredential(unknownToken)
		if err != nil {
			t.Fatalf("NewBearerCredential: %v", err)
		}

		for cycle := int64(2); cycle <= 4; cycle++ {
			gate := make(chan struct{})
			fixture.setGate(gate)
			ctx, cancel := context.WithCancel(t.Context())
			result := make(chan error, 1)
			go func() {
				_, authenticateErr := verifier.Authenticate(ctx, credential)
				result <- authenticateErr
			}()
			requireEventually(t, time.Second, func() bool { return fixture.hits.Load() == cycle })
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled reactive refresh error = %v, want context.Canceled", err)
			}

			for range 8 {
				retryCtx, retryCancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				_, retryErr := verifier.Authenticate(retryCtx, credential)
				retryCancel()
				requireAuthenticationError(t, retryErr, ports.ErrAuthenticationInvalid)
			}
			if got := fixture.hits.Load(); got != cycle {
				t.Fatalf("cycle %d reactive cancellation burst caused %d fetches", cycle, got)
			}
			clock.Advance(anchor.Cache.RefreshCooldown)
		}
	})
}

func TestJWKSContextCanceledOwnerCannotRelayRefreshThroughWaiters(t *testing.T) {
	const followers = 4

	t.Run("cold required refresh", func(t *testing.T) {
		fixture := newKeyServer(t)
		clock := newFakeClock(testNow)
		key := generateECDSAKey(t)
		fixture.setKeys(t, publicJWK(key, "relay-key", jose.ES256))
		gate := make(chan struct{})
		fixture.setGate(gate)
		anchor := testTrustAnchor(fixture, identity.KindHuman)
		verifier := newTestVerifier(t, fixture, anchor, clock)
		token := signClaims(t, key, jose.ES256, "relay-key", "at+jwt", cacheClaims(anchor, clock.Now()))
		credential, err := ports.NewBearerCredential(token)
		if err != nil {
			t.Fatalf("NewBearerCredential: %v", err)
		}

		ownerCtx, cancelOwner := context.WithCancel(t.Context())
		ownerResult := make(chan error, 1)
		go func() {
			_, authenticateErr := verifier.Authenticate(ownerCtx, credential)
			ownerResult <- authenticateErr
		}()
		requireEventually(t, time.Second, func() bool { return fixture.hits.Load() == 1 })

		followerResults := make(chan error, followers)
		for range followers {
			go func() {
				_, authenticateErr := verifier.Authenticate(t.Context(), credential)
				followerResults <- authenticateErr
			}()
		}
		requireEventually(t, time.Second, func() bool {
			return refreshFollowerCount(verifier.cache) == followers
		})
		cancelOwner()
		if err := <-ownerResult; !errors.Is(err, context.Canceled) {
			t.Fatalf("owner error = %v, want context.Canceled", err)
		}
		for range followers {
			requireAuthenticationError(t, <-followerResults, ports.ErrAuthenticationUnavailable)
		}
		_, err = verifier.Authenticate(t.Context(), credential)
		requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
		if got := fixture.hits.Load(); got != 1 {
			t.Fatalf("canceled owner relayed cold refresh into %d fetches, want 1", got)
		}
	})

	t.Run("fresh reactive refresh", func(t *testing.T) {
		fixture := newKeyServer(t)
		clock := newFakeClock(testNow)
		trustedKey := generateECDSAKey(t)
		unknownKey := generateECDSAKey(t)
		fixture.setKeys(t, publicJWK(trustedKey, "trusted-relay-key", jose.ES256))
		anchor := testTrustAnchor(fixture, identity.KindHuman)
		verifier := newTestVerifier(t, fixture, anchor, clock)
		claims := cacheClaims(anchor, clock.Now())
		if _, err := authenticate(t, verifier,
			signClaims(t, trustedKey, jose.ES256, "trusted-relay-key", "at+jwt", claims)); err != nil {
			t.Fatalf("warm cache: %v", err)
		}

		gate := make(chan struct{})
		fixture.setGate(gate)
		unknownToken := signClaims(t, unknownKey, jose.ES256, "unknown-relay-key", "at+jwt", claims)
		credential, err := ports.NewBearerCredential(unknownToken)
		if err != nil {
			t.Fatalf("NewBearerCredential: %v", err)
		}
		ownerCtx, cancelOwner := context.WithCancel(t.Context())
		ownerResult := make(chan error, 1)
		go func() {
			_, authenticateErr := verifier.Authenticate(ownerCtx, credential)
			ownerResult <- authenticateErr
		}()
		requireEventually(t, time.Second, func() bool { return fixture.hits.Load() == 2 })

		followerResults := make(chan error, followers)
		for range followers {
			go func() {
				_, authenticateErr := verifier.Authenticate(t.Context(), credential)
				followerResults <- authenticateErr
			}()
		}
		requireEventually(t, time.Second, func() bool {
			return refreshFollowerCount(verifier.cache) == followers
		})
		cancelOwner()
		if err := <-ownerResult; !errors.Is(err, context.Canceled) {
			t.Fatalf("owner error = %v, want context.Canceled", err)
		}
		for range followers {
			requireAuthenticationError(t, <-followerResults, ports.ErrAuthenticationInvalid)
		}
		_, err = verifier.Authenticate(t.Context(), credential)
		requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
		if got := fixture.hits.Load(); got != 2 {
			t.Fatalf("canceled owner relayed reactive refresh into %d fetches, want 2", got)
		}
	})
}

func TestJWKSClientRejectsRedirectsAndCookies(t *testing.T) {
	var redirectedHits atomic.Int64
	var cookieSeen atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/keys":
			cookieSeen.Store(request.Header.Get("Cookie") != "")
			http.Redirect(writer, request, "/redirected", http.StatusFound)
		case "/redirected":
			redirectedHits.Add(1)
			_, _ = writer.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	jar.SetCookies(serverURL, []*http.Cookie{{Name: "session", Value: "CANARY-COOKIE"}})
	client := server.Client()
	client.Jar = jar
	fixture := &keyServer{server: server}
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier, err := NewVerifier(anchor, client, newFakeClock(testNow))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	key := generateECDSAKey(t)
	token := signClaims(t, key, jose.ES256, "redirect-key", "at+jwt", cacheClaims(anchor, testNow))
	_, err = authenticate(t, verifier, token)
	requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
	if redirectedHits.Load() != 0 {
		t.Fatal("JWKS client followed a redirect")
	}
	if cookieSeen.Load() {
		t.Fatal("JWKS client sent an injected cookie")
	}
}

func TestJWKSAlgorithmBinding(t *testing.T) {
	rsaKey := generateRSAKey(t)
	tests := []struct {
		name       string
		algorithms []jose.SignatureAlgorithm
		keys       func() []jose.JSONWebKey
		signAlg    jose.SignatureAlgorithm
		want       error
	}{
		{
			name:       "omitted alg with one compatible configured algorithm",
			algorithms: []jose.SignatureAlgorithm{jose.RS256},
			keys: func() []jose.JSONWebKey {
				key := publicJWK(rsaKey, "rsa-key", jose.RS256)
				key.Algorithm = ""
				return []jose.JSONWebKey{key}
			},
			signAlg: jose.RS256,
		},
		{
			name:       "omitted alg is ambiguous",
			algorithms: []jose.SignatureAlgorithm{jose.RS256, jose.PS256},
			keys: func() []jose.JSONWebKey {
				key := publicJWK(rsaKey, "rsa-key", jose.RS256)
				key.Algorithm = ""
				return []jose.JSONWebKey{key}
			},
			signAlg: jose.RS256,
			want:    ports.ErrAuthenticationUnavailable,
		},
		{
			name:       "present alg mismatch is ignored",
			algorithms: []jose.SignatureAlgorithm{jose.RS256},
			keys: func() []jose.JSONWebKey {
				return []jose.JSONWebKey{publicJWK(rsaKey, "rsa-key", jose.PS256)}
			},
			signAlg: jose.RS256,
			want:    ports.ErrAuthenticationUnavailable,
		},
		{
			name:       "same kid can bind distinct explicit algorithms",
			algorithms: []jose.SignatureAlgorithm{jose.RS256, jose.PS256},
			keys: func() []jose.JSONWebKey {
				return []jose.JSONWebKey{
					publicJWK(rsaKey, "rsa-key", jose.RS256),
					publicJWK(rsaKey, "rsa-key", jose.PS256),
				}
			},
			signAlg: jose.PS256,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			fixture.setKeys(t, test.keys()...)
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			anchor.AllowedAlgorithms = test.algorithms
			verifier := newTestVerifier(t, fixture, anchor, clock)
			token := signClaims(t, rsaKey, test.signAlg, "rsa-key", "at+jwt", cacheClaims(anchor, clock.Now()))
			_, err := authenticate(t, verifier, token)
			if test.want != nil {
				requireAuthenticationError(t, err, test.want)
			} else if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
		})
	}
}

func TestJWKSKeyOperationsMustPermitVerification(t *testing.T) {
	key := generateEd25519Key(t)
	tests := []struct {
		name          string
		keyOperations any
		want          error
	}{
		{name: "absent"},
		{name: "verify", keyOperations: []string{"verify"}},
		{name: "verify with another unique operation", keyOperations: []string{"deriveKey", "verify"}},
		{name: "sign only", keyOperations: []string{"sign"}, want: ports.ErrAuthenticationUnavailable},
		{name: "duplicate", keyOperations: []string{"verify", "verify"}, want: ports.ErrAuthenticationUnavailable},
		{name: "wrong type", keyOperations: "verify", want: ports.ErrAuthenticationUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			jwk := publicJWK(key, "ed-key", jose.EdDSA)
			encodedKey := encodedJWK(t, jwk, test.keyOperations, test.keyOperations != nil)
			fixture.setResponse(http.StatusOK, rawJWKS(t, encodedKey))
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA}
			verifier := newTestVerifier(t, fixture, anchor, clock)
			token := signClaims(t, key, jose.EdDSA, "ed-key", "at+jwt", cacheClaims(anchor, clock.Now()))
			_, err := authenticate(t, verifier, token)
			if test.want != nil {
				requireAuthenticationError(t, err, test.want)
			} else if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
		})
	}
}

func TestJWKSRejectsMalformedAndOverBoundSets(t *testing.T) {
	key := generateECDSAKey(t)
	validKey := publicJWK(key, "bounded-key", jose.ES256)
	encodedValidKey := encodedJWK(t, validKey, nil, false)
	tests := []struct {
		name   string
		body   func(*testing.T) []byte
		mutate func(*TrustAnchor)
	}{
		{name: "malformed JSON", body: func(*testing.T) []byte { return []byte(`{"keys":[`) }},
		{name: "missing keys", body: func(*testing.T) []byte { return []byte(`{}`) }},
		{name: "empty keys", body: func(*testing.T) []byte { return []byte(`{"keys":[]}`) }},
		{name: "duplicate top-level member", body: func(*testing.T) []byte {
			return []byte(`{"keys":[],"keys":[]}`)
		}},
		{name: "invalid surrogate", body: func(*testing.T) []byte {
			return []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"\ud800","x":"AA"}]}`)
		}},
		{name: "too many keys", body: func(t *testing.T) []byte {
			return rawJWKS(t, encodedValidKey, encodedValidKey)
		}, mutate: func(anchor *TrustAnchor) { anchor.Cache.MaximumKeys = 1 }},
		{name: "duplicate bound key", body: func(t *testing.T) []byte {
			return rawJWKS(t, encodedValidKey, encodedValidKey)
		}},
		{name: "response too large", body: func(t *testing.T) []byte {
			return rawJWKS(t, encodedValidKey)
		}, mutate: func(anchor *TrustAnchor) { anchor.Cache.MaximumResponseBytes = 32 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			fixture.setResponse(http.StatusOK, test.body(t))
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			if test.mutate != nil {
				test.mutate(&anchor)
			}
			verifier := newTestVerifier(t, fixture, anchor, clock)
			token := signClaims(t, key, jose.ES256, "bounded-key", "at+jwt", cacheClaims(anchor, clock.Now()))
			_, err := authenticate(t, verifier, token)
			requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
		})
	}
}

func TestKeyAlgorithmCompatibilityMatrix(t *testing.T) {
	rsaKey := generateRSAKey(t)
	p256Key := generateECDSAKey(t)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-521 key: %v", err)
	}
	ed25519Key := generateEd25519Key(t)
	tests := []struct {
		name      string
		key       any
		algorithm jose.SignatureAlgorithm
		want      bool
	}{
		{name: "RSA PKCS", key: &rsaKey.PublicKey, algorithm: jose.RS512, want: true},
		{name: "RSA PSS", key: &rsaKey.PublicKey, algorithm: jose.PS384, want: true},
		{name: "RSA not ECDSA", key: &rsaKey.PublicKey, algorithm: jose.ES256},
		{name: "P-256", key: &p256Key.PublicKey, algorithm: jose.ES256, want: true},
		{name: "P-256 wrong hash", key: &p256Key.PublicKey, algorithm: jose.ES384},
		{name: "P-384", key: &p384Key.PublicKey, algorithm: jose.ES384, want: true},
		{name: "P-521", key: &p521Key.PublicKey, algorithm: jose.ES512, want: true},
		{name: "Ed25519", key: ed25519Key.Public().(ed25519.PublicKey), algorithm: jose.EdDSA, want: true},
		{name: "Ed25519 not RSA", key: ed25519Key.Public().(ed25519.PublicKey), algorithm: jose.RS256},
		{name: "private key", key: p256Key, algorithm: jose.ES256},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := keySupportsAlgorithm(test.key, test.algorithm); got != test.want {
				t.Fatalf("keySupportsAlgorithm() = %t, want %t", got, test.want)
			}
		})
	}
}

func cacheClaims(anchor TrustAnchor, now time.Time) map[string]any {
	claims := validClaims(anchor, now)
	claims["exp"] = now.Add(45 * time.Minute).Unix()
	return claims
}

func encodedJWK(t *testing.T, key jose.JSONWebKey, keyOperations any, includeOperations bool) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	var members map[string]any
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("unmarshal generated JWK: %v", err)
	}
	if includeOperations {
		members["key_ops"] = keyOperations
	}
	encoded, err = json.Marshal(members)
	if err != nil {
		t.Fatalf("marshal decorated JWK: %v", err)
	}
	return encoded
}

func rawJWKS(t *testing.T, keys ...json.RawMessage) []byte {
	t.Helper()
	body, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: keys})
	if err != nil {
		t.Fatalf("marshal raw JWKS: %v", err)
	}
	return body
}

func requireEventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true before timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

func refreshFollowerCount(cache *keyCache) int {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.flight == nil {
		return 0
	}
	return cache.flight.followers
}
