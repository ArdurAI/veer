package oidc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
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

func TestJWKSBadSignatureDoesNotRefetchJustResolvedGeneration(t *testing.T) {
	tests := []struct {
		name        string
		warmCache   bool
		wantFetches int64
	}{
		{name: "cold required refresh", wantFetches: 1},
		{name: "proactive refresh", warmCache: true, wantFetches: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			trustedKey := generateECDSAKey(t)
			untrustedKey := generateECDSAKey(t)
			fixture.setKeys(t, publicJWK(trustedKey, "stable-kid", jose.ES256))
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			verifier := newTestVerifier(t, fixture, anchor, clock)
			claims := cacheClaims(anchor, clock.Now())

			if test.warmCache {
				trustedToken := signClaims(t, trustedKey, jose.ES256, "stable-kid", "at+jwt", claims)
				if _, err := authenticate(t, verifier, trustedToken); err != nil {
					t.Fatalf("warm cache: %v", err)
				}
				clock.Advance(anchor.Cache.Freshness - anchor.Cache.RefreshAhead)
			}

			badToken := signClaims(t, untrustedKey, jose.ES256, "stable-kid", "at+jwt", claims)
			_, err := authenticate(t, verifier, badToken)
			requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
			if got := fixture.hits.Load(); got != test.wantFetches {
				t.Fatalf("JWKS fetches = %d, want %d", got, test.wantFetches)
			}
		})
	}
}

func TestJWKSFailedProactiveRefreshThrottlesReactiveRetry(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	trustedKey := generateECDSAKey(t)
	untrustedKey := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(trustedKey, "stable-outage-kid", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := cacheClaims(anchor, clock.Now())
	trustedToken := signClaims(t, trustedKey, jose.ES256, "stable-outage-kid", "at+jwt", claims)
	if _, err := authenticate(t, verifier, trustedToken); err != nil {
		t.Fatalf("warm cache: %v", err)
	}

	clock.Advance(anchor.Cache.Freshness - anchor.Cache.RefreshAhead)
	fixture.setResponse(http.StatusServiceUnavailable, []byte(`{"error":"unavailable"}`))
	if _, err := authenticate(t, verifier, trustedToken); err != nil {
		t.Fatalf("cached valid token after failed proactive refresh: %v", err)
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("failed proactive refresh caused %d fetches, want 2", got)
	}

	badToken := signClaims(t, untrustedKey, jose.ES256, "stable-outage-kid", "at+jwt", claims)
	for range 8 {
		_, err := authenticate(t, verifier, badToken)
		requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("failed proactive plus bad-signature retries caused %d fetches, want 2", got)
	}
}

func TestJWKSSuccessfulProactiveRefreshDoesNotThrottleRotation(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	firstKey := generateECDSAKey(t)
	rotatedKey := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(firstKey, "proactive-rotation-kid", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := cacheClaims(anchor, clock.Now())
	firstToken := signClaims(t, firstKey, jose.ES256, "proactive-rotation-kid", "at+jwt", claims)
	if _, err := authenticate(t, verifier, firstToken); err != nil {
		t.Fatalf("warm cache: %v", err)
	}

	clock.Advance(anchor.Cache.Freshness - anchor.Cache.RefreshAhead)
	if _, err := authenticate(t, verifier, firstToken); err != nil {
		t.Fatalf("successful proactive refresh: %v", err)
	}
	fixture.setKeys(t, publicJWK(rotatedKey, "proactive-rotation-kid", jose.ES256))
	rotatedToken := signClaims(t, rotatedKey, jose.ES256, "proactive-rotation-kid", "at+jwt", claims)
	if _, err := authenticate(t, verifier, rotatedToken); err != nil {
		t.Fatalf("same-kid rotation after successful proactive refresh: %v", err)
	}
	if got := fixture.hits.Load(); got != 3 {
		t.Fatalf("successful proactive refresh plus rotation caused %d fetches, want 3", got)
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

func TestJWKSFailedProactiveRefreshCooldownCarriesIntoRequiredRefresh(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(key, "proactive-cooldown-key", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	anchor.Cache.RefreshCooldown = 5 * time.Minute
	verifier := newTestVerifier(t, fixture, anchor, clock)
	token := signClaims(
		t,
		key,
		jose.ES256,
		"proactive-cooldown-key",
		"at+jwt",
		cacheClaims(anchor, clock.Now()),
	)
	if _, err := authenticate(t, verifier, token); err != nil {
		t.Fatalf("warm cache: %v", err)
	}

	clock.Advance(anchor.Cache.Freshness - anchor.Cache.RefreshAhead)
	fixture.setResponse(http.StatusServiceUnavailable, []byte(`{"error":"unavailable"}`))
	if _, err := authenticate(t, verifier, token); err != nil {
		t.Fatalf("fresh fallback after failed proactive refresh: %v", err)
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("failed proactive refresh fetches = %d, want 2", got)
	}

	fixture.setKeys(t, publicJWK(key, "proactive-cooldown-key", jose.ES256))
	clock.Advance(anchor.Cache.RefreshAhead)
	_, err := authenticate(t, verifier, token)
	requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("staleness bypassed proactive failure cooldown with %d fetches, want 2", got)
	}

	clock.Advance(anchor.Cache.RefreshCooldown - anchor.Cache.RefreshAhead)
	if _, err := authenticate(t, verifier, token); err != nil {
		t.Fatalf("required refresh after cooldown: %v", err)
	}
	if got := fixture.hits.Load(); got != 3 {
		t.Fatalf("post-cooldown required refresh fetches = %d, want 3", got)
	}
}

func TestJWKSSuccessfulReactiveInstallStartsNewFreshnessEpoch(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	initialKey := generateECDSAKey(t)
	rotatedKey := generateECDSAKey(t)
	unknownKey := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(initialKey, "initial-epoch-key", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	anchor.Cache.Freshness = 2 * time.Minute
	anchor.Cache.RefreshAhead = time.Minute
	anchor.Cache.RefreshCooldown = 10 * time.Minute
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := cacheClaims(anchor, clock.Now())
	initialToken := signClaims(t, initialKey, jose.ES256, "initial-epoch-key", "at+jwt", claims)
	if _, err := authenticate(t, verifier, initialToken); err != nil {
		t.Fatalf("warm cache: %v", err)
	}

	clock.Advance(anchor.Cache.Freshness - anchor.Cache.RefreshAhead)
	failedAt := clock.Now()
	fixture.setResponse(http.StatusServiceUnavailable, []byte(`{"error":"unavailable"}`))
	if _, err := authenticate(t, verifier, initialToken); err != nil {
		t.Fatalf("fresh fallback after failed proactive refresh: %v", err)
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("failed proactive refresh fetches = %d, want 2", got)
	}

	fixture.setKeys(t, publicJWK(rotatedKey, "rotated-epoch-key", jose.ES256))
	rotatedToken := signClaims(t, rotatedKey, jose.ES256, "rotated-epoch-key", "at+jwt", claims)
	if _, err := authenticate(t, verifier, rotatedToken); err != nil {
		t.Fatalf("reactive rotation refresh: %v", err)
	}
	if got := fixture.hits.Load(); got != 3 {
		t.Fatalf("reactive rotation fetches = %d, want 3", got)
	}

	wantReactiveCooldown := clock.Now().Add(anchor.Cache.RefreshCooldown)
	verifier.cache.mu.Lock()
	requiredCooldown := verifier.cache.nextRequiredRefreshAllowed
	proactiveCooldown := verifier.cache.nextProactiveRefreshAllowed
	reactiveCooldown := verifier.cache.nextReactiveRefreshAllowed
	verifier.cache.mu.Unlock()
	if !requiredCooldown.IsZero() || !proactiveCooldown.IsZero() {
		t.Fatalf(
			"successful install retained obsolete cooldowns: required=%v proactive=%v",
			requiredCooldown,
			proactiveCooldown,
		)
	}
	if !reactiveCooldown.Equal(wantReactiveCooldown) {
		t.Fatalf("reactive cooldown = %v, want %v", reactiveCooldown, wantReactiveCooldown)
	}

	unknownToken := signClaims(t, unknownKey, jose.ES256, "unknown-epoch-key", "at+jwt", claims)
	_, err := authenticate(t, verifier, unknownToken)
	requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
	if got := fixture.hits.Load(); got != 3 {
		t.Fatalf("successful reactive cooldown allowed %d fetches, want 3", got)
	}

	clock.Advance(anchor.Cache.Freshness)
	if !clock.Now().Before(failedAt.Add(anchor.Cache.RefreshCooldown)) {
		t.Fatal("test advanced beyond the obsolete proactive failure cooldown")
	}
	if _, err := authenticate(t, verifier, rotatedToken); err != nil {
		t.Fatalf("required refresh in new freshness epoch: %v", err)
	}
	if got := fixture.hits.Load(); got != 4 {
		t.Fatalf("new freshness epoch required refreshes = %d, want 4", got)
	}
}

func TestJWKSProactiveSnapshotObservesFailedReactiveAttemptCooldown(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	knownKey := generateECDSAKey(t)
	unknownKey := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(knownKey, "known-interleaved-key", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	anchor.Cache.RefreshCooldown = 5 * time.Minute
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := cacheClaims(anchor, clock.Now())
	knownToken := signClaims(t, knownKey, jose.ES256, "known-interleaved-key", "at+jwt", claims)
	unknownToken := signClaims(t, unknownKey, jose.ES256, "unknown-interleaved-key", "at+jwt", claims)
	if _, err := authenticate(t, verifier, knownToken); err != nil {
		t.Fatalf("warm cache: %v", err)
	}

	clock.Advance(anchor.Cache.Freshness - anchor.Cache.RefreshAhead)
	now := clock.Now()
	knownReference := keyReference{keyID: "known-interleaved-key", algorithm: jose.ES256}
	verifier.cache.mu.Lock()
	_, known := verifier.cache.keys[knownReference]
	fresh := now.Before(verifier.cache.freshUntil)
	due := !now.Before(verifier.cache.refreshAt)
	pausedProactiveAttempt := verifier.cache.attempt
	verifier.cache.mu.Unlock()
	if !known || !fresh || !due {
		t.Fatal("test did not capture a due known-key proactive snapshot")
	}

	fixture.setResponse(http.StatusServiceUnavailable, []byte(`{"error":"unavailable"}`))
	_, err := authenticate(t, verifier, unknownToken)
	requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("failed reactive attempt fetches = %d, want 2", got)
	}

	refreshErr := verifier.cache.refresh(t.Context(), pausedProactiveAttempt, refreshProactive)
	if !errors.Is(refreshErr, errKeySourceUnavailable) {
		t.Fatalf("proactive attempt-mismatch error = %v, want key source unavailable", refreshErr)
	}
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("attempt-mismatch path made %d fetches, want 2", got)
	}

	fixture.setKeys(t, publicJWK(knownKey, "known-interleaved-key", jose.ES256))
	clock.Advance(anchor.Cache.RefreshAhead)
	_, err = authenticate(t, verifier, knownToken)
	requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
	if got := fixture.hits.Load(); got != 2 {
		t.Fatalf("staleness bypassed interleaved failure cooldown with %d fetches, want 2", got)
	}

	clock.Advance(anchor.Cache.RefreshCooldown - anchor.Cache.RefreshAhead)
	if _, err := authenticate(t, verifier, knownToken); err != nil {
		t.Fatalf("required refresh after cooldown: %v", err)
	}
	if got := fixture.hits.Load(); got != 3 {
		t.Fatalf("post-cooldown required refresh fetches = %d, want 3", got)
	}
}

func TestJWKSAttemptMismatchCooldownBookkeeping(t *testing.T) {
	tests := []struct {
		name          string
		lastErr       error
		reason        refreshReason
		wantErr       error
		wantRequired  bool
		wantProactive bool
		wantReactive  bool
	}{
		{
			name:          "proactive after unavailable failure",
			lastErr:       errKeySourceUnavailable,
			reason:        refreshProactive,
			wantErr:       errKeySourceUnavailable,
			wantRequired:  true,
			wantProactive: true,
		},
		{
			name:          "proactive after canceled owner",
			lastErr:       context.Canceled,
			reason:        refreshProactive,
			wantErr:       errKeySourceUnavailable,
			wantRequired:  true,
			wantProactive: true,
		},
		{
			name:          "proactive after owner deadline",
			lastErr:       context.DeadlineExceeded,
			reason:        refreshProactive,
			wantErr:       errKeySourceUnavailable,
			wantRequired:  true,
			wantProactive: true,
		},
		{
			name:         "reactive after successful attempt",
			reason:       refreshReactive,
			wantReactive: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newKeyServer(t)
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			cache := newTestVerifier(t, fixture, anchor, newFakeClock(testNow)).cache
			cache.mu.Lock()
			cache.attempt = 2
			cache.lastAttemptAt = testNow
			cache.lastAttemptError = test.lastErr
			cache.mu.Unlock()

			err := cache.refresh(t.Context(), 1, test.reason)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("refresh attempt mismatch error = %v, want nil", err)
				}
			} else if !errors.Is(err, test.wantErr) {
				t.Fatalf("refresh attempt mismatch error = %v, want %v", err, test.wantErr)
			}

			wantCooldown := testNow.Add(anchor.Cache.RefreshCooldown)
			cache.mu.Lock()
			required := cache.nextRequiredRefreshAllowed
			proactive := cache.nextProactiveRefreshAllowed
			reactive := cache.nextReactiveRefreshAllowed
			cache.mu.Unlock()
			assertCooldown := func(name string, got time.Time, want bool) {
				t.Helper()
				if want && !got.Equal(wantCooldown) {
					t.Fatalf("%s cooldown = %v, want %v", name, got, wantCooldown)
				}
				if !want && !got.IsZero() {
					t.Fatalf("%s cooldown = %v, want zero", name, got)
				}
			}
			assertCooldown("required", required, test.wantRequired)
			assertCooldown("proactive", proactive, test.wantProactive)
			assertCooldown("reactive", reactive, test.wantReactive)
			if got := fixture.hits.Load(); got != 0 {
				t.Fatalf("attempt-mismatch bookkeeping made %d fetches, want zero", got)
			}
		})
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

func TestJWKSAdmissionContextErrorPreservesCallerCancellation(t *testing.T) {
	live := t.Context()
	callerCanceled, cancelCaller := context.WithCancel(live)
	cancelCaller()
	boundedCanceled, cancelBounded := context.WithCancel(live)
	cancelBounded()

	tests := []struct {
		name    string
		parent  context.Context
		bounded context.Context
		want    error
	}{
		{name: "live", parent: live, bounded: live},
		{name: "caller canceled", parent: callerCanceled, bounded: live, want: context.Canceled},
		{name: "internal deadline", parent: live, bounded: boundedCanceled, want: errKeySourceUnavailable},
		{name: "caller wins", parent: callerCanceled, bounded: boundedCanceled, want: context.Canceled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := jwksAdmissionContextError(test.parent, test.bounded)
			if test.want == nil {
				if err != nil {
					t.Fatalf("jwksAdmissionContextError() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("jwksAdmissionContextError() = %v, want %v", err, test.want)
			}
		})
	}
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

func TestJWKSOptionalStringMembersDistinguishOmissionFromInvalidValues(t *testing.T) {
	key := generateEd25519Key(t)
	tests := []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{name: "omitted use", mutate: func(members map[string]any) { delete(members, "use") }, valid: true},
		{name: "explicit sig use", mutate: func(map[string]any) {}, valid: true},
		{name: "empty use", mutate: func(members map[string]any) { members["use"] = "" }},
		{name: "null use", mutate: func(members map[string]any) { members["use"] = nil }},
		{name: "non-string use", mutate: func(members map[string]any) { members["use"] = []string{"sig"} }},
		{name: "whitespace use", mutate: func(members map[string]any) { members["use"] = " sig " }},
		{name: "omitted alg", mutate: func(members map[string]any) { delete(members, "alg") }, valid: true},
		{name: "explicit EdDSA alg", mutate: func(map[string]any) {}, valid: true},
		{name: "empty alg", mutate: func(members map[string]any) { members["alg"] = "" }},
		{name: "null alg", mutate: func(members map[string]any) { members["alg"] = nil }},
		{name: "non-string alg", mutate: func(members map[string]any) { members["alg"] = 1 }},
		{name: "whitespace alg", mutate: func(members map[string]any) { members["alg"] = " EdDSA " }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			jwk := publicJWK(key, "optional-string-key", jose.EdDSA)
			fixture.setResponse(http.StatusOK, rawJWKS(t, rewriteJWK(t, jwk, test.mutate)))
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA}
			verifier := newTestVerifier(t, fixture, anchor, clock)
			token := signClaims(
				t,
				key,
				jose.EdDSA,
				"optional-string-key",
				"at+jwt",
				cacheClaims(anchor, clock.Now()),
			)
			_, err := authenticate(t, verifier, token)
			if test.valid {
				if err != nil {
					t.Fatalf("Authenticate: %v", err)
				}
				return
			}
			requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
		})
	}
}

func TestJWKSOKPXMustBeCanonicalEd25519PublicKey(t *testing.T) {
	key := generateEd25519Key(t)
	publicKey := key.Public().(ed25519.PublicKey)
	canonical := base64.RawURLEncoding.EncodeToString(publicKey)
	tooLong := append(append([]byte(nil), publicKey...), 0x42)
	tests := []struct {
		name  string
		value any
		valid bool
	}{
		{name: "exact public key", value: canonical, valid: true},
		{name: "one byte short", value: base64.RawURLEncoding.EncodeToString(publicKey[:len(publicKey)-1])},
		{name: "trailing byte would be truncated", value: base64.RawURLEncoding.EncodeToString(tooLong)},
		{name: "non-canonical trailing bits", value: nonCanonicalBase64URL(t, canonical)},
		{name: "padded", value: canonical + "="},
		{name: "empty", value: ""},
		{name: "null", value: nil},
		{name: "non-string", value: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			jwk := publicJWK(key, "okp-key", jose.EdDSA)
			encodedKey := rewriteJWK(t, jwk, func(members map[string]any) {
				members["x"] = test.value
			})
			fixture.setResponse(http.StatusOK, rawJWKS(t, encodedKey))
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA}
			verifier := newTestVerifier(t, fixture, anchor, clock)
			token := signClaims(
				t,
				key,
				jose.EdDSA,
				"okp-key",
				"at+jwt",
				cacheClaims(anchor, clock.Now()),
			)
			_, err := authenticate(t, verifier, token)
			if test.valid {
				if err != nil {
					t.Fatalf("Authenticate: %v", err)
				}
				return
			}
			requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
		})
	}
}

func TestJWKSEd25519IdentityPointIsRejectedBeforeVerification(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	identityKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identityKey[0] = 1
	fixture.setKeys(t, jose.JSONWebKey{
		Key:       identityKey,
		KeyID:     "small-order-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	})
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA}
	verifier := newTestVerifier(t, fixture, anchor, clock)

	header := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"EdDSA","kid":"small-order-key","typ":"at+jwt"}`),
	)
	payloadJSON, err := json.Marshal(cacheClaims(anchor, clock.Now()))
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	forgedSignature := make([]byte, ed25519.SignatureSize)
	forgedSignature[0] = 0x58
	for index := 1; index < ed25519.PublicKeySize; index++ {
		forgedSignature[index] = 0x66
	}
	forgedSignature[ed25519.PublicKeySize] = 1
	if !ed25519.Verify(identityKey, []byte(signingInput), forgedSignature) {
		t.Fatal("Go verifier no longer accepts the constructive small-order signature")
	}
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(forgedSignature)

	_, err = authenticate(t, verifier, token)
	requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
}

func TestEd25519AdmissionRejectsEveryAcceptedLowOrderEncoding(t *testing.T) {
	lowOrderEncodings := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000080",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	for _, encoded := range lowOrderEncodings {
		encoded := encoded
		t.Run(encoded[:8], func(t *testing.T) {
			decoded, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatalf("decode low-order key: %v", err)
			}
			if validEd25519VerificationKey(ed25519.PublicKey(decoded)) {
				t.Fatal("accepted low-order Ed25519 public key")
			}
		})
	}

	validKey := generateEd25519Key(t).Public().(ed25519.PublicKey)
	if !validEd25519VerificationKey(validKey) {
		t.Fatal("rejected generated Ed25519 public key")
	}
}

func TestBoundAlgorithmRequiresRawEd25519KeyMatch(t *testing.T) {
	fixture := newKeyServer(t)
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA}
	verifier := newTestVerifier(t, fixture, anchor, newFakeClock(testNow))
	key := generateEd25519Key(t)
	jwk := publicJWK(key, "raw-ed25519-binding-key", jose.EdDSA)
	encoded, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	rawKey, ok := inspectVerificationJWK(encoded)
	if !ok {
		t.Fatal("inspectVerificationJWK rejected canonical Ed25519 key")
	}
	if algorithm, ok := verifier.cache.boundAlgorithm(jwk, rawKey); !ok || algorithm != jose.EdDSA {
		t.Fatalf("boundAlgorithm(matching key) = %q, %t, want EdDSA, true", algorithm, ok)
	}

	different := publicJWK(generateEd25519Key(t), "raw-ed25519-binding-key", jose.EdDSA)
	if algorithm, ok := verifier.cache.boundAlgorithm(different, rawKey); ok || algorithm != "" {
		t.Fatalf("boundAlgorithm(different typed key) = %q, %t, want empty false", algorithm, ok)
	}
	altered := cloneRawVerificationJWK(rawKey)
	altered.ed25519Key[0] ^= 1
	if algorithm, ok := verifier.cache.boundAlgorithm(jwk, altered); ok || algorithm != "" {
		t.Fatalf("boundAlgorithm(altered raw key) = %q, %t, want empty false", algorithm, ok)
	}
}

func TestCanonicalECPublicKeyRequiresExactCanonicalCoordinates(t *testing.T) {
	tests := []struct {
		name            string
		curve           elliptic.Curve
		curveName       string
		algorithm       jose.SignatureAlgorithm
		coordinateBytes int
	}{
		{name: "P-256", curve: elliptic.P256(), curveName: "P-256", algorithm: jose.ES256, coordinateBytes: p256CoordinateBytes},
		{name: "P-384", curve: elliptic.P384(), curveName: "P-384", algorithm: jose.ES384, coordinateBytes: p384CoordinateBytes},
		{name: "P-521", curve: elliptic.P521(), curveName: "P-521", algorithm: jose.ES512, coordinateBytes: p521CoordinateBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := generateECDSAKeyForCurve(t, test.curve)
			members := rawJWKMembers(t, publicJWK(key, "ec-key", test.algorithm))
			xEncoded := rawJSONStringMember(t, members, "x")
			yEncoded := rawJSONStringMember(t, members, "y")
			x, err := base64.RawURLEncoding.DecodeString(xEncoded)
			if err != nil {
				t.Fatalf("decode generated x: %v", err)
			}
			y, err := base64.RawURLEncoding.DecodeString(yEncoded)
			if err != nil {
				t.Fatalf("decode generated y: %v", err)
			}

			type mutationCase struct {
				name   string
				mutate func(map[string]json.RawMessage)
			}
			mutations := []mutationCase{
				{name: "missing curve", mutate: func(value map[string]json.RawMessage) { delete(value, "crv") }},
				{name: "null curve", mutate: func(value map[string]json.RawMessage) { value["crv"] = json.RawMessage(`null`) }},
				{name: "non-string curve", mutate: func(value map[string]json.RawMessage) { value["crv"] = json.RawMessage(`1`) }},
				{name: "empty curve", mutate: func(value map[string]json.RawMessage) { value["crv"] = json.RawMessage(`""`) }},
				{name: "unsupported curve", mutate: func(value map[string]json.RawMessage) { value["crv"] = json.RawMessage(`"P-255"`) }},
				{name: "missing x", mutate: func(value map[string]json.RawMessage) { delete(value, "x") }},
				{name: "null x", mutate: func(value map[string]json.RawMessage) { value["x"] = json.RawMessage(`null`) }},
				{name: "non-string x", mutate: func(value map[string]json.RawMessage) { value["x"] = json.RawMessage(`1`) }},
				{name: "empty x", mutate: func(value map[string]json.RawMessage) { value["x"] = json.RawMessage(`""`) }},
				{name: "padded x", mutate: func(value map[string]json.RawMessage) {
					value["x"] = json.RawMessage(strconv.Quote(xEncoded + "="))
				}},
				{name: "short x", mutate: func(value map[string]json.RawMessage) {
					value["x"] = json.RawMessage(strconv.Quote(base64.RawURLEncoding.EncodeToString(x[:len(x)-1])))
				}},
				{name: "long x", mutate: func(value map[string]json.RawMessage) {
					long := append(append([]byte(nil), x...), 0)
					value["x"] = json.RawMessage(strconv.Quote(base64.RawURLEncoding.EncodeToString(long)))
				}},
				{name: "missing y", mutate: func(value map[string]json.RawMessage) { delete(value, "y") }},
				{name: "null y", mutate: func(value map[string]json.RawMessage) { value["y"] = json.RawMessage(`null`) }},
				{name: "non-string y", mutate: func(value map[string]json.RawMessage) { value["y"] = json.RawMessage(`1`) }},
				{name: "empty y", mutate: func(value map[string]json.RawMessage) { value["y"] = json.RawMessage(`""`) }},
				{name: "padded y", mutate: func(value map[string]json.RawMessage) {
					value["y"] = json.RawMessage(strconv.Quote(yEncoded + "="))
				}},
				{name: "short y", mutate: func(value map[string]json.RawMessage) {
					value["y"] = json.RawMessage(strconv.Quote(base64.RawURLEncoding.EncodeToString(y[:len(y)-1])))
				}},
				{name: "long y", mutate: func(value map[string]json.RawMessage) {
					long := append(append([]byte(nil), y...), 0)
					value["y"] = json.RawMessage(strconv.Quote(base64.RawURLEncoding.EncodeToString(long)))
				}},
			}
			// A same-bytes trailing-bit alias exists only when the fixed width is
			// not divisible by three. P-384 and P-521 still exercise padding and
			// exact-length rejection above.
			if test.coordinateBytes%3 != 0 {
				mutations = append(mutations,
					mutationCase{name: "non-canonical x", mutate: func(value map[string]json.RawMessage) {
						value["x"] = json.RawMessage(strconv.Quote(nonCanonicalBase64URL(t, xEncoded)))
					}},
					mutationCase{name: "non-canonical y", mutate: func(value map[string]json.RawMessage) {
						value["y"] = json.RawMessage(strconv.Quote(nonCanonicalBase64URL(t, yEncoded)))
					}},
				)
			}

			curve, gotX, gotY, ok := canonicalECPublicKey(members)
			if !ok || curve != test.curveName || !bytes.Equal(gotX, x) || !bytes.Equal(gotY, y) {
				t.Fatalf("canonicalECPublicKey(valid) = %q, %x, %x, %t", curve, gotX, gotY, ok)
			}
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					mutated := cloneRawJWKMembers(members)
					mutation.mutate(mutated)
					if curve, x, y, ok := canonicalECPublicKey(mutated); ok || curve != "" || x != nil || y != nil {
						t.Fatalf("canonicalECPublicKey() = %q, %x, %x, %t, want empty false", curve, x, y, ok)
					}
				})
			}
		})
	}
}

func TestJWKSECCanonicalCoordinatesSupportAllAlgorithmsAndLeadingZero(t *testing.T) {
	tests := []struct {
		name            string
		curve           elliptic.Curve
		algorithm       jose.SignatureAlgorithm
		coordinateBytes int
	}{
		{name: "ES256", curve: elliptic.P256(), algorithm: jose.ES256, coordinateBytes: p256CoordinateBytes},
		{name: "ES384", curve: elliptic.P384(), algorithm: jose.ES384, coordinateBytes: p384CoordinateBytes},
		{name: "ES512", curve: elliptic.P521(), algorithm: jose.ES512, coordinateBytes: p521CoordinateBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := generateECDSAKeyWithLeadingZeroCoordinate(t, test.curve, test.coordinateBytes)
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			fixture.setKeys(t, publicJWK(key, "leading-zero-key", test.algorithm))
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{test.algorithm}
			verifier := newTestVerifier(t, fixture, anchor, clock)
			token := signClaims(
				t,
				key,
				test.algorithm,
				"leading-zero-key",
				"at+jwt",
				cacheClaims(anchor, clock.Now()),
			)
			if _, err := authenticate(t, verifier, token); err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
		})
	}
}

func TestJWKSRejectsNonCanonicalECCoordinateAliases(t *testing.T) {
	key := generateECDSAKeyForCurve(t, elliptic.P256())
	jwk := publicJWK(key, "aliased-ec-key", jose.ES256)
	members := rawJWKMembers(t, jwk)
	xEncoded := rawJSONStringMember(t, members, "x")
	yEncoded := rawJSONStringMember(t, members, "y")
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "x", mutate: func(value map[string]any) { value["x"] = nonCanonicalBase64URL(t, xEncoded) }},
		{name: "y", mutate: func(value map[string]any) { value["y"] = nonCanonicalBase64URL(t, yEncoded) }},
	}
	for _, test := range tests {
		t.Run(test.name+" only unusable key", func(t *testing.T) {
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			fixture.setResponse(http.StatusOK, rawJWKS(t, rewriteJWK(t, jwk, test.mutate)))
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.ES256}
			verifier := newTestVerifier(t, fixture, anchor, clock)
			token := signClaims(t, key, jose.ES256, "aliased-ec-key", "at+jwt", cacheClaims(anchor, clock.Now()))
			_, err := authenticate(t, verifier, token)
			requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
		})

		t.Run(test.name+" unusable key does not poison usable set", func(t *testing.T) {
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			fixture.setResponse(
				http.StatusOK,
				rawJWKS(t, rewriteJWK(t, jwk, test.mutate), rewriteJWK(t, jwk, func(map[string]any) {})),
			)
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.ES256}
			verifier := newTestVerifier(t, fixture, anchor, clock)
			token := signClaims(t, key, jose.ES256, "aliased-ec-key", "at+jwt", cacheClaims(anchor, clock.Now()))
			if _, err := authenticate(t, verifier, token); err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
		})
	}
}

func TestBoundAlgorithmRequiresRawECDSAKeyMatch(t *testing.T) {
	fixture := newKeyServer(t)
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.ES384}
	verifier := newTestVerifier(t, fixture, anchor, newFakeClock(testNow))
	key := generateECDSAKeyWithLeadingZeroCoordinate(t, elliptic.P256(), p256CoordinateBytes)
	jwk := publicJWK(key, "raw-binding-key", jose.ES256)
	rawKey, ok := inspectVerificationJWK(rewriteJWK(t, jwk, func(map[string]any) {}))
	if !ok {
		t.Fatal("inspectVerificationJWK rejected canonical EC key")
	}
	if rawKey.ecX[0] != 0 && rawKey.ecY[0] != 0 {
		t.Fatal("test key does not contain a leading-zero fixed-width coordinate")
	}
	if algorithm, ok := verifier.cache.boundAlgorithm(jwk, rawKey); !ok || algorithm != jose.ES256 {
		t.Fatalf("boundAlgorithm(matching key) = %q, %t, want ES256, true", algorithm, ok)
	}

	tests := []struct {
		name string
		key  jose.JSONWebKey
		raw  func() rawVerificationJWK
	}{
		{
			name: "different point",
			key:  publicJWK(generateECDSAKeyForCurve(t, elliptic.P256()), "raw-binding-key", jose.ES256),
			raw:  func() rawVerificationJWK { return cloneRawVerificationJWK(rawKey) },
		},
		{
			name: "different curve",
			key:  publicJWK(generateECDSAKeyForCurve(t, elliptic.P384()), "raw-binding-key", jose.ES384),
			raw:  func() rawVerificationJWK { return cloneRawVerificationJWK(rawKey) },
		},
		{
			name: "altered raw x",
			key:  jwk,
			raw: func() rawVerificationJWK {
				value := cloneRawVerificationJWK(rawKey)
				value.ecX[0] ^= 1
				return value
			},
		},
		{
			name: "altered raw y",
			key:  jwk,
			raw: func() rawVerificationJWK {
				value := cloneRawVerificationJWK(rawKey)
				value.ecY[0] ^= 1
				return value
			},
		},
		{
			name: "raw curve mismatch",
			key:  jwk,
			raw: func() rawVerificationJWK {
				value := cloneRawVerificationJWK(rawKey)
				value.ecCurve = "P-384"
				return value
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if algorithm, ok := verifier.cache.boundAlgorithm(test.key, test.raw()); ok || algorithm != "" {
				t.Fatalf("boundAlgorithm() = %q, %t, want empty false", algorithm, ok)
			}
		})
	}
	if rawECDSAKeyMatches(rawKey, nil) {
		t.Fatal("rawECDSAKeyMatches accepted nil typed key")
	}
}

func TestJWKSRSAPublicExponentMustBeCanonicalAndRepresentable(t *testing.T) {
	key := generateRSAKey(t)
	exponentBytes := big.NewInt(int64(key.E)).Bytes()
	canonical := base64.RawURLEncoding.EncodeToString(exponentBytes)
	leadingZero := append([]byte{0}, exponentBytes...)
	truncating := make([]byte, strconv.IntSize/8+1)
	truncating[0] = 1
	copy(truncating[len(truncating)-len(exponentBytes):], exponentBytes)
	overMaximumInt := make([]byte, strconv.IntSize/8)
	overMaximumInt[0] = 0x80
	tests := []struct {
		name  string
		value any
		omit  bool
		valid bool
	}{
		{name: "canonical exponent", value: canonical, valid: true},
		{name: "leading zero octet", value: base64.RawURLEncoding.EncodeToString(leadingZero)},
		{name: "higher bits would be truncated", value: base64.RawURLEncoding.EncodeToString(truncating)},
		{name: "not representable by int", value: base64.RawURLEncoding.EncodeToString(overMaximumInt)},
		{name: "padded", value: canonical + "="},
		{name: "zero", value: "AA"},
		{name: "empty", value: ""},
		{name: "null", value: nil},
		{name: "non-string", value: 65537},
		{name: "omitted", omit: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			jwk := publicJWK(key, "rsa-exponent-key", jose.RS256)
			encodedKey := rewriteJWK(t, jwk, func(members map[string]any) {
				if test.omit {
					delete(members, "e")
					return
				}
				members["e"] = test.value
			})
			fixture.setResponse(http.StatusOK, rawJWKS(t, encodedKey))
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
			verifier := newTestVerifier(t, fixture, anchor, clock)
			token := signClaims(
				t,
				key,
				jose.RS256,
				"rsa-exponent-key",
				"at+jwt",
				cacheClaims(anchor, clock.Now()),
			)
			_, err := authenticate(t, verifier, token)
			if test.valid {
				if err != nil {
					t.Fatalf("Authenticate: %v", err)
				}
				return
			}
			requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
		})
	}
}

func TestJWKSRSAModulusMustBeCanonicalMinimalBase64URLUInt(t *testing.T) {
	key := generateRSAKey(t)
	modulusBytes := key.N.Bytes()
	canonical := base64.RawURLEncoding.EncodeToString(modulusBytes)
	leadingZero := append([]byte{0}, modulusBytes...)
	tooLong := make([]byte, maxRSAKeyBits/8+1)
	tooLong[0] = 1
	tests := []struct {
		name  string
		value any
		omit  bool
		valid bool
	}{
		{name: "canonical modulus", value: canonical, valid: true},
		{name: "leading zero octet", value: base64.RawURLEncoding.EncodeToString(leadingZero)},
		{name: "non-canonical trailing bits", value: nonCanonicalBase64URL(t, canonical)},
		{name: "padded", value: canonical + "="},
		{name: "zero", value: "AA"},
		{name: "empty", value: ""},
		{name: "null", value: nil},
		{name: "non-string", value: 2048},
		{name: "omitted", omit: true},
		{name: "over maximum encoded size", value: base64.RawURLEncoding.EncodeToString(tooLong)},
		{name: "below typed minimum bit size", value: base64.RawURLEncoding.EncodeToString(modulusBytes[1:])},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newKeyServer(t)
			clock := newFakeClock(testNow)
			jwk := publicJWK(key, "rsa-modulus-key", jose.RS256)
			encodedKey := rewriteJWK(t, jwk, func(members map[string]any) {
				if test.omit {
					delete(members, "n")
					return
				}
				members["n"] = test.value
			})
			fixture.setResponse(http.StatusOK, rawJWKS(t, encodedKey))
			anchor := testTrustAnchor(fixture, identity.KindHuman)
			anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
			verifier := newTestVerifier(t, fixture, anchor, clock)
			token := signClaims(
				t,
				key,
				jose.RS256,
				"rsa-modulus-key",
				"at+jwt",
				cacheClaims(anchor, clock.Now()),
			)
			_, err := authenticate(t, verifier, token)
			if test.valid {
				if err != nil {
					t.Fatalf("Authenticate: %v", err)
				}
				return
			}
			requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
		})
	}
}

func TestJWKSRejectsPrimeRSAModulusWithoutPoisoningValidSibling(t *testing.T) {
	prime := rfc3526Group14Prime(t)
	primeKey := jose.JSONWebKey{
		Key:       &rsa.PublicKey{N: prime, E: 65537},
		KeyID:     "prime-key",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	validKey := generateRSAKey(t)

	t.Run("only unusable key", func(t *testing.T) {
		fixture := newKeyServer(t)
		clock := newFakeClock(testNow)
		fixture.setKeys(t, primeKey)
		anchor := testTrustAnchor(fixture, identity.KindHuman)
		anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
		verifier := newTestVerifier(t, fixture, anchor, clock)
		token := signClaims(t, validKey, jose.RS256, "prime-key", "at+jwt", cacheClaims(anchor, clock.Now()))

		_, err := authenticate(t, verifier, token)
		requireAuthenticationError(t, err, ports.ErrAuthenticationUnavailable)
	})

	t.Run("unusable key with valid sibling", func(t *testing.T) {
		fixture := newKeyServer(t)
		clock := newFakeClock(testNow)
		fixture.setKeys(t, primeKey, publicJWK(validKey, "valid-key", jose.RS256))
		anchor := testTrustAnchor(fixture, identity.KindHuman)
		anchor.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
		verifier := newTestVerifier(t, fixture, anchor, clock)
		token := signClaims(t, validKey, jose.RS256, "valid-key", "at+jwt", cacheClaims(anchor, clock.Now()))

		if _, err := authenticate(t, verifier, token); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	})
}

func rfc3526Group14Prime(t *testing.T) *big.Int {
	t.Helper()
	prime, ok := new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"+
			"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"+
			"3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625"+
			"E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5"+
			"AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48"+
			"361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F35620855"+
			"2BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905"+
			"E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C5"+
			"2C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5"+
			"A8AACAA68FFFFFFFFFFFFFFFF",
		16,
	)
	if !ok || prime.BitLen() != minRSAKeyBits || !prime.ProbablyPrime(0) {
		t.Fatal("fixed RSA admission fixture is not a 2048-bit probable prime")
	}
	return prime
}

func TestRSAVerificationKeyRejectsTriviallyInvalidModuli(t *testing.T) {
	validKey := generateRSAKey(t)
	even := new(big.Int).Lsh(big.NewInt(1), minRSAKeyBits-1)
	even.Add(even, big.NewInt(2))
	smallFactor := new(big.Int).Lsh(big.NewInt(1), minRSAKeyBits-2)
	smallFactor.Add(smallFactor, big.NewInt(1))
	smallFactor.Mul(smallFactor, big.NewInt(3))

	squareRoot := new(big.Int).Lsh(big.NewInt(1), minRSAKeyBits/2)
	squareRoot.Sub(squareRoot, big.NewInt(159))
	for {
		clean := true
		for _, divisor := range rsaSmallPrimeDivisors {
			if new(big.Int).Mod(squareRoot, big.NewInt(divisor)).Sign() == 0 {
				clean = false
				break
			}
		}
		if clean && new(big.Int).Mod(squareRoot, big.NewInt(int64(validKey.E))).Sign() != 0 {
			break
		}
		squareRoot.Sub(squareRoot, big.NewInt(2))
	}
	square := new(big.Int).Mul(squareRoot, squareRoot)

	exponentCofactor := new(big.Int).Lsh(big.NewInt(1), minRSAKeyBits-17)
	exponentCofactor.Add(exponentCofactor, big.NewInt(1))
	exponentFactor := new(big.Int).Mul(big.NewInt(int64(validKey.E)), exponentCofactor)

	tests := []struct {
		name    string
		modulus *big.Int
		valid   bool
	}{
		{name: "generated semiprime", modulus: validKey.N, valid: true},
		{name: "even", modulus: even},
		{name: "small factor", modulus: smallFactor},
		{name: "public exponent factor", modulus: exponentFactor},
		{name: "perfect square", modulus: square},
		{name: "prime", modulus: rfc3526Group14Prime(t)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := &rsa.PublicKey{N: test.modulus, E: validKey.E}
			if got := validRSAVerificationKey(key, nil); got != test.valid {
				t.Fatalf("validRSAVerificationKey() = %t, want %t", got, test.valid)
			}
		})
	}

	sharedExponentFactor := new(big.Int).Mul(new(big.Int).Set(validKey.N), big.NewInt(59))
	if validRSAVerificationKey(&rsa.PublicKey{N: sharedExponentFactor, E: 59 * 61}, nil) {
		t.Fatal("accepted RSA modulus sharing a proper factor with its public exponent")
	}
}

func TestJWKSAdmissionBudgetBoundsRSAValidationWork(t *testing.T) {
	tests := []struct {
		name      string
		bitLength int
		accepted  int
	}{
		{name: "2048-bit", bitLength: 2048, accepted: 256},
		{name: "4096-bit", bitLength: 4096, accepted: 32},
		{name: "8192-bit", bitLength: 8192, accepted: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var budget jwksAdmissionBudget
			for index := 0; index < test.accepted; index++ {
				if !budget.reserveRSA(test.bitLength) {
					t.Fatalf("reservation %d unexpectedly exceeded budget", index+1)
				}
			}
			if budget.reserveRSA(test.bitLength) {
				t.Fatal("reservation above the cubic-bit budget succeeded")
			}
			if !budget.exceeded {
				t.Fatal("budget did not retain exceeded state")
			}
		})
	}
}

func TestRSAAdmissionBudgetIgnoresAlgorithmIncompatibleKey(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	verifier := newTestVerifier(t, fixture, testTrustAnchor(fixture, identity.KindHuman), clock)
	key := jose.JSONWebKey{
		Key:       &rsa.PublicKey{N: rfc3526Group14Prime(t), E: 65537},
		KeyID:     "irrelevant-prime",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	rawKey, ok := inspectVerificationJWK(encoded)
	if !ok {
		t.Fatal("inspectVerificationJWK rejected structurally valid RSA key")
	}
	var budget jwksAdmissionBudget
	if algorithm, usable := verifier.cache.boundAlgorithmWithBudget(key, rawKey, &budget); usable || algorithm != "" {
		t.Fatalf("boundAlgorithmWithBudget() = %q, %t, want empty false", algorithm, usable)
	}
	if budget.rsaValidationWork != 0 || budget.exceeded {
		t.Fatalf("irrelevant key consumed RSA budget: %+v", budget)
	}
}

func TestCanonicalRSAModulusRejectsNonMinimalAndNonCanonicalValues(t *testing.T) {
	modulus := []byte{0x80, 0x01}
	canonical := base64.RawURLEncoding.EncodeToString(modulus)
	tests := []struct {
		name    string
		raw     json.RawMessage
		present bool
		want    []byte
	}{
		{name: "canonical", raw: json.RawMessage(strconv.Quote(canonical)), present: true, want: modulus},
		{
			name:    "leading zero octet",
			raw:     json.RawMessage(strconv.Quote(base64.RawURLEncoding.EncodeToString(append([]byte{0}, modulus...)))),
			present: true,
		},
		{
			name:    "non-canonical trailing bits",
			raw:     json.RawMessage(strconv.Quote(nonCanonicalBase64URL(t, canonical))),
			present: true,
		},
		{name: "padded", raw: json.RawMessage(strconv.Quote(canonical + "=")), present: true},
		{name: "empty", raw: json.RawMessage(`""`), present: true},
		{name: "null", raw: json.RawMessage(`null`), present: true},
		{name: "wrong type", raw: json.RawMessage(`1`), present: true},
		{name: "omitted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			members := make(map[string]json.RawMessage)
			if test.present {
				members["n"] = test.raw
			}
			got, ok := canonicalRSAModulus(members)
			if test.want == nil {
				if ok || got != nil {
					t.Fatalf("canonicalRSAModulus() = %x, %t, want nil, false", got, ok)
				}
				return
			}
			if !ok || !bytes.Equal(got, test.want) {
				t.Fatalf("canonicalRSAModulus() = %x, %t, want %x, true", got, ok, test.want)
			}
		})
	}
}

func TestCanonicalRSAExponentRejectsNonzeroTrailingBits(t *testing.T) {
	canonical := base64.RawURLEncoding.EncodeToString([]byte{3})
	members := map[string]json.RawMessage{
		"e": json.RawMessage(strconv.Quote(canonical)),
	}
	if exponent, ok := canonicalRSAExponent(members); !ok || exponent != 3 {
		t.Fatalf("canonicalRSAExponent(canonical) = %d, %t, want 3, true", exponent, ok)
	}

	nonCanonical := nonCanonicalBase64URL(t, canonical)
	members["e"] = json.RawMessage(strconv.Quote(nonCanonical))
	if exponent, ok := canonicalRSAExponent(members); ok || exponent != 0 {
		t.Fatalf("canonicalRSAExponent(non-canonical) = %d, %t, want 0, false", exponent, ok)
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
	return rewriteJWK(t, key, func(members map[string]any) {
		if includeOperations {
			members["key_ops"] = keyOperations
		}
	})
}

func rewriteJWK(
	t *testing.T,
	key jose.JSONWebKey,
	mutate func(map[string]any),
) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	var members map[string]any
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("unmarshal generated JWK: %v", err)
	}
	mutate(members)
	encoded, err = json.Marshal(members)
	if err != nil {
		t.Fatalf("marshal decorated JWK: %v", err)
	}
	return encoded
}

func nonCanonicalBase64URL(t *testing.T, canonical string) string {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(canonical)
	if err != nil || len(canonical) == 0 {
		t.Fatal("test input is not canonical base64url")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for index := range len(alphabet) {
		if alphabet[index] == canonical[len(canonical)-1] {
			continue
		}
		candidate := canonical[:len(canonical)-1] + string(alphabet[index])
		candidateBytes, decodeErr := base64.RawURLEncoding.DecodeString(candidate)
		if decodeErr == nil && bytes.Equal(candidateBytes, decoded) &&
			base64.RawURLEncoding.EncodeToString(candidateBytes) != candidate {
			return candidate
		}
	}
	t.Fatal("could not construct a non-canonical base64url encoding")
	return ""
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

func generateECDSAKeyForCurve(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	return key
}

func generateECDSAKeyWithLeadingZeroCoordinate(
	t *testing.T,
	curve elliptic.Curve,
	coordinateBytes int,
) *ecdsa.PrivateKey {
	t.Helper()
	for candidate := int64(1); candidate <= 1<<16; candidate++ {
		scalar := make([]byte, coordinateBytes)
		big.NewInt(candidate).FillBytes(scalar)
		key, err := ecdsa.ParseRawPrivateKey(curve, scalar)
		if err != nil {
			continue
		}
		encoded, err := key.PublicKey.Bytes()
		if err != nil || len(encoded) != 1+2*coordinateBytes || encoded[0] != 4 {
			continue
		}
		if encoded[1] == 0 || encoded[1+coordinateBytes] == 0 {
			return key
		}
	}
	t.Fatal("could not construct an EC key with a leading-zero fixed-width coordinate")
	return nil
}

func rawJWKMembers(t *testing.T, key jose.JSONWebKey) map[string]json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("unmarshal raw JWK members: %v", err)
	}
	return members
}

func rawJSONStringMember(
	t *testing.T,
	members map[string]json.RawMessage,
	name string,
) string {
	t.Helper()
	raw, present := members[name]
	if !present {
		t.Fatalf("generated JWK is missing %q", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		t.Fatalf("generated JWK %q is not a non-empty string", name)
	}
	return value
}

func cloneRawJWKMembers(input map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(input))
	for name, value := range input {
		result[name] = bytes.Clone(value)
	}
	return result
}

func cloneRawVerificationJWK(input rawVerificationJWK) rawVerificationJWK {
	result := input
	result.ecX = bytes.Clone(input.ecX)
	result.ecY = bytes.Clone(input.ecY)
	result.ed25519Key = bytes.Clone(input.ed25519Key)
	result.rsaModulus = bytes.Clone(input.rsaModulus)
	return result
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
