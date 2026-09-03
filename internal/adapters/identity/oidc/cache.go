package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	maxKeyIDBytes = 256
	minRSAKeyBits = 2_048
	maxRSAKeyBits = 8_192
)

var (
	errNoMatchingKey        = errors.New("no matching verification key")
	errKeySourceUnavailable = errors.New("verification key source unavailable")
)

// Clock makes claim and cache time deterministic in tests and embeds no
// scheduling behavior into verification.
type Clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func clockOrWall(clock Clock) Clock {
	if clock == nil {
		return wallClock{}
	}
	value := reflect.ValueOf(clock)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return wallClock{}
		}
	}
	return clock
}

type keyReference struct {
	keyID     string
	algorithm jose.SignatureAlgorithm
}

type cachedVerificationKey struct {
	key        jose.JSONWebKey
	generation uint64
}

type refreshFlight struct {
	done      chan struct{}
	err       error
	followers int
	required  bool
	proactive bool
	reactive  bool
}

type refreshReason uint8

const (
	refreshRequired refreshReason = iota + 1
	refreshProactive
	refreshReactive
)

type keyCache struct {
	anchor validatedTrustAnchor
	client *http.Client
	clock  Clock

	mu                          sync.Mutex
	keys                        map[keyReference]jose.JSONWebKey
	generation                  uint64
	freshUntil                  time.Time
	refreshAt                   time.Time
	nextRequiredRefreshAllowed  time.Time
	nextProactiveRefreshAllowed time.Time
	nextReactiveRefreshAllowed  time.Time
	attempt                     uint64
	lastAttemptAt               time.Time
	lastAttemptError            error
	flight                      *refreshFlight
}

func newKeyCache(anchor validatedTrustAnchor, client *http.Client, clock Clock) *keyCache {
	clock = clockOrWall(clock)
	return &keyCache{
		anchor: anchor,
		client: hardenedHTTPClient(client),
		clock:  clock,
		keys:   make(map[keyReference]jose.JSONWebKey),
	}
}

func hardenedHTTPClient(input *http.Client) *http.Client {
	var result http.Client
	if input != nil {
		result = *input
	} else {
		result.Transport = http.DefaultTransport
	}
	result.Jar = nil
	result.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &result
}

func (cache *keyCache) resolve(
	ctx context.Context,
	keyID string,
	algorithm jose.SignatureAlgorithm,
) (cachedVerificationKey, error) {
	if err := ctx.Err(); err != nil {
		return cachedVerificationKey{}, err
	}

	now := cache.clock.Now()
	reference := keyReference{keyID: keyID, algorithm: algorithm}
	cache.mu.Lock()
	key, found := cache.keys[reference]
	fresh := len(cache.keys) > 0 && now.Before(cache.freshUntil)
	due := fresh && !now.Before(cache.refreshAt)
	reason := refreshRequired
	refreshAllowed := !now.Before(cache.nextRequiredRefreshAllowed)
	if fresh && found {
		reason = refreshProactive
		refreshAllowed = !now.Before(cache.nextProactiveRefreshAllowed)
	} else if fresh {
		reason = refreshReactive
		refreshAllowed = !now.Before(cache.nextReactiveRefreshAllowed)
	}
	observedAttempt := cache.attempt
	generation := cache.generation
	cache.mu.Unlock()

	if found && fresh && (!due || !refreshAllowed) {
		return cachedVerificationKey{key: key, generation: generation}, nil
	}
	if !found && fresh && !refreshAllowed {
		return cachedVerificationKey{}, errNoMatchingKey
	}
	if !fresh && !refreshAllowed && observedAttempt > 0 {
		return cachedVerificationKey{}, errKeySourceUnavailable
	}

	refreshErr := cache.refresh(ctx, observedAttempt, reason)
	if refreshErr != nil {
		if err := ctx.Err(); err != nil {
			return cachedVerificationKey{}, err
		}
		now = cache.clock.Now()
		cache.mu.Lock()
		key, found = cache.keys[reference]
		fresh = len(cache.keys) > 0 && now.Before(cache.freshUntil)
		generation = cache.generation
		cache.mu.Unlock()
		if fresh && found {
			return cachedVerificationKey{key: key, generation: generation}, nil
		}
		if fresh {
			return cachedVerificationKey{}, errNoMatchingKey
		}
		return cachedVerificationKey{}, errKeySourceUnavailable
	}

	now = cache.clock.Now()
	cache.mu.Lock()
	key, found = cache.keys[reference]
	fresh = len(cache.keys) > 0 && now.Before(cache.freshUntil)
	generation = cache.generation
	cache.mu.Unlock()
	if found && fresh {
		return cachedVerificationKey{key: key, generation: generation}, nil
	}
	if fresh {
		cache.mu.Lock()
		cache.recordCooldown(refreshReactive, cache.lastAttemptAt)
		cache.mu.Unlock()
		return cachedVerificationKey{}, errNoMatchingKey
	}
	return cachedVerificationKey{}, errKeySourceUnavailable
}

func (cache *keyCache) resolveAfterSignatureFailure(
	ctx context.Context,
	keyID string,
	algorithm jose.SignatureAlgorithm,
	previousGeneration uint64,
) (cachedVerificationKey, bool, error) {
	if err := ctx.Err(); err != nil {
		return cachedVerificationKey{}, false, err
	}

	now := cache.clock.Now()
	reference := keyReference{keyID: keyID, algorithm: algorithm}
	cache.mu.Lock()
	if cache.generation != previousGeneration {
		key, found := cache.keys[reference]
		fresh := len(cache.keys) > 0 && now.Before(cache.freshUntil)
		generation := cache.generation
		cache.mu.Unlock()
		if found && fresh {
			return cachedVerificationKey{key: key, generation: generation}, true, nil
		}
		if fresh {
			return cachedVerificationKey{}, true, errNoMatchingKey
		}
		return cachedVerificationKey{}, true, errKeySourceUnavailable
	}
	freshBefore := len(cache.keys) > 0 && now.Before(cache.freshUntil)
	if now.Before(cache.nextReactiveRefreshAllowed) {
		cache.mu.Unlock()
		return cachedVerificationKey{}, false, nil
	}
	observedAttempt := cache.attempt
	cache.mu.Unlock()

	refreshErr := cache.refresh(ctx, observedAttempt, refreshReactive)
	if refreshErr != nil {
		if err := ctx.Err(); err != nil {
			return cachedVerificationKey{}, true, err
		}
		now = cache.clock.Now()
		cache.mu.Lock()
		stillFresh := len(cache.keys) > 0 && now.Before(cache.freshUntil)
		cache.mu.Unlock()
		if freshBefore && stillFresh {
			return cachedVerificationKey{}, true, errNoMatchingKey
		}
		return cachedVerificationKey{}, true, errKeySourceUnavailable
	}

	now = cache.clock.Now()
	cache.mu.Lock()
	key, found := cache.keys[reference]
	fresh := len(cache.keys) > 0 && now.Before(cache.freshUntil)
	generation := cache.generation
	cache.mu.Unlock()
	if found && fresh {
		return cachedVerificationKey{key: key, generation: generation}, true, nil
	}
	if fresh {
		return cachedVerificationKey{}, true, errNoMatchingKey
	}
	return cachedVerificationKey{}, true, errKeySourceUnavailable
}

func (cache *keyCache) refresh(
	ctx context.Context,
	observedAttempt uint64,
	reason refreshReason,
) error {
	cache.mu.Lock()
	if cache.flight != nil {
		flight := cache.flight
		flight.addReason(reason)
		flight.followers++
		cache.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-flight.done:
			if errors.Is(flight.err, context.Canceled) || errors.Is(flight.err, context.DeadlineExceeded) {
				if err := ctx.Err(); err != nil {
					return err
				}
				return errKeySourceUnavailable
			}
			return flight.err
		}
	}
	if cache.attempt != observedAttempt {
		lastErr := cache.lastAttemptError
		if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) {
			cache.mu.Unlock()
			if err := ctx.Err(); err != nil {
				return err
			}
			return errKeySourceUnavailable
		}
		if lastErr != nil || reason == refreshReactive {
			cache.recordCooldown(reason, cache.lastAttemptAt)
		}
		cache.mu.Unlock()
		return lastErr
	}
	flight := &refreshFlight{done: make(chan struct{})}
	flight.addReason(reason)
	cache.flight = flight
	cache.attempt++
	cache.mu.Unlock()

	keys, fetchErr := cache.fetch(ctx)
	now := cache.clock.Now()
	cache.mu.Lock()
	if fetchErr == nil {
		cache.keys = keys
		cache.generation++
		cache.freshUntil = now.Add(cache.anchor.cache.Freshness)
		cache.refreshAt = cache.freshUntil.Add(-cache.anchor.cache.RefreshAhead)
	}
	cache.lastAttemptAt = now
	if fetchErr != nil {
		if flight.required {
			cache.recordCooldown(refreshRequired, now)
		}
		if flight.proactive {
			cache.recordCooldown(refreshProactive, now)
		}
	}
	if flight.reactive {
		cache.recordCooldown(refreshReactive, now)
	}
	cache.lastAttemptError = fetchErr
	flight.err = fetchErr
	close(flight.done)
	cache.flight = nil
	cache.mu.Unlock()
	return fetchErr
}

func (flight *refreshFlight) addReason(reason refreshReason) {
	switch reason {
	case refreshRequired:
		flight.required = true
	case refreshProactive:
		flight.proactive = true
	case refreshReactive:
		flight.reactive = true
	}
}

// recordCooldown requires cache.mu to be held.
func (cache *keyCache) recordCooldown(reason refreshReason, attemptedAt time.Time) {
	if attemptedAt.IsZero() {
		return
	}
	next := attemptedAt.Add(cache.anchor.cache.RefreshCooldown)
	switch reason {
	case refreshRequired:
		if cache.nextRequiredRefreshAllowed.Before(next) {
			cache.nextRequiredRefreshAllowed = next
		}
	case refreshProactive:
		if cache.nextProactiveRefreshAllowed.Before(next) {
			cache.nextProactiveRefreshAllowed = next
		}
	case refreshReactive:
		if cache.nextReactiveRefreshAllowed.Before(next) {
			cache.nextReactiveRefreshAllowed = next
		}
	}
}

func (cache *keyCache) fetch(ctx context.Context) (map[keyReference]jose.JSONWebKey, error) {
	fetchContext, cancel := context.WithTimeout(ctx, cache.anchor.cache.FetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(fetchContext, http.MethodGet, cache.anchor.jwksURI.String(), nil)
	if err != nil {
		return nil, errKeySourceUnavailable
	}
	request.Header.Set("Accept", "application/json, application/jwk-set+json")

	response, err := cache.client.Do(request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, errKeySourceUnavailable
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.Request == nil || response.Request.URL == nil ||
		response.Request.URL.String() != cache.anchor.jwksURI.String() ||
		response.StatusCode != http.StatusOK {
		return nil, errKeySourceUnavailable
	}
	if response.ContentLength > cache.anchor.cache.MaximumResponseBytes {
		return nil, errKeySourceUnavailable
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, cache.anchor.cache.MaximumResponseBytes+1))
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, errKeySourceUnavailable
	}
	if int64(len(body)) > cache.anchor.cache.MaximumResponseBytes || !validateJSONObject(body) {
		return nil, errKeySourceUnavailable
	}
	var encodedSet struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &encodedSet); err != nil ||
		len(encodedSet.Keys) == 0 || len(encodedSet.Keys) > cache.anchor.cache.MaximumKeys {
		return nil, errKeySourceUnavailable
	}

	keys := make(map[keyReference]jose.JSONWebKey)
	for _, encodedKey := range encodedSet.Keys {
		if !keyPermitsVerification(encodedKey) {
			continue
		}
		var key jose.JSONWebKey
		if err := json.Unmarshal(encodedKey, &key); err != nil {
			continue
		}
		algorithm, usable := cache.boundAlgorithm(key)
		if !usable {
			continue
		}
		reference := keyReference{keyID: key.KeyID, algorithm: algorithm}
		if _, duplicate := keys[reference]; duplicate {
			return nil, errKeySourceUnavailable
		}
		keys[reference] = key
	}
	if len(keys) == 0 {
		return nil, errKeySourceUnavailable
	}
	return keys, nil
}

func keyPermitsVerification(encodedKey json.RawMessage) bool {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encodedKey, &members); err != nil {
		return false
	}
	rawOperations, present := members["key_ops"]
	if !present {
		return true
	}
	var operations []string
	if err := json.Unmarshal(rawOperations, &operations); err != nil ||
		operations == nil || len(operations) == 0 || len(operations) > 8 {
		return false
	}
	seen := make(map[string]struct{}, len(operations))
	permitsVerification := false
	for _, operation := range operations {
		if !validOpaqueValue(operation, 32) {
			return false
		}
		if _, duplicate := seen[operation]; duplicate {
			return false
		}
		seen[operation] = struct{}{}
		if operation == "verify" {
			permitsVerification = true
		}
	}
	return permitsVerification
}

func (cache *keyCache) boundAlgorithm(key jose.JSONWebKey) (jose.SignatureAlgorithm, bool) {
	if !key.Valid() || !key.IsPublic() || !validOpaqueValue(key.KeyID, maxKeyIDBytes) {
		return "", false
	}
	if key.Use != "" && key.Use != "sig" {
		return "", false
	}
	if key.Algorithm != "" {
		algorithm := jose.SignatureAlgorithm(key.Algorithm)
		if _, allowed := cache.anchor.algorithmSet[algorithm]; !allowed || !keySupportsAlgorithm(key.Key, algorithm) {
			return "", false
		}
		return algorithm, true
	}

	var selected jose.SignatureAlgorithm
	for _, candidate := range cache.anchor.algorithms {
		if !keySupportsAlgorithm(key.Key, candidate) {
			continue
		}
		if selected != "" {
			return "", false
		}
		selected = candidate
	}
	return selected, selected != ""
}

func keySupportsAlgorithm(key any, algorithm jose.SignatureAlgorithm) bool {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		if typed.N == nil || typed.N.BitLen() < minRSAKeyBits || typed.N.BitLen() > maxRSAKeyBits ||
			typed.E < 3 || typed.E%2 == 0 {
			return false
		}
		switch algorithm {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			return true
		default:
			return false
		}
	case *ecdsa.PublicKey:
		if typed.Curve == nil {
			return false
		}
		if _, err := typed.Bytes(); err != nil {
			return false
		}
		switch algorithm {
		case jose.ES256:
			return typed.Curve == elliptic.P256()
		case jose.ES384:
			return typed.Curve == elliptic.P384()
		case jose.ES512:
			return typed.Curve == elliptic.P521()
		default:
			return false
		}
	case ed25519.PublicKey:
		return algorithm == jose.EdDSA && len(typed) == ed25519.PublicKeySize
	default:
		return false
	}
}

func validOpaqueValue(value string, maximumBytes int) bool {
	if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
