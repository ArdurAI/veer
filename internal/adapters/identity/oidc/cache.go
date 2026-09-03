package oidc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	maxKeyIDBytes        = 256
	minRSAKeyBits        = 2_048
	maxRSAKeyBits        = 8_192
	maxRSAValidationWork = int64(4) * maxRSAKeyBits * maxRSAKeyBits * maxRSAKeyBits
	p256CoordinateBytes  = 32
	p384CoordinateBytes  = 48
	p521CoordinateBytes  = 66
)

var (
	ed25519FieldPrime, ed25519CurveD = ed25519FieldParameters()
	ed25519SmallOrderEncodings       = map[string]struct{}{
		"0000000000000000000000000000000000000000000000000000000000000000": {},
		"0000000000000000000000000000000000000000000000000000000000000080": {},
		"0100000000000000000000000000000000000000000000000000000000000000": {},
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05": {},
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85": {},
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a": {},
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa": {},
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": {},
	}
	rsaSmallPrimeDivisors = [...]int64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53}
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
	key                jose.JSONWebKey
	generation         uint64
	refreshAttempted   bool
	refreshAttemptedAt time.Time
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
		refreshAttemptedAt := cache.lastAttemptAt
		cache.mu.Unlock()
		if fresh && found {
			return cachedVerificationKey{
				key:                key,
				generation:         generation,
				refreshAttempted:   true,
				refreshAttemptedAt: refreshAttemptedAt,
			}, nil
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
	refreshAttemptedAt := cache.lastAttemptAt
	cache.mu.Unlock()
	if found && fresh {
		return cachedVerificationKey{
			key:                key,
			generation:         generation,
			refreshAttempted:   true,
			refreshAttemptedAt: refreshAttemptedAt,
		}, nil
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
	previous cachedVerificationKey,
) (cachedVerificationKey, bool, error) {
	if err := ctx.Err(); err != nil {
		return cachedVerificationKey{}, false, err
	}

	now := cache.clock.Now()
	reference := keyReference{keyID: keyID, algorithm: algorithm}
	cache.mu.Lock()
	if cache.generation != previous.generation {
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
	if now.Before(cache.nextProactiveRefreshAllowed) {
		attemptedAt := cache.nextProactiveRefreshAllowed.Add(-cache.anchor.cache.RefreshCooldown)
		cache.recordCooldown(refreshReactive, attemptedAt)
		cache.mu.Unlock()
		return cachedVerificationKey{}, false, nil
	}
	if previous.refreshAttempted {
		cache.recordCooldown(refreshReactive, previous.refreshAttemptedAt)
		cache.mu.Unlock()
		return cachedVerificationKey{}, false, nil
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
		if lastErr != nil || reason == refreshReactive {
			cache.recordCooldown(reason, cache.lastAttemptAt)
		}
		if lastErr != nil && reason == refreshProactive {
			// Match a proactive caller joining the completed failed flight: its
			// cooldown must continue to gate required refresh after staleness.
			cache.recordCooldown(refreshRequired, cache.lastAttemptAt)
		}
		if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) {
			cache.mu.Unlock()
			if err := ctx.Err(); err != nil {
				return err
			}
			return errKeySourceUnavailable
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
		// A usable replacement starts a new freshness epoch. Failure gates from
		// the superseded set must not block required or proactive refresh of the
		// newly installed set; a reactive attempt still receives its own cooldown
		// below so attacker-selected key IDs remain throttled.
		cache.nextRequiredRefreshAllowed = time.Time{}
		cache.nextProactiveRefreshAllowed = time.Time{}
	}
	cache.lastAttemptAt = now
	if fetchErr != nil {
		// A failed proactive attempt must also gate a required refresh if the
		// retained set becomes stale before the cooldown expires. Successful
		// refreshes do not set this gate, so a newly fetched short-lived set can
		// still refresh when its own freshness ends.
		if flight.required || flight.proactive {
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
	var budget jwksAdmissionBudget
	for _, encodedKey := range encodedSet.Keys {
		if err := jwksAdmissionContextError(ctx, fetchContext); err != nil {
			return nil, err
		}
		rawKey, usable := inspectVerificationJWK(encodedKey)
		if !usable {
			continue
		}
		var key jose.JSONWebKey
		if err := json.Unmarshal(encodedKey, &key); err != nil {
			continue
		}
		algorithm, usable := cache.boundAlgorithmWithBudget(key, rawKey, &budget)
		if err := jwksAdmissionContextError(ctx, fetchContext); err != nil {
			return nil, err
		}
		if !usable {
			continue
		}
		reference := keyReference{keyID: key.KeyID, algorithm: algorithm}
		if _, duplicate := keys[reference]; duplicate {
			return nil, errKeySourceUnavailable
		}
		keys[reference] = key
	}
	if err := jwksAdmissionContextError(ctx, fetchContext); err != nil {
		return nil, err
	}
	if budget.exceeded {
		return nil, errKeySourceUnavailable
	}
	if len(keys) == 0 {
		return nil, errKeySourceUnavailable
	}
	return keys, nil
}

func jwksAdmissionContextError(parent, bounded context.Context) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if bounded.Err() != nil {
		return errKeySourceUnavailable
	}
	return nil
}

type rawVerificationJWK struct {
	ecCurve     string
	ecX         []byte
	ecY         []byte
	ed25519Key  []byte
	rsaModulus  []byte
	rsaExponent int
}

type jwksAdmissionBudget struct {
	rsaValidationWork int64
	exceeded          bool
}

func (budget *jwksAdmissionBudget) reserveRSA(bitLength int) bool {
	bits := int64(bitLength)
	work := bits * bits * bits
	if work > maxRSAValidationWork-budget.rsaValidationWork {
		budget.exceeded = true
		return false
	}
	budget.rsaValidationWork += work
	return true
}

func inspectVerificationJWK(encodedKey json.RawMessage) (rawVerificationJWK, bool) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encodedKey, &members); err != nil {
		return rawVerificationJWK{}, false
	}
	// go-jose represents an absent, null, or empty optional string identically.
	// Inspect presence before its typed decoder so only truly omitted use/alg
	// members receive the RFC 7517 omitted-member behavior.
	if !validOptionalJWKString(members, "use", 32) ||
		!validOptionalJWKString(members, "alg", 32) {
		return rawVerificationJWK{}, false
	}
	if !keyOperationsPermitVerification(members) {
		return rawVerificationJWK{}, false
	}

	keyType, ok := requiredJSONString(members, "kty")
	if !ok {
		return rawVerificationJWK{}, false
	}
	switch keyType {
	case "EC":
		curve, x, y, ok := canonicalECPublicKey(members)
		if !ok {
			return rawVerificationJWK{}, false
		}
		return rawVerificationJWK{ecCurve: curve, ecX: x, ecY: y}, true
	case "OKP":
		curve, ok := requiredJSONString(members, "crv")
		if !ok || curve != "Ed25519" {
			return rawVerificationJWK{}, false
		}
		x, ok := requiredJSONString(members, "x")
		if !ok {
			return rawVerificationJWK{}, false
		}
		decoded, ok := decodeCanonicalSegment(x, ed25519.PublicKeySize)
		if !ok || len(decoded) != ed25519.PublicKeySize {
			return rawVerificationJWK{}, false
		}
		return rawVerificationJWK{ed25519Key: decoded}, true
	case "RSA":
		modulus, ok := canonicalRSAModulus(members)
		if !ok {
			return rawVerificationJWK{}, false
		}
		exponent, ok := canonicalRSAExponent(members)
		if !ok {
			return rawVerificationJWK{}, false
		}
		return rawVerificationJWK{rsaModulus: modulus, rsaExponent: exponent}, true
	}
	return rawVerificationJWK{}, true
}

func validOptionalJWKString(
	members map[string]json.RawMessage,
	name string,
	maximumBytes int,
) bool {
	raw, present := members[name]
	if !present {
		return true
	}
	var value string
	return json.Unmarshal(raw, &value) == nil && validOpaqueValue(value, maximumBytes)
}

func keyOperationsPermitVerification(members map[string]json.RawMessage) bool {
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

func canonicalECPublicKey(
	members map[string]json.RawMessage,
) (string, []byte, []byte, bool) {
	curve, ok := requiredJSONString(members, "crv")
	if !ok {
		return "", nil, nil, false
	}
	_, coordinateBytes, ok := supportedECDSACurve(curve)
	if !ok {
		return "", nil, nil, false
	}
	x, ok := canonicalECField(members, "x", coordinateBytes)
	if !ok {
		return "", nil, nil, false
	}
	y, ok := canonicalECField(members, "y", coordinateBytes)
	if !ok {
		return "", nil, nil, false
	}
	return curve, x, y, true
}

func canonicalECField(
	members map[string]json.RawMessage,
	name string,
	expectedBytes int,
) ([]byte, bool) {
	encoded, ok := requiredJSONString(members, name)
	if !ok {
		return nil, false
	}
	decoded, ok := decodeCanonicalSegment(encoded, expectedBytes)
	if !ok || len(decoded) != expectedBytes {
		return nil, false
	}
	return decoded, true
}

func canonicalRSAModulus(members map[string]json.RawMessage) ([]byte, bool) {
	encoded, ok := requiredJSONString(members, "n")
	if !ok {
		return nil, false
	}
	decoded, ok := decodeCanonicalSegment(encoded, maxRSAKeyBits/8)
	if !ok || decoded[0] == 0 {
		return nil, false
	}
	return decoded, true
}

func canonicalRSAExponent(members map[string]json.RawMessage) (int, bool) {
	encoded, ok := requiredJSONString(members, "e")
	if !ok {
		return 0, false
	}
	decoded, ok := decodeCanonicalSegment(encoded, strconv.IntSize/8)
	if !ok || decoded[0] == 0 {
		return 0, false
	}
	var value uint64
	for _, current := range decoded {
		value = value<<8 | uint64(current)
	}
	maximumInt := uint64(^uint(0) >> 1)
	if value == 0 || value > maximumInt {
		return 0, false
	}
	return int(value), true
}

func (cache *keyCache) boundAlgorithm(
	key jose.JSONWebKey,
	rawKey rawVerificationJWK,
) (jose.SignatureAlgorithm, bool) {
	return cache.boundAlgorithmWithBudget(key, rawKey, nil)
}

func (cache *keyCache) boundAlgorithmWithBudget(
	key jose.JSONWebKey,
	rawKey rawVerificationJWK,
	budget *jwksAdmissionBudget,
) (jose.SignatureAlgorithm, bool) {
	if !key.Valid() || !key.IsPublic() || !validOpaqueValue(key.KeyID, maxKeyIDBytes) {
		return "", false
	}
	if rawKey.ecCurve != "" {
		ecKey, ok := key.Key.(*ecdsa.PublicKey)
		if !ok || !rawECDSAKeyMatches(rawKey, ecKey) {
			return "", false
		}
	}
	if rawKey.rsaExponent != 0 || len(rawKey.rsaModulus) != 0 {
		rsaKey, ok := key.Key.(*rsa.PublicKey)
		if !ok || rsaKey.E != rawKey.rsaExponent ||
			rsaKey.N == nil || !bytes.Equal(rsaKey.N.Bytes(), rawKey.rsaModulus) {
			return "", false
		}
	}
	if len(rawKey.ed25519Key) != 0 {
		ed25519Key, ok := key.Key.(ed25519.PublicKey)
		if !ok || !bytes.Equal(ed25519Key, rawKey.ed25519Key) {
			return "", false
		}
	}
	if key.Use != "" && key.Use != "sig" {
		return "", false
	}
	var selected jose.SignatureAlgorithm
	if key.Algorithm != "" {
		algorithm := jose.SignatureAlgorithm(key.Algorithm)
		if _, allowed := cache.anchor.algorithmSet[algorithm]; !allowed || !keySupportsAlgorithm(key.Key, algorithm) {
			return "", false
		}
		selected = algorithm
	} else {
		for _, candidate := range cache.anchor.algorithms {
			if !keySupportsAlgorithm(key.Key, candidate) {
				continue
			}
			if selected != "" {
				return "", false
			}
			selected = candidate
		}
	}
	if selected == "" || !validVerificationKey(key.Key, budget) {
		return "", false
	}
	return selected, true
}

func rawECDSAKeyMatches(rawKey rawVerificationJWK, typed *ecdsa.PublicKey) bool {
	curve, coordinateBytes, ok := supportedECDSACurve(rawKey.ecCurve)
	if !ok || typed == nil || typed.Curve != curve ||
		len(rawKey.ecX) != coordinateBytes || len(rawKey.ecY) != coordinateBytes {
		return false
	}
	encoded, err := typed.Bytes()
	if err != nil || len(encoded) != 1+2*coordinateBytes || encoded[0] != 4 {
		return false
	}
	return bytes.Equal(encoded[1:1+coordinateBytes], rawKey.ecX) &&
		bytes.Equal(encoded[1+coordinateBytes:], rawKey.ecY)
}

func supportedECDSACurve(name string) (elliptic.Curve, int, bool) {
	switch name {
	case "P-256":
		return elliptic.P256(), p256CoordinateBytes, true
	case "P-384":
		return elliptic.P384(), p384CoordinateBytes, true
	case "P-521":
		return elliptic.P521(), p521CoordinateBytes, true
	default:
		return nil, 0, false
	}
}

func keySupportsAlgorithm(key any, algorithm jose.SignatureAlgorithm) bool {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		switch algorithm {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			return true
		default:
			return false
		}
	case *ecdsa.PublicKey:
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
		return algorithm == jose.EdDSA
	default:
		return false
	}
}

func validVerificationKey(key any, budget *jwksAdmissionBudget) bool {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		return validRSAVerificationKey(typed, budget)
	case *ecdsa.PublicKey:
		if typed == nil || typed.Curve == nil {
			return false
		}
		_, err := typed.Bytes()
		return err == nil
	case ed25519.PublicKey:
		return validEd25519VerificationKey(typed)
	default:
		return false
	}
}

func validRSAVerificationKey(key *rsa.PublicKey, budget *jwksAdmissionBudget) bool {
	if key == nil || key.N == nil || key.N.BitLen() < minRSAKeyBits || key.N.BitLen() > maxRSAKeyBits ||
		key.E < 3 || key.E%2 == 0 || key.N.Bit(0) == 0 {
		return false
	}

	remainder := new(big.Int)
	for _, divisor := range rsaSmallPrimeDivisors {
		if remainder.Mod(key.N, big.NewInt(divisor)).Sign() == 0 {
			return false
		}
	}
	if remainder.GCD(nil, nil, key.N, big.NewInt(int64(key.E))).Cmp(big.NewInt(1)) != 0 {
		return false
	}

	root := new(big.Int).Sqrt(key.N)
	if new(big.Int).Mul(root, root).Cmp(key.N) == 0 {
		return false
	}
	if budget != nil && !budget.reserveRSA(key.N.BitLen()) {
		return false
	}
	// Zero Miller-Rabin repetitions selects math/big's fixed Baillie-PSW
	// path. All primes are rejected; a composite false positive is a safe
	// rejection. The per-response cubic-bit budget caps adversarial work at
	// four 8192-bit equivalents while the outer key bound still limits count.
	return !key.N.ProbablyPrime(0)
}

func validEd25519VerificationKey(key ed25519.PublicKey) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	encodedY := append([]byte(nil), key...)
	xSign := encodedY[len(encodedY)-1] >> 7
	encodedY[len(encodedY)-1] &= 0x7f
	y := littleEndianInteger(encodedY)
	if y.Cmp(ed25519FieldPrime) >= 0 {
		return false
	}

	ySquared := new(big.Int).Mul(y, y)
	ySquared.Mod(ySquared, ed25519FieldPrime)
	numerator := new(big.Int).Sub(ySquared, big.NewInt(1))
	numerator.Mod(numerator, ed25519FieldPrime)
	denominator := new(big.Int).Mul(ed25519CurveD, ySquared)
	denominator.Add(denominator, big.NewInt(1))
	denominator.Mod(denominator, ed25519FieldPrime)
	denominatorInverse := new(big.Int).ModInverse(denominator, ed25519FieldPrime)
	if denominatorInverse == nil {
		return false
	}
	xSquared := new(big.Int).Mul(numerator, denominatorInverse)
	xSquared.Mod(xSquared, ed25519FieldPrime)
	if xSquared.Sign() == 0 {
		if xSign != 0 {
			return false
		}
	} else if big.Jacobi(xSquared, ed25519FieldPrime) != 1 {
		return false
	}

	_, smallOrder := ed25519SmallOrderEncodings[hex.EncodeToString(key)]
	return !smallOrder
}

func littleEndianInteger(encoded []byte) *big.Int {
	reversed := make([]byte, len(encoded))
	for index, value := range encoded {
		reversed[len(encoded)-1-index] = value
	}
	return new(big.Int).SetBytes(reversed)
}

func ed25519FieldParameters() (*big.Int, *big.Int) {
	prime := new(big.Int).Lsh(big.NewInt(1), 255)
	prime.Sub(prime, big.NewInt(19))
	denominatorInverse := new(big.Int).ModInverse(big.NewInt(121666), prime)
	d := new(big.Int).Mul(big.NewInt(-121665), denominatorInverse)
	d.Mod(d, prime)
	return prime, d
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
