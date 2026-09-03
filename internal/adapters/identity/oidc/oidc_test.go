package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
	jose "github.com/go-jose/go-jose/v4"
)

var testNow = time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu  sync.RWMutex
	now time.Time
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now}
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *fakeClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(delta)
}

type keyServer struct {
	server *httptest.Server
	hits   atomic.Int64

	mu     sync.RWMutex
	status int
	body   []byte
	gate   <-chan struct{}
}

func newKeyServer(t *testing.T) *keyServer {
	t.Helper()
	fixture := &keyServer{status: http.StatusOK}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/keys" {
			http.NotFound(writer, request)
			return
		}
		fixture.hits.Add(1)
		fixture.mu.RLock()
		status := fixture.status
		body := append([]byte(nil), fixture.body...)
		gate := fixture.gate
		fixture.mu.RUnlock()
		if gate != nil {
			select {
			case <-gate:
			case <-request.Context().Done():
				return
			}
		}
		writer.Header().Set("Content-Type", "application/jwk-set+json")
		writer.WriteHeader(status)
		_, _ = writer.Write(body)
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *keyServer) setKeys(t *testing.T, keys ...jose.JSONWebKey) {
	t.Helper()
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	fixture.setResponse(http.StatusOK, body)
}

func (fixture *keyServer) setResponse(status int, body []byte) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.status = status
	fixture.body = append([]byte(nil), body...)
}

func (fixture *keyServer) setGate(gate <-chan struct{}) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.gate = gate
}

func testTrustAnchor(fixture *keyServer, kind identity.Kind) TrustAnchor {
	workloadClaim := ""
	if kind == identity.KindWorkload {
		workloadClaim = "workload_id"
	}
	return TrustAnchor{
		Issuer:            fixture.server.URL + "/issuer",
		Audience:          "veer-api",
		JWKSURI:           fixture.server.URL + "/keys",
		Kind:              kind,
		AllowedAlgorithms: []jose.SignatureAlgorithm{jose.ES256},
		AcceptedTypes:     []string{"at+jwt", "application/at+jwt"},
		GroupClaim:        "groups",
		WorkloadClaim:     workloadClaim,
		MaxTokenLifetime:  time.Hour,
		ClockSkew:         30 * time.Second,
		Cache: CacheConfig{
			Freshness:            10 * time.Minute,
			RefreshAhead:         2 * time.Minute,
			RefreshCooldown:      time.Minute,
			FetchTimeout:         time.Second,
			MaximumResponseBytes: 64 * 1024,
			MaximumKeys:          16,
		},
	}
}

func newTestVerifier(
	t *testing.T,
	fixture *keyServer,
	anchor TrustAnchor,
	clock Clock,
) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(anchor, fixture.server.Client(), clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}

func generateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	return key
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, minRSAKeyBits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func generateEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return key
}

func publicJWK(privateKey any, keyID string, algorithm jose.SignatureAlgorithm) jose.JSONWebKey {
	privateJWK := jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(algorithm),
		Use:       "sig",
	}
	key := privateJWK.Public()
	key.KeyID = keyID
	key.Algorithm = string(algorithm)
	key.Use = "sig"
	return key
}

func validClaims(anchor TrustAnchor, now time.Time) map[string]any {
	return map[string]any{
		"iss":    anchor.Issuer,
		"sub":    "subject-123",
		"aud":    []string{"another-audience", anchor.Audience},
		"iat":    now.Unix(),
		"exp":    now.Add(5 * time.Minute).Unix(),
		"groups": []string{"operators", "developers", "operators"},
	}
}

func cloneClaims(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for name, value := range input {
		result[name] = value
	}
	return result
}

func signClaims(
	t *testing.T,
	privateKey any,
	algorithm jose.SignatureAlgorithm,
	keyID string,
	typeName string,
	claims any,
) string {
	return signClaimsWithHeaders(t, privateKey, algorithm, keyID, typeName, claims, nil)
}

func signClaimsWithHeaders(
	t *testing.T,
	privateKey any,
	algorithm jose.SignatureAlgorithm,
	keyID string,
	typeName string,
	claims any,
	extraHeaders map[jose.HeaderKey]any,
) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	options := new(jose.SignerOptions)
	if keyID != "" {
		options.WithHeader(jose.HeaderKey("kid"), keyID)
	}
	if typeName != "" {
		options.WithType(jose.ContentType(typeName))
	}
	for name, value := range extraHeaders {
		options.WithHeader(name, value)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: privateKey}, options)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign claims: %v", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize token: %v", err)
	}
	return compact
}

func authenticate(t *testing.T, verifier *Verifier, compact string) (identity.Principal, error) {
	t.Helper()
	credential, err := ports.NewBearerCredential(compact)
	if err != nil {
		t.Fatalf("NewBearerCredential for generated token: %v", err)
	}
	return verifier.Authenticate(context.Background(), credential)
}

func rawCompact(header, payload, signature []byte) string {
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature)
}

func requireAuthenticationError(t *testing.T, got, want error) {
	t.Helper()
	if got != want {
		t.Fatalf("error = %v, want exact %v", got, want)
	}
}
