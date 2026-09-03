package oidc

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
	jose "github.com/go-jose/go-jose/v4"
)

func TestVerifierAuthenticatesHumanAndCachesKeys(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(key, "human-key", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := validClaims(anchor, clock.Now())
	token := signClaims(t, key, jose.ES256, "human-key", "AT+JWT", claims)

	principal, err := authenticate(t, verifier, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.Kind() != identity.KindHuman || principal.Issuer() != anchor.Issuer ||
		principal.Subject() != "subject-123" {
		t.Fatal("principal identity was not normalized from verified claims")
	}
	if got, want := principal.Audiences(), []string{"another-audience", "veer-api"}; !slices.Equal(got, want) {
		t.Fatalf("audiences = %v, want %v", got, want)
	}
	if got, want := principal.Groups(), []string{"developers", "operators"}; !slices.Equal(got, want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}
	if _, present := principal.WorkloadIdentity(); present {
		t.Fatal("human principal carried a workload identity")
	}

	if _, err := authenticate(t, verifier, token); err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}
	if got := fixture.hits.Load(); got != 1 {
		t.Fatalf("JWKS fetches = %d, want 1", got)
	}
}

func TestVerifierAuthenticatesWorkload(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(key, "workload-key", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindWorkload)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := validClaims(anchor, clock.Now())
	claims[anchor.WorkloadClaim] = "spiffe://tenant.example/workload/api"
	token := signClaims(t, key, jose.ES256, "workload-key", "at+jwt", claims)

	principal, err := authenticate(t, verifier, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	workload, present := principal.WorkloadIdentity()
	if principal.Kind() != identity.KindWorkload || !present ||
		workload.Value() != "spiffe://tenant.example/workload/api" {
		t.Fatal("workload principal did not preserve its verified opaque identity")
	}
}

func TestVerifierUsesOneCaseFoldRelationForAcceptedType(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(key, "fold-key", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	anchor.AcceptedTypes = []string{"ſ"}
	verifier := newTestVerifier(t, fixture, anchor, clock)
	token := signClaims(t, key, jose.ES256, "fold-key", "S", validClaims(anchor, clock.Now()))

	if _, err := authenticate(t, verifier, token); err != nil {
		t.Fatalf("Authenticate Unicode-fold-equivalent type: %v", err)
	}
}

func TestVerifierRejectsHeadersBeforeJWKSLookup(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := validClaims(anchor, clock.Now())
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	validHeader := []byte(`{"alg":"ES256","kid":"key-1","typ":"at+jwt"}`)
	tests := []struct {
		name  string
		token func(*testing.T) string
	}{
		{name: "too many compact parts", token: func(*testing.T) string { return "a.b.c.d" }},
		{name: "non-JSON header", token: func(*testing.T) string { return rawCompact([]byte("not-json"), payload, []byte{1}) }},
		{name: "non-object header", token: func(*testing.T) string { return rawCompact([]byte(`[]`), payload, []byte{1}) }},
		{name: "missing algorithm", token: func(*testing.T) string {
			return rawCompact([]byte(`{"kid":"key-1","typ":"at+jwt"}`), payload, []byte{1})
		}},
		{name: "symmetric algorithm", token: func(*testing.T) string {
			return rawCompact([]byte(`{"alg":"HS256","kid":"key-1","typ":"at+jwt"}`), payload, []byte{1})
		}},
		{name: "missing key ID", token: func(t *testing.T) string {
			return signClaims(t, key, jose.ES256, "", "at+jwt", claims)
		}},
		{name: "oversized key ID", token: func(*testing.T) string {
			header := []byte(`{"alg":"ES256","kid":"` + strings.Repeat("k", maxKeyIDBytes+1) + `","typ":"at+jwt"}`)
			return rawCompact(header, payload, []byte{1})
		}},
		{name: "missing type", token: func(t *testing.T) string {
			return signClaims(t, key, jose.ES256, "key-1", "", claims)
		}},
		{name: "wrong type", token: func(t *testing.T) string {
			return signClaims(t, key, jose.ES256, "key-1", "JWT", claims)
		}},
		{name: "numeric type", token: func(*testing.T) string {
			return rawCompact([]byte(`{"alg":"ES256","kid":"key-1","typ":1}`), payload, []byte{1})
		}},
		{name: "duplicate header member", token: func(*testing.T) string {
			return rawCompact(
				[]byte(`{"alg":"ES256","alg":"ES256","kid":"key-1","typ":"at+jwt"}`),
				payload,
				[]byte{1},
			)
		}},
		{name: "invalid surrogate in header", token: func(*testing.T) string {
			return rawCompact([]byte(`{"alg":"ES256","kid":"key-1","typ":"\ud800"}`), payload, []byte{1})
		}},
		{name: "embedded JWK location", token: func(t *testing.T) string {
			return signClaimsWithHeaders(t, key, jose.ES256, "key-1", "at+jwt", claims,
				map[jose.HeaderKey]any{"jku": "https://attacker.invalid/keys"})
		}},
		{name: "certificate location", token: func(t *testing.T) string {
			return signClaimsWithHeaders(t, key, jose.ES256, "key-1", "at+jwt", claims,
				map[jose.HeaderKey]any{"x5u": "https://attacker.invalid/cert"})
		}},
		{name: "critical extension", token: func(t *testing.T) string {
			return signClaimsWithHeaders(t, key, jose.ES256, "key-1", "at+jwt", claims,
				map[jose.HeaderKey]any{"crit": []string{"custom"}, "custom": true})
		}},
		{name: "claims are not an object", token: func(*testing.T) string {
			return rawCompact(validHeader, []byte(`[]`), []byte{1})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := authenticate(t, verifier, test.token(t))
			requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
		})
	}
	if got := fixture.hits.Load(); got != 0 {
		t.Fatalf("malformed headers caused %d JWKS fetches", got)
	}
}

func TestVerifierRejectsNegativeClaimCorpusWithoutDisclosure(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(key, "claims-key", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	base := validClaims(anchor, clock.Now())
	validToken := signClaims(t, key, jose.ES256, "claims-key", "at+jwt", base)
	if _, err := authenticate(t, verifier, validToken); err != nil {
		t.Fatalf("warm cache: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "missing issuer", mutate: func(value map[string]any) { delete(value, "iss") }},
		{name: "wrong issuer", mutate: func(value map[string]any) { value["iss"] = "https://other.invalid" }},
		{name: "missing subject", mutate: func(value map[string]any) { delete(value, "sub") }},
		{name: "empty subject", mutate: func(value map[string]any) { value["sub"] = "" }},
		{name: "non-ASCII subject", mutate: func(value map[string]any) { value["sub"] = "subject-é" }},
		{name: "missing audience", mutate: func(value map[string]any) { delete(value, "aud") }},
		{name: "wrong audience", mutate: func(value map[string]any) { value["aud"] = []string{"other"} }},
		{name: "empty audience", mutate: func(value map[string]any) { value["aud"] = []string{} }},
		{name: "audience has wrong type", mutate: func(value map[string]any) { value["aud"] = 42 }},
		{name: "too many audiences", mutate: func(value map[string]any) {
			value["aud"] = append(make([]string, identity.MaxAudiences), anchor.Audience)
		}},
		{name: "missing expiry", mutate: func(value map[string]any) { delete(value, "exp") }},
		{name: "expiry is string", mutate: func(value map[string]any) { value["exp"] = "123" }},
		{name: "expiry is fractional", mutate: func(value map[string]any) { value["exp"] = 123.5 }},
		{name: "expiry uses exponent", mutate: func(value map[string]any) { value["exp"] = json.Number("2e9") }},
		{name: "expired", mutate: func(value map[string]any) { value["exp"] = clock.Now().Add(-31 * time.Second).Unix() }},
		{name: "expiry at skew boundary", mutate: func(value map[string]any) { value["exp"] = clock.Now().Add(-30 * time.Second).Unix() }},
		{name: "missing issued at", mutate: func(value map[string]any) { delete(value, "iat") }},
		{name: "issued at is fractional", mutate: func(value map[string]any) { value["iat"] = 123.5 }},
		{name: "issued in future", mutate: func(value map[string]any) { value["iat"] = clock.Now().Add(31 * time.Second).Unix() }},
		{name: "expiry before issued at", mutate: func(value map[string]any) {
			value["iat"] = clock.Now().Unix()
			value["exp"] = clock.Now().Unix()
		}},
		{name: "lifetime too long", mutate: func(value map[string]any) {
			value["exp"] = clock.Now().Add(anchor.MaxTokenLifetime + time.Second).Unix()
		}},
		{name: "not before is fractional", mutate: func(value map[string]any) { value["nbf"] = 123.5 }},
		{name: "not valid yet", mutate: func(value map[string]any) { value["nbf"] = clock.Now().Add(31 * time.Second).Unix() }},
		{name: "not before at expiry", mutate: func(value map[string]any) { value["nbf"] = value["exp"] }},
		{name: "groups scalar", mutate: func(value map[string]any) { value["groups"] = "operators" }},
		{name: "groups null", mutate: func(value map[string]any) { value["groups"] = nil }},
		{name: "too many groups", mutate: func(value map[string]any) {
			value["groups"] = make([]string, identity.MaxGroups+1)
		}},
		{name: "invalid group", mutate: func(value map[string]any) { value["groups"] = []string{"CANARY\nGROUP"} }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := cloneClaims(base)
			test.mutate(claims)
			token := signClaims(t, key, jose.ES256, "claims-key", "at+jwt", claims)
			_, err := authenticate(t, verifier, token)
			requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("authentication error disclosed credential or claim material: %q", err)
			}
		})
	}

	duplicatePayload := []byte(fmt.Sprintf(
		`{"iss":%q,"sub":"first","sub":"CANARY-SUBJECT","aud":%q,"iat":%d,"exp":%d}`,
		anchor.Issuer,
		anchor.Audience,
		clock.Now().Unix(),
		clock.Now().Add(time.Minute).Unix(),
	))
	duplicateToken := rawCompact(
		[]byte(`{"alg":"ES256","kid":"claims-key","typ":"at+jwt"}`),
		duplicatePayload,
		[]byte{1},
	)
	_, err := authenticate(t, verifier, duplicateToken)
	requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)

	surrogatePayload := []byte(fmt.Sprintf(
		`{"iss":%q,"sub":"\ud800","aud":%q,"iat":%d,"exp":%d}`,
		anchor.Issuer,
		anchor.Audience,
		clock.Now().Unix(),
		clock.Now().Add(time.Minute).Unix(),
	))
	surrogateToken := rawCompact(
		[]byte(`{"alg":"ES256","kid":"claims-key","typ":"at+jwt"}`),
		surrogatePayload,
		[]byte{1},
	)
	_, err = authenticate(t, verifier, surrogateToken)
	requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
}

func TestVerifierRejectsBadSignatureAndMissingWorkloadClaim(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	trustedKey := generateECDSAKey(t)
	otherKey := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(trustedKey, "shared-kid", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindWorkload)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	claims := validClaims(anchor, clock.Now())
	claims[anchor.WorkloadClaim] = "workload-canary"

	badSignature := signClaims(t, otherKey, jose.ES256, "shared-kid", "at+jwt", claims)
	_, err := authenticate(t, verifier, badSignature)
	requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
	if strings.Contains(err.Error(), badSignature) || strings.Contains(err.Error(), "workload-canary") {
		t.Fatalf("signature error disclosed credential material: %q", err)
	}

	delete(claims, anchor.WorkloadClaim)
	missingWorkload := signClaims(t, trustedKey, jose.ES256, "shared-kid", "at+jwt", claims)
	_, err = authenticate(t, verifier, missingWorkload)
	requireAuthenticationError(t, err, ports.ErrAuthenticationInvalid)
}

func TestVerifierClockSkewBoundaries(t *testing.T) {
	fixture := newKeyServer(t)
	clock := newFakeClock(testNow)
	key := generateECDSAKey(t)
	fixture.setKeys(t, publicJWK(key, "time-key", jose.ES256))
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier := newTestVerifier(t, fixture, anchor, clock)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "expiry inside skew", mutate: func(value map[string]any) {
			value["iat"] = clock.Now().Add(-time.Minute).Unix()
			value["exp"] = clock.Now().Add(-29 * time.Second).Unix()
		}},
		{name: "issued at skew boundary", mutate: func(value map[string]any) {
			value["iat"] = clock.Now().Add(30 * time.Second).Unix()
			value["exp"] = clock.Now().Add(5 * time.Minute).Unix()
		}},
		{name: "not before skew boundary", mutate: func(value map[string]any) {
			value["nbf"] = clock.Now().Add(30 * time.Second).Unix()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := validClaims(anchor, clock.Now())
			test.mutate(claims)
			token := signClaims(t, key, jose.ES256, "time-key", "at+jwt", claims)
			if _, err := authenticate(t, verifier, token); err != nil {
				t.Fatalf("Authenticate at accepted boundary: %v", err)
			}
		})
	}
}
