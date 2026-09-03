package oidc

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	jose "github.com/go-jose/go-jose/v4"
)

func TestNewVerifierValidatesAndCopiesTrustAnchor(t *testing.T) {
	fixture := newKeyServer(t)
	anchor := testTrustAnchor(fixture, identity.KindHuman)
	verifier, err := NewVerifier(anchor, fixture.server.Client(), newFakeClock(testNow))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	anchor.AllowedAlgorithms[0] = jose.HS256
	anchor.AcceptedTypes[0] = "mutated"
	if verifier.anchor.algorithms[0] != jose.ES256 {
		t.Fatal("allowed algorithm input was retained by reference")
	}
	if verifier.anchor.acceptedTypes[0] != "at+jwt" {
		t.Fatal("accepted type input was retained by reference")
	}
}

func TestNewVerifierRejectsInvalidTrustAnchors(t *testing.T) {
	fixture := newKeyServer(t)
	base := testTrustAnchor(fixture, identity.KindHuman)
	tests := []struct {
		name   string
		mutate func(*TrustAnchor)
	}{
		{name: "insecure issuer", mutate: func(value *TrustAnchor) { value.Issuer = "http://issuer.example" }},
		{name: "issuer query", mutate: func(value *TrustAnchor) { value.Issuer += "?tenant=a" }},
		{name: "issuer fragment", mutate: func(value *TrustAnchor) { value.Issuer += "#fragment" }},
		{name: "issuer user info", mutate: func(value *TrustAnchor) { value.Issuer = "https://user@issuer.example" }},
		{name: "empty audience", mutate: func(value *TrustAnchor) { value.Audience = "" }},
		{name: "trimmed audience", mutate: func(value *TrustAnchor) { value.Audience = " veer-api" }},
		{name: "insecure JWKS", mutate: func(value *TrustAnchor) { value.JWKSURI = "http://issuer.example/keys" }},
		{name: "JWKS fragment", mutate: func(value *TrustAnchor) { value.JWKSURI += "#fragment" }},
		{name: "unknown kind", mutate: func(value *TrustAnchor) { value.Kind = identity.Kind(99) }},
		{name: "human workload claim", mutate: func(value *TrustAnchor) { value.WorkloadClaim = "workload_id" }},
		{name: "workload claim missing", mutate: func(value *TrustAnchor) { value.Kind = identity.KindWorkload }},
		{name: "no algorithms", mutate: func(value *TrustAnchor) { value.AllowedAlgorithms = nil }},
		{name: "symmetric algorithm", mutate: func(value *TrustAnchor) { value.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.HS256} }},
		{name: "duplicate algorithm", mutate: func(value *TrustAnchor) { value.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.ES256} }},
		{name: "no accepted type", mutate: func(value *TrustAnchor) { value.AcceptedTypes = nil }},
		{name: "duplicate accepted type", mutate: func(value *TrustAnchor) { value.AcceptedTypes = []string{"at+jwt", "AT+JWT"} }},
		{name: "Unicode-fold duplicate accepted type", mutate: func(value *TrustAnchor) {
			value.AcceptedTypes = []string{"S", "ſ"}
		}},
		{name: "reserved group claim", mutate: func(value *TrustAnchor) { value.GroupClaim = "sub" }},
		{name: "empty group claim", mutate: func(value *TrustAnchor) { value.GroupClaim = "" }},
		{name: "same custom claims", mutate: func(value *TrustAnchor) {
			value.Kind = identity.KindWorkload
			value.WorkloadClaim = value.GroupClaim
		}},
		{name: "short lifetime", mutate: func(value *TrustAnchor) { value.MaxTokenLifetime = time.Millisecond }},
		{name: "long lifetime", mutate: func(value *TrustAnchor) { value.MaxTokenLifetime = 25 * time.Hour }},
		{name: "fractional lifetime", mutate: func(value *TrustAnchor) { value.MaxTokenLifetime = time.Second + time.Millisecond }},
		{name: "negative skew", mutate: func(value *TrustAnchor) { value.ClockSkew = -time.Second }},
		{name: "large skew", mutate: func(value *TrustAnchor) { value.ClockSkew = 5*time.Minute + time.Second }},
		{name: "fractional skew", mutate: func(value *TrustAnchor) { value.ClockSkew = time.Millisecond }},
		{name: "zero freshness", mutate: func(value *TrustAnchor) { value.Cache.Freshness = 0 }},
		{name: "long freshness", mutate: func(value *TrustAnchor) { value.Cache.Freshness = 25 * time.Hour }},
		{name: "zero refresh ahead", mutate: func(value *TrustAnchor) { value.Cache.RefreshAhead = 0 }},
		{name: "refresh ahead equals freshness", mutate: func(value *TrustAnchor) { value.Cache.RefreshAhead = value.Cache.Freshness }},
		{name: "zero cooldown", mutate: func(value *TrustAnchor) { value.Cache.RefreshCooldown = 0 }},
		{name: "long cooldown", mutate: func(value *TrustAnchor) { value.Cache.RefreshCooldown = 2 * time.Hour }},
		{name: "zero timeout", mutate: func(value *TrustAnchor) { value.Cache.FetchTimeout = 0 }},
		{name: "long timeout", mutate: func(value *TrustAnchor) { value.Cache.FetchTimeout = time.Minute }},
		{name: "zero response bound", mutate: func(value *TrustAnchor) { value.Cache.MaximumResponseBytes = 0 }},
		{name: "large response bound", mutate: func(value *TrustAnchor) { value.Cache.MaximumResponseBytes = MaxJWKSResponseBytesLimit + 1 }},
		{name: "zero key bound", mutate: func(value *TrustAnchor) { value.Cache.MaximumKeys = 0 }},
		{name: "large key bound", mutate: func(value *TrustAnchor) { value.Cache.MaximumKeys = MaxJWKSKeysLimit + 1 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			anchor := base
			anchor.AllowedAlgorithms = append([]jose.SignatureAlgorithm(nil), base.AllowedAlgorithms...)
			anchor.AcceptedTypes = append([]string(nil), base.AcceptedTypes...)
			test.mutate(&anchor)
			_, err := NewVerifier(anchor, fixture.server.Client(), newFakeClock(testNow))
			if !errors.Is(err, ErrInvalidTrustAnchor) {
				t.Fatalf("error = %v, want ErrInvalidTrustAnchor", err)
			}
			if anchor.Issuer != "" && strings.Contains(err.Error(), anchor.Issuer) ||
				anchor.Audience != "" && strings.Contains(err.Error(), anchor.Audience) {
				t.Fatalf("configuration error exposed configured values: %q", err)
			}
		})
	}
}
