// Package oidc verifies provider-neutral OIDC JWT access tokens against
// explicitly configured issuer trust anchors.
package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	jose "github.com/go-jose/go-jose/v4"
)

const (
	// MaxJWKSResponseBytesLimit is the largest configurable JWKS response bound.
	MaxJWKSResponseBytesLimit int64 = 1024 * 1024
	// MaxJWKSKeysLimit is the largest configurable number of keys in one set.
	MaxJWKSKeysLimit = 128
	// MaxTrustAnchors bounds provider and token-class dispatch work for one
	// authenticator.
	MaxTrustAnchors = 16

	maxURIBytes             = identity.MaxIssuerBytes
	maxAudienceBytes        = identity.MaxAudienceBytes
	maxClaimNameBytes       = 128
	maxAcceptedTypes        = 8
	maxTypeBytes            = 128
	maxAllowedAlgorithms    = 8
	maxTokenLifetimeLimit   = 24 * time.Hour
	maxClockSkewLimit       = 5 * time.Minute
	maxCacheFreshnessLimit  = 24 * time.Hour
	maxRefreshCooldownLimit = time.Hour
	maxFetchTimeoutLimit    = 30 * time.Second
)

var (
	// ErrInvalidTrustAnchor marks configuration that cannot establish a bounded
	// and unambiguous issuer trust relationship.
	ErrInvalidTrustAnchor = errors.New("invalid OIDC trust anchor")
)

// CacheConfig freezes all network, memory, and refresh bounds for a trust
// anchor. No value is defaulted implicitly.
type CacheConfig struct {
	Freshness            time.Duration
	RefreshAhead         time.Duration
	RefreshCooldown      time.Duration
	FetchTimeout         time.Duration
	MaximumResponseBytes int64
	MaximumKeys          int
}

// TrustAnchor binds one accepted token class to one exact issuer, audience,
// and JWKS endpoint. WorkloadClaim is required only for workload principals.
type TrustAnchor struct {
	Issuer            string
	Audience          string
	JWKSURI           string
	Kind              identity.Kind
	AllowedAlgorithms []jose.SignatureAlgorithm
	AcceptedTypes     []string
	GroupClaim        string
	WorkloadClaim     string
	MaxTokenLifetime  time.Duration
	ClockSkew         time.Duration
	Cache             CacheConfig
}

type validatedTrustAnchor struct {
	issuer           string
	audience         string
	jwksURI          *url.URL
	kind             identity.Kind
	algorithms       []jose.SignatureAlgorithm
	algorithmSet     map[jose.SignatureAlgorithm]struct{}
	acceptedTypes    []string
	groupClaim       string
	workloadClaim    string
	maxTokenLifetime time.Duration
	clockSkew        time.Duration
	cache            CacheConfig
}

func validateTrustAnchor(anchor TrustAnchor) (validatedTrustAnchor, error) {
	issuerURL, err := validateHTTPSURL(anchor.Issuer, false)
	if err != nil {
		return validatedTrustAnchor{}, configError("issuer must be an exact HTTPS URL without query or fragment")
	}
	if _, err := validateBoundedText(anchor.Audience, maxAudienceBytes); err != nil {
		return validatedTrustAnchor{}, configError("audience must be a bounded non-empty value")
	}
	jwksURL, err := validateHTTPSURL(anchor.JWKSURI, true)
	if err != nil {
		return validatedTrustAnchor{}, configError("JWKS URI must be an exact HTTPS URL without fragment")
	}

	if anchor.Kind != identity.KindHuman && anchor.Kind != identity.KindWorkload {
		return validatedTrustAnchor{}, configError("principal kind must be Human or Workload")
	}
	if anchor.Kind == identity.KindHuman && anchor.WorkloadClaim != "" {
		return validatedTrustAnchor{}, configError("human trust anchor must not configure a workload claim")
	}
	if anchor.Kind == identity.KindWorkload && anchor.WorkloadClaim == "" {
		return validatedTrustAnchor{}, configError("workload trust anchor must configure a workload claim")
	}

	algorithms, algorithmSet, err := validateAlgorithms(anchor.AllowedAlgorithms)
	if err != nil {
		return validatedTrustAnchor{}, err
	}
	types, err := validateTypes(anchor.AcceptedTypes)
	if err != nil {
		return validatedTrustAnchor{}, err
	}
	if err := validateClaimName(anchor.GroupClaim); err != nil {
		return validatedTrustAnchor{}, configError("group claim must be a bounded non-reserved claim name")
	}
	if anchor.WorkloadClaim != "" {
		if err := validateClaimName(anchor.WorkloadClaim); err != nil {
			return validatedTrustAnchor{}, configError("workload claim must be a bounded non-reserved claim name")
		}
		if anchor.WorkloadClaim == anchor.GroupClaim {
			return validatedTrustAnchor{}, configError("group and workload claims must be distinct")
		}
	}

	if anchor.MaxTokenLifetime < time.Second ||
		anchor.MaxTokenLifetime > maxTokenLifetimeLimit ||
		anchor.MaxTokenLifetime%time.Second != 0 {
		return validatedTrustAnchor{}, configError("maximum token lifetime must be whole seconds between one second and 24 hours")
	}
	if anchor.ClockSkew < 0 || anchor.ClockSkew > maxClockSkewLimit || anchor.ClockSkew%time.Second != 0 {
		return validatedTrustAnchor{}, configError("clock skew must be whole seconds between zero and five minutes")
	}
	if err := validateCacheConfig(anchor.Cache); err != nil {
		return validatedTrustAnchor{}, err
	}

	return validatedTrustAnchor{
		issuer:           issuerURL.String(),
		audience:         anchor.Audience,
		jwksURI:          jwksURL,
		kind:             anchor.Kind,
		algorithms:       algorithms,
		algorithmSet:     algorithmSet,
		acceptedTypes:    types,
		groupClaim:       anchor.GroupClaim,
		workloadClaim:    anchor.WorkloadClaim,
		maxTokenLifetime: anchor.MaxTokenLifetime,
		clockSkew:        anchor.ClockSkew,
		cache:            anchor.Cache,
	}, nil
}

func validateHTTPSURL(raw string, allowQuery bool) (*url.URL, error) {
	if _, err := validateBoundedText(raw, maxURIBytes); err != nil {
		return nil, err
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" {
		return nil, ErrInvalidTrustAnchor
	}
	if !allowQuery && parsed.RawQuery != "" {
		return nil, ErrInvalidTrustAnchor
	}
	if parsed.String() != raw {
		return nil, ErrInvalidTrustAnchor
	}
	return parsed, nil
}

func validateAlgorithms(input []jose.SignatureAlgorithm) (
	[]jose.SignatureAlgorithm,
	map[jose.SignatureAlgorithm]struct{},
	error,
) {
	if len(input) == 0 || len(input) > maxAllowedAlgorithms {
		return nil, nil, configError("allowed algorithms must contain between one and eight values")
	}
	result := append([]jose.SignatureAlgorithm(nil), input...)
	set := make(map[jose.SignatureAlgorithm]struct{}, len(result))
	for _, algorithm := range result {
		if !asymmetricAlgorithm(algorithm) {
			return nil, nil, configError("allowed algorithms must contain only supported asymmetric signatures")
		}
		if _, duplicate := set[algorithm]; duplicate {
			return nil, nil, configError("allowed algorithms must be unique")
		}
		set[algorithm] = struct{}{}
	}
	return result, set, nil
}

func validateTypes(input []string) ([]string, error) {
	if len(input) == 0 || len(input) > maxAcceptedTypes {
		return nil, configError("accepted types must contain between one and eight values")
	}
	result := make([]string, len(input))
	for index, value := range input {
		if _, err := validateBoundedText(value, maxTypeBytes); err != nil {
			return nil, configError("accepted types must contain bounded non-empty values")
		}
		for _, existing := range result[:index] {
			if strings.EqualFold(existing, value) {
				return nil, configError("accepted types must be unique")
			}
		}
		result[index] = value
	}
	return result, nil
}

func validateClaimName(value string) error {
	if _, err := validateBoundedText(value, maxClaimNameBytes); err != nil {
		return err
	}
	switch value {
	case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
		return ErrInvalidTrustAnchor
	default:
		return nil
	}
}

func validateCacheConfig(config CacheConfig) error {
	if config.Freshness <= 0 || config.Freshness > maxCacheFreshnessLimit {
		return configError("cache freshness must be greater than zero and at most 24 hours")
	}
	if config.RefreshAhead <= 0 || config.RefreshAhead >= config.Freshness {
		return configError("refresh-ahead interval must be greater than zero and shorter than cache freshness")
	}
	if config.RefreshCooldown <= 0 || config.RefreshCooldown > maxRefreshCooldownLimit {
		return configError("refresh cooldown must be greater than zero and at most one hour")
	}
	if config.FetchTimeout <= 0 || config.FetchTimeout > maxFetchTimeoutLimit {
		return configError("JWKS fetch timeout must be greater than zero and at most 30 seconds")
	}
	if config.MaximumResponseBytes <= 0 || config.MaximumResponseBytes > MaxJWKSResponseBytesLimit {
		return configError("JWKS response bound must be between one byte and one MiB")
	}
	if config.MaximumKeys <= 0 || config.MaximumKeys > MaxJWKSKeysLimit {
		return configError("JWKS key bound must be between one and 128")
	}
	return nil
}

func validateBoundedText(value string, maximumBytes int) (string, error) {
	if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return "", ErrInvalidTrustAnchor
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", ErrInvalidTrustAnchor
		}
	}
	return value, nil
}

func asymmetricAlgorithm(algorithm jose.SignatureAlgorithm) bool {
	switch algorithm {
	case jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.EdDSA:
		return true
	default:
		return false
	}
}

func configError(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidTrustAnchor, message)
}
