package oidc

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
)

func (verifier *Verifier) principalFromClaims(payload []byte) (identity.Principal, bool) {
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return identity.Principal{}, false
	}
	issuer, ok := requiredJSONString(claims, "iss")
	if !ok || issuer != verifier.anchor.issuer {
		return identity.Principal{}, false
	}
	subject, ok := requiredJSONString(claims, "sub")
	if !ok {
		return identity.Principal{}, false
	}
	audiences, ok := parseAudiences(claims["aud"])
	if !ok || !containsExact(audiences, verifier.anchor.audience) {
		return identity.Principal{}, false
	}
	expiresAt, ok := requiredNumericDate(claims, "exp")
	if !ok {
		return identity.Principal{}, false
	}
	issuedAt, ok := requiredNumericDate(claims, "iat")
	if !ok || expiresAt <= issuedAt ||
		expiresAt-issuedAt > int64(verifier.anchor.maxTokenLifetime/time.Second) {
		return identity.Principal{}, false
	}
	notBefore, hasNotBefore, ok := optionalNumericDate(claims, "nbf")
	if !ok || hasNotBefore && notBefore >= expiresAt {
		return identity.Principal{}, false
	}
	if !verifier.validTimes(issuedAt, expiresAt, notBefore, hasNotBefore) {
		return identity.Principal{}, false
	}

	groups, ok := parseOptionalStringSet(claims, verifier.anchor.groupClaim, identity.MaxGroups)
	if !ok {
		return identity.Principal{}, false
	}
	var workloadIdentity *identity.WorkloadIdentity
	if verifier.anchor.kind == identity.KindWorkload {
		workloadValue, ok := requiredJSONString(claims, verifier.anchor.workloadClaim)
		if !ok {
			return identity.Principal{}, false
		}
		workload, err := identity.NewWorkloadIdentity(workloadValue)
		if err != nil {
			return identity.Principal{}, false
		}
		workloadIdentity = &workload
	}

	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind:             verifier.anchor.kind,
		Issuer:           issuer,
		Subject:          subject,
		Audiences:        audiences,
		Groups:           groups,
		WorkloadIdentity: workloadIdentity,
	})
	if err != nil {
		return identity.Principal{}, false
	}
	return principal, true
}

func (verifier *Verifier) validTimes(issuedAt, expiresAt, notBefore int64, hasNotBefore bool) bool {
	now := verifier.clock.Now()
	skew := verifier.anchor.clockSkew
	if !now.Add(-skew).Before(time.Unix(expiresAt, 0)) {
		return false
	}
	if now.Add(skew).Before(time.Unix(issuedAt, 0)) {
		return false
	}
	if hasNotBefore && now.Add(skew).Before(time.Unix(notBefore, 0)) {
		return false
	}
	return true
}

func parseAudiences(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil, false
		}
		return []string{single}, true
	}
	var multiple []string
	if err := json.Unmarshal(raw, &multiple); err != nil ||
		len(multiple) == 0 || len(multiple) > identity.MaxAudiences {
		return nil, false
	}
	return multiple, true
}

func parseOptionalStringSet(
	claims map[string]json.RawMessage,
	claimName string,
	maximumValues int,
) ([]string, bool) {
	raw, present := claims[claimName]
	if !present {
		return nil, true
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || values == nil || len(values) > maximumValues {
		return nil, false
	}
	return values, true
}

func requiredNumericDate(claims map[string]json.RawMessage, name string) (int64, bool) {
	raw, present := claims[name]
	if !present {
		return 0, false
	}
	return parseNumericDate(raw)
}

func optionalNumericDate(claims map[string]json.RawMessage, name string) (int64, bool, bool) {
	raw, present := claims[name]
	if !present {
		return 0, false, true
	}
	value, valid := parseNumericDate(raw)
	return value, true, valid
}

func parseNumericDate(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || len(raw) > 19 || bytes.Equal(raw, []byte("0")) {
		return 0, false
	}
	for _, character := range raw {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(string(raw), 10, 64)
	return value, err == nil && value > 0
}

func containsExact(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
