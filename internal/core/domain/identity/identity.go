// Package identity defines Veer's transport-independent authenticated actor.
//
// The package deliberately models authentication only. Workspace membership,
// roles, policy, and authorization belong to later service boundaries.
package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxIssuerBytes bounds the exact configured OIDC Issuer Identifier.
	MaxIssuerBytes = 2_048
	// MaxSubjectBytes follows the OIDC subject length ceiling.
	MaxSubjectBytes = 255
	// MaxAudiences bounds one authenticated principal's audience set.
	MaxAudiences = 16
	// MaxAudienceBytes bounds one exact audience value.
	MaxAudienceBytes = 2_048
	// MaxGroups bounds optional policy-input group claims.
	MaxGroups = 256
	// MaxGroupBytes bounds one exact group value.
	MaxGroupBytes = 256
	// MaxWorkloadIdentityBytes bounds the provider-neutral workload claim.
	MaxWorkloadIdentityBytes = 512

	fingerprintPrefix = "prn1_"
	fingerprintDomain = "veer.identity.logical-principal.v1"
)

var (
	// ErrInvalidPrincipal marks a value that is not a complete canonical
	// authenticated principal.
	ErrInvalidPrincipal = errors.New("invalid principal")
	// ErrInvalidKind marks any kind other than Human or Workload.
	ErrInvalidKind = errors.New("invalid principal kind")
	// ErrInvalidLogicalIdentity marks an invalid exact issuer-and-subject pair.
	ErrInvalidLogicalIdentity = errors.New("invalid logical identity")
	// ErrInvalidIssuer marks an invalid or over-limit OIDC issuer.
	ErrInvalidIssuer = errors.New("invalid principal issuer")
	// ErrInvalidSubject marks an invalid or over-limit OIDC subject.
	ErrInvalidSubject = errors.New("invalid principal subject")
	// ErrInvalidAudiences marks an invalid or non-canonical audience set.
	ErrInvalidAudiences = errors.New("invalid principal audiences")
	// ErrAudienceRequired marks an empty authenticated audience set.
	ErrAudienceRequired = errors.New("principal audience is required")
	// ErrTooManyAudiences marks an audience set over the alpha bound.
	ErrTooManyAudiences = errors.New("principal audience limit exceeded")
	// ErrInvalidGroups marks an invalid or non-canonical group set.
	ErrInvalidGroups = errors.New("invalid principal groups")
	// ErrTooManyGroups marks a group set over the alpha bound.
	ErrTooManyGroups = errors.New("principal group limit exceeded")
	// ErrInvalidWorkloadIdentity marks an invalid provider-neutral workload
	// claim.
	ErrInvalidWorkloadIdentity = errors.New("invalid workload identity")
	// ErrWorkloadIdentityRequired keeps Workload principals structurally
	// distinct from Human principals.
	ErrWorkloadIdentityRequired = errors.New("workload identity is required")
	// ErrWorkloadIdentityForbidden prevents a Human principal from carrying a
	// workload claim through an ambiguous optional field.
	ErrWorkloadIdentityForbidden = errors.New("workload identity is forbidden")
	// ErrInvalidFingerprint marks a forged, stale, or zero logical-identity
	// fingerprint.
	ErrInvalidFingerprint = errors.New("invalid principal fingerprint")
	// ErrSerializationForbidden prevents personal identity claims from being
	// copied implicitly into resources, queues, JSON logs, or other payloads.
	ErrSerializationForbidden = errors.New("identity serialization forbidden")
)

// Kind distinguishes authenticated people from authenticated workloads. There
// is intentionally no Anonymous kind: absence of credentials is represented at
// the transport boundary and never becomes an authenticated Principal.
type Kind uint8

const (
	KindHuman Kind = iota + 1
	KindWorkload
)

// String returns a bounded non-sensitive classification.
func (kind Kind) String() string {
	switch kind {
	case KindHuman:
		return "human"
	case KindWorkload:
		return "workload"
	default:
		return "unknown"
	}
}

// GoString prevents diagnostic formatting from exposing implementation state.
func (kind Kind) GoString() string { return "identity.Kind(" + kind.String() + ")" }

// Fingerprint is a deterministic, domain-separated SHA-256 pseudonym for one
// exact issuer-and-subject logical identity. It is suitable for bounded
// correlation, but it is not an authorization decision or a collision-proof
// substitute for exact logical-identity equality.
type Fingerprint struct {
	initialized bool
	digest      [sha256.Size]byte
}

// String returns the versioned URL-safe fingerprint.
func (fingerprint Fingerprint) String() string {
	if !fingerprint.initialized {
		return fingerprintPrefix + "invalid"
	}
	return fingerprintPrefix + base64.RawURLEncoding.EncodeToString(fingerprint.digest[:])
}

// GoString returns only the non-reversible fingerprint.
func (fingerprint Fingerprint) GoString() string {
	return "identity.Fingerprint(" + fingerprint.String() + ")"
}

// Equal compares fingerprint bytes without exposing mutable storage.
func (fingerprint Fingerprint) Equal(other Fingerprint) bool {
	return fingerprint.initialized && other.initialized && fingerprint.digest == other.digest
}

// LogicalIdentity is the exact case-sensitive OIDC issuer-and-subject pair.
// It is private-by-construction and cannot be serialized implicitly.
type LogicalIdentity struct {
	issuer      string
	subject     string
	fingerprint Fingerprint
}

// NewLogicalIdentity validates and preserves the issuer and subject exactly.
// It never trims, case-folds, or Unicode-normalizes either identity component.
func NewLogicalIdentity(issuer, subject string) (LogicalIdentity, error) {
	if err := validateIssuer(issuer); err != nil {
		return LogicalIdentity{}, fmt.Errorf("%w: %w", ErrInvalidLogicalIdentity, err)
	}
	if err := validateSubject(subject); err != nil {
		return LogicalIdentity{}, fmt.Errorf("%w: %w", ErrInvalidLogicalIdentity, ErrInvalidSubject)
	}
	return LogicalIdentity{
		issuer:      issuer,
		subject:     subject,
		fingerprint: deriveFingerprint(issuer, subject),
	}, nil
}

// Issuer returns the exact personal identity claim. Callers must not log,
// trace, meter, or serialize it.
func (logical LogicalIdentity) Issuer() string { return logical.issuer }

// Subject returns the exact personal identity claim. Callers must not log,
// trace, meter, or serialize it.
func (logical LogicalIdentity) Subject() string { return logical.subject }

// Fingerprint returns the non-reversible correlation identifier.
func (logical LogicalIdentity) Fingerprint() Fingerprint { return logical.fingerprint }

// String returns only the non-reversible fingerprint.
func (logical LogicalIdentity) String() string {
	if err := ValidateLogicalIdentity(logical); err != nil {
		return "logical-identity(invalid)"
	}
	return "logical-identity(fingerprint=" + logical.fingerprint.String() + ")"
}

// GoString prevents %#v formatting from exposing personal identity claims.
func (logical LogicalIdentity) GoString() string { return logical.String() }

// Format keeps every fmt verb on the redacted representation. String and
// GoString alone do not intercept numeric verbs applied to a struct.
func (logical LogicalIdentity) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, logical.String())
}

// MarshalJSON rejects implicit persistence of personal identity claims.
func (LogicalIdentity) MarshalJSON() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

// MarshalText rejects generic text-based persistence of personal claims.
func (LogicalIdentity) MarshalText() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

// ValidateLogicalIdentity checks a complete value without returning issuer or
// subject values in its error chain.
func ValidateLogicalIdentity(logical LogicalIdentity) error {
	if err := validateIssuer(logical.issuer); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidLogicalIdentity, err)
	}
	if err := validateSubject(logical.subject); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidLogicalIdentity, ErrInvalidSubject)
	}
	if !logical.fingerprint.Equal(deriveFingerprint(logical.issuer, logical.subject)) {
		return fmt.Errorf("%w: %w", ErrInvalidLogicalIdentity, ErrInvalidFingerprint)
	}
	return nil
}

// EqualLogicalIdentity performs exact issuer-and-subject equality. The digest
// is validated separately and is never used as the equality oracle.
func EqualLogicalIdentity(left, right LogicalIdentity) bool {
	return ValidateLogicalIdentity(left) == nil && ValidateLogicalIdentity(right) == nil &&
		left.issuer == right.issuer && left.subject == right.subject
}

// WorkloadIdentity is one provider-neutral opaque workload claim. Subject is
// retained separately because the issuer-and-subject pair remains the logical
// identity for both human and workload principals.
type WorkloadIdentity struct {
	value string
}

// NewWorkloadIdentity validates an exact, bounded workload claim.
func NewWorkloadIdentity(value string) (WorkloadIdentity, error) {
	if err := validateClaim(value, MaxWorkloadIdentityBytes); err != nil {
		return WorkloadIdentity{}, ErrInvalidWorkloadIdentity
	}
	return WorkloadIdentity{value: value}, nil
}

// Value returns the exact workload claim. Callers must not log, trace, meter,
// or serialize it.
func (workload WorkloadIdentity) Value() string { return workload.value }

// String always redacts the workload claim.
func (workload WorkloadIdentity) String() string {
	if err := validateClaim(workload.value, MaxWorkloadIdentityBytes); err != nil {
		return "workload-identity(invalid)"
	}
	return "workload-identity(redacted)"
}

// GoString prevents %#v formatting from exposing the workload claim.
func (workload WorkloadIdentity) GoString() string { return workload.String() }

// Format keeps every fmt verb on the redacted representation.
func (workload WorkloadIdentity) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, workload.String())
}

// MarshalJSON rejects implicit persistence of the workload claim.
func (WorkloadIdentity) MarshalJSON() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

// MarshalText rejects generic text-based persistence of the workload claim.
func (WorkloadIdentity) MarshalText() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

// PrincipalInput contains claims already verified by an authentication
// adapter. NewPrincipal still validates all bounds and canonicalizes sets so
// malformed adapter output cannot enter core services.
type PrincipalInput struct {
	Kind             Kind
	Issuer           string
	Subject          string
	Audiences        []string
	Groups           []string
	WorkloadIdentity *WorkloadIdentity
}

// String redacts every claim carried by the construction input.
func (input PrincipalInput) String() string {
	return "principal-input(kind=" + input.Kind.String() + ",claims=redacted)"
}

// GoString prevents %#v formatting from reflecting exported claim fields.
func (input PrincipalInput) GoString() string { return input.String() }

// Format keeps every fmt verb on the redacted representation.
func (input PrincipalInput) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, input.String())
}

// MarshalJSON rejects implicit persistence of construction-time claims.
func (PrincipalInput) MarshalJSON() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

// MarshalText rejects generic text-based persistence of construction claims.
func (PrincipalInput) MarshalText() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

// GobEncode rejects generic binary persistence of construction-time claims.
func (PrincipalInput) GobEncode() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

// Principal is an immutable normalized authenticated actor. Its fields remain
// private and its accessors return values or defensive copies.
type Principal struct {
	kind             Kind
	logicalIdentity  LogicalIdentity
	audiences        []string
	groups           []string
	workloadIdentity *WorkloadIdentity
}

// NewPrincipal validates, canonicalizes, and takes ownership-independent
// copies of all supplied claims.
func NewPrincipal(input PrincipalInput) (Principal, error) {
	if !validKind(input.Kind) {
		return Principal{}, fmt.Errorf("%w: %w", ErrInvalidPrincipal, ErrInvalidKind)
	}
	logical, err := NewLogicalIdentity(input.Issuer, input.Subject)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %w", ErrInvalidPrincipal, err)
	}
	audiences, err := normalizeClaims(
		input.Audiences,
		MaxAudiences,
		MaxAudienceBytes,
		ErrInvalidAudiences,
		ErrTooManyAudiences,
	)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %w", ErrInvalidPrincipal, err)
	}
	if len(audiences) == 0 {
		return Principal{}, fmt.Errorf("%w: %w", ErrInvalidPrincipal, ErrAudienceRequired)
	}
	groups, err := normalizeClaims(
		input.Groups,
		MaxGroups,
		MaxGroupBytes,
		ErrInvalidGroups,
		ErrTooManyGroups,
	)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %w", ErrInvalidPrincipal, err)
	}
	workload, err := validateWorkloadForKind(input.Kind, input.WorkloadIdentity)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %w", ErrInvalidPrincipal, err)
	}

	return Principal{
		kind:             input.Kind,
		logicalIdentity:  logical,
		audiences:        audiences,
		groups:           groups,
		workloadIdentity: workload,
	}, nil
}

// Kind returns the explicit authenticated actor kind.
func (principal Principal) Kind() Kind { return principal.kind }

// LogicalIdentity returns the immutable exact issuer-and-subject identity.
func (principal Principal) LogicalIdentity() LogicalIdentity {
	return principal.logicalIdentity
}

// Issuer returns the exact personal identity claim. Callers must not log,
// trace, meter, or serialize it.
func (principal Principal) Issuer() string { return principal.logicalIdentity.issuer }

// Subject returns the exact personal identity claim. Callers must not log,
// trace, meter, or serialize it.
func (principal Principal) Subject() string { return principal.logicalIdentity.subject }

// Audiences returns an independent canonical sorted audience set.
func (principal Principal) Audiences() []string { return slices.Clone(principal.audiences) }

// Groups returns an independent canonical sorted group set.
func (principal Principal) Groups() []string { return slices.Clone(principal.groups) }

// WorkloadIdentity returns the explicit workload claim for a Workload
// principal. Human principals return false.
func (principal Principal) WorkloadIdentity() (WorkloadIdentity, bool) {
	if principal.workloadIdentity == nil {
		return WorkloadIdentity{}, false
	}
	return *principal.workloadIdentity, true
}

// Fingerprint returns the deterministic issuer-and-subject pseudonym.
func (principal Principal) Fingerprint() Fingerprint {
	return principal.logicalIdentity.fingerprint
}

// String returns only bounded non-sensitive classification and correlation
// data. It never returns issuer, subject, audience, group, or workload claims.
func (principal Principal) String() string {
	if err := ValidatePrincipal(principal); err != nil {
		return "principal(invalid)"
	}
	return "principal(kind=" + principal.kind.String() +
		",fingerprint=" + principal.Fingerprint().String() + ")"
}

// GoString prevents %#v formatting from exposing claims through private-field
// reflection.
func (principal Principal) GoString() string { return principal.String() }

// Format keeps every fmt verb on the safe fingerprint representation rather
// than allowing an incompatible verb to reflect private claim fields.
func (principal Principal) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, principal.String())
}

// MarshalJSON rejects implicit persistence of principal claims.
func (Principal) MarshalJSON() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

// MarshalText rejects generic text-based persistence of principal claims.
func (Principal) MarshalText() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

// ValidatePrincipal checks a complete canonical value. It is safe for a zero
// value and never includes submitted claim values in an error.
func ValidatePrincipal(principal Principal) error {
	if !validKind(principal.kind) {
		return fmt.Errorf("%w: %w", ErrInvalidPrincipal, ErrInvalidKind)
	}
	if err := ValidateLogicalIdentity(principal.logicalIdentity); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPrincipal, err)
	}
	if err := validateCanonicalClaims(
		principal.audiences,
		MaxAudiences,
		MaxAudienceBytes,
		ErrInvalidAudiences,
		ErrTooManyAudiences,
	); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPrincipal, err)
	}
	if len(principal.audiences) == 0 {
		return fmt.Errorf("%w: %w", ErrInvalidPrincipal, ErrAudienceRequired)
	}
	if err := validateCanonicalClaims(
		principal.groups,
		MaxGroups,
		MaxGroupBytes,
		ErrInvalidGroups,
		ErrTooManyGroups,
	); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPrincipal, err)
	}
	if _, err := validateWorkloadForKind(principal.kind, principal.workloadIdentity); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPrincipal, err)
	}
	return nil
}

// ClonePrincipal returns an independent immutable principal value.
func ClonePrincipal(principal Principal) Principal {
	result := principal
	result.audiences = slices.Clone(principal.audiences)
	result.groups = slices.Clone(principal.groups)
	result.workloadIdentity = cloneWorkload(principal.workloadIdentity)
	return result
}

// EqualPrincipal compares every normalized principal attribute exactly.
func EqualPrincipal(left, right Principal) bool {
	if ValidatePrincipal(left) != nil || ValidatePrincipal(right) != nil ||
		left.kind != right.kind ||
		!EqualLogicalIdentity(left.logicalIdentity, right.logicalIdentity) ||
		!left.logicalIdentity.fingerprint.Equal(right.logicalIdentity.fingerprint) ||
		!slices.Equal(left.audiences, right.audiences) ||
		!slices.Equal(left.groups, right.groups) {
		return false
	}
	return equalWorkload(left.workloadIdentity, right.workloadIdentity)
}

// SameLogicalIdentity compares exact issuer and subject values rather than
// trusting their digest or considering mutable authorization inputs.
func SameLogicalIdentity(left, right Principal) bool {
	return ValidatePrincipal(left) == nil && ValidatePrincipal(right) == nil &&
		EqualLogicalIdentity(left.logicalIdentity, right.logicalIdentity)
}

func validKind(kind Kind) bool {
	return kind == KindHuman || kind == KindWorkload
}

func validateIssuer(value string) error {
	if err := validateClaim(value, MaxIssuerBytes); err != nil {
		return ErrInvalidIssuer
	}
	if strings.ContainsAny(value, "?#") {
		return ErrInvalidIssuer
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Opaque != "" ||
		!strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" ||
		parsed.Hostname() == "" || parsed.User != nil || parsed.String() != value {
		return ErrInvalidIssuer
	}
	return nil
}

func validateClaim(value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return ErrInvalidPrincipal
	}
	for _, current := range value {
		if unicode.IsControl(current) {
			return ErrInvalidPrincipal
		}
	}
	return nil
}

func validateSubject(value string) error {
	if value == "" || len(value) > MaxSubjectBytes || strings.TrimSpace(value) != value {
		return ErrInvalidSubject
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return ErrInvalidSubject
		}
	}
	return nil
}

func normalizeClaims(
	values []string,
	maxValues int,
	maxValueBytes int,
	invalidError error,
	limitError error,
) ([]string, error) {
	if len(values) > maxValues {
		return nil, fmt.Errorf("%w: %w", invalidError, limitError)
	}
	result := slices.Clone(values)
	for _, value := range result {
		if err := validateClaim(value, maxValueBytes); err != nil {
			return nil, invalidError
		}
	}
	slices.Sort(result)
	result = slices.Compact(result)
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func validateCanonicalClaims(
	values []string,
	maxValues int,
	maxValueBytes int,
	invalidError error,
	limitError error,
) error {
	if len(values) > maxValues {
		return fmt.Errorf("%w: %w", invalidError, limitError)
	}
	for index, value := range values {
		if err := validateClaim(value, maxValueBytes); err != nil {
			return invalidError
		}
		if index > 0 && values[index-1] >= value {
			return invalidError
		}
	}
	return nil
}

func validateWorkloadForKind(
	kind Kind,
	workload *WorkloadIdentity,
) (*WorkloadIdentity, error) {
	switch kind {
	case KindHuman:
		if workload != nil {
			return nil, ErrWorkloadIdentityForbidden
		}
		return nil, nil
	case KindWorkload:
		if workload == nil {
			return nil, ErrWorkloadIdentityRequired
		}
		if err := validateClaim(workload.value, MaxWorkloadIdentityBytes); err != nil {
			return nil, ErrInvalidWorkloadIdentity
		}
		return cloneWorkload(workload), nil
	default:
		return nil, ErrInvalidKind
	}
}

func cloneWorkload(value *WorkloadIdentity) *WorkloadIdentity {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func equalWorkload(left, right *WorkloadIdentity) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.value == right.value
}

func deriveFingerprint(issuer, subject string) Fingerprint {
	payload := make([]byte, 0, len(fingerprintDomain)+1+8+len(issuer)+len(subject))
	payload = append(payload, fingerprintDomain...)
	payload = append(payload, 0)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(issuer)))
	payload = append(payload, issuer...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(subject)))
	payload = append(payload, subject...)
	return Fingerprint{initialized: true, digest: sha256.Sum256(payload)}
}

func writeSafeFormat(state fmt.State, verb rune, value string) {
	var formatted string
	switch verb {
	case 'q':
		formatted = fmt.Sprintf("%q", value)
	case 'x':
		formatted = fmt.Sprintf("%x", value)
	case 'X':
		formatted = fmt.Sprintf("%X", value)
	default:
		formatted = value
	}
	_, _ = state.Write([]byte(formatted))
}
