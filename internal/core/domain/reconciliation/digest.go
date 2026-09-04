package reconciliation

import (
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"log/slog"
	"strings"
)

const (
	evidenceDigestPrefix     = "rve1_"
	planDigestPrefix         = "rvp1_"
	effectKeyPrefix          = "rfx1_"
	requestFingerprintPrefix = "rrq1_"
	resultDigestPrefix       = "rrs1_"
	workKeyPrefix            = "rwk1_"
)

type digestValue struct {
	initialized bool
	digest      [sha256.Size]byte
}

// EvidenceDigest identifies one kind-and-version-bound evidence value.
type EvidenceDigest struct{ digestValue }

func (value EvidenceDigest) String() string {
	return formatDigest(evidenceDigestPrefix, value.digestValue)
}
func (value EvidenceDigest) Equal(other EvidenceDigest) bool {
	return equalDigest(value.digestValue, other.digestValue)
}
func ParseEvidenceDigest(value string) (EvidenceDigest, error) {
	parsed, err := parseDigest(evidenceDigestPrefix, value)
	return EvidenceDigest{parsed}, err
}
func (value EvidenceDigest) MarshalText() ([]byte, error) {
	return marshalDigest(value.String(), value.initialized)
}
func (value EvidenceDigest) GoString() string     { return value.String() }
func (value EvidenceDigest) LogValue() slog.Value { return redactedLogValue(value.String()) }

// PlanDigest is the semantic identity of canonical plan inputs. Plan ID,
// revision, and predecessor metadata deliberately do not perturb it.
type PlanDigest struct{ digestValue }

func (value PlanDigest) String() string { return formatDigest(planDigestPrefix, value.digestValue) }
func (value PlanDigest) Equal(other PlanDigest) bool {
	return equalDigest(value.digestValue, other.digestValue)
}
func ParsePlanDigest(value string) (PlanDigest, error) {
	parsed, err := parseDigest(planDigestPrefix, value)
	return PlanDigest{parsed}, err
}
func (value PlanDigest) MarshalText() ([]byte, error) {
	return marshalDigest(value.String(), value.initialized)
}
func (value PlanDigest) GoString() string     { return value.String() }
func (value PlanDigest) LogValue() slog.Value { return redactedLogValue(value.String()) }

// RequestFingerprint binds the normalized query/defaulted body and provider
// request semantics without retaining either representation.
type RequestFingerprint struct{ digestValue }

// NewRequestFingerprint hashes one non-empty bounded canonical request.
func NewRequestFingerprint(canonical []byte) (RequestFingerprint, error) {
	if len(canonical) == 0 || len(canonical) > MaxEvidenceBytes {
		return RequestFingerprint{}, ErrInvalidDigest
	}
	return RequestFingerprint{deriveDigest("veer.reconciliation.request.v1", canonical)}, nil
}
func (value RequestFingerprint) String() string {
	return formatDigest(requestFingerprintPrefix, value.digestValue)
}
func (value RequestFingerprint) Equal(other RequestFingerprint) bool {
	return equalDigest(value.digestValue, other.digestValue)
}
func ParseRequestFingerprint(value string) (RequestFingerprint, error) {
	parsed, err := parseDigest(requestFingerprintPrefix, value)
	return RequestFingerprint{parsed}, err
}
func (value RequestFingerprint) MarshalText() ([]byte, error) {
	return marshalDigest(value.String(), value.initialized)
}
func (value RequestFingerprint) GoString() string     { return value.String() }
func (value RequestFingerprint) LogValue() slog.Value { return redactedLogValue(value.String()) }

// ResultDigest identifies a replayable semantic status/header/body result.
type ResultDigest struct{ digestValue }

// NewResultDigest hashes one non-empty bounded canonical semantic result.
func NewResultDigest(canonical []byte) (ResultDigest, error) {
	if len(canonical) == 0 || len(canonical) > MaxEvidenceBytes {
		return ResultDigest{}, ErrInvalidDigest
	}
	return ResultDigest{deriveDigest("veer.reconciliation.result.v1", canonical)}, nil
}
func (value ResultDigest) String() string { return formatDigest(resultDigestPrefix, value.digestValue) }
func (value ResultDigest) Equal(other ResultDigest) bool {
	return equalDigest(value.digestValue, other.digestValue)
}
func ParseResultDigest(value string) (ResultDigest, error) {
	parsed, err := parseDigest(resultDigestPrefix, value)
	return ResultDigest{parsed}, err
}
func (value ResultDigest) MarshalText() ([]byte, error) {
	return marshalDigest(value.String(), value.initialized)
}
func (value ResultDigest) GoString() string     { return value.String() }
func (value ResultDigest) LogValue() slog.Value { return redactedLogValue(value.String()) }

// WorkKey is a compact durable queue identity derived from an Operation and
// plan. Its wire form retains the plan digest needed to check lease binding.
type WorkKey struct {
	digestValue
	planDigest PlanDigest
}

func (value WorkKey) String() string {
	if !validWorkKey(value) {
		return workKeyPrefix + "invalid"
	}
	return workKeyPrefix +
		base64.RawURLEncoding.EncodeToString(value.planDigest.digest[:]) + "." +
		base64.RawURLEncoding.EncodeToString(value.digest[:])
}
func (value WorkKey) Equal(other WorkKey) bool {
	return validWorkKey(value) && validWorkKey(other) &&
		value.planDigest.Equal(other.planDigest) && equalDigest(value.digestValue, other.digestValue)
}
func ParseWorkKey(value string) (WorkKey, error) {
	if !strings.HasPrefix(value, workKeyPrefix) {
		return WorkKey{}, ErrInvalidDigest
	}
	parts := strings.Split(strings.TrimPrefix(value, workKeyPrefix), ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return WorkKey{}, ErrInvalidDigest
	}
	plan, err := parseDigest(planDigestPrefix, planDigestPrefix+parts[0])
	if err != nil {
		return WorkKey{}, ErrInvalidDigest
	}
	work, err := parseDigest(workKeyPrefix, workKeyPrefix+parts[1])
	if err != nil {
		return WorkKey{}, ErrInvalidDigest
	}
	return WorkKey{digestValue: work, planDigest: PlanDigest{plan}}, nil
}
func (value WorkKey) MarshalText() ([]byte, error) {
	return marshalDigest(value.String(), validWorkKey(value))
}
func (value WorkKey) PlanDigest() PlanDigest { return value.planDigest }
func (value WorkKey) GoString() string       { return value.String() }
func (value WorkKey) LogValue() slog.Value   { return redactedLogValue(value.String()) }

func validWorkKey(value WorkKey) bool {
	return value.initialized && value.planDigest.initialized
}

func deriveDigest(domain string, values ...[]byte) digestValue {
	hasher := sha256.New()
	writeHashFrame(hasher, domain)
	writeHashFrame(hasher, ContractVersion)
	for _, value := range values {
		writeHashBytes(hasher, value)
	}
	return digestFromHasher(hasher)
}

func digestFromHasher(hasher hash.Hash) digestValue {
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return digestValue{initialized: true, digest: result}
}

func equalDigest(left, right digestValue) bool {
	return left.initialized && right.initialized && left.digest == right.digest
}

func formatDigest(prefix string, value digestValue) string {
	if !value.initialized {
		return prefix + "invalid"
	}
	return prefix + base64.RawURLEncoding.EncodeToString(value.digest[:])
}

func parseDigest(prefix, value string) (digestValue, error) {
	if !strings.HasPrefix(value, prefix) {
		return digestValue{}, ErrInvalidDigest
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(decoded) != sha256.Size ||
		prefix+base64.RawURLEncoding.EncodeToString(decoded) != value {
		return digestValue{}, ErrInvalidDigest
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return digestValue{initialized: true, digest: result}, nil
}

func marshalDigest(value string, initialized bool) ([]byte, error) {
	if !initialized {
		return nil, ErrInvalidDigest
	}
	return []byte(value), nil
}
