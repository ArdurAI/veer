package reconciliation

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
)

// Evidence retains only a closed kind, opaque version, and domain-separated
// digest. Canonical input bytes are validated and hashed but never retained.
type Evidence struct {
	initialized bool
	kind        EvidenceKind
	version     string
	digest      EvidenceDigest
}

// NewEvidence reduces one bounded canonical input to safe immutable plan evidence.
func NewEvidence(kind EvidenceKind, version string, canonical []byte) (Evidence, error) {
	if _, err := ParseEvidenceKind(kind.String()); err != nil {
		return Evidence{}, ErrInvalidEvidence
	}
	if !validVersion(version) {
		return Evidence{}, fmt.Errorf("%w: %w", ErrInvalidEvidence, ErrInvalidVersion)
	}
	if len(canonical) == 0 {
		return Evidence{}, ErrInvalidEvidence
	}
	if len(canonical) > MaxEvidenceBytes {
		return Evidence{}, fmt.Errorf("%w: %w", ErrInvalidEvidence, ErrEvidenceTooLarge)
	}
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.evidence.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashFrame(hasher, kind.String())
	writeHashFrame(hasher, version)
	writeHashBytes(hasher, canonical)
	return Evidence{
		initialized: true,
		kind:        kind,
		version:     version,
		digest:      EvidenceDigest{digestFromHasher(hasher)},
	}, nil
}

// ValidateEvidence checks a complete evidence value without exposing input bytes.
func ValidateEvidence(value Evidence) error {
	if !value.initialized || !validVersion(value.version) || !value.digest.initialized {
		return ErrInvalidEvidence
	}
	if _, err := ParseEvidenceKind(value.kind.String()); err != nil {
		return ErrInvalidEvidence
	}
	return nil
}

// Kind returns the closed evidence dimension.
func (value Evidence) Kind() EvidenceKind { return value.kind }

// Version returns the exact opaque evidence version.
func (value Evidence) Version() string { return value.version }

// Digest returns the kind-and-version-bound digest.
func (value Evidence) Digest() EvidenceDigest { return value.digest }

// Equal compares the complete safe evidence projection.
func (value Evidence) Equal(other Evidence) bool {
	return ValidateEvidence(value) == nil && ValidateEvidence(other) == nil &&
		value.kind == other.kind && value.version == other.version && value.digest.Equal(other.digest)
}

func (value Evidence) String() string {
	if ValidateEvidence(value) != nil {
		return "reconciliation-evidence(invalid)"
	}
	return "reconciliation-evidence(kind=" + value.kind.String() + ",version=redacted,digest=redacted)"
}
func (value Evidence) GoString() string { return value.String() }
func (value Evidence) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value Evidence) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (Evidence) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Evidence) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Evidence) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Evidence) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
