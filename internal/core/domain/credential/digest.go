package credential

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"log/slog"
)

const (
	sourceDigestDomain  = "veer.credentials.source.v1alpha1"
	bindingDigestDomain = "veer.credentials.binding.v1alpha1"
)

// SourceDigest is a comparable, opaque digest of one exact scoped source
// lookup. It contains no credential material and is deliberately not exposed
// as text so it cannot become an accidental cross-system correlation key.
type SourceDigest struct {
	initialized bool
	digest      [sha256.Size]byte
}

// Valid reports whether the digest could have been produced by this package.
func (digest SourceDigest) Valid() bool { return digest.initialized }

// Equal compares two initialized source digests.
func (digest SourceDigest) Equal(other SourceDigest) bool {
	return digest.initialized && other.initialized && digest.digest == other.digest
}

func (digest SourceDigest) String() string {
	if !digest.initialized {
		return "credential-source-digest(invalid)"
	}
	return "credential-source-digest(redacted)"
}

func (digest SourceDigest) GoString() string { return digest.String() }

func (digest SourceDigest) Format(state fmt.State, _ rune) {
	writeSafeFormat(state, digest.String())
}

func (digest SourceDigest) LogValue() slog.Value { return redactedLogValue(digest.String()) }

func (SourceDigest) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (SourceDigest) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (SourceDigest) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (SourceDigest) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

// BindingDigest is a comparable, opaque digest of a complete provider-session
// request, including its source, operation, target, purpose, and recipient.
type BindingDigest struct {
	initialized bool
	digest      [sha256.Size]byte
}

// Valid reports whether the digest could have been produced by this package.
func (digest BindingDigest) Valid() bool { return digest.initialized }

// Equal compares two initialized request-binding digests.
func (digest BindingDigest) Equal(other BindingDigest) bool {
	return digest.initialized && other.initialized && digest.digest == other.digest
}

func (digest BindingDigest) String() string {
	if !digest.initialized {
		return "credential-binding-digest(invalid)"
	}
	return "credential-binding-digest(redacted)"
}

func (digest BindingDigest) GoString() string { return digest.String() }

func (digest BindingDigest) Format(state fmt.State, _ rune) {
	writeSafeFormat(state, digest.String())
}

func (digest BindingDigest) LogValue() slog.Value { return redactedLogValue(digest.String()) }

func (BindingDigest) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (BindingDigest) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (BindingDigest) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (BindingDigest) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

func deriveSourceDigest(source SourceLookup) SourceDigest {
	hasher := sha256.New()
	writeFrame(hasher, []byte(sourceDigestDomain))
	writeFrame(hasher, []byte(ContractVersion))
	writeFrame(hasher, []byte(source.workspaceID.String()))
	writeFrame(hasher, []byte(source.environmentID.String()))
	writeFrame(hasher, []byte(source.providerConnectionID.String()))
	writeInt64(hasher, source.connectionGeneration.Int64())
	writeFrame(hasher, []byte(source.provider))
	writeFrame(hasher, []byte(source.referenceID.String()))
	writeFrame(hasher, []byte(source.version))
	return digestSource(hasher)
}

func deriveBindingDigest(request Request) BindingDigest {
	hasher := sha256.New()
	writeFrame(hasher, []byte(bindingDigestDomain))
	writeFrame(hasher, []byte(ContractVersion))
	writeFrame(hasher, request.source.digest.digest[:])
	writeFrame(hasher, []byte(request.operationID.String()))
	writeFrame(hasher, []byte(request.targetResourceID.String()))
	writeFrame(hasher, []byte(request.targetKind.String()))
	writeInt64(hasher, request.targetGeneration.Int64())
	writeFrame(hasher, []byte(request.action.String()))
	writeFrame(hasher, []byte(request.recipient.provider))
	writeFrame(hasher, []byte(request.recipient.name))

	var sum [sha256.Size]byte
	copy(sum[:], hasher.Sum(nil))
	return BindingDigest{initialized: true, digest: sum}
}

func digestSource(hasher hash.Hash) SourceDigest {
	var sum [sha256.Size]byte
	copy(sum[:], hasher.Sum(nil))
	return SourceDigest{initialized: true, digest: sum}
}

func writeFrame(hasher hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(value)
}

func writeInt64(hasher hash.Hash, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	writeFrame(hasher, encoded[:])
}
