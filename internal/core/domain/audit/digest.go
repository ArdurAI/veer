package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// ChainDigest is one initialized SHA-256 chain value.
type ChainDigest struct {
	initialized bool
	digest      [sha256.Size]byte
}

func (digest ChainDigest) String() string {
	if !digest.initialized {
		return ChainDigestPrefix + "invalid"
	}
	return ChainDigestPrefix + base64.RawURLEncoding.EncodeToString(digest.digest[:])
}

func (digest ChainDigest) Equal(other ChainDigest) bool {
	return digest.initialized && other.initialized && digest.digest == other.digest
}

func (digest ChainDigest) MarshalText() ([]byte, error) {
	if !digest.initialized {
		return nil, ErrInvalidDigest
	}
	return []byte(digest.String()), nil
}

func ParseChainDigest(value string) (ChainDigest, error) {
	raw, err := parseDigest(value, ChainDigestPrefix)
	if err != nil {
		return ChainDigest{}, err
	}
	return ChainDigest{initialized: true, digest: raw}, nil
}

// ExportBodyDigest is a domain-separated SHA-256 digest of one canonical
// segment body. It is intentionally not interchangeable with ChainDigest.
type ExportBodyDigest struct {
	initialized bool
	digest      [sha256.Size]byte
}

func (digest ExportBodyDigest) String() string {
	if !digest.initialized {
		return ExportBodyDigestPrefix + "invalid"
	}
	return ExportBodyDigestPrefix + base64.RawURLEncoding.EncodeToString(digest.digest[:])
}

func (digest ExportBodyDigest) Equal(other ExportBodyDigest) bool {
	return digest.initialized && other.initialized && digest.digest == other.digest
}

func (digest ExportBodyDigest) MarshalText() ([]byte, error) {
	if !digest.initialized {
		return nil, ErrInvalidDigest
	}
	return []byte(digest.String()), nil
}

func ParseExportBodyDigest(value string) (ExportBodyDigest, error) {
	raw, err := parseDigest(value, ExportBodyDigestPrefix)
	if err != nil {
		return ExportBodyDigest{}, err
	}
	return ExportBodyDigest{initialized: true, digest: raw}, nil
}

func parseDigest(value, prefix string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if !strings.HasPrefix(value, prefix) {
		return result, ErrInvalidDigest
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(decoded) != sha256.Size ||
		prefix+base64.RawURLEncoding.EncodeToString(decoded) != value {
		return result, ErrInvalidDigest
	}
	copy(result[:], decoded)
	return result, nil
}
