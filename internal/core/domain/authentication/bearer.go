// Package authentication owns credential value objects shared by core ports
// and domain services. It performs no authentication or external I/O.
package authentication

import (
	"errors"
	"fmt"
)

const (
	// MaxBearerTokenBytes bounds credential memory before an authentication
	// adapter performs cryptographic or claim validation.
	MaxBearerTokenBytes = 8_192
)

var (
	// ErrInvalidBearerCredential marks an empty, malformed, or over-limit
	// credential without retaining the submitted value.
	ErrInvalidBearerCredential = errors.New("invalid bearer credential")
	// ErrCredentialSerializationForbidden prevents raw bearer material from
	// entering JSON, resources, queues, logs, or generic text encoders.
	ErrCredentialSerializationForbidden = errors.New("credential serialization forbidden")
)

// BearerCredential is a bounded in-memory bearer token. Its raw value is
// private and every generic formatting or serialization path is redacted or
// rejected.
type BearerCredential struct {
	token string
}

// NewBearerCredential validates the RFC 6750 b64token character envelope and
// takes an immutable string value. Scheme parsing remains a transport concern.
func NewBearerCredential(token string) (BearerCredential, error) {
	if !validBearerToken(token) {
		return BearerCredential{}, ErrInvalidBearerCredential
	}
	return BearerCredential{token: token}, nil
}

// Token returns raw credential material for an authentication adapter only.
// It must not be logged, traced, persisted, included in errors, or retained
// after authentication completes.
func (credential BearerCredential) Token() string { return credential.token }

// Valid reports whether this credential could have been produced by the
// constructor. It is safe for the zero value.
func (credential BearerCredential) Valid() bool {
	return validBearerToken(credential.token)
}

// String always redacts raw bearer material, including for a zero value.
func (BearerCredential) String() string { return "bearer-credential(redacted)" }

// Error permits defensive error-path formatting without exposing raw bearer
// material. A credential is not itself an authentication classification.
func (credential BearerCredential) Error() string { return credential.String() }

// GoString prevents %#v formatting from reflecting private token state.
func (credential BearerCredential) GoString() string { return credential.String() }

// Format keeps every fmt verb on the redacted representation. String and
// GoString alone do not intercept numeric verbs applied to a struct.
func (credential BearerCredential) Format(state fmt.State, verb rune) {
	value := credential.String()
	switch verb {
	case 'q':
		value = fmt.Sprintf("%q", value)
	case 'x':
		value = fmt.Sprintf("%x", value)
	case 'X':
		value = fmt.Sprintf("%X", value)
	}
	_, _ = state.Write([]byte(value))
}

// MarshalJSON rejects implicit persistence of raw credential material.
func (BearerCredential) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialSerializationForbidden
}

// MarshalText rejects generic text-based persistence of raw credentials.
func (BearerCredential) MarshalText() ([]byte, error) {
	return nil, ErrCredentialSerializationForbidden
}

func validBearerToken(token string) bool {
	if token == "" || len(token) > MaxBearerTokenBytes {
		return false
	}
	padding := false
	for index := range len(token) {
		current := token[index]
		if current == '=' {
			if index == 0 {
				return false
			}
			padding = true
			continue
		}
		if padding || !validBearerByte(current) {
			return false
		}
	}
	return true
}

func validBearerByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '-' || value == '.' || value == '_' || value == '~' ||
		value == '+' || value == '/'
}

var (
	_ error          = BearerCredential{}
	_ fmt.Formatter  = BearerCredential{}
	_ fmt.Stringer   = BearerCredential{}
	_ fmt.GoStringer = BearerCredential{}
)
