// Package ports defines core-owned boundaries implemented by external
// adapters.
package ports

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
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

// AuthenticationError is one stable, token-free authentication outcome. Its
// numeric representation cannot itself retain untrusted diagnostic text.
type AuthenticationError uint8

const (
	// ErrAuthenticationInvalid means a credential was presented but did not
	// authenticate. It is intentionally indistinguishable across parse,
	// signature, key, issuer, audience, kind, and claim-validation failures.
	ErrAuthenticationInvalid AuthenticationError = iota + 1
	// ErrAuthenticationUnavailable means configured trust data could not be
	// obtained or used. Callers may retry within their overall deadline.
	ErrAuthenticationUnavailable
)

// Error returns only a closed stable classification.
func (failure AuthenticationError) Error() string {
	switch failure {
	case ErrAuthenticationInvalid:
		return "authentication-invalid"
	case ErrAuthenticationUnavailable:
		return "authentication-unavailable"
	default:
		return "authentication-error"
	}
}

// String returns only a closed stable classification.
func (failure AuthenticationError) String() string { return failure.Error() }

// GoString prevents an invalid underlying value from entering diagnostics.
func (failure AuthenticationError) GoString() string {
	return "ports.AuthenticationError(" + failure.Error() + ")"
}

// ClassifyAuthenticationError recognizes the two port-level failure classes,
// including safely wrapped instances.
func ClassifyAuthenticationError(err error) (AuthenticationError, bool) {
	switch {
	case errors.Is(err, ErrAuthenticationInvalid):
		return ErrAuthenticationInvalid, true
	case errors.Is(err, ErrAuthenticationUnavailable):
		return ErrAuthenticationUnavailable, true
	default:
		return 0, false
	}
}

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

// Token returns raw credential material for the authentication adapter only.
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

// Authenticator validates one explicitly present bearer credential and returns
// a complete Principal. Missing credentials are represented by the transport
// layer and must not call this port; there is no anonymous Principal.
//
// Implementations return ErrAuthenticationInvalid for rejected credentials,
// ErrAuthenticationUnavailable for non-context trust-data failures, and the
// caller's context error when cancellation or deadline expiry wins. Returned
// errors must never wrap token, claim, endpoint, or provider response values.
type Authenticator interface {
	Authenticate(
		ctx context.Context,
		credential BearerCredential,
	) (identity.Principal, error)
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

// Compile-time guards keep safe diagnostic behavior part of the port contract.
var (
	_ error          = ErrAuthenticationInvalid
	_ error          = BearerCredential{}
	_ fmt.Formatter  = BearerCredential{}
	_ fmt.Stringer   = BearerCredential{}
	_ fmt.GoStringer = BearerCredential{}
)
