// Package credentialbroker provides a provider-neutral, process-local broker
// for bounded credential sessions. Its caches, epochs, tombstones, and
// single-flight groups deliberately make no cross-process guarantee.
package credentialbroker

import (
	"errors"
	"fmt"
)

// Failure is the broker's closed, diagnostic-safe failure vocabulary.
// Backend errors are collapsed into ErrUnavailable and never wrapped.
type Failure uint8

const (
	ErrInvalid Failure = iota + 1
	ErrConflict
	ErrStale
	ErrRevoked
	ErrOperationTerminated
	ErrExpired
	ErrClosed
	ErrUnavailable
	ErrCapacity
	ErrCredentialRotationRequired
	ErrSerializationForbidden
)

func (failure Failure) Error() string {
	switch failure {
	case ErrInvalid:
		return "credential-broker-invalid"
	case ErrConflict:
		return "credential-broker-conflict"
	case ErrStale:
		return "credential-broker-stale"
	case ErrRevoked:
		return "credential-broker-revoked"
	case ErrOperationTerminated:
		return "credential-broker-operation-terminated"
	case ErrExpired:
		return "credential-broker-expired"
	case ErrClosed:
		return "credential-broker-closed"
	case ErrUnavailable:
		return "credential-broker-unavailable"
	case ErrCapacity:
		return "credential-broker-capacity"
	case ErrCredentialRotationRequired:
		return "credential-broker-rotation-required"
	case ErrSerializationForbidden:
		return "credential-broker-serialization-forbidden"
	default:
		return "credential-broker-error"
	}
}

func (failure Failure) String() string { return failure.Error() }

func (failure Failure) GoString() string {
	return "credentialbroker.Failure(" + failure.Error() + ")"
}

// Classify recognizes a closed broker failure, including a safely wrapped
// instance. Broker methods themselves return these values without provider
// text so errors cannot become a secret or backend-response side channel.
func Classify(err error) (Failure, bool) {
	for candidate := ErrInvalid; candidate <= ErrSerializationForbidden; candidate++ {
		if errors.Is(err, candidate) {
			return candidate, true
		}
	}
	return 0, false
}

var (
	_ error          = ErrInvalid
	_ fmt.Stringer   = ErrInvalid
	_ fmt.GoStringer = ErrInvalid
)
