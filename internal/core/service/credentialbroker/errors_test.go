package credentialbroker

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestClassifyRecognizesOnlyClosedFailureVocabulary(t *testing.T) {
	failures := []Failure{
		ErrInvalid,
		ErrConflict,
		ErrStale,
		ErrRevoked,
		ErrOperationTerminated,
		ErrExpired,
		ErrClosed,
		ErrUnavailable,
		ErrCapacity,
		ErrCredentialRotationRequired,
		ErrSerializationForbidden,
	}
	for _, failure := range failures {
		t.Run(failure.Error(), func(t *testing.T) {
			for _, err := range []error{failure, fmt.Errorf("safe wrapper: %w", failure)} {
				classified, ok := Classify(err)
				if !ok || classified != failure {
					t.Fatalf("Classify(%v) = %v, %t, want %v, true", err, classified, ok, failure)
				}
			}
		})
	}

	unknown := []error{
		nil,
		Failure(0),
		Failure(ErrSerializationForbidden + 1),
		errors.New("arbitrary adapter error"),
		context.Canceled,
		context.DeadlineExceeded,
	}
	for _, err := range unknown {
		if classified, ok := Classify(err); ok || classified != 0 {
			t.Errorf("Classify(%v) = %v, %t, want 0, false", err, classified, ok)
		}
	}
}
