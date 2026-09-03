package model

import (
	"errors"
	"fmt"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

var (
	// ErrInvalidWriteMetadata marks caller-owned metadata that cannot enter the
	// immutable hub.
	ErrInvalidWriteMetadata = errors.New("invalid admitted write metadata")
	// ErrInvalidDisplayName marks a display name outside the common envelope
	// contract.
	ErrInvalidDisplayName = errors.New("invalid admitted display name")
	// ErrInvalidLabels marks labels outside the common envelope contract.
	ErrInvalidLabels = errors.New("invalid admitted labels")
)

// WriteMetadata is the immutable hub form of caller-owned metadata. Server-
// owned identity, placement, revision, and lifecycle fields cannot be carried
// by this type.
type WriteMetadata struct {
	displayName string
	labels      map[string]string
}

// NewWriteMetadata validates the common envelope rules and takes an
// independent copy of labels. Empty and nil labels have the same canonical hub
// form.
func NewWriteMetadata(displayName string, labels map[string]string) (WriteMetadata, error) {
	if err := resource.ValidateDisplayName(displayName); err != nil {
		return WriteMetadata{}, fmt.Errorf("%w: %w", ErrInvalidWriteMetadata, ErrInvalidDisplayName)
	}
	normalized, err := resource.NormalizeLabels(labels)
	if err != nil {
		return WriteMetadata{}, fmt.Errorf("%w: %w", ErrInvalidWriteMetadata, ErrInvalidLabels)
	}
	return WriteMetadata{displayName: displayName, labels: normalized}, nil
}

// DisplayName returns the admitted human-readable name.
func (metadata WriteMetadata) DisplayName() string { return metadata.displayName }

// Labels returns an independent copy of admitted labels.
func (metadata WriteMetadata) Labels() map[string]string { return cloneLabels(metadata.labels) }

// ValidateWriteMetadata defensively checks a value, including a zero value
// constructed outside the package.
func ValidateWriteMetadata(metadata WriteMetadata) error {
	if err := resource.ValidateDisplayName(metadata.displayName); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidWriteMetadata, ErrInvalidDisplayName)
	}
	if _, err := resource.NormalizeLabels(metadata.labels); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidWriteMetadata, ErrInvalidLabels)
	}
	return nil
}

// CloneWriteMetadata returns a value with independent mutable storage.
func CloneWriteMetadata(metadata WriteMetadata) WriteMetadata {
	metadata.labels = cloneLabels(metadata.labels)
	return metadata
}

// EqualWriteMetadata compares normalized values rather than map identity.
func EqualWriteMetadata(left, right WriteMetadata) bool {
	if left.displayName != right.displayName || len(left.labels) != len(right.labels) {
		return false
	}
	for key, value := range left.labels {
		rightValue, exists := right.labels[key]
		if !exists || rightValue != value {
			return false
		}
	}
	return true
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
