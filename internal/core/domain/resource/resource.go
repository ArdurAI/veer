// Package resource defines Veer's transport-independent common resource envelope.
package resource

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// MaxCanonicalBytes matches the alpha resource representation ceiling.
	MaxCanonicalBytes   = 262_144
	maxJSONDepth        = 64
	maxJSONNodes        = 50_000
	maxLabels           = 64
	maxDisplayNameRunes = 128
	maxLabelValueRunes  = 256
	timestampLayout     = "2006-01-02T15:04:05.000Z"
)

var (
	apiVersionPattern      = regexp.MustCompile(`^v[1-9][0-9]*((alpha|beta)[1-9][0-9]*)?$`)
	idPattern              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$`)
	kindPattern            = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,63}$`)
	labelKeyPattern        = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,62}$`)
	resourceVersionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

	// ErrGenerationOverflow reports that a desired-state transition cannot be
	// represented without wrapping the signed 64-bit generation counter.
	ErrGenerationOverflow = errors.New("resource generation would overflow")
	// ErrRepresentationTooLarge reports that the canonical resource would
	// exceed the alpha representation ceiling.
	ErrRepresentationTooLarge = errors.New("canonical resource exceeds size limit")
)

// ID is a stable opaque resource identifier. It carries no tenant, provider,
// display-name, or ordering semantics.
type ID string

// String returns the opaque wire value.
func (id ID) String() string { return string(id) }

// ResourceVersion is an opaque complete-resource revision.
type ResourceVersion string

// String returns the opaque wire value.
func (version ResourceVersion) String() string { return string(version) }

// Generation identifies a desired-spec revision.
type Generation int64

// Int64 returns the signed 64-bit generation value.
func (generation Generation) Int64() int64 { return int64(generation) }

// Metadata contains stable identity, hierarchy, revision, and lifecycle state.
// Its fields are private so changes must use Resource transitions.
type Metadata struct {
	id              ID
	displayName     string
	parent          *ID
	labels          map[string]string
	generation      Generation
	resourceVersion ResourceVersion
	createdAt       time.Time
	updatedAt       time.Time
}

// ID returns the stable resource identity.
func (metadata Metadata) ID() ID { return metadata.id }

// DisplayName returns the mutable human-readable name.
func (metadata Metadata) DisplayName() string { return metadata.displayName }

// Parent returns the stable parent ID and whether one is present. Root
// resources have no parent.
func (metadata Metadata) Parent() (ID, bool) {
	if metadata.parent == nil {
		return "", false
	}
	return *metadata.parent, true
}

// Labels returns a defensive copy of the bounded caller labels.
func (metadata Metadata) Labels() map[string]string { return cloneLabels(metadata.labels) }

// Generation returns the desired-spec revision.
func (metadata Metadata) Generation() Generation { return metadata.generation }

// ResourceVersion returns the opaque complete-resource revision.
func (metadata Metadata) ResourceVersion() ResourceVersion { return metadata.resourceVersion }

// CreatedAt returns the normalized creation instant.
func (metadata Metadata) CreatedAt() time.Time { return metadata.createdAt }

// UpdatedAt returns the normalized last-write instant.
func (metadata Metadata) UpdatedAt() time.Time { return metadata.updatedAt }

// GenerationObservations must be implemented by every status value to expose
// its outer and condition-level observations for the common future-generation
// fence. A status with no observations returns an empty slice; concrete
// condition modeling remains owned by the resource schema.
type GenerationObservations interface {
	ObservedGenerations() []int64
}

// CreateInput supplies server-issued identity/version values and already
// admitted desired and observed state. Parent is nil only for a root resource.
type CreateInput[Spec any, Status GenerationObservations] struct {
	APIVersion      string
	Kind            string
	ID              string
	DisplayName     string
	Parent          *ID
	Labels          map[string]string
	ResourceVersion string
	CreatedAt       time.Time
	Spec            Spec
	Status          Status
}

// Resource is Veer's immutable common envelope. Spec and status are retained
// as canonical JSON so callers cannot mutate stored maps or slices through an
// alias returned by an accessor.
type Resource[Spec any, Status GenerationObservations] struct {
	apiVersion string
	kind       string
	metadata   Metadata
	spec       []byte
	status     []byte
}

// New creates a resource at generation one. ID and resource version issuance
// are deliberately injected; allocation and durable uniqueness belong to the
// persistence boundary.
func New[Spec any, Status GenerationObservations](input CreateInput[Spec, Status]) (Resource[Spec, Status], error) {
	var zero Resource[Spec, Status]
	if err := validateAPIVersion(input.APIVersion); err != nil {
		return zero, err
	}
	if err := validateKind(input.Kind); err != nil {
		return zero, err
	}
	id, err := validateID(input.ID, "metadata.id")
	if err != nil {
		return zero, err
	}
	if err := validateDisplayName(input.DisplayName); err != nil {
		return zero, err
	}
	parent, err := validateParent(input.Parent)
	if err != nil {
		return zero, err
	}
	labels, err := validateLabels(input.Labels)
	if err != nil {
		return zero, err
	}
	version, err := validateResourceVersion(input.ResourceVersion)
	if err != nil {
		return zero, err
	}
	createdAt, err := normalizeTimestamp(input.CreatedAt, "metadata.createdAt")
	if err != nil {
		return zero, err
	}
	spec, err := canonicalizeObject(input.Spec, "spec")
	if err != nil {
		return zero, err
	}
	status, err := canonicalizeObject(input.Status, "status")
	if err != nil {
		return zero, err
	}
	if err := validateObservations(input.Status, 1); err != nil {
		return zero, err
	}

	result := Resource[Spec, Status]{
		apiVersion: input.APIVersion,
		kind:       input.Kind,
		metadata: Metadata{
			id:              id,
			displayName:     input.DisplayName,
			parent:          parent,
			labels:          labels,
			generation:      1,
			resourceVersion: version,
			createdAt:       createdAt,
			updatedAt:       createdAt,
		},
		spec:   spec,
		status: status,
	}
	if err := result.validateSize(); err != nil {
		return zero, err
	}
	return result, nil
}

// APIVersion returns the resource representation version.
func (resource Resource[Spec, Status]) APIVersion() string { return resource.apiVersion }

// Kind returns the resource kind.
func (resource Resource[Spec, Status]) Kind() string { return resource.kind }

// Metadata returns immutable metadata; its Labels method returns a copy.
func (resource Resource[Spec, Status]) Metadata() Metadata { return resource.metadata }

// Spec decodes and returns an independent copy of the desired state.
func (resource Resource[Spec, Status]) Spec() (Spec, error) {
	return decodeValue[Spec](resource.spec, "spec")
}

// Status decodes and returns an independent copy of the observed state.
func (resource Resource[Spec, Status]) Status() (Status, error) {
	return decodeValue[Status](resource.status, "status")
}

// CanonicalSpec returns a copy of the normalized desired-state bytes used for
// semantic equality at this boundary.
func (resource Resource[Spec, Status]) CanonicalSpec() []byte {
	return bytes.Clone(resource.spec)
}

// Rename returns a copy with a new display name. An identical name is a no-op
// and consumes neither a resource version nor an update timestamp.
func (resource Resource[Spec, Status]) Rename(
	displayName, nextResourceVersion string,
	updatedAt time.Time,
) (Resource[Spec, Status], error) {
	if err := validateDisplayName(displayName); err != nil {
		return resource, err
	}
	if displayName == resource.metadata.displayName {
		return resource, nil
	}
	result, err := resource.advance(nextResourceVersion, updatedAt)
	if err != nil {
		return resource, err
	}
	result.metadata.displayName = displayName
	if err := result.validateSize(); err != nil {
		return resource, err
	}
	return result, nil
}

// ReplaceLabels returns a copy with normalized labels. Identical labels are a
// no-op; a label-only write never advances generation.
func (resource Resource[Spec, Status]) ReplaceLabels(
	labels map[string]string,
	nextResourceVersion string,
	updatedAt time.Time,
) (Resource[Spec, Status], error) {
	normalized, err := validateLabels(labels)
	if err != nil {
		return resource, err
	}
	if labelsEqual(normalized, resource.metadata.labels) {
		return resource, nil
	}
	result, err := resource.advance(nextResourceVersion, updatedAt)
	if err != nil {
		return resource, err
	}
	result.metadata.labels = normalized
	if err := result.validateSize(); err != nil {
		return resource, err
	}
	return result, nil
}

// ReplaceSpec returns a copy with already-defaulted desired state. Canonical
// equality is a no-op; a semantic change advances generation exactly once.
func (resource Resource[Spec, Status]) ReplaceSpec(
	spec Spec,
	nextResourceVersion string,
	updatedAt time.Time,
) (Resource[Spec, Status], error) {
	canonical, err := canonicalizeObject(spec, "spec")
	if err != nil {
		return resource, err
	}
	if bytes.Equal(canonical, resource.spec) {
		return resource, nil
	}
	if resource.metadata.generation == Generation(math.MaxInt64) {
		return resource, ErrGenerationOverflow
	}
	result, err := resource.advance(nextResourceVersion, updatedAt)
	if err != nil {
		return resource, err
	}
	result.spec = canonical
	result.metadata.generation++
	if err := result.validateSize(); err != nil {
		return resource, err
	}
	return result, nil
}

// ReplaceStatus returns a copy with new observed state. A status-only write
// advances the complete-resource version but never advances generation.
func (resource Resource[Spec, Status]) ReplaceStatus(
	status Status,
	nextResourceVersion string,
	updatedAt time.Time,
) (Resource[Spec, Status], error) {
	canonical, err := canonicalizeObject(status, "status")
	if err != nil {
		return resource, err
	}
	if err := validateObservations(status, resource.metadata.generation); err != nil {
		return resource, err
	}
	if bytes.Equal(canonical, resource.status) {
		return resource, nil
	}
	result, err := resource.advance(nextResourceVersion, updatedAt)
	if err != nil {
		return resource, err
	}
	result.status = canonical
	if err := result.validateSize(); err != nil {
		return resource, err
	}
	return result, nil
}

func (resource Resource[Spec, Status]) advance(
	nextResourceVersion string,
	updatedAt time.Time,
) (Resource[Spec, Status], error) {
	version, err := validateResourceVersion(nextResourceVersion)
	if err != nil {
		return resource, err
	}
	if version == resource.metadata.resourceVersion {
		return resource, errors.New("next resource version must differ from the current version")
	}
	normalizedTime, err := normalizeTimestamp(updatedAt, "metadata.updatedAt")
	if err != nil {
		return resource, err
	}
	if normalizedTime.Before(resource.metadata.updatedAt) {
		return resource, errors.New("metadata.updatedAt cannot move backwards")
	}
	result := resource
	result.metadata.labels = cloneLabels(resource.metadata.labels)
	result.metadata.parent = cloneID(resource.metadata.parent)
	result.metadata.resourceVersion = version
	result.metadata.updatedAt = normalizedTime
	result.spec = bytes.Clone(resource.spec)
	result.status = bytes.Clone(resource.status)
	return result, nil
}

func (resource Resource[Spec, Status]) validateSize() error {
	encoded, err := marshalCanonical(resource)
	if err != nil {
		return err
	}
	if len(encoded) > MaxCanonicalBytes {
		return fmt.Errorf("%w: %d > %d bytes", ErrRepresentationTooLarge, len(encoded), MaxCanonicalBytes)
	}
	return nil
}

func validateAPIVersion(value string) error {
	if !apiVersionPattern.MatchString(value) {
		return errors.New("apiVersion must be a version label such as v1alpha1")
	}
	return nil
}

func validateKind(value string) error {
	if !kindPattern.MatchString(value) {
		return errors.New("kind must start with an uppercase letter and contain at most 64 alphanumeric characters")
	}
	return nil
}

func validateID(value, field string) (ID, error) {
	if !idPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be a 16..128 character opaque ID", field)
	}
	return ID(value), nil
}

func validateDisplayName(value string) error {
	if !utf8.ValidString(value) {
		return errors.New("metadata.displayName must be valid UTF-8")
	}
	length := utf8.RuneCountInString(value)
	if length < 1 || length > maxDisplayNameRunes {
		return fmt.Errorf("metadata.displayName must contain 1..%d characters", maxDisplayNameRunes)
	}
	return nil
}

func validateParent(value *ID) (*ID, error) {
	if value == nil {
		return nil, nil
	}
	parent, err := validateID(value.String(), "metadata.parent")
	if err != nil {
		return nil, err
	}
	return &parent, nil
}

func validateLabels(labels map[string]string) (map[string]string, error) {
	if len(labels) > maxLabels {
		return nil, fmt.Errorf("metadata.labels must contain at most %d entries", maxLabels)
	}
	if len(labels) == 0 {
		return nil, nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		if !labelKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("metadata.labels key %q has an invalid format", key)
		}
		if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxLabelValueRunes {
			return nil, fmt.Errorf("metadata.labels[%q] must be valid UTF-8 with at most %d characters", key, maxLabelValueRunes)
		}
		result[key] = value
	}
	return result, nil
}

func validateResourceVersion(value string) (ResourceVersion, error) {
	if !resourceVersionPattern.MatchString(value) {
		return "", errors.New("metadata.resourceVersion must be a 1..128 character opaque version")
	}
	return ResourceVersion(value), nil
}

func normalizeTimestamp(value time.Time, field string) (time.Time, error) {
	if value.IsZero() {
		return time.Time{}, fmt.Errorf("%s is required", field)
	}
	value = value.UTC().Truncate(time.Millisecond)
	if value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, fmt.Errorf("%s year must be in 0001..9999", field)
	}
	return value, nil
}

func validateObservations[Status GenerationObservations](status Status, generation Generation) error {
	for index, observed := range status.ObservedGenerations() {
		if observed < 0 {
			return fmt.Errorf("status observed generation at index %d cannot be negative", index)
		}
		if observed > generation.Int64() {
			return fmt.Errorf("status observed generation at index %d exceeds resource generation", index)
		}
	}
	return nil
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

func cloneID(id *ID) *ID {
	if id == nil {
		return nil
	}
	copy := *id
	return &copy
}

func labelsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		rightValue, exists := right[key]
		if !exists || rightValue != value {
			return false
		}
	}
	return true
}

func parseTimestamp(value, field string) (time.Time, error) {
	if len(value) != len(timestampLayout) || !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("%s must use UTC RFC 3339 with exact milliseconds", field)
	}
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || parsed.Format(timestampLayout) != value {
		return time.Time{}, fmt.Errorf("%s must use UTC RFC 3339 with exact milliseconds", field)
	}
	return normalizeTimestamp(parsed, field)
}
