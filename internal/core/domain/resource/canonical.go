package resource

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

var preserveInterfaceNumbers = jsonv2.UnmarshalFromFunc(func(decoder *jsontext.Decoder, value *any) error {
	if decoder.PeekKind() != jsontext.KindNumber {
		return errors.ErrUnsupported
	}
	raw, err := decoder.ReadValue()
	if err != nil {
		return err
	}
	*value = json.Number(string(raw))
	return nil
})

var rejectCustomJSONUnmarshalers = jsonv2.JoinUnmarshalers(
	jsonv2.UnmarshalFromFunc(func(decoder *jsontext.Decoder, value jsonv2.UnmarshalerFrom) error {
		return rejectStructuredJSONUnmarshaler(decoder, value)
	}),
	jsonv2.UnmarshalFromFunc(func(decoder *jsontext.Decoder, value jsonv2.Unmarshaler) error {
		return rejectStructuredJSONUnmarshaler(decoder, value)
	}),
	preserveInterfaceNumbers,
)

func rejectStructuredJSONUnmarshaler(decoder *jsontext.Decoder, value any) error {
	switch decoder.PeekKind() {
	case jsontext.KindBeginObject, jsontext.KindBeginArray:
		return fmt.Errorf("custom JSON unmarshaler %T cannot consume structured values at canonical typed boundaries", value)
	default:
		return errors.ErrUnsupported
	}
}

type wireResource struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   wireMetadata    `json:"metadata"`
	Spec       json.RawMessage `json:"spec"`
	Status     json.RawMessage `json:"status"`
}

type wireMetadata struct {
	ID              string            `json:"id"`
	DisplayName     string            `json:"displayName"`
	Parent          *string           `json:"parent,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Generation      int64             `json:"generation"`
	ResourceVersion string            `json:"resourceVersion"`
	CreatedAt       string            `json:"createdAt"`
	UpdatedAt       string            `json:"updatedAt"`
}

// MarshalCanonical serializes a resource with stable envelope/metadata field
// order, sorted nested object keys, compact whitespace, and exact timestamps.
func MarshalCanonical[Spec any, Status GenerationObservations](resource Resource[Spec, Status]) ([]byte, error) {
	encoded, err := marshalCanonical(resource)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxCanonicalBytes {
		return nil, fmt.Errorf("%w: %d > %d bytes", ErrRepresentationTooLarge, len(encoded), MaxCanonicalBytes)
	}
	return encoded, nil
}

func marshalCanonical[Spec any, Status GenerationObservations](resource Resource[Spec, Status]) ([]byte, error) {
	if err := validateAPIVersion(resource.apiVersion); err != nil {
		return nil, err
	}
	if err := validateKind(resource.kind); err != nil {
		return nil, err
	}
	if _, err := validateID(resource.metadata.id.String(), "metadata.id"); err != nil {
		return nil, err
	}
	if err := validateDisplayName(resource.metadata.displayName); err != nil {
		return nil, err
	}
	if _, err := validateParent(resource.metadata.parent); err != nil {
		return nil, err
	}
	if _, err := validateLabels(resource.metadata.labels); err != nil {
		return nil, err
	}
	if resource.metadata.generation < 1 {
		return nil, errors.New("metadata.generation must be at least one")
	}
	if _, err := validateResourceVersion(resource.metadata.resourceVersion.String()); err != nil {
		return nil, err
	}
	if resource.metadata.createdAt.IsZero() || resource.metadata.updatedAt.Before(resource.metadata.createdAt) {
		return nil, errors.New("resource timestamps are invalid")
	}
	if len(resource.spec) == 0 || len(resource.status) == 0 {
		return nil, errors.New("resource spec and status are required")
	}

	var parent *string
	if resource.metadata.parent != nil {
		value := resource.metadata.parent.String()
		parent = &value
	}
	wire := wireResource{
		APIVersion: resource.apiVersion,
		Kind:       resource.kind,
		Metadata: wireMetadata{
			ID:              resource.metadata.id.String(),
			DisplayName:     resource.metadata.displayName,
			Parent:          parent,
			Labels:          cloneLabels(resource.metadata.labels),
			Generation:      resource.metadata.generation.Int64(),
			ResourceVersion: resource.metadata.resourceVersion.String(),
			CreatedAt:       resource.metadata.createdAt.Format(timestampLayout),
			UpdatedAt:       resource.metadata.updatedAt.Format(timestampLayout),
		},
		Spec:   bytes.Clone(resource.spec),
		Status: bytes.Clone(resource.status),
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical resource: %w", err)
	}
	if err := validateJSON(encoded); err != nil {
		return nil, fmt.Errorf("canonical resource: %w", err)
	}
	return encoded, nil
}

// UnmarshalCanonical decodes a bounded resource and normalizes it into the
// canonical profile. Unknown envelope fields and duplicate JSON keys fail.
func UnmarshalCanonical[Spec any, Status GenerationObservations](data []byte) (Resource[Spec, Status], error) {
	var zero Resource[Spec, Status]
	if len(data) == 0 {
		return zero, errors.New("canonical resource is empty")
	}
	if len(data) > MaxCanonicalBytes {
		return zero, fmt.Errorf("%w: %d > %d bytes", ErrRepresentationTooLarge, len(data), MaxCanonicalBytes)
	}
	if err := validateJSON(data); err != nil {
		return zero, err
	}
	wire, err := decodeWireResource(data)
	if err != nil {
		return zero, err
	}
	if len(wire.Spec) == 0 || len(wire.Status) == 0 {
		return zero, errors.New("resource spec and status are required")
	}

	id, err := validateID(wire.Metadata.ID, "metadata.id")
	if err != nil {
		return zero, err
	}
	if err := validateAPIVersion(wire.APIVersion); err != nil {
		return zero, err
	}
	if err := validateKind(wire.Kind); err != nil {
		return zero, err
	}
	if err := validateDisplayName(wire.Metadata.DisplayName); err != nil {
		return zero, err
	}
	var parentInput *ID
	if wire.Metadata.Parent != nil {
		value := ID(*wire.Metadata.Parent)
		parentInput = &value
	}
	parent, err := validateParent(parentInput)
	if err != nil {
		return zero, err
	}
	labels, err := validateLabels(wire.Metadata.Labels)
	if err != nil {
		return zero, err
	}
	if wire.Metadata.Generation < 1 {
		return zero, errors.New("metadata.generation must be at least one")
	}
	version, err := validateResourceVersion(wire.Metadata.ResourceVersion)
	if err != nil {
		return zero, err
	}
	createdAt, err := parseTimestamp(wire.Metadata.CreatedAt, "metadata.createdAt")
	if err != nil {
		return zero, err
	}
	updatedAt, err := parseTimestamp(wire.Metadata.UpdatedAt, "metadata.updatedAt")
	if err != nil {
		return zero, err
	}
	if updatedAt.Before(createdAt) {
		return zero, errors.New("metadata.updatedAt cannot precede metadata.createdAt")
	}

	spec, specValue, err := decodeObject[Spec](wire.Spec, "spec")
	if err != nil {
		return zero, err
	}
	status, statusValue, err := decodeObject[Status](wire.Status, "status")
	if err != nil {
		return zero, err
	}
	if err := validateObservations(statusValue, Generation(wire.Metadata.Generation)); err != nil {
		return zero, err
	}

	resource := Resource[Spec, Status]{
		apiVersion: wire.APIVersion,
		kind:       wire.Kind,
		metadata: Metadata{
			id:              id,
			displayName:     wire.Metadata.DisplayName,
			parent:          parent,
			labels:          labels,
			generation:      Generation(wire.Metadata.Generation),
			resourceVersion: version,
			createdAt:       createdAt,
			updatedAt:       updatedAt,
		},
		spec:   spec,
		status: status,
	}
	if _, err := MarshalCanonical(resource); err != nil {
		return zero, err
	}
	_ = specValue // Decoding proves the caller's concrete type accepts the value.
	return resource, nil
}

func canonicalizeObject[Value any](value Value, field string) ([]byte, Value, error) {
	var zero Value
	if err := validateTypedJSONContractFor[Value](field); err != nil {
		return nil, zero, err
	}
	encoded, err := encodeTypedJSON(value)
	if err != nil {
		return nil, zero, fmt.Errorf("encode %s with strict JSON: %w", field, err)
	}
	return decodeObject[Value](encoded, field)
}

func decodeObject[Value any](data []byte, field string) ([]byte, Value, error) {
	var zero Value
	if err := validateTypedJSONContractFor[Value](field); err != nil {
		return nil, zero, err
	}
	canonical, err := canonicalizeRawObject(data, field)
	if err != nil {
		return nil, zero, err
	}
	for range 2 {
		value, err := decodeExactJSON[Value](canonical, field)
		if err != nil {
			return nil, zero, err
		}
		encoded, err := encodeTypedJSON(value)
		if err != nil {
			return nil, zero, fmt.Errorf("encode decoded %s with strict JSON: %w", field, err)
		}
		normalized, err := canonicalizeRawObject(encoded, field)
		if err != nil {
			return nil, zero, err
		}
		if bytes.Equal(canonical, normalized) {
			return canonical, value, nil
		}
		canonical = normalized
	}
	return nil, zero, fmt.Errorf("%s typed JSON normalization did not converge", field)
}

func encodeTypedJSON(value any) ([]byte, error) {
	return jsonv2.Marshal(
		value,
		json.DefaultOptionsV1(),
		jsontext.AllowInvalidUTF8(false),
	)
}

func canonicalizeRawObject(data []byte, field string) ([]byte, error) {
	if len(data) > MaxCanonicalBytes {
		return nil, fmt.Errorf("%s: %w", field, ErrRepresentationTooLarge)
	}
	if err := validateJSON(data); err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}

	var normalized any
	normalizer := json.NewDecoder(bytes.NewReader(data))
	normalizer.UseNumber()
	if err := normalizer.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("decode %s: %w", field, err)
	}
	if err := requireEOF(normalizer); err != nil {
		return nil, fmt.Errorf("decode %s: %w", field, err)
	}
	if _, ok := normalized.(map[string]any); !ok {
		return nil, fmt.Errorf("%s must be a JSON object", field)
	}
	normalized, err := normalizeCanonicalValue(normalized)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("canonicalize %s: %w", field, err)
	}
	return canonical, nil
}

func decodeValue[Value any](data []byte, field string) (Value, error) {
	_, value, err := decodeObject[Value](data, field)
	return value, err
}

func normalizeCanonicalValue(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized, err := normalizeCanonicalValue(child)
			if err != nil {
				return nil, err
			}
			typed[key] = normalized
		}
		return typed, nil
	case []any:
		for index, child := range typed {
			normalized, err := normalizeCanonicalValue(child)
			if err != nil {
				return nil, err
			}
			typed[index] = normalized
		}
		return typed, nil
	case json.Number:
		integer, err := strconv.ParseInt(typed.String(), 10, 64)
		if err != nil {
			return nil, errors.New("numbers must be canonical signed 64-bit integers")
		}
		return json.Number(strconv.FormatInt(integer, 10)), nil
	case string, bool, nil:
		return typed, nil
	default:
		return nil, fmt.Errorf("unsupported JSON value type %T", value)
	}
}

func validateJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid JSON: input must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	nodes := 0
	if err := scanJSONValue(decoder, 0, &nodes); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return requireTokenEOF(decoder)
}

func decodeExactJSON[Value any](data []byte, field string) (Value, error) {
	var value Value
	if err := jsonv2.Unmarshal(
		data,
		&value,
		jsonv2.RejectUnknownMembers(true),
		jsonv2.WithUnmarshalers(rejectCustomJSONUnmarshalers),
	); err != nil {
		return value, fmt.Errorf("decode %s with exact JSON names or unknown fields: %w", field, err)
	}
	return value, nil
}

func decodeWireResource(data []byte) (wireResource, error) {
	var wire wireResource
	if err := jsonv2.Unmarshal(
		data,
		&wire,
		jsonv2.RejectUnknownMembers(true),
	); err != nil {
		return wire, fmt.Errorf("decode resource envelope with exact JSON names or unknown fields: %w", err)
	}
	return wire, nil
}

func scanJSONValue(decoder *json.Decoder, depth int, nodes *int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("maximum depth %d exceeded", maxJSONDepth)
	}
	*nodes++
	if *nodes > maxJSONNodes {
		return fmt.Errorf("maximum node count %d exceeded", maxJSONNodes)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delimiter)
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("more than one JSON value")
	}
	return fmt.Errorf("decode trailing JSON: %w", err)
}

func requireTokenEOF(decoder *json.Decoder) error {
	_, err := decoder.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("more than one JSON value")
	}
	return fmt.Errorf("decode trailing JSON: %w", err)
}
