package admission

import (
	"encoding/json/jsontext"
	"strings"
	"unicode/utf8"
)

// Stage is one fixed admission stage. Values are ordered by the Admit
// functions, never by lexical comparison.
type Stage string

const (
	StageSchema     Stage = "schema"
	StageSemantic   Stage = "semantic"
	StageImmutable  Stage = "immutable"
	StageReference  Stage = "reference"
	StageDefault    Stage = "default"
	StageConversion Stage = "conversion"
)

// Code is a stable machine-readable rejection reason. It deliberately
// carries no submitted value or implementation error text.
type Code string

const (
	CodeRequestTooLarge    Code = "request-too-large"
	CodeInvalidJSON        Code = "invalid-json"
	CodeJSONTooDeep        Code = "json-too-deep"
	CodeTooManyJSONNodes   Code = "too-many-json-nodes"
	CodeDuplicateField     Code = "duplicate-field"
	CodeUnknownField       Code = "unknown-field"
	CodeMissingField       Code = "missing-field"
	CodeInvalidType        Code = "invalid-type"
	CodeInvalidValue       Code = "invalid-value"
	CodeUnsupportedVersion Code = "unsupported-version"
	CodeUnsupportedKind    Code = "unsupported-kind"

	CodeInvalidSpec       Code = "invalid-spec"
	CodeInvalidStatus     Code = "invalid-status"
	CodeInvalidOrder      Code = "invalid-order"
	CodeDuplicateItem     Code = "duplicate-item"
	CodeFutureObservation Code = "future-observation"

	CodeImmutableField Code = "immutable-field"

	CodeInvalidPlacement   Code = "invalid-placement"
	CodeParentNotFound     Code = "parent-not-found"
	CodeParentKindMismatch Code = "parent-kind-mismatch"
	CodeWorkspaceMismatch  Code = "workspace-mismatch"

	CodeDefaultFailed    Code = "default-failed"
	CodeConversionFailed Code = "conversion-failed"
)

const (
	// MaxFieldPathRunes is the external RFC 6901 pointer limit adopted by the
	// API contract. An exact pointer that does not fit is omitted, not cut.
	MaxFieldPathRunes = 96
	// MaxEncodedFieldPathBytes includes the two JSON string quotes.
	MaxEncodedFieldPathBytes = 98

	// unrepresentablePointer is internal-only and cannot be confused with the
	// empty root pointer. It is not a valid RFC 6901 pointer.
	unrepresentablePointer = "\x00"
)

// Error is an immutable, bounded admission failure. Error deliberately omits
// Path and every underlying error so logs cannot echo credentials, provider
// bodies, labels, display names, or other untrusted request data.
type Error struct {
	stage Stage
	code  Code
	path  string
}

// Error returns a stable safe token suitable for logs and metrics.
func (failure *Error) Error() string {
	if failure == nil {
		return "admission-error"
	}
	return "admission-" + string(failure.stage) + "-" + string(failure.code)
}

// Stage returns the stage that rejected the request.
func (failure *Error) Stage() Stage {
	if failure == nil {
		return ""
	}
	return failure.stage
}

// Code returns the stable machine-readable reason.
func (failure *Error) Code() Code {
	if failure == nil {
		return ""
	}
	return failure.code
}

// Path returns an exact bounded RFC 6901 pointer or the empty string when the
// root failed or the exact pointer cannot safely fit the API field bound.
func (failure *Error) Path() string {
	if failure == nil {
		return ""
	}
	return failure.path
}

func reject(stage Stage, code Code, path string) *Error {
	return &Error{stage: stage, code: code, path: boundedPointer(path)}
}

func boundedPointer(path string) string {
	if path == "" {
		return ""
	}
	if path == unrepresentablePointer || !jsontext.Pointer(path).IsValid() {
		return ""
	}
	_, encodedBytes, valid := boundedStringMetrics(path)
	if !valid || encodedBytes+2 > MaxEncodedFieldPathBytes {
		return ""
	}
	return path
}

func appendPointer(path, token string) string {
	if path == unrepresentablePointer || !utf8.ValidString(token) {
		return unrepresentablePointer
	}
	pathRunes, pathEncodedBytes, valid := boundedStringMetrics(path)
	if !valid || (path != "" && !jsontext.Pointer(path).IsValid()) {
		return unrepresentablePointer
	}
	runes := pathRunes + 1
	encodedBytes := pathEncodedBytes + 1
	if runes > MaxFieldPathRunes || encodedBytes+2 > MaxEncodedFieldPathBytes {
		return unrepresentablePointer
	}
	for _, value := range token {
		if value == '~' || value == '/' {
			runes += 2
			encodedBytes += 2
		} else {
			runes++
			encodedBytes += jsonEncodedRuneBytes(value)
		}
		if runes > MaxFieldPathRunes || encodedBytes+2 > MaxEncodedFieldPathBytes {
			return unrepresentablePointer
		}
	}

	var result strings.Builder
	result.Grow(len(path) + 1 + len(token))
	result.WriteString(path)
	result.WriteByte('/')
	for _, value := range token {
		switch value {
		case '~':
			result.WriteString("~0")
		case '/':
			result.WriteString("~1")
		default:
			result.WriteRune(value)
		}
	}
	return result.String()
}

func boundedStringMetrics(value string) (runes int, encodedBytes int, valid bool) {
	if !utf8.ValidString(value) {
		return 0, 0, false
	}
	for _, current := range value {
		runes++
		encodedBytes += jsonEncodedRuneBytes(current)
		if runes > MaxFieldPathRunes || encodedBytes+2 > MaxEncodedFieldPathBytes {
			return 0, 0, false
		}
	}
	return runes, encodedBytes, true
}

func jsonEncodedRuneBytes(value rune) int {
	switch value {
	case '\b', '\f', '\n', '\r', '\t', '"', '\\':
		return 2
	case '<', '>', '&':
		return 6
	case '\u2028', '\u2029':
		return 6
	default:
		if value < 0x20 {
			return 6
		}
		return utf8.RuneLen(value)
	}
}
