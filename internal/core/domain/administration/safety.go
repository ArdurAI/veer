package administration

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const timestampResolution = time.Millisecond

func writeSafeFormat(state fmt.State, verb rune, safe string) {
	switch verb {
	case 'q':
		safe = fmt.Sprintf("%q", safe)
	case 'x':
		safe = fmt.Sprintf("%x", safe)
	case 'X':
		safe = fmt.Sprintf("%X", safe)
	}
	_, _ = io.WriteString(state, safe)
}

func redactedLogValue(value string) slog.Value { return slog.StringValue(value) }

func normalizeContractTime(value time.Time) (time.Time, error) {
	if value.IsZero() {
		return time.Time{}, ErrInvalidClock
	}
	normalized := value.UTC().Truncate(timestampResolution)
	if normalized.Year() < 1 || normalized.Year() > 9999 {
		return time.Time{}, ErrInvalidClock
	}
	return normalized, nil
}

func canonicalContractTime(value time.Time) bool {
	normalized, err := normalizeContractTime(value)
	return err == nil && value.Location() == time.UTC && value.Nanosecond()%int(timestampResolution) == 0 &&
		value.Equal(normalized)
}

func validBoundedText(value string, minimum, maximum int) bool {
	if len(value) > maximum*utf8.UTFMax || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return false
	}
	for _, current := range value {
		if unicode.IsControl(current) {
			return false
		}
	}
	return true
}
