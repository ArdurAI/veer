package reconciliation

import (
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

func validVersion(value string) bool {
	return len(value) <= MaxEvidenceVersionBytes && utf8.ValidString(value) && versionPattern.MatchString(value)
}

func validID(value resource.ID) bool {
	_, err := resource.ParseID(value.String())
	return err == nil
}

func normalizeTime(value time.Time) (time.Time, error) {
	if value.IsZero() {
		return time.Time{}, ErrInvalidTime
	}
	value = value.UTC().Truncate(time.Millisecond)
	if value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, ErrInvalidTime
	}
	return value, nil
}

func addNormalizedDuration(value time.Time, duration time.Duration) (time.Time, error) {
	if duration < 0 {
		return time.Time{}, ErrInvalidTime
	}
	return normalizeTime(value.Add(duration))
}

func writeHashFrame(hasher hash.Hash, value string) {
	writeHashBytes(hasher, []byte(value))
}

func writeHashBytes(hasher hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(value)
}

func writeHashInt64(hasher hash.Hash, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	writeHashBytes(hasher, encoded[:])
}

func writeHashUint64(hasher hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeHashBytes(hasher, encoded[:])
}

func writeOptionalID(hasher hash.Hash, value *resource.ID) {
	if value == nil {
		writeHashFrame(hasher, "0")
		return
	}
	writeHashFrame(hasher, "1")
	writeHashFrame(hasher, value.String())
}

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
