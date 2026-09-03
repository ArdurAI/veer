package credential

import (
	"fmt"
	"io"
	"log/slog"
)

func writeSafeFormat(state fmt.State, safe string) {
	_, _ = io.WriteString(state, safe)
}

func redactedLogValue(value string) slog.Value {
	return slog.StringValue(value)
}
