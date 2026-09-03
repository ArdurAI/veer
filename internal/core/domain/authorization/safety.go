package authorization

import (
	"fmt"
	"io"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func writeSafeFormat(state fmt.State, verb rune, safe string) {
	switch verb {
	case 's', 'v', 'q', 'x', 'X':
		_, _ = io.WriteString(state, safe)
	default:
		_, _ = io.WriteString(state, safe)
	}
}

func cloneIDPointer(id *resource.ID) *resource.ID {
	if id == nil {
		return nil
	}
	result := *id
	return &result
}

func equalIDPointers(left, right *resource.ID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
