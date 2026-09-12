package ports

import (
	"context"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// ReferenceStore is the narrow, provider-free persistence boundary used by
// the deterministic reference service. It is intentionally not the durable
// production StateStore described by ADR 0002: issue #30 owns transactions,
// audit, integrity, outbox, leases, and recovery in that adapter.
type ReferenceStore interface {
	// View runs one consistent read-only callback.
	View(context.Context, func(ReferenceReader) error) error
	// Update runs one all-or-nothing callback. Returning an error, cancellation,
	// or deadline expiry commits none of the callback's resource or operation
	// changes.
	Update(context.Context, func(ReferenceTransaction) error) error
}

// ReferenceReader exposes ownership-safe canonical resource and operation
// snapshots. Implementations must return independent byte slices.
type ReferenceReader interface {
	GetResource(resource.ID) ([]byte, bool)
	ListResources() [][]byte
	GetOperation(resource.ID) ([]byte, bool)
}

// ReferenceTransaction extends a consistent reader with bounded mutation.
// Inputs must be copied before the callback returns.
type ReferenceTransaction interface {
	ReferenceReader
	PutResource(resource.ID, []byte)
	DeleteResource(resource.ID)
	PutOperation(resource.ID, []byte)
}
