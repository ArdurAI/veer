package reconciliation

import (
	"fmt"
	"log/slog"
	"sync"
)

// QueueReservation is one pre-admission allocation of every baseline and
// visibility-change request unit a work item may consume.
type QueueReservation struct {
	initialized bool
	work        WorkKey
	total       int64
	consumed    int64
	completed   bool
}

func (value QueueReservation) Total() int64    { return value.total }
func (value QueueReservation) Consumed() int64 { return value.consumed }
func (value QueueReservation) Completed() bool { return value.completed }

func (value QueueReservation) String() string {
	if validateQueueReservation(value) != nil {
		return "reconciliation-queue-reservation(invalid)"
	}
	return fmt.Sprintf(
		"reconciliation-queue-reservation(total=%d,consumed=%d,completed=%t,identity=redacted)",
		value.total,
		value.consumed,
		value.completed,
	)
}
func (value QueueReservation) GoString() string { return value.String() }
func (value QueueReservation) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value QueueReservation) LogValue() slog.Value { return redactedLogValue(value.String()) }

// QueueBudget is a bounded process-local request-unit oracle. Production
// durability and transactional work admission remain StateStore concerns.
type QueueBudget struct {
	mu          sync.Mutex
	initialized bool
	requestCap  int64
	maximumWork int
	used        int64
	reserved    int64
	records     map[string]QueueReservation
}

// NewQueueBudget creates one hard monthly request partition.
func NewQueueBudget(requestCap int64, maximumWork int) (*QueueBudget, error) {
	if requestCap < 1 || maximumWork < 1 {
		return nil, ErrInvalidDelivery
	}
	return &QueueBudget{
		initialized: true,
		requestCap:  requestCap,
		maximumWork: maximumWork,
		records:     make(map[string]QueueReservation, maximumWork),
	}, nil
}

// Reserve atomically pre-allocates all billable request units before work admission.
func (budget *QueueBudget) Reserve(work WorkKey, requestUnits int64) (QueueReservation, error) {
	if budget == nil || !budget.initialized || !validWorkKey(work) || requestUnits < 1 {
		return QueueReservation{}, ErrInvalidDelivery
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	key := work.String()
	if current, exists := budget.records[key]; exists {
		if current.completed {
			return QueueReservation{}, ErrReservationLost
		}
		if current.total == requestUnits {
			return current, nil
		}
		return QueueReservation{}, ErrInvalidDelivery
	}
	if len(budget.records) >= budget.maximumWork || requestUnits > budget.requestCap-budget.used-budget.reserved {
		return QueueReservation{}, ErrCapacity
	}
	reservation := QueueReservation{initialized: true, work: work, total: requestUnits}
	budget.records[key] = reservation
	budget.reserved += requestUnits
	return reservation, nil
}

// Consume charges units before an SQS action. Retries, redeliveries, visibility
// changes, and partial-batch retries are each separate billable units.
func (budget *QueueBudget) Consume(reservation QueueReservation, requestUnits int64) (QueueReservation, error) {
	if budget == nil || !budget.initialized || validateQueueReservation(reservation) != nil || requestUnits < 1 {
		return QueueReservation{}, ErrInvalidDelivery
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	key := reservation.work.String()
	current, exists := budget.records[key]
	if !exists || current.completed || current.total != reservation.total ||
		requestUnits > current.total-current.consumed {
		return QueueReservation{}, ErrReservationLost
	}
	current.consumed += requestUnits
	budget.reserved -= requestUnits
	budget.used += requestUnits
	budget.records[key] = current
	return current, nil
}

// Complete atomically releases only never-consumed units. A concurrent
// heartbeat either consumes first or loses to completion; it can never escape accounting.
func (budget *QueueBudget) Complete(reservation QueueReservation) (QueueReservation, error) {
	if budget == nil || !budget.initialized || validateQueueReservation(reservation) != nil {
		return QueueReservation{}, ErrInvalidDelivery
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	key := reservation.work.String()
	current, exists := budget.records[key]
	if !exists || current.total != reservation.total {
		return QueueReservation{}, ErrInvalidDelivery
	}
	if current.completed {
		return current, nil
	}
	budget.reserved -= current.total - current.consumed
	current.completed = true
	budget.records[key] = current
	return current, nil
}

// Usage returns consumed, still-reserved, and unallocated request units.
func (budget *QueueBudget) Usage() (used, reserved, available int64) {
	if budget == nil || !budget.initialized {
		return 0, 0, 0
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.used, budget.reserved, budget.requestCap - budget.used - budget.reserved
}

func (budget *QueueBudget) String() string {
	if budget == nil || !budget.initialized {
		return "reconciliation-queue-budget(invalid)"
	}
	return "reconciliation-queue-budget(state=redacted)"
}
func (budget *QueueBudget) GoString() string { return budget.String() }
func (budget *QueueBudget) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, budget.String())
}
func (budget *QueueBudget) LogValue() slog.Value { return redactedLogValue(budget.String()) }

func validateQueueReservation(value QueueReservation) error {
	if !value.initialized || !validWorkKey(value.work) || value.total < 1 ||
		value.consumed < 0 || value.consumed > value.total {
		return ErrInvalidDelivery
	}
	return nil
}

func (QueueReservation) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (QueueReservation) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (QueueReservation) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (QueueReservation) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (*QueueBudget) MarshalJSON() ([]byte, error)       { return nil, ErrSerializationForbidden }
func (*QueueBudget) MarshalText() ([]byte, error)       { return nil, ErrSerializationForbidden }
func (*QueueBudget) MarshalBinary() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (*QueueBudget) GobEncode() ([]byte, error)         { return nil, ErrSerializationForbidden }
