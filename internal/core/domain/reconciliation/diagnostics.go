package reconciliation

import (
	"fmt"
	"log/slog"
)

func formatTypedDigest(state fmt.State, verb rune, value string) {
	writeSafeFormat(state, verb, value)
}

func (value EvidenceDigest) Format(state fmt.State, verb rune) {
	formatTypedDigest(state, verb, value.String())
}
func (value PlanDigest) Format(state fmt.State, verb rune) {
	formatTypedDigest(state, verb, value.String())
}
func (value RequestFingerprint) Format(state fmt.State, verb rune) {
	formatTypedDigest(state, verb, value.String())
}
func (value ResultDigest) Format(state fmt.State, verb rune) {
	formatTypedDigest(state, verb, value.String())
}
func (value WorkKey) Format(state fmt.State, verb rune) {
	formatTypedDigest(state, verb, value.String())
}

func (value LeaseBinding) String() string {
	if validateLeaseBinding(value) != nil {
		return "reconciliation-lease-binding(invalid)"
	}
	return "reconciliation-lease-binding(identity=redacted)"
}
func (value LeaseBinding) GoString() string { return value.String() }
func (value LeaseBinding) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value LeaseBinding) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (value DispatchAuthority) String() string {
	if validateDispatchAuthority(value) != nil {
		return "reconciliation-dispatch-authority(invalid)"
	}
	return "reconciliation-dispatch-authority(evidence=redacted)"
}
func (value DispatchAuthority) GoString() string { return value.String() }
func (value DispatchAuthority) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value DispatchAuthority) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (value DispatchPermit) String() string {
	if validateDispatchPermit(value) != nil {
		return "reconciliation-dispatch-permit(invalid)"
	}
	return fmt.Sprintf("reconciliation-dispatch-permit(fence=%d,identity=redacted)", value.token.fence)
}
func (value DispatchPermit) GoString() string { return value.String() }
func (value DispatchPermit) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value DispatchPermit) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (table *LeaseTable) String() string {
	if table == nil || !table.initialized {
		return "reconciliation-lease-table(invalid)"
	}
	return "reconciliation-lease-table(state=redacted)"
}
func (table *LeaseTable) GoString() string { return table.String() }
func (table *LeaseTable) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, table.String())
}
func (table *LeaseTable) LogValue() slog.Value { return redactedLogValue(table.String()) }

func (value EffectProjection) String() string {
	if validateEffectProjection(value) != nil {
		return "reconciliation-effect-projection(invalid)"
	}
	return "reconciliation-effect-projection(state=" + value.state.String() + ",identity=redacted)"
}
func (value EffectProjection) GoString() string { return value.String() }
func (value EffectProjection) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value EffectProjection) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (value RetryProof) String() string {
	if !validRetryProof(value) {
		return "reconciliation-retry-proof(invalid)"
	}
	return "reconciliation-retry-proof(evidence=redacted)"
}
func (value RetryProof) GoString() string { return value.String() }
func (value RetryProof) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value RetryProof) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (value SafeSupersessionProof) String() string {
	if !validSupersessionProof(value) {
		return "reconciliation-supersession-proof(invalid)"
	}
	return "reconciliation-supersession-proof(evidence=redacted)"
}
func (value SafeSupersessionProof) GoString() string { return value.String() }
func (value SafeSupersessionProof) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value SafeSupersessionProof) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (value CompensationProof) String() string {
	if !validCompensationProof(value) {
		return "reconciliation-compensation-proof(invalid)"
	}
	return fmt.Sprintf("reconciliation-compensation-proof(order=%d,evidence=redacted)", value.dependencyOrder)
}
func (value CompensationProof) GoString() string { return value.String() }
func (value CompensationProof) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value CompensationProof) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (value CompensationStep) String() string {
	if !validCompensationStep(value) {
		return "reconciliation-compensation-step(invalid)"
	}
	return fmt.Sprintf(
		"reconciliation-compensation-step(position=%d,total=%d,order=%d,evidence=redacted)",
		value.position,
		value.total,
		value.dependencyOrder,
	)
}
func (value CompensationStep) GoString() string { return value.String() }
func (value CompensationStep) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value CompensationStep) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (value TransitionBundle) String() string {
	if !value.initialized {
		return "reconciliation-transition-bundle(invalid)"
	}
	return fmt.Sprintf(
		"reconciliation-transition-bundle(audit=%d,outbox=%d)",
		value.providerAttemptAuditEvents,
		value.successorOutboxRecords,
	)
}
func (value TransitionBundle) GoString() string { return value.String() }
func (value TransitionBundle) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value TransitionBundle) LogValue() slog.Value { return redactedLogValue(value.String()) }

func (ledger *DeliveryLedger) String() string {
	if ledger == nil || !ledger.initialized {
		return "reconciliation-delivery-ledger(invalid)"
	}
	return "reconciliation-delivery-ledger(state=redacted)"
}
func (ledger *DeliveryLedger) GoString() string { return ledger.String() }
func (ledger *DeliveryLedger) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, ledger.String())
}
func (ledger *DeliveryLedger) LogValue() slog.Value { return redactedLogValue(ledger.String()) }
