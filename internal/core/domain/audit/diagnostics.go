package audit

import (
	"fmt"
	"log/slog"
	"time"
)

func (stream Stream) LogValue() slog.Value  { return slog.StringValue(stream.String()) }
func (actor ActorRef) LogValue() slog.Value { return slog.StringValue(actor.String()) }
func (event Event) LogValue() slog.Value    { return slog.StringValue(event.String()) }
func (checkpoint Checkpoint) LogValue() slog.Value {
	return slog.StringValue(checkpoint.String())
}

func (reference RequestRef) String() string {
	if validateRequestRef(reference) != nil {
		return "audit-request-reference(invalid)"
	}
	return "audit-request-reference(id=redacted)"
}
func (reference RequestRef) GoString() string { return reference.String() }
func (reference RequestRef) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, reference.String())
}
func (reference RequestRef) LogValue() slog.Value { return slog.StringValue(reference.String()) }

func (reference TargetRef) String() string {
	if validateTargetRef(reference) != nil {
		return "audit-target-reference(invalid)"
	}
	return "audit-target-reference(objectKind=" + reference.objectKind.String() +
		",resourceKind=" + reference.resourceKind + ",scope=redacted)"
}
func (reference TargetRef) GoString() string { return reference.String() }
func (reference TargetRef) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, reference.String())
}
func (reference TargetRef) LogValue() slog.Value { return slog.StringValue(reference.String()) }

func (reference DecisionRef) String() string {
	if validateDecisionRef(reference) != nil {
		return "audit-decision-reference(invalid)"
	}
	return "audit-decision-reference(effect=" + reference.effect.String() +
		",reason=" + reference.reason.String() + ",policy=redacted,input=redacted)"
}
func (reference DecisionRef) GoString() string { return reference.String() }
func (reference DecisionRef) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, reference.String())
}
func (reference DecisionRef) LogValue() slog.Value { return slog.StringValue(reference.String()) }

func (reference OperationRef) String() string {
	if validateOperationRef(reference) != nil {
		return "audit-operation-reference(invalid)"
	}
	return "audit-operation-reference(phase=" + string(reference.phase) +
		",scope=redacted,reason=redacted)"
}
func (reference OperationRef) GoString() string { return reference.String() }
func (reference OperationRef) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, reference.String())
}
func (reference OperationRef) LogValue() slog.Value { return slog.StringValue(reference.String()) }

func (reference AttemptRef) String() string {
	if validateAttemptRef(reference) != nil {
		return "audit-attempt-reference(invalid)"
	}
	return fmt.Sprintf("audit-attempt-reference(ordinal=%d,id=redacted)", reference.ordinal)
}
func (reference AttemptRef) GoString() string { return reference.String() }
func (reference AttemptRef) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, reference.String())
}
func (reference AttemptRef) LogValue() slog.Value { return slog.StringValue(reference.String()) }

func (record Record) String() string {
	if validateRecord(record) != nil {
		return "audit-record(invalid)"
	}
	return fmt.Sprintf("audit-record(sequence=%d,digests=redacted)", record.event.sequence)
}
func (record Record) GoString() string { return record.String() }
func (record Record) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, record.String())
}
func (record Record) LogValue() slog.Value { return slog.StringValue(record.String()) }

func (value SequenceRange) String() string {
	if value.first == 0 || value.last < value.first {
		return "audit-sequence-range(invalid)"
	}
	return fmt.Sprintf("audit-sequence-range(first=%d,last=%d)", value.first, value.last)
}
func (value SequenceRange) GoString() string { return value.String() }
func (value SequenceRange) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value SequenceRange) LogValue() slog.Value { return slog.StringValue(value.String()) }

func (segment Segment) String() string {
	if validateSegmentStructure(segment) != nil {
		return "audit-segment(invalid)"
	}
	if len(segment.records) == 0 {
		return "audit-segment(records=0)"
	}
	return fmt.Sprintf(
		"audit-segment(records=%d,first=%d,last=%d)",
		len(segment.records),
		segment.records[0].event.sequence,
		segment.records[len(segment.records)-1].event.sequence,
	)
}
func (segment Segment) GoString() string { return segment.String() }
func (segment Segment) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, segment.String())
}
func (segment Segment) LogValue() slog.Value { return slog.StringValue(segment.String()) }

func (descriptor ExportDescriptor) String() string {
	if ValidateExportDescriptor(descriptor) != nil {
		return "audit-export-descriptor(invalid)"
	}
	return fmt.Sprintf(
		"audit-export-descriptor(stream=%s,first=%d,last=%d,events=%d,key=redacted,digests=redacted)",
		descriptor.stream.kind,
		descriptor.sequenceRange.first,
		descriptor.sequenceRange.last,
		descriptor.eventCount,
	)
}
func (descriptor ExportDescriptor) GoString() string { return descriptor.String() }
func (descriptor ExportDescriptor) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, descriptor.String())
}
func (descriptor ExportDescriptor) LogValue() slog.Value {
	return slog.StringValue(descriptor.String())
}

func (manifest ExportManifest) String() string {
	if ValidateExportManifest(manifest) != nil {
		return "audit-export-manifest(invalid)"
	}
	return "audit-export-manifest(" + manifest.descriptor.String() + ",signature=redacted)"
}
func (manifest ExportManifest) GoString() string { return manifest.String() }
func (manifest ExportManifest) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, manifest.String())
}
func (manifest ExportManifest) LogValue() slog.Value { return slog.StringValue(manifest.String()) }

func (hold Hold) String() string {
	if ValidateHold(hold) != nil {
		return "audit-hold(invalid)"
	}
	return "audit-hold(kind=" + hold.kind.String() + ",id=redacted)"
}
func (hold Hold) GoString() string { return hold.String() }
func (hold Hold) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, hold.String())
}
func (hold Hold) LogValue() slog.Value { return slog.StringValue(hold.String()) }

func (decision RetentionDecision) String() string {
	if !validRetentionDecision(decision) {
		return "audit-retention-decision(invalid)"
	}
	return "audit-retention-decision(disposition=" + decision.disposition.String() + ")"
}
func (decision RetentionDecision) GoString() string { return decision.String() }
func (decision RetentionDecision) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, decision.String())
}
func (decision RetentionDecision) LogValue() slog.Value {
	return slog.StringValue(decision.String())
}

func validRetentionDecision(decision RetentionDecision) bool {
	if !decision.initialized || decision.onlineUntil.IsZero() || decision.archiveUntil.IsZero() {
		return false
	}
	if _, err := ParseRetentionDisposition(decision.disposition.String()); err != nil {
		return false
	}
	return decision.archiveUntil.After(decision.onlineUntil) &&
		decision.archiveUntil.Sub(decision.onlineUntil) == ArchiveRetention-OnlineRetention &&
		decision.onlineUntil.Location() == time.UTC && decision.archiveUntil.Location() == time.UTC &&
		decision.onlineUntil.Nanosecond()%int(time.Millisecond) == 0 &&
		decision.archiveUntil.Nanosecond()%int(time.Millisecond) == 0
}

func (digest ChainDigest) GoString() string { return digest.String() }
func (digest ChainDigest) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, digest.String())
}
func (digest ChainDigest) LogValue() slog.Value { return slog.StringValue(digest.String()) }

func (digest ExportBodyDigest) GoString() string { return digest.String() }
func (digest ExportBodyDigest) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, digest.String())
}
func (digest ExportBodyDigest) LogValue() slog.Value { return slog.StringValue(digest.String()) }
