package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"hash"
	"math"
)

const (
	chainGenesisDomain = "veer.audit.chain.genesis.v1"
	chainRecordDomain  = "veer.audit.chain.record.v1"
	segmentPrefix      = `{"contractVersion":"` + ContractVersion + `","records":[`
	recordFramingBytes = 256
)

// Checkpoint is a chain head supplied by or returned to a durable trust
// boundary. A sequence-zero checkpoint has the stream-specific genesis digest.
// It deliberately has no generic JSON representation: callers must bind it to
// their own independently protected trust boundary.
type Checkpoint struct {
	initialized bool
	stream      Stream
	sequence    uint64
	digest      ChainDigest
}

func GenesisCheckpoint(stream Stream) (Checkpoint, error) {
	if err := ValidateStream(stream); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: %w", ErrInvalidCheckpoint, ErrInvalidStream)
	}
	return Checkpoint{
		initialized: true,
		stream:      stream,
		digest:      deriveGenesisDigest(stream),
	}, nil
}

// NewCheckpoint validates a checkpoint loaded from a caller-controlled trust
// boundary. This package cannot determine whether a non-genesis head is trusted.
func NewCheckpoint(stream Stream, sequence uint64, digest ChainDigest) (Checkpoint, error) {
	checkpoint := Checkpoint{
		initialized: true,
		stream:      stream,
		sequence:    sequence,
		digest:      digest,
	}
	if err := ValidateCheckpoint(checkpoint); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

func ValidateCheckpoint(checkpoint Checkpoint) error {
	if !checkpoint.initialized || ValidateStream(checkpoint.stream) != nil || !checkpoint.digest.initialized {
		return ErrInvalidCheckpoint
	}
	genesis := checkpoint.digest.Equal(deriveGenesisDigest(checkpoint.stream))
	if (checkpoint.sequence == 0) != genesis {
		return ErrInvalidCheckpoint
	}
	return nil
}

func (checkpoint Checkpoint) Stream() Stream      { return checkpoint.stream }
func (checkpoint Checkpoint) Sequence() uint64    { return checkpoint.sequence }
func (checkpoint Checkpoint) Digest() ChainDigest { return checkpoint.digest }
func (checkpoint Checkpoint) Equal(other Checkpoint) bool {
	return ValidateCheckpoint(checkpoint) == nil && ValidateCheckpoint(other) == nil &&
		checkpoint.stream.Equal(other.stream) && checkpoint.sequence == other.sequence &&
		checkpoint.digest.Equal(other.digest)
}
func (checkpoint Checkpoint) String() string {
	if ValidateCheckpoint(checkpoint) != nil {
		return "audit-checkpoint(invalid)"
	}
	return fmt.Sprintf("audit-checkpoint(stream=%s,sequence=%d)", checkpoint.stream.kind, checkpoint.sequence)
}
func (checkpoint Checkpoint) GoString() string { return checkpoint.String() }
func (checkpoint Checkpoint) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, checkpoint.String())
}

// Record binds one canonical event to its predecessor and derived chain digest.
type Record struct {
	event          Event
	previousDigest ChainDigest
	digest         ChainDigest
}

// Record deliberately has no generic JSON representation. It is serialized
// only as part of a bounded canonical Segment.

func (record Record) Event() Event                { return cloneEvent(record.event) }
func (record Record) PreviousDigest() ChainDigest { return record.previousDigest }
func (record Record) Digest() ChainDigest         { return record.digest }

// Append creates one record and next checkpoint without performing I/O.
func Append(previous Checkpoint, event Event) (Record, Checkpoint, error) {
	if err := ValidateCheckpoint(previous); err != nil {
		return Record{}, previous, err
	}
	if err := ValidateEvent(event); err != nil {
		return Record{}, previous, err
	}
	if previous.sequence == math.MaxUint64 || event.sequence != previous.sequence+1 {
		return Record{}, previous, ErrInvalidSequence
	}
	if !event.stream.Equal(previous.stream) {
		return Record{}, previous, fmt.Errorf("%w: %w", ErrInvalidRecord, ErrInvalidStream)
	}
	canonical, err := MarshalCanonicalEvent(event)
	if err != nil {
		return Record{}, previous, err
	}
	digest := deriveRecordDigest(previous.digest, event, canonical)
	record := Record{
		event:          cloneEvent(event),
		previousDigest: previous.digest,
		digest:         digest,
	}
	next := Checkpoint{
		initialized: true,
		stream:      previous.stream,
		sequence:    event.sequence,
		digest:      digest,
	}
	return record, next, nil
}

// SequenceRange is one inclusive contiguous range.
type SequenceRange struct {
	first uint64
	last  uint64
}

func (value SequenceRange) First() uint64 { return value.first }
func (value SequenceRange) Last() uint64  { return value.last }

// Segment is an immutable bounded collection of records. A zero-record segment
// is valid for checkpoint comparison but cannot be exported.
type Segment struct {
	records []Record
}

// NewSegment preflights count and aggregate encoded bounds before allocating
// records or performing chain hash work.
func NewSegment(previous Checkpoint, events []Event) (Segment, Checkpoint, error) {
	if err := ValidateCheckpoint(previous); err != nil {
		return Segment{}, previous, err
	}
	if len(events) > MaxSegmentEvents {
		return Segment{}, previous, ErrSegmentTooLarge
	}
	if err := preflightEvents(previous, events); err != nil {
		return Segment{}, previous, err
	}

	records := make([]Record, len(events))
	head := previous
	for index, event := range events {
		record, next, err := Append(head, event)
		if err != nil {
			return Segment{}, previous, err
		}
		records[index] = record
		head = next
	}
	return Segment{records: records}, head, nil
}

func (segment Segment) Len() int { return len(segment.records) }
func (segment Segment) Records() []Record {
	result := make([]Record, len(segment.records))
	for index, record := range segment.records {
		result[index] = cloneRecord(record)
	}
	return result
}
func (segment Segment) Range() (SequenceRange, bool) {
	if len(segment.records) == 0 {
		return SequenceRange{}, false
	}
	return SequenceRange{
		first: segment.records[0].event.sequence,
		last:  segment.records[len(segment.records)-1].event.sequence,
	}, true
}

func (segment Segment) MarshalJSON() ([]byte, error) {
	return MarshalCanonicalSegment(segment)
}

func (segment *Segment) UnmarshalJSON(data []byte) error {
	if segment == nil {
		return ErrInvalidSegment
	}
	parsed, err := UnmarshalCanonicalSegment(data)
	if err != nil {
		return err
	}
	*segment = parsed
	return nil
}

// VerifySegment verifies every retained record against a predecessor. Without
// expected, a valid prefix cannot prove that its tail is complete. Supplying a
// trusted expected checkpoint makes tail deletion observable.
func VerifySegment(
	previous Checkpoint,
	segment Segment,
	expected *Checkpoint,
) (Checkpoint, error) {
	if err := ValidateCheckpoint(previous); err != nil {
		return previous, err
	}
	if len(segment.records) > MaxSegmentEvents {
		return previous, ErrSegmentTooLarge
	}
	if err := validateSegmentStructure(segment); err != nil {
		return previous, err
	}
	head := previous
	for _, record := range segment.records {
		if head.sequence == math.MaxUint64 || record.event.sequence != head.sequence+1 {
			return previous, fmt.Errorf("%w: %w", ErrIntegrity, ErrInvalidSequence)
		}
		if !record.event.stream.Equal(head.stream) || !record.previousDigest.Equal(head.digest) {
			return previous, fmt.Errorf("%w: predecessor mismatch", ErrIntegrity)
		}
		canonical, err := MarshalCanonicalEvent(record.event)
		if err != nil {
			return previous, fmt.Errorf("%w: invalid event", ErrIntegrity)
		}
		want := deriveRecordDigest(head.digest, record.event, canonical)
		if !record.digest.Equal(want) {
			return previous, fmt.Errorf("%w: record digest mismatch", ErrIntegrity)
		}
		head = Checkpoint{
			initialized: true,
			stream:      head.stream,
			sequence:    record.event.sequence,
			digest:      record.digest,
		}
	}
	if expected != nil {
		if ValidateCheckpoint(*expected) != nil || !head.Equal(*expected) {
			return previous, ErrExpectedHead
		}
	}
	return head, nil
}

// MarshalCanonicalSegment emits a strict compact export body.
func MarshalCanonicalSegment(segment Segment) ([]byte, error) {
	if len(segment.records) > MaxSegmentEvents {
		return nil, ErrSegmentTooLarge
	}
	if err := validateSegmentStructure(segment); err != nil {
		return nil, err
	}
	wire := segmentWire{ContractVersion: ContractVersion, Records: make([]recordWire, len(segment.records))}
	for index, record := range segment.records {
		wire.Records[index] = recordWire{
			Event:          eventToWire(record.event),
			PreviousDigest: record.previousDigest.String(),
			Digest:         record.digest.String(),
		}
	}
	data, err := jsonv2.Marshal(wire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
	if err != nil {
		return nil, fmt.Errorf("%w: encode", ErrInvalidSegment)
	}
	if len(data) > MaxCanonicalSegmentBytes {
		return nil, ErrSegmentTooLarge
	}
	return data, nil
}

// UnmarshalCanonicalSegment performs byte and top-level element-count
// preflights before allocating the decoded record slice or hashing content.
func UnmarshalCanonicalSegment(data []byte) (Segment, error) {
	if len(data) == 0 {
		return Segment{}, ErrNonCanonical
	}
	if len(data) > MaxCanonicalSegmentBytes {
		return Segment{}, ErrSegmentTooLarge
	}
	count, err := preflightSegmentCount(data)
	if err != nil {
		return Segment{}, err
	}
	if count > MaxSegmentEvents {
		return Segment{}, ErrSegmentTooLarge
	}
	var wire segmentWire
	if err := jsonv2.Unmarshal(data, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return Segment{}, ErrNonCanonical
	}
	if wire.ContractVersion != ContractVersion || len(wire.Records) != count {
		return Segment{}, ErrNonCanonical
	}
	records := make([]Record, count)
	for index, encoded := range wire.Records {
		event, parseErr := eventFromWire(encoded.Event)
		if parseErr != nil {
			return Segment{}, parseErr
		}
		previousDigest, parseErr := ParseChainDigest(encoded.PreviousDigest)
		if parseErr != nil {
			return Segment{}, parseErr
		}
		digest, parseErr := ParseChainDigest(encoded.Digest)
		if parseErr != nil {
			return Segment{}, parseErr
		}
		records[index] = Record{event: event, previousDigest: previousDigest, digest: digest}
	}
	segment := Segment{records: records}
	if err := validateSegmentStructure(segment); err != nil {
		return Segment{}, err
	}
	canonical, err := MarshalCanonicalSegment(segment)
	if err != nil {
		return Segment{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Segment{}, ErrNonCanonical
	}
	return segment, nil
}

type recordWire struct {
	Event          eventWire `json:"event"`
	PreviousDigest string    `json:"previousDigest"`
	Digest         string    `json:"digest"`
}

type segmentWire struct {
	ContractVersion string       `json:"contractVersion"`
	Records         []recordWire `json:"records"`
}

func preflightEvents(previous Checkpoint, events []Event) error {
	estimated := len(segmentPrefix) + 2
	sequence := previous.sequence
	for _, event := range events {
		if err := ValidateEvent(event); err != nil {
			return err
		}
		if sequence == math.MaxUint64 || event.sequence != sequence+1 || !event.stream.Equal(previous.stream) {
			return ErrInvalidSequence
		}
		sequence = event.sequence
		canonical, err := MarshalCanonicalEvent(event)
		if err != nil {
			return err
		}
		addition, ok := checkedAdd(len(canonical), recordFramingBytes)
		if !ok {
			return ErrSegmentTooLarge
		}
		estimated, ok = checkedAdd(estimated, addition)
		if !ok || estimated > MaxCanonicalSegmentBytes {
			return ErrSegmentTooLarge
		}
	}
	return nil
}

func validateSegmentStructure(segment Segment) error {
	if len(segment.records) > MaxSegmentEvents {
		return ErrSegmentTooLarge
	}
	for index, record := range segment.records {
		if err := validateRecord(record); err != nil {
			return err
		}
		if index == 0 {
			if _, err := NewCheckpoint(
				record.event.stream,
				record.event.sequence-1,
				record.previousDigest,
			); err != nil {
				return fmt.Errorf("%w: invalid first-record predecessor", ErrInvalidSegment)
			}
			continue
		}
		previous := segment.records[index-1]
		if previous.event.sequence == math.MaxUint64 ||
			record.event.sequence != previous.event.sequence+1 ||
			!record.event.stream.Equal(previous.event.stream) ||
			!record.previousDigest.Equal(previous.digest) {
			return fmt.Errorf("%w: non-contiguous records", ErrInvalidSegment)
		}
	}
	return nil
}

func validateRecord(record Record) error {
	if ValidateEvent(record.event) != nil || !record.previousDigest.initialized || !record.digest.initialized {
		return ErrInvalidRecord
	}
	canonical, err := MarshalCanonicalEvent(record.event)
	if err != nil {
		return ErrInvalidRecord
	}
	want := deriveRecordDigest(record.previousDigest, record.event, canonical)
	if !record.digest.Equal(want) {
		return fmt.Errorf("%w: %w", ErrInvalidRecord, ErrIntegrity)
	}
	return nil
}

func deriveGenesisDigest(stream Stream) ChainDigest {
	hasher := sha256.New()
	writeHashFrame(hasher, []byte(chainGenesisDomain))
	writeHashFrame(hasher, []byte(ContractVersion))
	writeStreamFrames(hasher, stream)
	return chainDigestFromHash(hasher)
}

func deriveRecordDigest(previous ChainDigest, event Event, canonical []byte) ChainDigest {
	hasher := sha256.New()
	writeHashFrame(hasher, []byte(chainRecordDomain))
	writeHashFrame(hasher, []byte(ContractVersion))
	writeStreamFrames(hasher, event.stream)
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], event.sequence)
	writeHashFrame(hasher, sequence[:])
	writeHashFrame(hasher, previous.digest[:])
	writeHashFrame(hasher, canonical)
	return chainDigestFromHash(hasher)
}

func writeStreamFrames(hasher hash.Hash, stream Stream) {
	writeHashFrame(hasher, []byte(stream.kind.String()))
	writeHashFrame(hasher, []byte(stream.workspaceID.String()))
}

func writeHashFrame(hasher hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(value)
}

func chainDigestFromHash(hasher hash.Hash) ChainDigest {
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return ChainDigest{initialized: true, digest: digest}
}

func cloneRecord(record Record) Record {
	record.event = cloneEvent(record.event)
	return record
}

func cloneEvent(event Event) Event {
	event.request = cloneRequestRef(event.request)
	event.target = cloneTargetRef(event.target)
	event.decision = cloneDecisionRef(event.decision)
	event.operation = cloneOperationRef(event.operation)
	event.attempt = cloneAttemptRef(event.attempt)
	event.elevation = cloneElevationRef(event.elevation)
	return event
}

func checkedAdd(left, right int) (int, bool) {
	if right < 0 || left > math.MaxInt-right {
		return 0, false
	}
	return left + right, true
}

func preflightSegmentCount(data []byte) (int, error) {
	prefix := []byte(segmentPrefix)
	if !bytes.HasPrefix(data, prefix) {
		return 0, ErrNonCanonical
	}
	index := len(prefix)
	if index+2 == len(data) && data[index] == ']' && data[index+1] == '}' {
		return 0, nil
	}
	count := 0
	for {
		if index >= len(data) || data[index] != '{' {
			return 0, ErrNonCanonical
		}
		count++
		if count > MaxSegmentEvents {
			return count, ErrSegmentTooLarge
		}
		depth := 0
		inString := false
		escaped := false
		for ; index < len(data); index++ {
			current := data[index]
			if inString {
				if escaped {
					escaped = false
					continue
				}
				switch current {
				case '\\':
					escaped = true
				case '"':
					inString = false
				}
				continue
			}
			switch current {
			case '"':
				inString = true
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					index++
					goto recordComplete
				}
				if depth < 0 {
					return 0, ErrNonCanonical
				}
			}
		}
		return 0, ErrNonCanonical

	recordComplete:
		if index >= len(data) {
			return 0, ErrNonCanonical
		}
		switch data[index] {
		case ',':
			index++
			continue
		case ']':
			if index+2 != len(data) || data[index+1] != '}' {
				return 0, ErrNonCanonical
			}
			return count, nil
		default:
			return 0, ErrNonCanonical
		}
	}
}
