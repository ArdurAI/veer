package audit

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"math"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestChainDetectsMutationReorderAndInteriorDeletion(t *testing.T) {
	t.Parallel()

	genesis, err := GenesisCheckpoint(mustWorkspaceStream(t))
	if err != nil {
		t.Fatal(err)
	}
	events := []Event{
		mustRequestEvent(t, 1),
		mustRequestEvent(t, 2),
		mustRequestEvent(t, 3),
		mustRequestEvent(t, 4),
	}
	segment, terminal, err := NewSegment(genesis, events)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySegment(genesis, segment, &terminal)
	if err != nil || !verified.Equal(terminal) {
		t.Fatalf("VerifySegment(valid) = %v, %v", verified, err)
	}

	mutated := Segment{records: segment.Records()}
	mutated.records[1].event.outcome = OutcomeFailed
	if _, err := VerifySegment(genesis, mutated, nil); err == nil {
		t.Fatal("mutation was not detected")
	}

	reordered := Segment{records: segment.Records()}
	reordered.records[1], reordered.records[2] = reordered.records[2], reordered.records[1]
	if _, err := VerifySegment(genesis, reordered, nil); err == nil {
		t.Fatal("reordering was not detected")
	}

	interiorDeletedRecords := segment.Records()
	interiorDeletedRecords = append(interiorDeletedRecords[:1], interiorDeletedRecords[2:]...)
	interiorDeleted := Segment{records: interiorDeletedRecords}
	if _, err := VerifySegment(genesis, interiorDeleted, nil); err == nil {
		t.Fatal("interior deletion was not detected")
	}
}

func TestTailDeletionRequiresTrustedExpectedHead(t *testing.T) {
	t.Parallel()

	genesis, err := GenesisCheckpoint(mustWorkspaceStream(t))
	if err != nil {
		t.Fatal(err)
	}
	events := []Event{mustRequestEvent(t, 1), mustRequestEvent(t, 2), mustRequestEvent(t, 3)}
	complete, terminal, err := NewSegment(genesis, events)
	if err != nil {
		t.Fatal(err)
	}
	prefix := Segment{records: complete.Records()[:2]}
	prefixHead, err := VerifySegment(genesis, prefix, nil)
	if err != nil || prefixHead.Sequence() != 2 {
		t.Fatalf("valid prefix without expected head = %v, %v", prefixHead, err)
	}
	if _, err := VerifySegment(genesis, prefix, &terminal); !errors.Is(err, ErrExpectedHead) {
		t.Fatalf("tail deletion with trusted head = %v", err)
	}
}

func TestCanonicalSegmentGoldenStrictDecodeAndDigest(t *testing.T) {
	t.Parallel()

	genesis, err := GenesisCheckpoint(mustWorkspaceStream(t))
	if err != nil {
		t.Fatal(err)
	}
	segment, terminal, err := NewSegment(genesis, []Event{mustRequestEvent(t, 1), mustProviderAttemptEvent(t, 2)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := MarshalCanonicalSegment(segment)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/segment.golden.json")
	if err != nil {
		t.Fatalf("read golden: %v; terminal=%s; got=%s", err, terminal.Digest(), got)
	}
	want = bytes.TrimSpace(want)
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical segment mismatch\nterminal=%s\ngot:  %s\nwant: %s", terminal.Digest(), got, want)
	}
	if terminal.Digest().String() != "ach1_TQ68Ow4hZh0cmr1nTOlbieUzz8ZYYHx-3n0Czn_jqt4" {
		t.Fatalf("terminal digest = %s", terminal.Digest())
	}
	parsed, err := UnmarshalCanonicalSegment(got)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySegment(genesis, parsed, &terminal); err != nil {
		t.Fatal(err)
	}

	for _, invalid := range [][]byte{
		append(slices.Clone(got), ' '),
		bytes.Replace(got, []byte(`"records":`), []byte(`"unknown":true,"records":`), 1),
		bytes.Replace(got, []byte(`"digest":`), []byte(`"digest":"ach1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","digest":`), 1),
	} {
		if _, err := UnmarshalCanonicalSegment(invalid); err == nil {
			t.Fatalf("accepted non-canonical segment: %.120q", invalid)
		}
	}
}

func TestStreamSeparatedGenesisAndSequenceOverflow(t *testing.T) {
	t.Parallel()

	workspace, err := GenesisCheckpoint(mustWorkspaceStream(t))
	if err != nil {
		t.Fatal(err)
	}
	platform, err := GenesisCheckpoint(NewPlatformStream())
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Digest().Equal(platform.Digest()) {
		t.Fatal("workspace and platform genesis digests collided")
	}
	parsed, err := ParseChainDigest(workspace.Digest().String())
	if err != nil || !parsed.Equal(workspace.Digest()) {
		t.Fatalf("ParseChainDigest = %s, %v", parsed, err)
	}
	if _, err := ParseChainDigest(strings.Replace(workspace.Digest().String(), "ach1_", "aeb1_", 1)); err == nil {
		t.Fatal("accepted export digest as chain digest")
	}

	_, nonGenesis, err := Append(workspace, mustRequestEvent(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	maximum, err := NewCheckpoint(mustWorkspaceStream(t), math.MaxUint64, nonGenesis.Digest())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Append(maximum, mustRequestEvent(t, 1)); !errors.Is(err, ErrInvalidSequence) {
		t.Fatalf("Append at sequence saturation = %v", err)
	}
}

func TestCheckpointBindsGenesisDigestToSequenceZero(t *testing.T) {
	t.Parallel()

	stream := mustWorkspaceStream(t)
	genesis, err := GenesisCheckpoint(stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCheckpoint(genesis); err != nil {
		t.Fatalf("ValidateCheckpoint(genesis) = %v", err)
	}
	if _, err := NewCheckpoint(stream, 0, genesis.Digest()); err != nil {
		t.Fatalf("NewCheckpoint(explicit genesis) = %v", err)
	}

	_, nonGenesis, err := Append(genesis, mustRequestEvent(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCheckpoint(stream, nonGenesis.Sequence(), nonGenesis.Digest()); err != nil {
		t.Fatalf("NewCheckpoint(non-genesis) = %v", err)
	}

	for _, sequence := range []uint64{1, math.MaxUint64} {
		if _, err := NewCheckpoint(stream, sequence, genesis.Digest()); !errors.Is(err, ErrInvalidCheckpoint) {
			t.Fatalf("NewCheckpoint(sequence=%d, genesis digest) = %v", sequence, err)
		}
	}
	if _, err := NewCheckpoint(stream, 0, nonGenesis.Digest()); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("NewCheckpoint(sequence=0, non-genesis digest) = %v", err)
	}
}

func TestSegmentFirstRecordRequiresStructurallyValidPredecessor(t *testing.T) {
	t.Parallel()

	stream := mustWorkspaceStream(t)
	genesis, err := GenesisCheckpoint(stream)
	if err != nil {
		t.Fatal(err)
	}
	_, nonGenesis, err := Append(genesis, mustRequestEvent(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	validMidstream, _, err := NewSegment(nonGenesis, []Event{mustRequestEvent(t, 2)})
	if err != nil {
		t.Fatal(err)
	}
	validData, err := MarshalCanonicalSegment(validMidstream)
	if err != nil {
		t.Fatalf("MarshalCanonicalSegment(valid midstream) = %v", err)
	}
	if _, err := UnmarshalCanonicalSegment(validData); err != nil {
		t.Fatalf("UnmarshalCanonicalSegment(valid midstream) = %v", err)
	}

	tests := []struct {
		name        string
		event       Event
		predecessor ChainDigest
	}{
		{name: "sequence two with genesis", event: mustRequestEvent(t, 2), predecessor: genesis.Digest()},
		{name: "sequence one with non-genesis", event: mustRequestEvent(t, 1), predecessor: nonGenesis.Digest()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			canonicalEvent, err := MarshalCanonicalEvent(test.event)
			if err != nil {
				t.Fatal(err)
			}
			record := Record{
				event:          test.event,
				previousDigest: test.predecessor,
				digest:         deriveRecordDigest(test.predecessor, test.event, canonicalEvent),
			}
			if err := validateRecord(record); err != nil {
				t.Fatalf("fixture record must be digest-valid: %v", err)
			}

			segment := Segment{records: []Record{record}}
			if _, err := MarshalCanonicalSegment(segment); !errors.Is(err, ErrInvalidSegment) {
				t.Fatalf("MarshalCanonicalSegment() = %v, want %v", err, ErrInvalidSegment)
			}

			wire := segmentWire{
				ContractVersion: ContractVersion,
				Records: []recordWire{{
					Event:          eventToWire(record.event),
					PreviousDigest: record.previousDigest.String(),
					Digest:         record.digest.String(),
				}},
			}
			data, err := jsonv2.Marshal(wire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalCanonicalSegment(data); !errors.Is(err, ErrInvalidSegment) {
				t.Fatalf("UnmarshalCanonicalSegment() = %v, want %v; segment=%s", err, ErrInvalidSegment, data)
			}
		})
	}
}

func TestSegmentPreflightsCountBeforeEventOrRecordWork(t *testing.T) {
	t.Parallel()

	genesis, err := GenesisCheckpoint(mustWorkspaceStream(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewSegment(genesis, make([]Event, MaxSegmentEvents+1)); !errors.Is(err, ErrSegmentTooLarge) {
		t.Fatalf("NewSegment(over count) = %v", err)
	}

	var input strings.Builder
	input.WriteString(segmentPrefix)
	for index := 0; index < MaxSegmentEvents+1; index++ {
		if index > 0 {
			input.WriteByte(',')
		}
		input.WriteString("{}")
	}
	input.WriteString("]}")
	if _, err := UnmarshalCanonicalSegment([]byte(input.String())); !errors.Is(err, ErrSegmentTooLarge) {
		t.Fatalf("UnmarshalCanonicalSegment(over count) = %v", err)
	}
}
