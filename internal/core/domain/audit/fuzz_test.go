package audit

import (
	"bytes"
	"testing"
)

func FuzzCanonicalEventRoundTrip(f *testing.F) {
	seed, err := MarshalCanonicalEvent(mustRequestEvent(f, 1))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add(append(bytes.Clone(seed), ' '))
	f.Fuzz(func(t *testing.T, data []byte) {
		event, err := UnmarshalCanonicalEvent(data)
		if err != nil {
			return
		}
		if len(data) > MaxCanonicalEventBytes || ValidateEvent(event) != nil {
			t.Fatal("decoder accepted an event outside its validation bounds")
		}
		canonical, err := MarshalCanonicalEvent(event)
		if err != nil || !bytes.Equal(canonical, data) {
			t.Fatalf("accepted event did not round trip: %v", err)
		}
	})
}

func FuzzCanonicalSegmentRoundTrip(f *testing.F) {
	genesis, err := GenesisCheckpoint(mustWorkspaceStream(f))
	if err != nil {
		f.Fatal(err)
	}
	segment, _, err := NewSegment(genesis, []Event{mustRequestEvent(f, 1), mustRequestEvent(f, 2)})
	if err != nil {
		f.Fatal(err)
	}
	seed, err := MarshalCanonicalSegment(segment)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"contractVersion":"veer.audit.v1alpha1","records":[]}`))
	f.Add(append(bytes.Clone(seed), ' '))
	f.Fuzz(func(t *testing.T, data []byte) {
		segment, err := UnmarshalCanonicalSegment(data)
		if err != nil {
			return
		}
		if segment.Len() > MaxSegmentEvents || len(data) > MaxCanonicalSegmentBytes {
			t.Fatal("decoder accepted a segment outside its bounds")
		}
		canonical, err := MarshalCanonicalSegment(segment)
		if err != nil || !bytes.Equal(canonical, data) {
			t.Fatalf("accepted segment did not round trip: %v", err)
		}
		if segment.Len() == 0 {
			return
		}
		first := segment.records[0]
		previous, err := NewCheckpoint(
			first.event.stream,
			first.event.sequence-1,
			first.previousDigest,
		)
		if err != nil {
			t.Fatalf("accepted segment has invalid predecessor: %v", err)
		}
		if _, err := VerifySegment(previous, segment, nil); err != nil {
			t.Fatalf("accepted segment does not verify: %v", err)
		}
	})
}
