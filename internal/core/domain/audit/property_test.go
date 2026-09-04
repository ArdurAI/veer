package audit

import (
	"bytes"
	"testing"
	"testing/quick"
)

func TestPropertyCanonicalSegmentsRoundTripAtEveryBoundedPrefix(t *testing.T) {
	t.Parallel()

	genesis, err := GenesisCheckpoint(mustWorkspaceStream(t))
	if err != nil {
		t.Fatal(err)
	}
	events := make([]Event, 64)
	for index := range events {
		events[index] = mustRequestEvent(t, uint64(index+1))
	}
	property := func(value uint8) bool {
		length := int(value%uint8(len(events))) + 1
		segment, terminal, err := NewSegment(genesis, events[:length])
		if err != nil {
			return false
		}
		canonical, err := MarshalCanonicalSegment(segment)
		if err != nil {
			return false
		}
		parsed, err := UnmarshalCanonicalSegment(canonical)
		if err != nil {
			return false
		}
		reencoded, err := MarshalCanonicalSegment(parsed)
		if err != nil || !bytes.Equal(canonical, reencoded) {
			return false
		}
		verified, err := VerifySegment(genesis, parsed, &terminal)
		return err == nil && verified.Equal(terminal) && parsed.Len() == length
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 256}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyDigestTextIsTypedAndRoundTrips(t *testing.T) {
	t.Parallel()

	property := func(raw [32]byte) bool {
		chain := ChainDigest{initialized: true, digest: raw}
		parsedChain, err := ParseChainDigest(chain.String())
		if err != nil || !parsedChain.Equal(chain) {
			return false
		}
		body := ExportBodyDigest{initialized: true, digest: raw}
		parsedBody, err := ParseExportBodyDigest(body.String())
		return err == nil && parsedBody.Equal(body) && chain.String() != body.String()
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 256}); err != nil {
		t.Fatal(err)
	}
}
