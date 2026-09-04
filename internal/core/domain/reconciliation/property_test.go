package reconciliation

import (
	"bytes"
	"testing"
	"testing/quick"
	"time"
)

func TestPropertyEvidenceDigestIsDeterministicAndKindSeparated(t *testing.T) {
	t.Parallel()
	property := func(raw []byte) bool {
		if len(raw) == 0 || len(raw) > 4_096 {
			return true
		}
		first, err := NewEvidence(EvidenceDesiredIntent, "version-1", raw)
		if err != nil {
			return false
		}
		second, err := NewEvidence(EvidenceDesiredIntent, "version-1", bytes.Clone(raw))
		if err != nil || !first.Equal(second) {
			return false
		}
		otherKind, err := NewEvidence(EvidenceObservedSnapshot, "version-1", raw)
		return err == nil && !first.digest.Equal(otherKind.digest)
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 256}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertySignedFenceIsStrictlyMonotonicUntilExhaustion(t *testing.T) {
	t.Parallel()
	property := func(value uint64) bool {
		current := int64(value % uint64(MaxFence))
		next, err := NextFence(current)
		return err == nil && next > current && next <= MaxFence
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1_024}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyFixedWindowNeverDependsOnReplayCount(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 70, false)
	scope, err := NewIdempotencyScope(fixture.actor, "PUT", []byte("/target"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := mustRequestFingerprint(t, "request")
	result := mustResultDigest(t, "result")
	property := func(replays uint8) bool {
		ledger, err := NewIdempotencyLedger(1)
		if err != nil {
			return false
		}
		reservation, _, err := ledger.Reserve(fixtureTime, scope, fixtureIdempotencyKey, fingerprint)
		if err != nil {
			return false
		}
		completed, err := ledger.Complete(reservation, result)
		if err != nil {
			return false
		}
		for index := uint8(0); index < replays; index++ {
			offset := timeFraction(index, replays)
			replay, disposition, err := ledger.Reserve(
				fixtureTime.Add(offset), scope, fixtureIdempotencyKey, fingerprint,
			)
			if err != nil || disposition != IdempotencyReplay || !replay.expiresAt.Equal(completed.expiresAt) {
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 128}); err != nil {
		t.Fatal(err)
	}
}

func timeFraction(index, count uint8) time.Duration {
	if count == 0 {
		return 0
	}
	return time.Duration(index) * (HTTPIdempotencyWindow - time.Millisecond) / time.Duration(count)
}
