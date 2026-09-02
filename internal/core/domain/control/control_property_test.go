package control

import (
	"math/rand"
	"strconv"
	"testing"
	"testing/quick"
)

func TestPropertyQuotaRelationMatchesIntegers(t *testing.T) {
	t.Parallel()

	property := func(requestedRaw, availableRaw uint64) bool {
		requestedRaw %= 1_000_000_000
		availableRaw %= 1_000_000_000
		requested := strconv.FormatUint(requestedRaw, 10)
		available := strconv.FormatUint(availableRaw, 10)
		state := QuotaWithinLimit
		if requestedRaw > availableRaw {
			state = QuotaExceeded
		}
		return ValidateQuotaCheck(knownQuota(requested, available, state)) == nil
	}
	if err := quick.Check(property, &quick.Config{
		MaxCount: 1_000,
		Rand:     rand.New(rand.NewSource(21)),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyCanonicalDecimalOrder(t *testing.T) {
	t.Parallel()

	property := func(leftRaw, rightRaw uint64) bool {
		leftRaw %= 1_000_000_000
		rightRaw %= 1_000_000_000
		comparison, err := compareCanonicalDecimals(
			strconv.FormatUint(leftRaw, 10),
			strconv.FormatUint(rightRaw, 10),
		)
		if err != nil {
			return false
		}
		return (comparison < 0) == (leftRaw < rightRaw) &&
			(comparison == 0) == (leftRaw == rightRaw) &&
			(comparison > 0) == (leftRaw > rightRaw)
	}
	if err := quick.Check(property, &quick.Config{
		MaxCount: 1_000,
		Rand:     rand.New(rand.NewSource(22)),
	}); err != nil {
		t.Fatal(err)
	}
}
