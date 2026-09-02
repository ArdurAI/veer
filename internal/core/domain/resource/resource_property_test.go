package resource

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
	"time"
)

func TestPropertyRenameNeverChangesStableIdentity(t *testing.T) {
	t.Parallel()

	initial := newTestResource(t, true)
	property := func(value uint64) bool {
		name := fmt.Sprintf("name-%016x", value)
		updated, err := initial.Rename(
			name,
			fmt.Sprintf("rv_%016x", value),
			initial.Metadata().UpdatedAt().Add(time.Duration(value%10_000+1)*time.Millisecond),
		)
		if err != nil {
			return false
		}
		before := initial.Metadata()
		after := updated.Metadata()
		beforeParent, beforePresent := before.Parent()
		afterParent, afterPresent := after.Parent()
		beforeSpec, beforeSpecErr := initial.Spec()
		afterSpec, afterSpecErr := updated.Spec()
		beforeStatus, beforeStatusErr := initial.Status()
		afterStatus, afterStatusErr := updated.Status()
		return before.ID() == after.ID() &&
			before.Generation() == after.Generation() &&
			before.CreatedAt().Equal(after.CreatedAt()) &&
			beforeParent == afterParent && beforePresent == afterPresent &&
			beforeSpecErr == nil && afterSpecErr == nil && reflect.DeepEqual(beforeSpec, afterSpec) &&
			beforeStatusErr == nil && afterStatusErr == nil && reflect.DeepEqual(beforeStatus, afterStatus)
	}
	checkProperty(t, property)
}

func TestPropertyGenerationTracksSemanticSpecChanges(t *testing.T) {
	t.Parallel()

	property := func(operations []byte) bool {
		current := newTestResource(t, false)
		expected := int64(1)
		revision := int64(0)
		for index, operation := range operations {
			spec, err := current.Spec()
			if err != nil {
				return false
			}
			if operation%2 == 0 {
				revision++
				spec.Revision = revision
				expected++
			}
			next, err := current.ReplaceSpec(
				spec,
				resourceVersionFor(index+1),
				current.Metadata().UpdatedAt().Add(time.Millisecond),
			)
			if err != nil {
				return false
			}
			current = next
		}
		return current.Metadata().Generation().Int64() == expected
	}
	checkProperty(t, property)
}

func TestPropertyLabelInsertionOrderDoesNotChangeCanonicalBytes(t *testing.T) {
	t.Parallel()

	property := func(first, second, third uint16) bool {
		pairs := []struct {
			key   string
			value string
		}{
			{key: "a", value: fmt.Sprintf("%d", first)},
			{key: "middle", value: fmt.Sprintf("%d", second)},
			{key: "z", value: fmt.Sprintf("%d", third)},
		}
		forward := make(map[string]string, len(pairs))
		reverse := make(map[string]string, len(pairs))
		for _, pair := range pairs {
			forward[pair.key] = pair.value
		}
		for index := len(pairs) - 1; index >= 0; index-- {
			reverse[pairs[index].key] = pairs[index].value
		}

		left := newTestResource(t, false)
		right := newTestResource(t, false)
		left, leftErr := left.ReplaceLabels(forward, "rv_left", left.Metadata().UpdatedAt().Add(time.Millisecond))
		right, rightErr := right.ReplaceLabels(reverse, "rv_left", right.Metadata().UpdatedAt().Add(time.Millisecond))
		if leftErr != nil || rightErr != nil {
			return false
		}
		leftJSON, leftErr := MarshalCanonical(left)
		rightJSON, rightErr := MarshalCanonical(right)
		return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
	}
	checkProperty(t, property)
}

func TestPropertyCanonicalRoundTripIsIdempotent(t *testing.T) {
	t.Parallel()

	property := func(region uint16, revision uint16) bool {
		current := newTestResource(t, true)
		spec := testSpec{
			Config:   map[string]string{"z": fmt.Sprintf("%d", region), "a": "first"},
			Region:   fmt.Sprintf("region-%d", region),
			Revision: int64(revision),
		}
		current, err := current.ReplaceSpec(spec, "rv_roundtrip", current.Metadata().UpdatedAt().Add(time.Millisecond))
		if err != nil {
			return false
		}
		first, err := MarshalCanonical(current)
		if err != nil {
			return false
		}
		decoded, err := UnmarshalCanonical[testSpec, testStatus](first)
		if err != nil {
			return false
		}
		second, err := MarshalCanonical(decoded)
		return err == nil && bytes.Equal(first, second)
	}
	checkProperty(t, property)
}

func TestPropertyStatusWritesPreserveGeneration(t *testing.T) {
	t.Parallel()

	property := func(value uint16) bool {
		initial := newTestResource(t, false)
		observed := int64(value % 3)
		status := testStatus{
			Conditions:         []testCondition{{Type: "Ready", ObservedGeneration: observed}},
			ObservedGeneration: observed,
		}
		updated, err := initial.ReplaceStatus(
			status,
			"rv_status",
			initial.Metadata().UpdatedAt().Add(time.Millisecond),
		)
		if observed > initial.Metadata().Generation().Int64() {
			return err != nil
		}
		return err == nil && updated.Metadata().Generation() == initial.Metadata().Generation()
	}
	checkProperty(t, property)
}

func checkProperty(t *testing.T, property any) {
	t.Helper()
	configuration := &quick.Config{
		MaxCount: 250,
		Rand:     rand.New(rand.NewSource(17)),
	}
	if err := quick.Check(property, configuration); err != nil {
		t.Fatal(err)
	}
}
