package admission

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"testing"
	"testing/quick"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/model"
)

func TestExactMathematicalIntegerAdmission(t *testing.T) {
	t.Parallel()

	snapshot, records := admissionFixture(t, testWorkspaceID)
	tests := []struct {
		number     string
		generation int64
		want       int64
	}{
		{number: "0", generation: 1, want: 0},
		{number: "-0.0e999999", generation: 1, want: 0},
		{number: "1.0", generation: 1, want: 1},
		{number: "1e0", generation: 1, want: 1},
		{number: "10e-1", generation: 1, want: 1},
		{number: "0.10e1", generation: 1, want: 1},
		{number: "1.20e1", generation: 12, want: 12},
		{number: "9.223372036854775807e18", generation: math.MaxInt64, want: math.MaxInt64},
		{number: "92233720368547758070e-1", generation: math.MaxInt64, want: math.MaxInt64},
	}
	for _, test := range tests {
		test := test
		t.Run(test.number, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"apiVersion":"v1alpha1","kind":"Workspace","status":{"observedGeneration":%s,"conditions":[]}}`, test.number))
			status, err := AdmitStatus(raw, records[hierarchy.KindWorkspace], test.generation, snapshot)
			if err != nil {
				t.Fatalf("AdmitStatus(%s) error = %v", test.number, err)
			}
			got := status.(*model.WorkspaceStatusWrite).Status().ObservedGeneration
			if got != test.want {
				t.Fatalf("observedGeneration = %d, want %d", got, test.want)
			}
		})
	}
}

func TestNonIntegralAndOutOfRangeNumbersAreRejected(t *testing.T) {
	t.Parallel()

	snapshot, records := admissionFixture(t, testWorkspaceID)
	for _, number := range []string{
		"0.1", "1e-1", "1.0000000000000000001", "-1", "-1.0",
		"9223372036854775808", "9223372036854775807.1", "1e999999",
	} {
		number := number
		t.Run(number, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"apiVersion":"v1alpha1","kind":"Workspace","status":{"observedGeneration":%s,"conditions":[]}}`, number))
			_, err := AdmitStatus(raw, records[hierarchy.KindWorkspace], math.MaxInt64, snapshot)
			assertFailure(t, err, StageSchema, CodeInvalidValue, "/status/observedGeneration")
		})
	}
}

func TestPropertyExactIntegerSpellings(t *testing.T) {
	t.Parallel()

	property := func(value uint64) bool {
		value &= math.MaxInt64
		text := strconv.FormatUint(value, 10)
		scaled := text + "0e-1"
		if value == 0 {
			scaled = "0e-1"
		}
		for _, representation := range []string{text, text + ".0", text + "e0", scaled} {
			got, valid := nonNegativeInt64(json.Number(representation))
			if !valid || uint64(got) != value {
				return false
			}
		}
		if value > 0 {
			if _, valid := nonNegativeInt64(json.Number(text + ".5")); valid {
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 2_000}); err != nil {
		t.Fatal(err)
	}
}
