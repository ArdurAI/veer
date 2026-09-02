package control

import (
	"errors"
	"testing"
)

func FuzzQuotaCheck(f *testing.F) {
	f.Add("compute.instances", "WithinLimit", "3", "10", true, true)
	f.Add("network.load-balancers", "Unknown", "", "", false, false)

	f.Fuzz(func(t *testing.T, name, state, requested, available string, includeRequested, includeAvailable bool) {
		if len(name)+len(state)+len(requested)+len(available) > 4_096 {
			t.Skip()
		}
		quota := QuotaCheck{
			Name: name, State: QuotaState(state), Source: "provider-observation",
			ObservedAt: "2026-09-03T01:02:03.000Z", Reason: "Observed",
		}
		if includeRequested {
			quota.Requested = &requested
		}
		if includeAvailable {
			quota.Available = &available
		}
		err := ValidateQuotaCheck(quota)
		if err != nil && !errors.Is(err, ErrInvalidQuotaCheck) {
			t.Fatalf("ValidateQuotaCheck() returned unclassified error: %v", err)
		}
	})
}

func FuzzCostEstimate(f *testing.F) {
	f.Add("Known", "12.34", true, "USD", "us-east-1", "High")
	f.Add("Unknown", "", false, "USD", "us-east-1", "Unknown")

	f.Fuzz(func(t *testing.T, state, amount string, includeAmount bool, currency, region, confidence string) {
		if len(state)+len(amount)+len(currency)+len(region)+len(confidence) > 4_096 {
			t.Skip()
		}
		estimate := CostEstimate{
			State: CostState(state), Currency: currency, Region: region,
			Source: "provider-observation", ObservedAt: "2026-09-03T01:02:03.000Z",
			Confidence: Confidence(confidence), Reason: "Observed",
		}
		if includeAmount {
			estimate.Amount = &amount
		}
		err := ValidateCostEstimate(estimate)
		if err != nil && !errors.Is(err, ErrInvalidCostEstimate) {
			t.Fatalf("ValidateCostEstimate() returned unclassified error: %v", err)
		}
	})
}
