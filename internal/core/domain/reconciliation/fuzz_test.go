package reconciliation

import "testing"

func FuzzEvidenceConstruction(f *testing.F) {
	f.Add("DesiredIntent", "version-1", []byte(`{"desired":true}`))
	f.Add("future", "", []byte{})
	f.Fuzz(func(t *testing.T, kind, version string, canonical []byte) {
		parsed, err := ParseEvidenceKind(kind)
		if err != nil {
			return
		}
		value, err := NewEvidence(parsed, version, canonical)
		if err != nil {
			return
		}
		if len(canonical) == 0 || len(canonical) > MaxEvidenceBytes || ValidateEvidence(value) != nil {
			t.Fatal("constructor admitted evidence outside its bounds")
		}
	})
}

func FuzzTypedDigestRoundTrip(f *testing.F) {
	f.Add([]byte("canonical-request"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, canonical []byte) {
		value, err := NewRequestFingerprint(canonical)
		if err != nil {
			return
		}
		parsed, err := ParseRequestFingerprint(value.String())
		if err != nil || !parsed.Equal(value) {
			t.Fatalf("accepted fingerprint did not round trip: %v", err)
		}
	})
}
