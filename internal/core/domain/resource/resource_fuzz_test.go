package resource

import (
	"bytes"
	"os"
	"testing"
)

func FuzzCanonicalRoundTrip(f *testing.F) {
	for _, name := range []string{"root", "parented"} {
		fixture, err := os.ReadFile("testdata/" + name + ".golden.json")
		if err != nil {
			f.Fatalf("os.ReadFile(%q) error = %v", name, err)
		}
		f.Add(bytes.TrimSuffix(fixture, []byte("\n")))
	}
	f.Add([]byte(`{"apiVersion":"v1alpha1"}`))
	f.Add([]byte(`{"kind":"Workspace","kind":"Environment"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxCanonicalBytes {
			t.Skip()
		}
		decoded, err := UnmarshalCanonical[testSpec, testStatus](data)
		if err != nil {
			return
		}
		first, err := MarshalCanonical(decoded)
		if err != nil {
			t.Fatalf("MarshalCanonical() after successful decode: %v", err)
		}
		again, err := UnmarshalCanonical[testSpec, testStatus](first)
		if err != nil {
			t.Fatalf("UnmarshalCanonical(canonical) error = %v", err)
		}
		second, err := MarshalCanonical(again)
		if err != nil {
			t.Fatalf("second MarshalCanonical() error = %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("canonical encoding is not idempotent:\n first %s\nsecond %s", first, second)
		}
	})
}
