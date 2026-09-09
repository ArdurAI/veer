package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunAcceptsRequiredPolicy(t *testing.T) {
	var output bytes.Buffer
	if err := run(strings.NewReader(expectedPolicy), &output); err != nil {
		t.Fatalf("verify required policy: %v", err)
	}
	if got, want := output.String(), "veer-branch-protection status=passed\n"; got != want {
		t.Fatalf("unexpected output: got %q, want %q", got, want)
	}
}

func TestVerifyPolicyRejectsEffectiveChange(t *testing.T) {
	changed := strings.Replace(expectedPolicy, `"enforce_admins": true`, `"enforce_admins": false`, 1)
	if err := verifyPolicy([]byte(changed)); err == nil ||
		!strings.Contains(err.Error(), "policy differs from required effective policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeJSONRejectsDuplicateKeys(t *testing.T) {
	_, err := decodeJSON([]byte(`{"required_status_checks": {}, "required_status_checks": null}`))
	if err == nil || !strings.Contains(err.Error(), `duplicate object key "required_status_checks"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}
