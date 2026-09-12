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

func TestVerifyPolicyRejectsLegacyStatusContexts(t *testing.T) {
	changed := strings.Replace(expectedPolicy, `"strict": true,`, `"strict": true, "contexts": [],`, 1)
	if err := verifyPolicy([]byte(changed)); err == nil ||
		!strings.Contains(err.Error(), "required_status_checks.contexts must be omitted") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyPolicyRejectsMissingPullRequestGate(t *testing.T) {
	changed := strings.Replace(
		expectedPolicy,
		`"required_pull_request_reviews": {`,
		`"removed_pull_request_reviews": {`,
		1,
	)
	if err := verifyPolicy([]byte(changed)); err == nil ||
		!strings.Contains(err.Error(), "required_pull_request_reviews must preserve the pull-request gate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyPolicyRejectsRequiredApprovingReview(t *testing.T) {
	changed := strings.Replace(expectedPolicy, `"required_approving_review_count": 0`, `"required_approving_review_count": 1`, 1)
	if err := verifyPolicy([]byte(changed)); err == nil ||
		!strings.Contains(err.Error(), "required_approving_review_count must be 0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyPolicyRejectsLastPushApproval(t *testing.T) {
	changed := strings.Replace(expectedPolicy, `"require_last_push_approval": false`, `"require_last_push_approval": true`, 1)
	if err := verifyPolicy([]byte(changed)); err == nil ||
		!strings.Contains(err.Error(), "require_last_push_approval must be false") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyPolicyRejectsForkSyncingOnUnlockedBranch(t *testing.T) {
	changed := strings.Replace(expectedPolicy, `"allow_fork_syncing": false`, `"allow_fork_syncing": true`, 1)
	if err := verifyPolicy([]byte(changed)); err == nil ||
		!strings.Contains(err.Error(), "allow_fork_syncing must be false when lock_branch is false") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeJSONRejectsDuplicateKeys(t *testing.T) {
	_, err := decodeJSON([]byte(`{"required_status_checks": {}, "required_status_checks": null}`))
	if err == nil || !strings.Contains(err.Error(), `duplicate object key "required_status_checks"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}
