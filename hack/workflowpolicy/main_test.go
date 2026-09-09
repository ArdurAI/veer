package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func repositoryWorkflow(t *testing.T, name string) ([]byte, map[string]string) {
	t.Helper()
	contents, err := os.ReadFile("../../.github/workflows/" + name)
	if err != nil {
		t.Fatalf("read %s workflow: %v", name, err)
	}
	root, err := os.OpenRoot("../..")
	if err != nil {
		t.Fatalf("open repository root: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("close repository root: %v", err)
		}
	})
	locks, err := readActionLocks(root, ".github/actions-lock.tsv")
	if err != nil {
		t.Fatalf("read action locks: %v", err)
	}
	return contents, locks
}

func repositorySupplyWorkflow(t *testing.T) ([]byte, map[string]string) {
	t.Helper()
	return repositoryWorkflow(t, "supply-chain.yml")
}

func TestRunAcceptsRepositoryPolicies(t *testing.T) {
	var output bytes.Buffer
	err := run("../..", []string{
		".github/workflows/bootstrap.yml",
		".github/workflows/dco.yml",
		".github/workflows/supply-chain.yml",
	}, &output)
	if err != nil {
		t.Fatalf("verify repository policies: %v", err)
	}
	want := "veer-workflow-policy workflows=3 actions=18 checkouts=9 security_steps=17 status=passed\n"
	if got := output.String(); got != want {
		t.Fatalf("unexpected output: got %q, want %q", got, want)
	}
}

func TestVerifyWorkflowAcceptsExactSupplyPolicy(t *testing.T) {
	contents, locks := repositorySupplyWorkflow(t)
	result, err := verifyWorkflow("supply-chain.yml", contents, locks)
	if err != nil {
		t.Fatalf("verify exact policy: %v", err)
	}
	if result.securitySteps["trivy"] != 1 {
		t.Fatalf("unexpected Trivy step count: got %d, want 1", result.securitySteps["trivy"])
	}
}

func TestRequireExactCardinalityRejectsDuplicateSubtype(t *testing.T) {
	actual := map[string]int{
		"attestation/Attest source provenance": 2,
		"attestation/Attest source SBOM":       0,
	}
	expected := map[string]int{
		"attestation/Attest source provenance": 1,
		"attestation/Attest source SBOM":       1,
	}
	err := requireExactCardinality(actual, expected, "security step")
	if err == nil || !strings.Contains(err.Error(), `security step "attestation/Attest source SBOM" must occur exactly 1 time(s), found 0`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyWorkflowRejectsQuotedWritePermission(t *testing.T) {
	contents, locks := repositorySupplyWorkflow(t)
	changed := strings.Replace(string(contents), "      contents: read\n      security-events: write", "      \"contents\": write\n      security-events: write", 1)
	_, err := verifyWorkflow("supply-chain.yml", []byte(changed), locks)
	if err == nil || !strings.Contains(err.Error(), "$.jobs.codeql.permissions differs from required policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyWorkflowScopesTrivyInputsToStep(t *testing.T) {
	contents, locks := repositorySupplyWorkflow(t)
	changed := strings.Replace(string(contents), "          severity: UNKNOWN,MEDIUM,HIGH,CRITICAL", "          severity: CRITICAL", 1) + "\nenv:\n  severity: UNKNOWN,MEDIUM,HIGH,CRITICAL\n"
	_, err := verifyWorkflow("supply-chain.yml", []byte(changed), locks)
	if err == nil || !strings.Contains(err.Error(), ".with differs from required policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyWorkflowRejectsDuplicateKeys(t *testing.T) {
	contents, locks := repositorySupplyWorkflow(t)
	changed := strings.Replace(string(contents), "permissions:\n", "permissions:\npermissions:\n", 1)
	_, err := verifyWorkflow("supply-chain.yml", []byte(changed), locks)
	if err == nil || !strings.Contains(err.Error(), `duplicate mapping key "permissions"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyWorkflowParsesQuotedActionKey(t *testing.T) {
	contents, locks := repositorySupplyWorkflow(t)
	changed := strings.Replace(
		string(contents),
		"        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25",
		"        \"uses\": evil/example@v1",
		1,
	)
	_, err := verifyWorkflow("supply-chain.yml", []byte(changed), locks)
	if err == nil || !strings.Contains(err.Error(), `action "evil/example" is not registered`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyWorkflowRejectsRequiredJobSkip(t *testing.T) {
	contents, locks := repositorySupplyWorkflow(t)
	changed := strings.Replace(string(contents), "  repository-scan:\n", "  repository-scan:\n    if: ${{ false }}\n", 1)
	_, err := verifyWorkflow("supply-chain.yml", []byte(changed), locks)
	if err == nil || !strings.Contains(err.Error(), "$.jobs.repository-scan.if is forbidden") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyWorkflowRejectsBootstrapStepSkip(t *testing.T) {
	contents, locks := repositoryWorkflow(t, "bootstrap.yml")
	changed := strings.Replace(string(contents), "        run: ./hack/dev check\n", "        run: ./hack/dev check\n        if: ${{ false }}\n", 1)
	_, err := verifyWorkflow("bootstrap.yml", []byte(changed), locks)
	if err == nil || !strings.Contains(err.Error(), "$.jobs.clean-bootstrap.steps[3].if is forbidden on a policy-governed run step") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyWorkflowRejectsChangedRunner(t *testing.T) {
	contents, locks := repositoryWorkflow(t, "bootstrap.yml")
	changed := strings.Replace(string(contents), "    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-latest\n", 1)
	_, err := verifyWorkflow("bootstrap.yml", []byte(changed), locks)
	if err == nil || !strings.Contains(err.Error(), `$.jobs.clean-bootstrap.runs-on must equal "ubuntu-24.04"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyWorkflowRejectsCollapsedPlatformMatrix(t *testing.T) {
	contents, locks := repositoryWorkflow(t, "bootstrap.yml")
	changed := strings.Replace(string(contents), "            runner: ubuntu-24.04-arm\n", "            runner: ubuntu-24.04\n", 1)
	_, err := verifyWorkflow("bootstrap.yml", []byte(changed), locks)
	if err == nil || !strings.Contains(err.Error(), "$.jobs.supported-platforms.strategy differs from required effective policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyWorkflowRejectsFalseDCOCompletion(t *testing.T) {
	contents, locks := repositoryWorkflow(t, "dco.yml")
	changed := strings.Replace(string(contents), "          VEER_DCO_VERIFICATION_OUTCOME: ${{ steps.verification.outcome }}\n", "          VEER_DCO_VERIFICATION_OUTCOME: success\n", 1)
	_, err := verifyWorkflow("dco.yml", []byte(changed), locks)
	if err == nil || !strings.Contains(err.Error(), "$.jobs.signoff.steps[3].env.VEER_DCO_VERIFICATION_OUTCOME differs from required scalar policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyWorkflowRejectsChangedDCOVerifierRun(t *testing.T) {
	contents, locks := repositoryWorkflow(t, "dco.yml")
	changed := strings.Replace(string(contents), "          ./hack/verify-dco.sh \"$VEER_DCO_BASE_SHA\" \"$VEER_DCO_HEAD_SHA\"\n", "          true\n", 1)
	_, err := verifyWorkflow("dco.yml", []byte(changed), locks)
	if err == nil || !strings.Contains(err.Error(), "$.jobs.signoff.steps[2].run differs from required scalar digest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyArchiveAttributesRejectsArchiveTransform(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(rootPath+"/.gitattributes", []byte("go.mod export-ignore\n"), 0o600); err != nil {
		t.Fatalf("write attributes: %v", err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err := verifyArchiveAttributes(root, "."); err == nil || !strings.Contains(err.Error(), "export-ignore is forbidden") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyActionReferenceRejectsLocalAction(t *testing.T) {
	_, err := verifyActionReference("./.github/actions/untrusted", nil)
	if err == nil || !strings.Contains(err.Error(), "is forbidden in governed workflows") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequireExactStepNamesRejectsReorderedSteps(t *testing.T) {
	node, err := decodeWorkflow([]byte("- name: Scan source\n- name: Check out source\n"))
	if err != nil {
		t.Fatalf("decode steps: %v", err)
	}
	err = requireExactStepNames(node, []string{"Check out source", "Scan source"}, "$.steps")
	if err == nil || !strings.Contains(err.Error(), `$.steps[0].name must equal "Check out source", got "Scan source"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}
