package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	maximumPolicyBytes   = 512 * 1024
	sourceArchiveCommand = `mkdir -p dist
if archive_attributes=$(git grep -n -E 'export-(ignore|subst)' HEAD -- .gitattributes ':(glob)**/.gitattributes'); then
  printf '%s\n' "$archive_attributes" >&2
  printf '%s\n' 'archive-affecting Git attributes are forbidden' >&2
  exit 1
else
  archive_attribute_status=$?
  [ "$archive_attribute_status" -eq 1 ] || exit "$archive_attribute_status"
fi
git_tree=$(git ls-tree -r HEAD)
if printf '%s\n' "$git_tree" | grep -q '^160000 '; then
  printf '%s\n' "$git_tree" | grep '^160000 ' >&2
  printf '%s\n' 'Git submodules are forbidden in the source archive' >&2
  exit 1
fi
git archive --format=tar --output "dist/veer-source-${GITHUB_SHA}.tar" HEAD
`
	trivyAction = "aquasecurity/trivy-action"
)

const expectedDependencyReviewConfig = `
fail-on-severity: moderate
fail-on-scopes:
  - runtime
  - development
license-check: true
allow-licenses:
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC
  - MIT
show-openssf-scorecard: true
warn-only: false
`

const expectedDependabotConfig = `
version: 2
updates:
  - package-ecosystem: gomod
    directory: /
    vendor: true
    schedule:
      interval: weekly
      day: monday
      time: "06:00"
      timezone: Etc/UTC
    open-pull-requests-limit: 5
    groups:
      go-minor-and-patch:
        applies-to: version-updates
        patterns:
          - "*"
        update-types:
          - minor
          - patch
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
      day: monday
      time: "06:10"
      timezone: Etc/UTC
    open-pull-requests-limit: 5
    groups:
      actions-minor-and-patch:
        applies-to: version-updates
        patterns:
          - "*"
        update-types:
          - minor
          - patch
`

var expectedWorkflowNames = map[string]string{
	"bootstrap.yml":    "Foundation bootstrap",
	"dco.yml":          "DCO sign-off",
	"supply-chain.yml": "Supply-chain security",
}

var expectedEventPolicies = map[string]string{
	"bootstrap.yml": `
pull_request:
push:
  branches:
    - main
`,
	"dco.yml": `
pull_request_target:
  types:
    - opened
    - synchronize
    - reopened
    - ready_for_review
    - edited
`,
	"supply-chain.yml": `
pull_request:
push:
  branches:
    - main
schedule:
  - cron: "17 6 * * 1"
workflow_dispatch:
`,
}

var expectedConcurrencyPolicies = map[string]string{
	"bootstrap.yml": `
group: foundation-bootstrap-${{ github.workflow }}-${{ github.ref }}
cancel-in-progress: true
`,
	"dco.yml": `
group: dco-${{ github.workflow }}-${{ github.event.pull_request.number }}
cancel-in-progress: true
`,
	"supply-chain.yml": `
group: supply-chain-${{ github.workflow }}-${{ github.event_name }}-${{ github.ref == 'refs/heads/main' && github.run_id || github.ref }}
cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
`,
}

var expectedJobDisplayNames = map[string]map[string]string{
	"bootstrap.yml": {
		"clean-bootstrap":     "Clean checkout contract",
		"race-coverage":       "Race and coverage",
		"supported-platforms": "Supported platform (${{ matrix.label }})",
	},
	"dco.yml": {
		"signoff": "DCO sign-off",
	},
	"supply-chain.yml": {
		"attest-source":     "Source provenance",
		"codeql":            "CodeQL",
		"dependency-review": "Dependency review",
		"repository-scan":   "Repository scan",
		"sbom":              "SBOM",
	},
}

var expectedJobFields = map[string][]string{
	"bootstrap.yml/clean-bootstrap":      {"name", "runs-on", "steps", "timeout-minutes"},
	"bootstrap.yml/race-coverage":        {"name", "runs-on", "steps", "timeout-minutes"},
	"bootstrap.yml/supported-platforms":  {"name", "runs-on", "steps", "strategy", "timeout-minutes"},
	"dco.yml/signoff":                    {"name", "runs-on", "steps", "timeout-minutes"},
	"supply-chain.yml/attest-source":     {"if", "name", "permissions", "runs-on", "steps", "timeout-minutes"},
	"supply-chain.yml/codeql":            {"name", "permissions", "runs-on", "steps", "timeout-minutes"},
	"supply-chain.yml/dependency-review": {"if", "name", "runs-on", "steps", "timeout-minutes"},
	"supply-chain.yml/repository-scan":   {"name", "runs-on", "steps", "timeout-minutes"},
	"supply-chain.yml/sbom":              {"name", "runs-on", "steps", "timeout-minutes"},
}

var expectedJobRunners = map[string]string{
	"bootstrap.yml/clean-bootstrap":      "ubuntu-24.04",
	"bootstrap.yml/race-coverage":        "ubuntu-24.04",
	"bootstrap.yml/supported-platforms":  "${{ matrix.runner }}",
	"dco.yml/signoff":                    "ubuntu-24.04",
	"supply-chain.yml/attest-source":     "ubuntu-24.04",
	"supply-chain.yml/codeql":            "ubuntu-24.04",
	"supply-chain.yml/dependency-review": "ubuntu-24.04",
	"supply-chain.yml/repository-scan":   "ubuntu-24.04",
	"supply-chain.yml/sbom":              "ubuntu-24.04",
}

var expectedJobTimeouts = map[string]string{
	"bootstrap.yml/clean-bootstrap":      "15",
	"bootstrap.yml/race-coverage":        "20",
	"bootstrap.yml/supported-platforms":  "20",
	"dco.yml/signoff":                    "7",
	"supply-chain.yml/attest-source":     "15",
	"supply-chain.yml/codeql":            "20",
	"supply-chain.yml/dependency-review": "10",
	"supply-chain.yml/repository-scan":   "15",
	"supply-chain.yml/sbom":              "15",
}

var expectedJobStrategies = map[string]string{
	"bootstrap.yml/supported-platforms": `
fail-fast: false
matrix:
  include:
    - label: Linux arm64
      runner: ubuntu-24.04-arm
    - label: macOS arm64
      runner: macos-15
    - label: macOS Intel
      runner: macos-15-intel
`,
}

type workflowResult struct {
	actionSteps   int
	checkoutSteps int
	checkoutJobs  map[string]int
	securitySteps map[string]int
}

var expectedCheckoutJobs = map[string]int{
	"bootstrap.yml/clean-bootstrap":      1,
	"bootstrap.yml/race-coverage":        1,
	"bootstrap.yml/supported-platforms":  1,
	"dco.yml/signoff":                    1,
	"supply-chain.yml/attest-source":     1,
	"supply-chain.yml/codeql":            1,
	"supply-chain.yml/dependency-review": 1,
	"supply-chain.yml/repository-scan":   1,
	"supply-chain.yml/sbom":              1,
}

var expectedSecuritySteps = map[string]int{
	"artifact-upload/sbom":                 1,
	"attestation/Attest source provenance": 1,
	"attestation/Attest source SBOM":       1,
	"codeql/analyze":                       1,
	"codeql/init":                          1,
	"dependency-review":                    1,
	"run/action-module-authentication":     1,
	"run/attest-source/bootstrap-syft":     1,
	"run/attest-source/archive":            1,
	"run/attest-source/generate-sbom":      1,
	"run/codeql/bootstrap":                 1,
	"run/codeql/build":                     1,
	"run/codeql/select-go":                 1,
	"run/sbom/bootstrap-syft":              1,
	"run/sbom/archive":                     1,
	"run/sbom/generate":                    1,
	"trivy":                                1,
}

var expectedWorkflowStepNames = map[string][]string{
	"bootstrap.yml/clean-bootstrap": {
		"Check out source",
		"Bootstrap pinned tools",
		"Authenticate action and module sources",
		"Run the local fast gate",
		"Verify a non-mutating check",
	},
	"bootstrap.yml/race-coverage": {
		"Check out source",
		"Bootstrap pinned tools",
		"Run race detector",
		"Enforce coverage floor",
	},
	"bootstrap.yml/supported-platforms": {
		"Check out source",
		"Bootstrap pinned tools",
		"Run complete local gate",
		"Verify a non-mutating check",
	},
	"dco.yml/signoff": {
		"Start exact-head DCO check",
		"Check out trusted verifier",
		"Fetch commit data and verify every contribution",
		"Complete exact-head DCO check",
	},
	"supply-chain.yml/dependency-review": {
		"Check out source",
		"Review dependency changes",
	},
	"supply-chain.yml/repository-scan": {
		"Check out source",
		"Scan vulnerabilities, secrets, licenses, containers, and IaC",
	},
	"supply-chain.yml/codeql": {
		"Check out source",
		"Bootstrap pinned build tools",
		"Select pinned Go for CodeQL",
		"Initialize CodeQL",
		"Build analyzed source",
		"Analyze source",
	},
	"supply-chain.yml/sbom": {
		"Check out source",
		"Bootstrap checksum-pinned Syft",
		"Create source snapshot",
		"Generate SPDX JSON SBOM",
		"Retain source snapshot and SBOM",
	},
	"supply-chain.yml/attest-source": {
		"Check out source",
		"Bootstrap checksum-pinned Syft",
		"Create attestation subject",
		"Generate attestation SBOM",
		"Attest source provenance",
		"Attest source SBOM",
	},
}

type exactMapPolicy struct {
	fields        []string
	scalars       map[string]scalarPolicyValue
	scalarDigests map[string]string
}

type exactStepPolicy struct {
	fields        []string
	maps          map[string]exactMapPolicy
	scalars       map[string]scalarPolicyValue
	scalarDigests map[string]string
}

var expectedDCOStepPolicies = map[string]exactStepPolicy{
	"dco.yml/signoff/Start exact-head DCO check": {
		fields: []string{"continue-on-error", "env", "id", "name", "timeout-minutes", "uses", "with"},
		scalars: map[string]scalarPolicyValue{
			"continue-on-error": {tag: "!!bool", value: "true"},
			"id":                {tag: "!!str", value: "exact-head-check"},
			"timeout-minutes":   {tag: "!!int", value: "1"},
			"uses":              {tag: "!!str", value: "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3"},
		},
		maps: map[string]exactMapPolicy{
			"env": {
				fields: []string{"VEER_DCO_CHECK_DETAILS_URL", "VEER_DCO_CHECK_EXTERNAL_ID", "VEER_DCO_HEAD_SHA"},
				scalars: map[string]scalarPolicyValue{
					"VEER_DCO_CHECK_DETAILS_URL": {tag: "!!str", value: "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}/attempts/${{ github.run_attempt }}"},
					"VEER_DCO_CHECK_EXTERNAL_ID": {tag: "!!str", value: "dco:${{ github.run_id }}:${{ github.run_attempt }}:${{ github.event.pull_request.base.sha }}:${{ github.event.pull_request.head.sha }}"},
					"VEER_DCO_HEAD_SHA":          {tag: "!!str", value: "${{ github.event.pull_request.head.sha }}"},
				},
			},
			"with": {
				fields: []string{"github-token", "result-encoding", "script"},
				scalars: map[string]scalarPolicyValue{
					"github-token":    {tag: "!!str", value: "${{ github.token }}"},
					"result-encoding": {tag: "!!str", value: "string"},
				},
				scalarDigests: map[string]string{
					"script": "d9812465e62d74b87a2bf411cdb3b68afd40a3fd942eaaaf56e9b6b6f79f5579",
				},
			},
		},
	},
	"dco.yml/signoff/Fetch commit data and verify every contribution": {
		fields: []string{"continue-on-error", "env", "id", "name", "run", "shell", "timeout-minutes"},
		scalars: map[string]scalarPolicyValue{
			"continue-on-error": {tag: "!!bool", value: "true"},
			"id":                {tag: "!!str", value: "verification"},
			"shell":             {tag: "!!str", value: "sh"},
			"timeout-minutes":   {tag: "!!int", value: "3"},
		},
		scalarDigests: map[string]string{
			"run": "9591170e563161aa750c1f8c394175d6b055374d7e40bfa8f26dc328423a51e6",
		},
		maps: map[string]exactMapPolicy{
			"env": {
				fields: []string{"VEER_COMMUNITY_POLICY_SHA256", "VEER_DCO_BASE_SHA", "VEER_DCO_HEAD_SHA", "VEER_DCO_PR_NUMBER", "VEER_DCO_VERIFIER_SHA256", "VEER_DCO_WORKFLOW_SHA256"},
				scalars: map[string]scalarPolicyValue{
					"VEER_COMMUNITY_POLICY_SHA256": {tag: "!!str", value: "${{ vars.VEER_COMMUNITY_POLICY_SHA256 }}"},
					"VEER_DCO_BASE_SHA":            {tag: "!!str", value: "${{ github.event.pull_request.base.sha }}"},
					"VEER_DCO_HEAD_SHA":            {tag: "!!str", value: "${{ github.event.pull_request.head.sha }}"},
					"VEER_DCO_PR_NUMBER":           {tag: "!!str", value: "${{ github.event.pull_request.number }}"},
					"VEER_DCO_VERIFIER_SHA256":     {tag: "!!str", value: "${{ vars.VEER_DCO_VERIFIER_SHA256 }}"},
					"VEER_DCO_WORKFLOW_SHA256":     {tag: "!!str", value: "${{ vars.VEER_DCO_WORKFLOW_SHA256 }}"},
				},
			},
		},
	},
	"dco.yml/signoff/Complete exact-head DCO check": {
		fields: []string{"env", "if", "name", "timeout-minutes", "uses", "with"},
		scalars: map[string]scalarPolicyValue{
			"if":              {tag: "!!str", value: "${{ always() }}"},
			"timeout-minutes": {tag: "!!int", value: "1"},
			"uses":            {tag: "!!str", value: "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3"},
		},
		maps: map[string]exactMapPolicy{
			"env": {
				fields: []string{"VEER_DCO_CHECK_DETAILS_URL", "VEER_DCO_CHECK_EXTERNAL_ID", "VEER_DCO_CHECK_ID", "VEER_DCO_HEAD_SHA", "VEER_DCO_VERIFICATION_OUTCOME"},
				scalars: map[string]scalarPolicyValue{
					"VEER_DCO_CHECK_DETAILS_URL":    {tag: "!!str", value: "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}/attempts/${{ github.run_attempt }}"},
					"VEER_DCO_CHECK_EXTERNAL_ID":    {tag: "!!str", value: "dco:${{ github.run_id }}:${{ github.run_attempt }}:${{ github.event.pull_request.base.sha }}:${{ github.event.pull_request.head.sha }}"},
					"VEER_DCO_CHECK_ID":             {tag: "!!str", value: "${{ steps.exact-head-check.outputs.result }}"},
					"VEER_DCO_HEAD_SHA":             {tag: "!!str", value: "${{ github.event.pull_request.head.sha }}"},
					"VEER_DCO_VERIFICATION_OUTCOME": {tag: "!!str", value: "${{ steps.verification.outcome }}"},
				},
			},
			"with": {
				fields: []string{"github-token", "script"},
				scalars: map[string]scalarPolicyValue{
					"github-token": {tag: "!!str", value: "${{ github.token }}"},
				},
				scalarDigests: map[string]string{
					"script": "e30816dbeee084933c5583df31c4f0856b9dc71c457bc570f7ababf7934d2a71",
				},
			},
		},
	},
}

var expectedSupplyChainActions = map[string]string{
	"supply-chain.yml/dependency-review/Check out source":                                           "actions/checkout",
	"supply-chain.yml/dependency-review/Review dependency changes":                                  "actions/dependency-review-action",
	"supply-chain.yml/repository-scan/Check out source":                                             "actions/checkout",
	"supply-chain.yml/repository-scan/Scan vulnerabilities, secrets, licenses, containers, and IaC": trivyAction,
	"supply-chain.yml/codeql/Check out source":                                                      "actions/checkout",
	"supply-chain.yml/codeql/Initialize CodeQL":                                                     "github/codeql-action/init",
	"supply-chain.yml/codeql/Analyze source":                                                        "github/codeql-action/analyze",
	"supply-chain.yml/sbom/Check out source":                                                        "actions/checkout",
	"supply-chain.yml/sbom/Retain source snapshot and SBOM":                                         "actions/upload-artifact",
	"supply-chain.yml/attest-source/Check out source":                                               "actions/checkout",
	"supply-chain.yml/attest-source/Attest source provenance":                                       "actions/attest",
	"supply-chain.yml/attest-source/Attest source SBOM":                                             "actions/attest",
}

type runStepPolicy struct {
	command string
	role    string
	shell   string
}

var expectedRunSteps = map[string]runStepPolicy{
	"bootstrap.yml/clean-bootstrap/Bootstrap pinned tools": {
		command: "./hack/dev bootstrap",
		shell:   "sh",
	},
	"bootstrap.yml/clean-bootstrap/Authenticate action and module sources": {
		command: "./hack/verify-online-sources.sh",
		role:    "run/action-module-authentication",
		shell:   "sh",
	},
	"bootstrap.yml/clean-bootstrap/Run the local fast gate": {
		command: "./hack/dev check",
		shell:   "sh",
	},
	"bootstrap.yml/clean-bootstrap/Verify a non-mutating check": {
		command: "git diff --exit-code",
		shell:   "sh",
	},
	"bootstrap.yml/race-coverage/Bootstrap pinned tools": {
		command: "./hack/dev bootstrap",
		shell:   "sh",
	},
	"bootstrap.yml/race-coverage/Run race detector": {
		command: "./hack/dev race",
		shell:   "sh",
	},
	"bootstrap.yml/race-coverage/Enforce coverage floor": {
		command: "./hack/dev coverage",
		shell:   "sh",
	},
	"bootstrap.yml/supported-platforms/Bootstrap pinned tools": {
		command: "./hack/dev bootstrap",
		shell:   "sh",
	},
	"bootstrap.yml/supported-platforms/Run complete local gate": {
		command: "./hack/dev check",
		shell:   "sh",
	},
	"bootstrap.yml/supported-platforms/Verify a non-mutating check": {
		command: "git diff --exit-code",
		shell:   "sh",
	},
	"supply-chain.yml/codeql/Bootstrap pinned build tools": {
		command: "./hack/dev bootstrap",
		role:    "run/codeql/bootstrap",
		shell:   "sh",
	},
	"supply-chain.yml/codeql/Select pinned Go for CodeQL": {
		command: `printf '%s\n' "$GITHUB_WORKSPACE/.tools/bin" >> "$GITHUB_PATH"`,
		role:    "run/codeql/select-go",
		shell:   "sh",
	},
	"supply-chain.yml/codeql/Build analyzed source": {
		command: "./hack/dev _codeql-build",
		role:    "run/codeql/build",
		shell:   "sh",
	},
	"supply-chain.yml/sbom/Create source snapshot": {
		command: sourceArchiveCommand,
		role:    "run/sbom/archive",
		shell:   "sh",
	},
	"supply-chain.yml/sbom/Bootstrap checksum-pinned Syft": {
		command: "./hack/dev bootstrap syft",
		role:    "run/sbom/bootstrap-syft",
		shell:   "sh",
	},
	"supply-chain.yml/sbom/Generate SPDX JSON SBOM": {
		command: `SYFT_CHECK_FOR_APP_UPDATE=false ./.tools/bin/syft scan "file:dist/veer-source-${GITHUB_SHA}.tar" --output "spdx-json=dist/veer-source.spdx.json"`,
		role:    "run/sbom/generate",
		shell:   "sh",
	},
	"supply-chain.yml/attest-source/Create attestation subject": {
		command: sourceArchiveCommand,
		role:    "run/attest-source/archive",
		shell:   "sh",
	},
	"supply-chain.yml/attest-source/Bootstrap checksum-pinned Syft": {
		command: "./hack/dev bootstrap syft",
		role:    "run/attest-source/bootstrap-syft",
		shell:   "sh",
	},
	"supply-chain.yml/attest-source/Generate attestation SBOM": {
		command: `SYFT_CHECK_FOR_APP_UPDATE=false ./.tools/bin/syft scan "file:dist/veer-source-${GITHUB_SHA}.tar" --output "spdx-json=dist/veer-source.spdx.json"`,
		role:    "run/attest-source/generate-sbom",
		shell:   "sh",
	},
}

var rootPermissionPolicies = map[string]map[string]string{
	"bootstrap.yml": {
		"contents": "read",
	},
	"dco.yml": {
		"checks":   "write",
		"contents": "read",
	},
	"supply-chain.yml": {
		"contents": "read",
	},
}

var jobPermissionPolicies = map[string]map[string]string{
	"supply-chain.yml/codeql": {
		"contents":        "read",
		"security-events": "write",
	},
	"supply-chain.yml/attest-source": {
		"attestations": "write",
		"contents":     "read",
		"id-token":     "write",
	},
}

var trivyInputPolicy = map[string]string{
	"cache":          "false",
	"exit-code":      "1",
	"ignore-unfixed": "false",
	"scan-ref":       ".",
	"scan-type":      "fs",
	"scanners":       "vuln,misconfig,secret,license",
	"severity":       "UNKNOWN,MEDIUM,HIGH,CRITICAL",
	"trivyignores":   ".trivyignore.yaml",
	"version":        "v0.74.0",
}

var expectedJobConditions = map[string]string{
	"supply-chain.yml/dependency-review": "github.event_name == 'pull_request'",
	"supply-chain.yml/attest-source":     "github.event_name == 'push' && github.ref == 'refs/heads/main'",
}

var dependencyReviewInputPolicy = map[string]string{
	"config-file": "./.github/dependency-review-config.yml",
}

var checkoutInputPolicies = map[string]map[string]string{
	"bootstrap.yml/clean-bootstrap": {
		"fetch-depth":         "1",
		"persist-credentials": "false",
	},
	"bootstrap.yml/race-coverage": {
		"fetch-depth":         "1",
		"persist-credentials": "false",
	},
	"bootstrap.yml/supported-platforms": {
		"fetch-depth":         "1",
		"persist-credentials": "false",
	},
	"dco.yml/signoff": {
		"fetch-depth":         "0",
		"persist-credentials": "false",
		"ref":                 "${{ github.event.pull_request.base.sha }}",
	},
	"supply-chain.yml/attest-source": {
		"fetch-depth":         "1",
		"persist-credentials": "false",
	},
	"supply-chain.yml/codeql": {
		"fetch-depth":         "1",
		"persist-credentials": "false",
	},
	"supply-chain.yml/dependency-review": {
		"fetch-depth":         "1",
		"persist-credentials": "false",
	},
	"supply-chain.yml/repository-scan": {
		"fetch-depth":         "1",
		"persist-credentials": "false",
	},
	"supply-chain.yml/sbom": {
		"fetch-depth":         "1",
		"persist-credentials": "false",
	},
}

var policyActionTimeouts = map[string]string{
	"dco.yml/signoff/Check out trusted verifier": "1",
}

var attestationInputPolicies = map[string]map[string]string{
	"Attest source provenance": {
		"subject-path": "dist/veer-source-${{ github.sha }}.tar",
	},
	"Attest source SBOM": {
		"sbom-path":    "dist/veer-source.spdx.json",
		"subject-path": "dist/veer-source-${{ github.sha }}.tar",
	},
}

var uploadArtifactInputPolicy = map[string]string{
	"compression-level": "9",
	"if-no-files-found": "error",
	"name":              "veer-source-sbom-${{ github.sha }}",
	"path":              "dist/veer-source-${{ github.sha }}.tar\ndist/veer-source.spdx.json\n",
	"retention-days":    "30",
}

var codeQLInputPolicies = map[string]map[string]string{
	"github/codeql-action/init": {
		"build-mode": "manual",
		"languages":  "go",
	},
	"github/codeql-action/analyze": {
		"category": "/language:go",
	},
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "veer-workflow-policy: usage: workflowpolicy ROOT WORKFLOW...")
		os.Exit(1)
	}
	if err := run(os.Args[1], os.Args[2:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "veer-workflow-policy: %v\n", err)
		os.Exit(1)
	}
}

func run(rootPath string, paths []string, output io.Writer) (returnedErr error) {
	if len(paths) == 0 {
		return errors.New("at least one workflow path is required")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open repository root: %w", err)
	}
	defer func() {
		if closeErr := root.Close(); returnedErr == nil && closeErr != nil {
			returnedErr = fmt.Errorf("close repository root: %w", closeErr)
		}
	}()
	actionLocks, err := readActionLocks(root, ".github/actions-lock.tsv")
	if err != nil {
		return fmt.Errorf("action lock: %w", err)
	}
	for path, expected := range map[string]string{
		".github/dependency-review-config.yml": expectedDependencyReviewConfig,
		".github/dependabot.yml":               expectedDependabotConfig,
	} {
		if err := verifyExactYAMLFile(root, path, expected); err != nil {
			return err
		}
	}
	if err := verifyArchiveAttributes(root, "."); err != nil {
		return err
	}

	seenPaths := make(map[string]struct{}, len(paths))
	var totals workflowResult
	for _, path := range paths {
		cleanPath := filepath.Clean(path)
		if filepath.IsAbs(cleanPath) || cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
			return fmt.Errorf("workflow path %q must remain repository-relative", path)
		}
		if _, duplicate := seenPaths[cleanPath]; duplicate {
			return fmt.Errorf("duplicate workflow path %q", cleanPath)
		}
		seenPaths[cleanPath] = struct{}{}

		workflow, err := readBoundedFile(root, cleanPath)
		if err != nil {
			return fmt.Errorf("%s: %w", cleanPath, err)
		}
		result, err := verifyWorkflow(filepath.Base(cleanPath), workflow, actionLocks)
		if err != nil {
			return fmt.Errorf("%s: %w", cleanPath, err)
		}
		totals.add(result)
	}
	if err := requireExactCardinality(totals.checkoutJobs, expectedCheckoutJobs, "checkout job"); err != nil {
		return err
	}
	if err := requireExactCardinality(totals.securitySteps, expectedSecuritySteps, "security step"); err != nil {
		return err
	}

	_, err = fmt.Fprintf(
		output,
		"veer-workflow-policy workflows=%d actions=%d checkouts=%d security_steps=%d status=passed\n",
		len(paths),
		totals.actionSteps,
		totals.checkoutSteps,
		totalCardinality(totals.securitySteps),
	)
	return err
}

func (result *workflowResult) add(other workflowResult) {
	result.actionSteps += other.actionSteps
	result.checkoutSteps += other.checkoutSteps
	result.checkoutJobs = mergeCardinality(result.checkoutJobs, other.checkoutJobs)
	result.securitySteps = mergeCardinality(result.securitySteps, other.securitySteps)
}

func (result *workflowResult) recordCheckout(job string) {
	result.checkoutSteps++
	result.checkoutJobs = incrementCardinality(result.checkoutJobs, job)
}

func (result *workflowResult) recordSecurityStep(role string) {
	result.securitySteps = incrementCardinality(result.securitySteps, role)
}

func incrementCardinality(counts map[string]int, key string) map[string]int {
	if counts == nil {
		counts = make(map[string]int)
	}
	counts[key]++
	return counts
}

func mergeCardinality(destination, source map[string]int) map[string]int {
	for key, count := range source {
		if destination == nil {
			destination = make(map[string]int)
		}
		destination[key] += count
	}
	return destination
}

func requireExactCardinality(actual, expected map[string]int, label string) error {
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if actual[key] != expected[key] {
			return fmt.Errorf("%s %q must occur exactly %d time(s), found %d", label, key, expected[key], actual[key])
		}
	}
	for key, count := range actual {
		if _, known := expected[key]; !known {
			return fmt.Errorf("unexpected %s %q occurs %d time(s)", label, key, count)
		}
	}
	return nil
}

func totalCardinality(counts map[string]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}

func readBoundedFile(root *os.Root, path string) (contents []byte, returnedErr error) {
	file, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); returnedErr == nil && closeErr != nil {
			returnedErr = fmt.Errorf("close workflow: %w", closeErr)
		}
	}()

	contents, err = io.ReadAll(io.LimitReader(file, maximumPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read workflow: %w", err)
	}
	if len(contents) > maximumPolicyBytes {
		return nil, fmt.Errorf("policy file exceeds %d bytes", maximumPolicyBytes)
	}
	return contents, nil
}

func verifyArchiveAttributes(root *os.Root, directory string) (returnedErr error) {
	directoryHandle, err := root.Open(directory)
	if err != nil {
		return fmt.Errorf("open repository directory %q: %w", directory, err)
	}
	defer func() {
		if closeErr := directoryHandle.Close(); returnedErr == nil && closeErr != nil {
			returnedErr = fmt.Errorf("close repository directory %q: %w", directory, closeErr)
		}
	}()

	entries, err := directoryHandle.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read repository directory %q: %w", directory, err)
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name() < entries[right].Name()
	})
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(directory, name)
		if entry.IsDir() {
			if directory == "." && (name == ".git" || name == ".tools") {
				continue
			}
			if err := verifyArchiveAttributes(root, path); err != nil {
				return err
			}
			continue
		}
		if name != ".gitattributes" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular file", path)
		}
		contents, err := readBoundedFile(root, path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for lineNumber, line := range strings.Split(string(contents), "\n") {
			for _, attribute := range []string{"export-ignore", "export-subst"} {
				if strings.Contains(line, attribute) {
					return fmt.Errorf("%s:%d: archive-affecting Git attribute %s is forbidden", path, lineNumber+1, attribute)
				}
			}
		}
	}
	return nil
}

func verifyWorkflow(name string, contents []byte, actionLocks map[string]string) (workflowResult, error) {
	var result workflowResult
	root, err := decodeWorkflow(contents)
	if err != nil {
		return result, err
	}
	if err := validateNode(root, "$"); err != nil {
		return result, err
	}

	rootFields, err := mappingFields(root, "$")
	if err != nil {
		return result, err
	}
	expectedRootPermissions, knownWorkflow := rootPermissionPolicies[name]
	if !knownWorkflow {
		return result, fmt.Errorf("workflow %q has no permission policy", name)
	}
	if err := requireExactStringMap(rootFields["permissions"], expectedRootPermissions, "$.permissions"); err != nil {
		return result, err
	}
	if err := requireScalarValue(rootFields["name"], expectedWorkflowNames[name], "$.name"); err != nil {
		return result, err
	}
	if err := verifyExactYAMLNode(rootFields["on"], expectedEventPolicies[name], "$.on"); err != nil {
		return result, err
	}
	if err := verifyExactYAMLNode(rootFields["concurrency"], expectedConcurrencyPolicies[name], "$.concurrency"); err != nil {
		return result, err
	}

	jobs, present := rootFields["jobs"]
	if !present {
		return result, errors.New("$.jobs is required")
	}
	jobFields, err := mappingFields(jobs, "$.jobs")
	if err != nil {
		return result, err
	}
	expectedJobs := expectedJobDisplayNames[name]
	expectedJobIDs := make([]string, 0, len(expectedJobs))
	for jobName := range expectedJobs {
		expectedJobIDs = append(expectedJobIDs, jobName)
	}
	sort.Strings(expectedJobIDs)
	for _, jobName := range expectedJobIDs {
		if _, present := jobFields[jobName]; !present {
			return result, fmt.Errorf("$.jobs.%s is required", jobName)
		}
	}

	for jobName, job := range jobFields {
		jobPath := "$.jobs." + jobName
		fields, err := mappingFields(job, jobPath)
		if err != nil {
			return result, err
		}
		if _, hasReusableWorkflow := fields["uses"]; hasReusableWorkflow {
			return result, fmt.Errorf("%s.uses is forbidden; governed jobs must define local steps", jobPath)
		}
		if _, hasDependency := fields["needs"]; hasDependency {
			return result, fmt.Errorf("%s.needs is forbidden on a governed workflow job", jobPath)
		}
		if _, toleratesFailure := fields["continue-on-error"]; toleratesFailure {
			return result, fmt.Errorf("%s.continue-on-error is forbidden on a governed workflow job", jobPath)
		}

		permissionPolicy, requiresJobPermissions := jobPermissionPolicies[name+"/"+jobName]
		permissions, hasJobPermissions := fields["permissions"]
		switch {
		case requiresJobPermissions:
			if err := requireExactStringMap(permissions, permissionPolicy, jobPath+".permissions"); err != nil {
				return result, err
			}
		case hasJobPermissions:
			return result, fmt.Errorf("%s.permissions is not an allowed permission override", jobPath)
		}

		expectedCondition, conditionAllowed := expectedJobConditions[name+"/"+jobName]
		condition, hasCondition := fields["if"]
		switch {
		case conditionAllowed:
			if err := requireScalarValue(condition, expectedCondition, jobPath+".if"); err != nil {
				return result, err
			}
		case hasCondition:
			return result, fmt.Errorf("%s.if is forbidden on a required workflow job", jobPath)
		}

		expectedDisplayName, governedJob := expectedJobs[jobName]
		if governedJob {
			jobPolicyKey := name + "/" + jobName
			if err := requireScalarValue(fields["name"], expectedDisplayName, jobPath+".name"); err != nil {
				return result, err
			}
			if err := requireScalarValue(fields["runs-on"], expectedJobRunners[jobPolicyKey], jobPath+".runs-on"); err != nil {
				return result, err
			}
			if err := requireScalarValue(fields["timeout-minutes"], expectedJobTimeouts[jobPolicyKey], jobPath+".timeout-minutes"); err != nil {
				return result, err
			}
			if expectedStrategy, hasStrategy := expectedJobStrategies[jobPolicyKey]; hasStrategy {
				if err := verifyExactYAMLNode(fields["strategy"], expectedStrategy, jobPath+".strategy"); err != nil {
					return result, err
				}
			}
			if err := requireExactFields(fields, expectedJobFields[jobPolicyKey], jobPath, "governed workflow job"); err != nil {
				return result, err
			}
		}

		steps, hasSteps := fields["steps"]
		if !hasSteps {
			continue
		}
		if steps.Kind != yaml.SequenceNode {
			return result, fmt.Errorf("%s.steps must be a sequence", jobPath)
		}
		if expectedNames, governed := expectedWorkflowStepNames[name+"/"+jobName]; governed {
			if err := requireExactStepNames(steps, expectedNames, jobPath+".steps"); err != nil {
				return result, err
			}
		}
		for index, step := range steps.Content {
			stepPath := fmt.Sprintf("%s.steps[%d]", jobPath, index)
			stepFields, err := mappingFields(step, stepPath)
			if err != nil {
				return result, err
			}
			stepName := ""
			if nameNode, hasName := stepFields["name"]; hasName {
				stepName, err = scalarValue(nameNode, stepPath+".name")
				if err != nil {
					return result, err
				}
			}
			stepPolicyKey := name + "/" + jobName + "/" + stepName
			if policy, governed := expectedDCOStepPolicies[stepPolicyKey]; governed {
				if err := verifyExactStepPolicy(stepFields, policy, stepPath); err != nil {
					return result, err
				}
			}
			if policy, governed := expectedRunSteps[stepPolicyKey]; governed {
				if err := requireExactFields(stepFields, []string{"name", "run", "shell"}, stepPath, "policy-governed run step"); err != nil {
					return result, err
				}
				if err := requireScalarValue(stepFields["shell"], policy.shell, stepPath+".shell"); err != nil {
					return result, err
				}
				if err := requireScalarValue(stepFields["run"], policy.command, stepPath+".run"); err != nil {
					return result, err
				}
				if policy.role != "" {
					result.recordSecurityStep(policy.role)
				}
			}
			uses, hasUses := stepFields["uses"]
			expectedAction, actionExpected := expectedSupplyChainActions[stepPolicyKey]
			if !hasUses {
				if actionExpected {
					return result, fmt.Errorf("%s.uses must invoke %q", stepPath, expectedAction)
				}
				continue
			}
			if uses.Kind != yaml.ScalarNode {
				return result, fmt.Errorf("%s.uses must be a scalar", stepPath)
			}
			action, err := verifyActionReference(uses.Value, actionLocks)
			if err != nil {
				return result, fmt.Errorf("%s.uses: %w", stepPath, err)
			}
			if action == "" {
				continue
			}
			if actionExpected && action != expectedAction {
				return result, fmt.Errorf("%s.uses must invoke %q, got %q", stepPath, expectedAction, action)
			}
			if isPolicyGovernedAction(action) {
				expectedFields := []string{"name", "uses", "with"}
				if expectedTimeout, hasTimeout := policyActionTimeouts[stepPolicyKey]; hasTimeout {
					expectedFields = append(expectedFields, "timeout-minutes")
					if err := requireScalarValue(stepFields["timeout-minutes"], expectedTimeout, stepPath+".timeout-minutes"); err != nil {
						return result, err
					}
				}
				if err := requireExactFields(stepFields, expectedFields, stepPath, "policy-governed action step"); err != nil {
					return result, err
				}
				if stepName == "" {
					return result, fmt.Errorf("%s.name is required on a policy-governed action step", stepPath)
				}
			}
			result.actionSteps++

			switch action {
			case "actions/checkout":
				if err := requireMapEntry(stepFields["with"], "persist-credentials", "false", stepPath+".with"); err != nil {
					return result, err
				}
				checkoutPolicy, expectedCheckout := checkoutInputPolicies[name+"/"+jobName]
				if !expectedCheckout {
					return result, fmt.Errorf("%s places checkout outside an expected workflow job", stepPath)
				}
				if err := requireExactStringMap(stepFields["with"], checkoutPolicy, stepPath+".with"); err != nil {
					return result, err
				}
				result.recordCheckout(name + "/" + jobName)
			case trivyAction:
				if name != "supply-chain.yml" || jobName != "repository-scan" {
					return result, fmt.Errorf("%s places the Trivy step outside supply-chain.yml/repository-scan", stepPath)
				}
				if err := requireExactStringMap(stepFields["with"], trivyInputPolicy, stepPath+".with"); err != nil {
					return result, err
				}
				result.recordSecurityStep("trivy")
			case "actions/dependency-review-action":
				if name != "supply-chain.yml" || jobName != "dependency-review" {
					return result, fmt.Errorf("%s places dependency review outside its required job", stepPath)
				}
				if err := requireExactStringMap(stepFields["with"], dependencyReviewInputPolicy, stepPath+".with"); err != nil {
					return result, err
				}
				result.recordSecurityStep("dependency-review")
			case "actions/attest":
				if name != "supply-chain.yml" || jobName != "attest-source" {
					return result, fmt.Errorf("%s places source attestation outside its required job", stepPath)
				}
				stepName, err := scalarValue(stepFields["name"], stepPath+".name")
				if err != nil {
					return result, err
				}
				policy, expected := attestationInputPolicies[stepName]
				if !expected {
					return result, fmt.Errorf("%s has unexpected attestation name %q", stepPath, stepName)
				}
				if err := requireExactStringMap(stepFields["with"], policy, stepPath+".with"); err != nil {
					return result, err
				}
				result.recordSecurityStep("attestation/" + stepName)
			case "actions/upload-artifact":
				if name != "supply-chain.yml" || jobName != "sbom" {
					return result, fmt.Errorf("%s places retained SBOM artifacts outside supply-chain.yml/sbom", stepPath)
				}
				if err := requireExactStringMap(stepFields["with"], uploadArtifactInputPolicy, stepPath+".with"); err != nil {
					return result, err
				}
				result.recordSecurityStep("artifact-upload/sbom")
			case "github/codeql-action/init", "github/codeql-action/analyze":
				if name != "supply-chain.yml" || jobName != "codeql" {
					return result, fmt.Errorf("%s places CodeQL outside its required job", stepPath)
				}
				if err := requireExactStringMap(stepFields["with"], codeQLInputPolicies[action], stepPath+".with"); err != nil {
					return result, err
				}
				result.recordSecurityStep("codeql/" + strings.TrimPrefix(action, "github/codeql-action/"))
			}
		}
	}

	for policyPath := range jobPermissionPolicies {
		prefix := name + "/"
		if !strings.HasPrefix(policyPath, prefix) {
			continue
		}
		jobName := strings.TrimPrefix(policyPath, prefix)
		if _, present := jobFields[jobName]; !present {
			return result, fmt.Errorf("$.jobs.%s is required by the permission policy", jobName)
		}
	}
	actualJobIDs := make([]string, 0, len(jobFields))
	for jobName := range jobFields {
		actualJobIDs = append(actualJobIDs, jobName)
	}
	sort.Strings(actualJobIDs)
	for _, jobName := range actualJobIDs {
		if _, expected := expectedJobs[jobName]; !expected {
			return result, fmt.Errorf("$.jobs.%s is not an allowed workflow job", jobName)
		}
	}
	if err := requireExactFields(rootFields, []string{"concurrency", "jobs", "name", "on", "permissions"}, "$", "governed workflow"); err != nil {
		return result, err
	}
	return result, nil
}

func readActionLocks(root *os.Root, path string) (map[string]string, error) {
	contents, err := readBoundedFile(root, path)
	if err != nil {
		return nil, err
	}
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		return nil, errors.New("action lock must end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	if len(lines) < 2 || lines[0] != "action\tsha\tversion\tsource_url" {
		return nil, errors.New("unexpected action-lock header")
	}
	locks := make(map[string]string, len(lines)-1)
	for index, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return nil, fmt.Errorf("action-lock line %d must have four fields", index+2)
		}
		if _, duplicate := locks[fields[0]]; duplicate {
			return nil, fmt.Errorf("duplicate action lock %q", fields[0])
		}
		if !isLowerHexSHA(fields[1]) {
			return nil, fmt.Errorf("action lock %q has an invalid SHA", fields[0])
		}
		locks[fields[0]] = fields[1]
	}
	return locks, nil
}

func verifyActionReference(reference string, locks map[string]string) (string, error) {
	if strings.HasPrefix(reference, "./") {
		return "", fmt.Errorf("local action %q is forbidden in governed workflows", reference)
	}
	separator := strings.LastIndex(reference, "@")
	if separator <= 0 || separator == len(reference)-1 {
		return "", fmt.Errorf("action ref %q must contain an immutable revision", reference)
	}
	action := reference[:separator]
	sha := reference[separator+1:]
	expectedSHA, locked := locks[action]
	if !locked {
		return "", fmt.Errorf("action %q is not registered in actions-lock.tsv", action)
	}
	if !isLowerHexSHA(sha) {
		return "", fmt.Errorf("action %q ref is not a full lowercase commit ID", action)
	}
	if sha != expectedSHA {
		return "", fmt.Errorf("action %q ref differs from its lock", action)
	}
	return action, nil
}

func isLowerHexSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func verifyExactYAMLFile(root *os.Root, path, expected string) error {
	contents, err := readBoundedFile(root, path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	actualNode, err := decodeWorkflow(contents)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := validateNode(actualNode, "$"); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return verifyExactYAMLNode(actualNode, expected, path)
}

func verifyExactYAMLNode(actualNode *yaml.Node, expected, path string) error {
	if actualNode == nil {
		return fmt.Errorf("%s is required", path)
	}
	expectedNode, err := decodeWorkflow([]byte(expected))
	if err != nil {
		return fmt.Errorf("embedded policy for %s: %w", path, err)
	}
	if err := validateNode(expectedNode, "$"); err != nil {
		return fmt.Errorf("embedded policy for %s: %w", path, err)
	}
	actualValue, err := normalizedYAML(actualNode, "$")
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	expectedValue, err := normalizedYAML(expectedNode, "$")
	if err != nil {
		return fmt.Errorf("embedded policy for %s: %w", path, err)
	}
	if !reflect.DeepEqual(actualValue, expectedValue) {
		return fmt.Errorf("%s differs from required effective policy", path)
	}
	return nil
}

type scalarPolicyValue struct {
	tag   string
	value string
}

func normalizedYAML(node *yaml.Node, path string) (any, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		return scalarPolicyValue{tag: node.Tag, value: node.Value}, nil
	case yaml.SequenceNode:
		values := make([]any, 0, len(node.Content))
		for index, child := range node.Content {
			value, err := normalizedYAML(child, fmt.Sprintf("%s[%d]", path, index))
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return values, nil
	case yaml.MappingNode:
		fields, err := mappingFields(node, path)
		if err != nil {
			return nil, err
		}
		values := make(map[string]any, len(fields))
		for key, child := range fields {
			value, err := normalizedYAML(child, path+"."+key)
			if err != nil {
				return nil, err
			}
			values[key] = value
		}
		return values, nil
	default:
		return nil, fmt.Errorf("%s has unsupported YAML node kind %d", path, node.Kind)
	}
}

func requireMapEntry(node *yaml.Node, key, expected, path string) error {
	fields, err := mappingFields(node, path)
	if err != nil {
		return err
	}
	value, present := fields[key]
	if !present {
		return fmt.Errorf("%s.%s is required", path, key)
	}
	return requireScalarValue(value, expected, path+"."+key)
}

func requireExactStepNames(node *yaml.Node, expected []string, path string) error {
	if len(node.Content) != len(expected) {
		return fmt.Errorf("%s must contain exactly %d governed steps, found %d", path, len(expected), len(node.Content))
	}
	for index, step := range node.Content {
		fields, err := mappingFields(step, fmt.Sprintf("%s[%d]", path, index))
		if err != nil {
			return err
		}
		if err := requireScalarValue(fields["name"], expected[index], fmt.Sprintf("%s[%d].name", path, index)); err != nil {
			return err
		}
	}
	return nil
}

func requireExactFields(fields map[string]*yaml.Node, expected []string, path, label string) error {
	expectedSet := make(map[string]struct{}, len(expected))
	for _, field := range expected {
		expectedSet[field] = struct{}{}
		if _, present := fields[field]; !present {
			return fmt.Errorf("%s.%s is required on a %s", path, field, label)
		}
	}
	actual := make([]string, 0, len(fields))
	for field := range fields {
		actual = append(actual, field)
	}
	sort.Strings(actual)
	for _, field := range actual {
		if _, allowed := expectedSet[field]; !allowed {
			return fmt.Errorf("%s.%s is forbidden on a %s", path, field, label)
		}
	}
	return nil
}

func verifyExactStepPolicy(fields map[string]*yaml.Node, policy exactStepPolicy, path string) error {
	if err := requireExactFields(fields, policy.fields, path, "exact policy step"); err != nil {
		return err
	}
	if err := verifyExactScalars(fields, policy.scalars, policy.scalarDigests, path); err != nil {
		return err
	}
	mapNames := make([]string, 0, len(policy.maps))
	for name := range policy.maps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	for _, name := range mapNames {
		mapPolicy := policy.maps[name]
		mapPath := path + "." + name
		mapFields, err := mappingFields(fields[name], mapPath)
		if err != nil {
			return err
		}
		if err := requireExactFields(mapFields, mapPolicy.fields, mapPath, "exact policy map"); err != nil {
			return err
		}
		if err := verifyExactScalars(mapFields, mapPolicy.scalars, mapPolicy.scalarDigests, mapPath); err != nil {
			return err
		}
	}
	return nil
}

func verifyExactScalars(fields map[string]*yaml.Node, expected map[string]scalarPolicyValue, digests map[string]string, path string) error {
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := requireExactScalar(fields[name], expected[name], path+"."+name); err != nil {
			return err
		}
	}
	digestNames := make([]string, 0, len(digests))
	for name := range digests {
		digestNames = append(digestNames, name)
	}
	sort.Strings(digestNames)
	for _, name := range digestNames {
		if err := requireScalarDigest(fields[name], digests[name], path+"."+name); err != nil {
			return err
		}
	}
	return nil
}

func requireExactScalar(node *yaml.Node, expected scalarPolicyValue, path string) error {
	if node == nil || node.Kind != yaml.ScalarNode {
		return fmt.Errorf("%s must be a scalar", path)
	}
	actual := scalarPolicyValue{tag: node.Tag, value: node.Value}
	if actual != expected {
		return fmt.Errorf("%s differs from required scalar policy", path)
	}
	return nil
}

func requireScalarDigest(node *yaml.Node, expected, path string) error {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("%s must be a string scalar", path)
	}
	digest := sha256.Sum256([]byte(node.Value))
	if fmt.Sprintf("%x", digest) != expected {
		return fmt.Errorf("%s differs from required scalar digest", path)
	}
	return nil
}

func isPolicyGovernedAction(action string) bool {
	switch action {
	case "actions/checkout",
		"actions/dependency-review-action",
		"actions/attest",
		"actions/upload-artifact",
		"github/codeql-action/init",
		"github/codeql-action/analyze",
		trivyAction:
		return true
	default:
		return false
	}
}

func requireScalarValue(node *yaml.Node, expected, path string) error {
	actual, err := scalarValue(node, path)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("%s must equal %q, got %q", path, expected, actual)
	}
	return nil
}

func scalarValue(node *yaml.Node, path string) (string, error) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("%s must be a scalar", path)
	}
	return node.Value, nil
}

func decodeWorkflow(contents []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode YAML: %w", err)
	}
	if len(document.Content) != 1 {
		return nil, errors.New("workflow must contain one YAML document")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("decode trailing YAML: %w", err)
		}
		return nil, errors.New("multiple YAML documents are forbidden")
	}
	return document.Content[0], nil
}

func validateNode(node *yaml.Node, path string) error {
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("%s: YAML aliases are forbidden", path)
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("%s: malformed mapping", path)
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("%s: mapping keys must be strings", path)
			}
			if key.Value == "<<" {
				return fmt.Errorf("%s: YAML merge keys are forbidden", path)
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("%s: duplicate mapping key %q", path, key.Value)
			}
			seen[key.Value] = struct{}{}
			if err := validateNode(node.Content[index+1], path+"."+key.Value); err != nil {
				return err
			}
		}
		return nil
	}
	for index, child := range node.Content {
		if err := validateNode(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
			return err
		}
	}
	return nil
}

func mappingFields(node *yaml.Node, path string) (map[string]*yaml.Node, error) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s must be a mapping", path)
	}
	fields := make(map[string]*yaml.Node, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		fields[node.Content[index].Value] = node.Content[index+1]
	}
	return fields, nil
}

func requireExactStringMap(node *yaml.Node, expected map[string]string, path string) error {
	fields, err := mappingFields(node, path)
	if err != nil {
		return err
	}
	actual := make(map[string]string, len(fields))
	for key, value := range fields {
		if value.Kind != yaml.ScalarNode {
			return fmt.Errorf("%s.%s must be a scalar", path, key)
		}
		actual[key] = value.Value
	}
	if !equalStringMaps(actual, expected) {
		return fmt.Errorf("%s differs from required policy: got %s, want %s", path, formatStringMap(actual), formatStringMap(expected))
	}
	return nil
}

func equalStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func formatStringMap(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, values[key]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}
