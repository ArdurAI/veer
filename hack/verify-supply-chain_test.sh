#!/bin/sh
set -eu

script_dir=$(
  unset CDPATH
  cd -- "$(dirname -- "$0")"
  pwd -P
)
repo_root=$(
  unset CDPATH
  cd -- "$script_dir/.."
  pwd -P
)
fixture_base=${TMPDIR:-/tmp}
fixture_root=$(mktemp -d "$fixture_base/veer-supply-chain.XXXXXX")
case "$fixture_root" in
  "$fixture_base"/veer-supply-chain.*) ;;
  *)
    printf '%s\n' "veer-supply-chain-test: unsafe temporary path $fixture_root" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -rf -- "$fixture_root"
}
trap cleanup 0 1 2 15

fail() {
  printf '%s\n' "veer-supply-chain-test: $*" >&2
  exit 1
}

new_fixture() {
  test_root="$fixture_root/repository"
  case "$test_root" in
    "$fixture_root"/repository) ;;
    *) fail "unsafe reusable fixture path $test_root" ;;
  esac
  rm -rf -- "$test_root"
  mkdir -p \
    "$test_root/api" \
    "$test_root/hack/branchprotection" \
    "$test_root/hack/workflowpolicy" \
    "$test_root/internal" \
    "$test_root/hack" \
    "$test_root/vendor/github.com/go-jose/go-jose/v4" \
    "$test_root/vendor/go.yaml.in"
  cp -R "$repo_root/.github" "$test_root/.github"
  cp "$repo_root/.gitattributes" "$test_root/.gitattributes"
  cp "$repo_root/.trivyignore.yaml" "$test_root/.trivyignore.yaml"
  cp "$repo_root/go.mod" "$test_root/go.mod"
  cp "$repo_root/hack/dev" "$test_root/hack/dev"
  cp "$repo_root/hack/branchprotection/main.go" "$test_root/hack/branchprotection/main.go"
  cp "$repo_root/hack/workflowpolicy/main.go" "$test_root/hack/workflowpolicy/main.go"
  cp "$repo_root/hack/verify-online-sources.sh" "$test_root/hack/verify-online-sources.sh"
  cp "$repo_root/hack/verify-supply-chain.sh" "$test_root/hack/verify-supply-chain.sh"
  cp "$repo_root/vendor/modules.txt" "$test_root/vendor/modules.txt"
  cp "$repo_root/vendor/github.com/go-jose/go-jose/v4/LICENSE" \
    "$test_root/vendor/github.com/go-jose/go-jose/v4/LICENSE"
  cp -R "$repo_root/vendor/go.yaml.in/yaml" "$test_root/vendor/go.yaml.in/yaml"
  ln -s "$repo_root/.tools" "$test_root/.tools"
  suppression_tab=$(printf '\t')
  while IFS="$suppression_tab" read -r suppression_id _ suppression_scope _ _ _; do
    [ "$suppression_id" != id ] || continue
    mkdir -p -- "$test_root/$(dirname -- "$suppression_scope")"
    cp "$repo_root/$suppression_scope" "$test_root/$suppression_scope"
  done <"$repo_root/.github/gosec-suppressions.tsv"
}

replace_once() {
  relative_file=$1
  target=$2
  replacement=$3
  source_file="$test_root/$relative_file"
  rewritten_file="$fixture_root/rewritten"
  LC_ALL=C awk -v target="$target" -v replacement="$replacement" '
    !changed && (position = index($0, target)) {
        $0 = substr($0, 1, position - 1) replacement \
            substr($0, position + length(target))
        changed = 1
    }
    { print }
    END { exit changed ? 0 : 1 }
  ' "$source_file" >"$rewritten_file" || fail "fixture target not found: $target"
  mv "$rewritten_file" "$source_file"
}

insert_after_once() {
  relative_file=$1
  target=$2
  inserted=$3
  source_file="$test_root/$relative_file"
  rewritten_file="$fixture_root/rewritten"
  LC_ALL=C awk -v target="$target" -v inserted="$inserted" '
    { print }
    !changed && $0 == target {
        print inserted
        changed = 1
    }
    END { exit changed ? 0 : 1 }
  ' "$source_file" >"$rewritten_file" || fail "fixture target not found: $target"
  mv "$rewritten_file" "$source_file"
}

expect_rejection() {
  case_name=$1
  expected_text=$2
  set +e
  output=$("$test_root/hack/verify-supply-chain.sh" 2>&1)
  status=$?
  set -e
  [ "$status" -ne 0 ] || fail "$case_name unexpectedly passed"
  case "$output" in
    *"$expected_text"*) ;;
    *) fail "$case_name produced an unexpected failure: $output" ;;
  esac
}

"$script_dir/verify-supply-chain.sh" >/dev/null

codeql_runner_temp="$fixture_root/codeql-runner"
codeql_wrapper="$codeql_runner_temp/codeql-action-go-tracing/bin/go"
mkdir -p -- "$(dirname -- "$codeql_wrapper")"
printf '#!/bin/bash\n\nexec %s "$@"' "$repo_root/.tools/bin/go" >"$codeql_wrapper"
chmod 0700 "$codeql_wrapper"
GITHUB_ACTIONS=true \
  RUNNER_OS=Linux \
  RUNNER_TEMP="$codeql_runner_temp" \
  CODEQL_ACTION_GO_BINARY="$codeql_wrapper" \
  "$repo_root/hack/dev" _codeql-build >/dev/null

printf '#!/bin/bash\n\nexec /usr/bin/false "$@"' >"$codeql_wrapper"
set +e
output=$(
  GITHUB_ACTIONS=true \
    RUNNER_OS=Linux \
    RUNNER_TEMP="$codeql_runner_temp" \
    CODEQL_ACTION_GO_BINARY="$codeql_wrapper" \
    "$repo_root/hack/dev" _codeql-build 2>&1
)
status=$?
set -e
[ "$status" -ne 0 ] || fail 'tampered CodeQL Go wrapper unexpectedly passed'
case "$output" in
  *'CodeQL Go wrapper does not delegate exactly to the pinned toolchain'*) ;;
  *) fail "tampered CodeQL Go wrapper produced an unexpected failure: $output" ;;
esac

gitlink_root="$fixture_root/gitlink-repository"
mkdir -p "$gitlink_root"
git -C "$gitlink_root" init -q
printf '%s\n' 'gitlink fixture' >"$gitlink_root/README.md"
git -C "$gitlink_root" add README.md
GIT_AUTHOR_NAME='Veer fixture' \
  GIT_AUTHOR_EMAIL=info@ardur.ai \
  GIT_COMMITTER_NAME='Veer fixture' \
  GIT_COMMITTER_EMAIL=info@ardur.ai \
  git -C "$gitlink_root" -c commit.gpgsign=false \
  commit -q -m 'test: seed gitlink fixture'
gitlink_target=$(git -C "$gitlink_root" rev-parse HEAD)
git -C "$gitlink_root" update-index --add --cacheinfo \
  160000 "$gitlink_target" dependency
GIT_AUTHOR_NAME='Veer fixture' \
  GIT_AUTHOR_EMAIL=info@ardur.ai \
  GIT_COMMITTER_NAME='Veer fixture' \
  GIT_COMMITTER_EMAIL=info@ardur.ai \
  git -C "$gitlink_root" -c commit.gpgsign=false \
  commit -q -m 'test: add gitlink fixture'
gitlink_tree=$(git -C "$gitlink_root" ls-tree -r HEAD)
printf '%s\n' "$gitlink_tree" | grep -q '^160000 ' ||
  fail 'mode-160000 Git submodule entry was not detected'

new_fixture
replace_once .github/workflows/bootstrap.yml \
  'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' \
  'actions/checkout@v7.0.1'
expect_rejection floating-action-ref 'action ref is not a full lowercase commit ID'

new_fixture
replace_once .github/workflows/bootstrap.yml \
  'uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' \
  'uses: evil/example@v1'
expect_rejection shorthand-floating-action-ref \
  'action ref is not a full lowercase commit ID: evil/example@v1'

new_fixture
printf '%s\n' \
  '  quoted-action-fixture:' \
  '    name: Quoted action fixture' \
  '    runs-on: ubuntu-24.04' \
  '    steps:' \
  '      - name: Invoke quoted external action' \
  '        "uses": evil/example@v1' \
  >>"$test_root/.github/workflows/bootstrap.yml"
expect_rejection quoted-floating-action-ref \
  'action "evil/example" is not registered in actions-lock.tsv'

new_fixture
replace_once .github/workflows/bootstrap.yml \
  'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' \
  'actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
expect_rejection unlocked-action-sha 'action SHA differs from actions-lock.tsv'

new_fixture
replace_once .github/actions-lock.tsv \
  'https://github.com/actions/attest/releases/tag/v4.2.2' \
  'https://github.com/evil/example/releases/tag/v4.2.2'
expect_rejection unrelated-action-source \
  'action source must equal canonical release URL https://github.com/actions/attest/releases/tag/v4.2.2'

new_fixture
printf '%s\n' 'permissions: write-all' >>"$test_root/.github/workflows/bootstrap.yml"
expect_rejection write-all-permission 'contains forbidden policy: write-all'

new_fixture
printf '%s\n' 'permissions: {issues: write}' >>"$test_root/.github/workflows/bootstrap.yml"
expect_rejection flow-mapping-write-permission 'permissions must use a block mapping'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  '      contents: read' '      "contents": write'
printf '%s\n' 'env:' '  security-events: write' \
  >>"$test_root/.github/workflows/supply-chain.yml"
expect_rejection quoted-write-permission \
  '$.jobs.codeql.permissions differs from required policy'

new_fixture
replace_once .github/workflows/bootstrap.yml 'persist-credentials: false' 'persist-credentials: true'
expect_rejection persisted-checkout-credential \
  'must disable credential persistence for every checkout'

new_fixture
replace_once .github/workflows/bootstrap.yml \
  'persist-credentials: false' 'persist-credentials: true'
printf '%s\n' \
  'env:' \
  '  persist-credentials: false' >>"$test_root/.github/workflows/bootstrap.yml"
expect_rejection misplaced-checkout-credential-guard \
  'persist-credentials must equal "false", got "true"'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  'scanners: vuln,misconfig,secret,license' 'scanners: vuln,secret'
printf '%s\n' '# scanners: vuln,misconfig,secret,license' \
  >>"$test_root/.github/workflows/supply-chain.yml"
expect_rejection missing-container-iac-license-scanners \
  'missing required active policy: scanners: vuln,misconfig,secret,license'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  'severity: UNKNOWN,MEDIUM,HIGH,CRITICAL' 'severity: CRITICAL'
printf '%s\n' 'env:' '  severity: UNKNOWN,MEDIUM,HIGH,CRITICAL' \
  >>"$test_root/.github/workflows/supply-chain.yml"
expect_rejection misplaced-trivy-severity \
  '$.jobs.repository-scan.steps[1].with differs from required policy'

new_fixture
insert_after_once .github/workflows/supply-chain.yml \
  '  repository-scan:' "    if: \${{ false }}"
expect_rejection skipped-repository-scan-job \
  '$.jobs.repository-scan.if is forbidden on a required workflow job'

new_fixture
insert_after_once .github/workflows/supply-chain.yml \
  '  repository-scan:' '    needs: attest-source'
expect_rejection dependent-repository-scan-job \
  '$.jobs.repository-scan.needs is forbidden on a governed workflow job'

new_fixture
insert_after_once .github/workflows/supply-chain.yml \
  '  repository-scan:' '    continue-on-error: true'
expect_rejection nonfatal-repository-scan-job \
  '$.jobs.repository-scan.continue-on-error is forbidden on a governed workflow job'

new_fixture
replace_once .github/workflows/bootstrap.yml \
  '    runs-on: ubuntu-24.04' '    runs-on: ubuntu-latest'
expect_rejection mutable-bootstrap-runner \
  '$.jobs.clean-bootstrap.runs-on must equal "ubuntu-24.04", got "ubuntu-latest"'

new_fixture
replace_once .github/workflows/bootstrap.yml \
  '          - label: Linux arm64' '          - label: Linux arm64 duplicate'
expect_rejection collapsed-platform-matrix \
  '$.jobs.supported-platforms.strategy differs from required effective policy'

new_fixture
replace_once .github/workflows/bootstrap.yml \
  '    timeout-minutes: 15' '    timeout-minutes: 1'
expect_rejection shortened-bootstrap-timeout \
  '$.jobs.clean-bootstrap.timeout-minutes must equal "15", got "1"'

new_fixture
insert_after_once .github/workflows/supply-chain.yml \
  '        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0' \
  "        if: \${{ false }}"
expect_rejection skipped-repository-scan-step \
  '$.jobs.repository-scan.steps[1].if is forbidden on a policy-governed action step'

new_fixture
insert_after_once .github/workflows/bootstrap.yml \
  '        run: ./hack/dev check' "        if: \${{ false }}"
expect_rejection skipped-bootstrap-gate-step \
  '$.jobs.clean-bootstrap.steps[3].if is forbidden on a policy-governed run step'

new_fixture
printf '%s\n' \
  '      - name: Unmodeled DCO step' \
  '        shell: sh' \
  '        run: "true"' \
  >>"$test_root/.github/workflows/dco.yml"
expect_rejection added-dco-signoff-step \
  '$.jobs.signoff.steps must contain exactly 4 governed steps, found 5'

new_fixture
replace_once .github/workflows/dco.yml \
  "          VEER_DCO_VERIFICATION_OUTCOME: \${{ steps.verification.outcome }}" \
  '          VEER_DCO_VERIFICATION_OUTCOME: success'
expect_rejection false-dco-completion \
  '$.jobs.signoff.steps[3].env.VEER_DCO_VERIFICATION_OUTCOME differs from required scalar policy'

new_fixture
replace_once .github/workflows/dco.yml \
  "          ./hack/verify-dco.sh \"\$VEER_DCO_BASE_SHA\" \"\$VEER_DCO_HEAD_SHA\"" \
  '          true'
expect_rejection replaced-dco-verifier \
  '$.jobs.signoff.steps[2].run differs from required scalar digest'

new_fixture
insert_after_once .github/workflows/supply-chain.yml \
  '        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0' \
  '        continue-on-error: true'
expect_rejection nonfatal-repository-scan-step \
  '$.jobs.repository-scan.steps[1].continue-on-error is forbidden on a policy-governed action step'

new_fixture
insert_after_once .github/workflows/supply-chain.yml \
  '          fetch-depth: 1' '          ref: main'
expect_rejection checkout-ref-override \
  '$.jobs.dependency-review.steps[0].with differs from required policy'

new_fixture
printf '%s\n' \
  '  external-reusable:' \
  '    "uses": evil/example/.github/workflows/pwn.yml@main' \
  >>"$test_root/.github/workflows/supply-chain.yml"
expect_rejection external-reusable-workflow \
  '$.jobs.external-reusable.uses is forbidden; governed jobs must define local steps'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  'run: ./hack/dev _codeql-build' 'run: ./hack/dev build'
expect_rejection untraced-codeql-build \
  'missing required active policy: run: ./hack/dev _codeql-build'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  'name: Bootstrap pinned build tools' 'name: Temporary CodeQL ordering marker'
replace_once .github/workflows/supply-chain.yml \
  'name: Select pinned Go for CodeQL' 'name: Bootstrap pinned build tools'
replace_once .github/workflows/supply-chain.yml \
  'name: Temporary CodeQL ordering marker' 'name: Select pinned Go for CodeQL'
expect_rejection codeql-bootstrap-after-init \
  'out-of-order policy marker: name: Select pinned Go for CodeQL'

new_fixture
insert_after_once .github/workflows/supply-chain.yml \
  '      - main' '    paths-ignore:'
insert_after_once .github/workflows/supply-chain.yml \
  '    paths-ignore:' '      - docs/**'
expect_rejection filtered-main-trigger \
  '$.on differs from required effective policy'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  "cancel-in-progress: \${{ github.ref != 'refs/heads/main' }}" \
  'cancel-in-progress: true'
insert_after_once .github/workflows/supply-chain.yml \
  '  repository-scan:' \
  "    concurrency:\n      group: relocated-policy-decoy\n      cancel-in-progress: \${{ github.ref != 'refs/heads/main' }}"
expect_rejection cancelable-main-provenance \
  '$.concurrency differs from required effective policy'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  '    name: Repository scan' '    name: Unprotected repository scan'
printf '%s\n' \
  '  protected-name-decoy:' \
  '    name: Repository scan' \
  '    runs-on: ubuntu-24.04' \
  '    steps:' \
  '      - name: Decoy success' \
  '        run: "true"' \
  >>"$test_root/.github/workflows/supply-chain.yml"
expect_rejection protected-context-name-decoy \
  '$.jobs.repository-scan.name must equal "Repository scan", got "Unprotected repository scan"'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  'run: ./hack/dev bootstrap syft' 'run: ./hack/dev bootstrap'
expect_rejection unpinned-syft-bootstrap \
  'must contain exactly two checksum-pinned Syft bootstraps'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  'SYFT_CHECK_FOR_APP_UPDATE=false ./.tools/bin/syft scan' \
  'syft scan'
expect_rejection unpinned-syft-execution \
  'must contain exactly two pinned source-archive Syft scans'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  "subject-path: dist/veer-source-\${{ github.sha }}.tar" \
  'subject-path: go.mod'
expect_rejection misplaced-provenance-subject \
  '$.jobs.attest-source.steps[4].with differs from required policy'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  'name: Attest source SBOM' 'name: Attest source provenance'
replace_once .github/workflows/supply-chain.yml \
  '          sbom-path: dist/veer-source.spdx.json' \
  '          # sbom-path moved to unrelated workflow metadata'
printf '%s\n' \
  'env:' \
  '  sbom-path: dist/veer-source.spdx.json' \
  >>"$test_root/.github/workflows/supply-chain.yml"
expect_rejection duplicate-provenance-attestation \
  '$.jobs.attest-source.steps[5].name must equal "Attest source SBOM", got "Attest source provenance"'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  "git archive --format=tar --output \"dist/veer-source-\${GITHUB_SHA}.tar\" HEAD" \
  "tar -cf \"dist/veer-source-\${GITHUB_SHA}.tar\" go.mod"
expect_rejection partial-source-archive \
  '$.jobs.sbom.steps[2].run must equal'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  "git_tree=\$(git ls-tree -r HEAD)" \
  'git_tree='
expect_rejection missing-gitlink-guard \
  '$.jobs.sbom.steps[2].run must equal'

new_fixture
printf '%s\n' 'go.mod export-ignore' >>"$test_root/.gitattributes"
expect_rejection filtered-source-archive \
  'archive-affecting Git attribute export-ignore is forbidden'

new_fixture
mkdir -p "$test_root/internal/fixture"
printf '%s\n' '*.go export-subst' >"$test_root/internal/fixture/.gitattributes"
expect_rejection substituted-source-archive \
  'archive-affecting Git attribute export-subst is forbidden'

new_fixture
mkdir -p "$test_root/.github/actions/fixture"
printf '%s\n' \
  'name: Nested action fixture' \
  'description: Exercises governed local-action rejection' \
  'runs:' \
  '  using: composite' \
  '  steps:' \
  '    - shell: sh' \
  '      run: "true"' \
  >"$test_root/.github/actions/fixture/action.yml"
printf '%s\n' \
  '  local-action-fixture:' \
  '    name: Local action fixture' \
  '    runs-on: ubuntu-24.04' \
  '    steps:' \
  '      - name: Invoke local fixture' \
  '        uses: ./.github/actions/fixture' \
  >>"$test_root/.github/workflows/bootstrap.yml"
expect_rejection governed-local-action \
  'local action "./.github/actions/fixture" is forbidden in governed workflows'

new_fixture
replace_once .github/workflows/supply-chain.yml \
  '            dist/veer-source.spdx.json' ''
expect_rejection incomplete-retained-sbom-artifact \
  '$.jobs.sbom.steps[4].with differs from required policy'

new_fixture
replace_once .github/workflows/supply-chain.yml 'retention-days: 30' 'retention-days: 1'
expect_rejection shortened-sbom-retention 'missing required active policy: retention-days: 30'

new_fixture
replace_once .github/dependency-review-config.yml \
  'fail-on-severity: moderate' 'fail-on-severity: critical'
expect_rejection weakened-dependency-severity \
  'missing required policy: fail-on-severity: moderate'

new_fixture
replace_once .github/dependency-review-config.yml 'warn-only: false' 'warn-only: true'
expect_rejection warning-only-dependency-review 'missing required policy: warn-only: false'

new_fixture
replace_once .github/dependency-review-config.yml 'warn-only: false' 'warn-only: true'
printf '%s\n' '# warn-only: false' \
  >>"$test_root/.github/dependency-review-config.yml"
expect_rejection commented-dependency-review-policy \
  '.github/dependency-review-config.yml differs from required effective policy'

new_fixture
replace_once .github/dependabot.yml 'interval: weekly' 'interval: monthly'
expect_rejection monthly-go-dependabot-schedule \
  '.github/dependabot.yml differs from required effective policy'

new_fixture
replace_once .github/branch-protection.json \
  '"required_approving_review_count": 1' '"required_approving_review_count": 0'
expect_rejection missing-independent-approval \
  'policy differs from required effective policy'

new_fixture
replace_once .github/branch-protection.json \
  '"allow_force_pushes": false' '"allow_force_pushes": true'
expect_rejection enabled-force-push 'policy differs from required effective policy'

new_fixture
replace_once .github/branch-protection.json \
  '"app_id": 15368' '"app_id": -1'
expect_rejection unbound-required-check-app 'policy differs from required effective policy'

new_fixture
insert_after_once .github/branch-protection.json \
  '    "strict": true,' \
  '    "contexts": [],'
expect_rejection legacy-required-status-contexts \
  'required_status_checks.contexts must be omitted'

new_fixture
replace_once .github/branch-protection.json \
  '"allow_fork_syncing": true' \
  '"allow_fork_syncing": true, "required_status_checks": null'
expect_rejection duplicate-branch-protection-key \
  'duplicate object key "required_status_checks"'

new_fixture
replace_once .trivyignore.yaml 'licenses: []' 'licenses:'
printf '%s\n' \
  '  - id: gocardless-api-token' \
  '    paths:' \
  '      - "docs/architecture/cost-model/verify-operational-bounds.awk"' \
  '    statement: owner=info@ardur.ai; reason=duplicate audit identity fixture' \
  '    expired_at: 2027-03-08' >>"$test_root/.trivyignore.yaml"
expect_rejection duplicate-suppression-identifier \
  'duplicate suppression identifier gocardless-api-token'

new_fixture
LC_ALL=C awk '
  /^vulnerabilities: \[\]$/ {
      print "vulnerabilities:"
      print "  - id: CVE-2099-0001"
      print "    paths:"
      print "      - \"go.mod\""
      print "    statement: reason=no owner"
      print "    expired_at: 2099-01-01"
      next
  }
  { print }
' "$test_root/.trivyignore.yaml" >"$fixture_root/rewritten"
mv "$fixture_root/rewritten" "$test_root/.trivyignore.yaml"
expect_rejection suppression-without-owner 'suppression statement requires owner and reason'

new_fixture
LC_ALL=C awk '
  /^vulnerabilities: \[\]$/ {
      print "vulnerabilities:"
      print "  - id: CVE-2099-0001"
      print "    paths:"
      print "      - \"go.mod\""
      print "    statement: owner=info@ardur.ai; reason=test fixture"
      print "    expired_at: 2026-09-08"
      next
  }
  { print }
' "$test_root/.trivyignore.yaml" >"$fixture_root/rewritten"
mv "$fixture_root/rewritten" "$test_root/.trivyignore.yaml"
expect_rejection expired-suppression 'suppression is expired or expires today'

new_fixture
LC_ALL=C awk '
  /^vulnerabilities: \[\]$/ {
      print "vulnerabilities:"
      print "  - id: CVE-2099-0001"
      print "    statement: owner=info@ardur.ai; reason=global exceptions are forbidden"
      print "    expired_at: 2099-01-01"
      next
  }
  { print }
' "$test_root/.trivyignore.yaml" >"$fixture_root/rewritten"
mv "$fixture_root/rewritten" "$test_root/.trivyignore.yaml"
expect_rejection suppression-without-path \
  'suppression requires at least one exact path before statement'

new_fixture
replace_once go.mod 'github.com/go-jose/go-jose/v4 v4.1.5' \
  'github.com/go-jose/go-jose/v4 v4.1.4'
expect_rejection vulnerable-jose-regression \
  'missing required policy: github.com/go-jose/go-jose/v4 v4.1.5'

new_fixture
replace_once go.mod 'go.yaml.in/yaml/v3 v3.0.5' \
  'go.yaml.in/yaml/v3 v3.0.4'
expect_rejection workflow-parser-version-regression \
  'missing required policy: go.yaml.in/yaml/v3 v3.0.5'

new_fixture
current_expiry=$(LC_ALL=C awk -F '\t' 'NR == 2 { print $5 }' \
  "$repo_root/.github/gosec-suppressions.tsv")
[ -n "$current_expiry" ] || fail 'cannot read current gosec suppression expiry'
replace_once .github/gosec-suppressions.tsv "$current_expiry" "$(date -u '+%Y-%m-%d')"
expect_rejection expired-gosec-suppression 'gosec suppression is expired or expires today'

new_fixture
printf '%s\n' '// #nosec G101 -- VEER-SEC-999: unregistered test annotation' \
  >"$test_root/hack/unregistered.go"
expect_rejection unregistered-gosec-annotation 'unregistered #nosec annotation VEER-SEC-999'

new_fixture
mkdir -p "$test_root/cmd/fixture"
printf '%s\n' \
  'package main' \
  '// #nosec G204 -- VEER-SEC-998: unregistered command annotation' \
  'func main() {}' >"$test_root/cmd/fixture/main.go"
expect_rejection unregistered-command-gosec-annotation \
  'cmd/fixture/main.go: unregistered #nosec annotation VEER-SEC-998'

new_fixture
replace_once internal/core/service/credentialbroker/state.go \
  '#nosec G115 -- VEER-SEC-001:' '#security-reviewed G115 -- VEER-SEC-001:'
expect_rejection orphaned-gosec-registry-entry \
  'VEER-SEC-001 must appear in exactly one source annotation; found 0'

new_fixture
printf '%s\n' '//nolint:gosec' >>"$test_root/api/openapi/contract.go"
expect_rejection ungoverned-lint-annotation 'ungoverned lint suppression is forbidden'

new_fixture
replace_once hack/dev \
  '    ./...' \
  '    -exclude-generated ./...'
expect_rejection excluded-generated-go \
  'contains forbidden policy: -exclude-generated'

printf '%s\n' 'veer-supply-chain-tests cases=66 status=passed'
