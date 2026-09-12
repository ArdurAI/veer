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
workflow_dir="$repo_root/.github/workflows"
action_lock="$repo_root/.github/actions-lock.tsv"
branch_policy="$repo_root/.github/branch-protection.json"
dependency_config="$repo_root/.github/dependency-review-config.yml"
dependabot_config="$repo_root/.github/dependabot.yml"
gosec_suppressions="$repo_root/.github/gosec-suppressions.tsv"
trivy_ignore="$repo_root/.trivyignore.yaml"
dev_script="$repo_root/hack/dev"
branch_verifier="$repo_root/hack/branchprotection/main.go"
workflow_verifier="$repo_root/hack/workflowpolicy/main.go"
online_verifier="$repo_root/hack/verify-online-sources.sh"
supply_chain_doc="$repo_root/docs/security/supply-chain.md"

fail() {
  printf '%s\n' "veer-supply-chain: $*" >&2
  exit 1
}

require_regular_file() {
  [ -f "$1" ] && [ ! -L "$1" ] || fail "required input is not a regular non-symlink file: $1"
}

require_text() {
  checked_file=$1
  required_text=$2
  grep -Fq -- "$required_text" "$checked_file" ||
    fail "$checked_file is missing required policy: $required_text"
}

active_yaml_line_numbers() {
  checked_file=$1
  required_text_value=$2
  LC_ALL=C awk -v required="$required_text_value" '
    {
        line = $0
        sub(/^[[:space:]]*/, "", line)
        sub(/^-[[:space:]]+/, "", line)
        if (line ~ /^#/) {
            next
        }
        sub(/[[:space:]]+#.*$/, "", line)
        sub(/[[:space:]]*$/, "", line)
        if (line == required) {
            print FNR
        }
    }
  ' "$checked_file"
}

require_active_yaml_text() {
  checked_file=$1
  required_text_value=$2
  matches=$(active_yaml_line_numbers "$checked_file" "$required_text_value")
  [ -n "$matches" ] ||
    fail "$checked_file is missing required active policy: $required_text_value"
}

require_ordered_text() {
  checked_file=$1
  shift
  previous_line=0
  for required_text_value; do
    matches=$(active_yaml_line_numbers "$checked_file" "$required_text_value")
    match_count=$(printf '%s\n' "$matches" | LC_ALL=C awk 'NF { count++ } END { print count + 0 }')
    [ "$match_count" -eq 1 ] ||
      fail "$checked_file must contain exactly one ordered policy marker: $required_text_value"
    current_line=${matches%%:*}
    [ "$current_line" -gt "$previous_line" ] ||
      fail "$checked_file has an out-of-order policy marker: $required_text_value"
    previous_line=$current_line
  done
}

reject_text() {
  checked_file=$1
  forbidden_text=$2
  if grep -Fq -- "$forbidden_text" "$checked_file"; then
    fail "$checked_file contains forbidden policy: $forbidden_text"
  fi
}

for required_file in \
  "$repo_root/.gitattributes" \
  "$action_lock" \
  "$branch_policy" \
  "$dependency_config" \
  "$dependabot_config" \
  "$dev_script" \
  "$branch_verifier" \
  "$workflow_verifier" \
  "$online_verifier" \
  "$supply_chain_doc" \
  "$gosec_suppressions" \
  "$trivy_ignore" \
  "$workflow_dir/bootstrap.yml" \
  "$workflow_dir/dco.yml" \
  "$workflow_dir/supply-chain.yml"; do
  require_regular_file "$required_file"
done

set --
for workflow_file in "$workflow_dir"/*.yml "$workflow_dir"/*.yaml; do
  [ -e "$workflow_file" ] || continue
  require_regular_file "$workflow_file"
  set -- "$@" "$workflow_file"
done
[ "$#" -eq 3 ] || fail "expected exactly three workflow files, found $#"

LC_ALL=C awk -F '\t' '
NR == FNR {
    if (FNR == 1) {
        if ($0 != "action\tsha\tversion\tsource_url") {
            print FILENAME ": unexpected action-lock header" > "/dev/stderr"
            failed = 1
        }
        next
    }
    if (NF != 4) {
        print FILENAME ":" FNR ": expected four tab-separated fields" > "/dev/stderr"
        failed = 1
        next
    }
    if ($1 !~ /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.\/-]+$/ || $1 ~ /\/\.\.?\//) {
        print FILENAME ":" FNR ": invalid action path " $1 > "/dev/stderr"
        failed = 1
    }
    if (length($2) != 40 || $2 !~ /^[0-9a-f]+$/) {
        print FILENAME ":" FNR ": action SHA is not a full lowercase commit ID" > "/dev/stderr"
        failed = 1
    }
    if ($3 !~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/) {
        print FILENAME ":" FNR ": invalid release annotation" > "/dev/stderr"
        failed = 1
    }
    split($1, action_path, "/")
    expected_source = "https://github.com/" action_path[1] "/" action_path[2] "/releases/tag/" $3
    if ($4 != expected_source) {
        print FILENAME ":" FNR ": action source must equal canonical release URL " expected_source > "/dev/stderr"
        failed = 1
    }
    if ($1 in locked_sha) {
        print FILENAME ":" FNR ": duplicate action lock " $1 > "/dev/stderr"
        failed = 1
    }
    locked_sha[$1] = $2
    lock_count++
    next
}

{
    line = $0
    sub(/^[[:space:]]*/, "", line)
    sub(/^-[[:space:]]+/, "", line)
    if (line !~ /^uses:[[:space:]]*/) {
        next
    }
    sub(/^uses:[[:space:]]*/, "", line)
    sub(/[[:space:]]*#.*/, "", line)
    sub(/[[:space:]]*$/, "", line)
    if (line ~ /^\.\//) {
        next
    }
    if (split(line, reference, "@") != 2 || reference[1] == "" || reference[2] == "") {
        print FILENAME ":" FNR ": external action must have one immutable ref: " line > "/dev/stderr"
        failed = 1
        next
    }
    action = reference[1]
    sha = reference[2]
    if (length(sha) != 40 || sha !~ /^[0-9a-f]+$/) {
        print FILENAME ":" FNR ": action ref is not a full lowercase commit ID: " line > "/dev/stderr"
        failed = 1
        next
    }
    if (!(action in locked_sha)) {
        print FILENAME ":" FNR ": action is absent from actions-lock.tsv: " action > "/dev/stderr"
        failed = 1
        next
    }
    if (locked_sha[action] != sha) {
        print FILENAME ":" FNR ": action SHA differs from actions-lock.tsv: " action > "/dev/stderr"
        failed = 1
    }
    used[action] = 1
    use_count++
}

END {
    for (action in locked_sha) {
        if (!(action in used)) {
            print ARGV[1] ": locked action is unused: " action > "/dev/stderr"
            failed = 1
        }
    }
    if (lock_count != 8) {
        print ARGV[1] ": expected eight locked actions, found " lock_count > "/dev/stderr"
        failed = 1
    }
    if (failed) {
        exit 1
    }
    print "veer-action-pins locked=" lock_count " uses=" use_count " status=passed"
}
' "$action_lock" "$@" || fail 'workflow action-lock verification failed'

for workflow_file in "$@"; do
  require_active_yaml_text "$workflow_file" 'permissions:'
  require_active_yaml_text "$workflow_file" 'contents: read'
  reject_text "$workflow_file" 'write-all'
  reject_text "$workflow_file" 'contents: write'
  reject_text "$workflow_file" 'pull-requests: write'
  reject_text "$workflow_file" 'packages: write'
  reject_text "$workflow_file" '@latest'
  reject_text "$workflow_file" ':latest'

  checkout_count=$(grep -Ec '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]+actions/checkout@[0-9a-f]{40}' "$workflow_file" || true)
  credential_guard_count=$(grep -Ec '^[[:space:]]*persist-credentials: false$' "$workflow_file" || true)
  [ "$checkout_count" -eq "$credential_guard_count" ] ||
    fail "$workflow_file must disable credential persistence for every checkout"

  workflow_name=${workflow_file##*/}
  LC_ALL=C awk -v workflow="$workflow_name" '
    {
        active = $0
        sub(/^[[:space:]]*/, "", active)
        if (active ~ /^#/) {
            next
        }
        sub(/[[:space:]]+#.*$/, "", active)
        sub(/[[:space:]]*$/, "", active)
        if (active ~ /^permissions:/ && active != "permissions:") {
            print FILENAME ":" FNR ": permissions must use a block mapping" > "/dev/stderr"
            failed = 1
        }
    }
    /^[[:space:]]+[a-z-]+:[[:space:]]+write[[:space:]]*$/ {
        permission = $0
        sub(/^[[:space:]]*/, "", permission)
        sub(/[[:space:]]*$/, "", permission)
        allowed = (workflow == "dco.yml" && permission == "checks: write") ||
            (workflow == "supply-chain.yml" &&
                (permission == "security-events: write" ||
                 permission == "id-token: write" ||
                 permission == "attestations: write"))
        if (!allowed) {
            print FILENAME ":" FNR ": unexpected write permission " permission > "/dev/stderr"
            failed = 1
        }
    }
    END { exit failed ? 1 : 0 }
  ' "$workflow_file" || fail "$workflow_file has an unexpected write permission"
done

bootstrap_workflow="$workflow_dir/bootstrap.yml"
for required_text_value in \
  'name: Clean checkout contract' \
  'name: Race and coverage' \
  'run: ./hack/dev race' \
  'run: ./hack/dev coverage' \
  "name: Supported platform (\${{ matrix.label }})" \
  'runner: ubuntu-24.04-arm' \
  'runner: macos-15' \
  'runner: macos-15-intel' \
  'run: ./hack/dev check' \
  'run: ./hack/verify-online-sources.sh' \
  'run: git diff --exit-code'; do
  require_active_yaml_text "$bootstrap_workflow" "$required_text_value"
done

supply_workflow="$workflow_dir/supply-chain.yml"
reject_text "$supply_workflow" 'pull_request_target:'
for required_text_value in \
  'name: Dependency review' \
  'config-file: ./.github/dependency-review-config.yml' \
  'name: Repository scan' \
  'scanners: vuln,misconfig,secret,license' \
  'severity: UNKNOWN,MEDIUM,HIGH,CRITICAL' \
  'exit-code: 1' \
  'trivyignores: .trivyignore.yaml' \
  'version: v0.74.0' \
  'cache: false' \
  "group: supply-chain-\${{ github.workflow }}-\${{ github.event_name }}-\${{ github.ref == 'refs/heads/main' && github.run_id || github.ref }}" \
  "cancel-in-progress: \${{ github.ref != 'refs/heads/main' }}" \
  'name: CodeQL' \
  'languages: go' \
  'build-mode: manual' \
  'run: ./hack/dev _codeql-build' \
  'name: SBOM' \
  'run: ./hack/dev bootstrap syft' \
  "run: SYFT_CHECK_FOR_APP_UPDATE=false ./.tools/bin/syft scan \"file:dist/veer-source-\${GITHUB_SHA}.tar\" --output \"spdx-json=dist/veer-source.spdx.json\"" \
  'retention-days: 30' \
  'if-no-files-found: error' \
  'name: Source provenance' \
  "if: github.event_name == 'push' && github.ref == 'refs/heads/main'" \
  'id-token: write' \
  'attestations: write' \
  "subject-path: dist/veer-source-\${{ github.sha }}.tar" \
  'sbom-path: dist/veer-source.spdx.json'; do
  require_active_yaml_text "$supply_workflow" "$required_text_value"
done
reject_text "$supply_workflow" 'run: ./hack/dev build'
syft_bootstraps=$(active_yaml_line_numbers "$supply_workflow" \
  'run: ./hack/dev bootstrap syft' | LC_ALL=C awk 'END { print NR + 0 }')
[ "$syft_bootstraps" -eq 2 ] ||
  fail "$supply_workflow must contain exactly two checksum-pinned Syft bootstraps"
syft_scans=$(active_yaml_line_numbers "$supply_workflow" \
  "run: SYFT_CHECK_FOR_APP_UPDATE=false ./.tools/bin/syft scan \"file:dist/veer-source-\${GITHUB_SHA}.tar\" --output \"spdx-json=dist/veer-source.spdx.json\"" |
  LC_ALL=C awk 'END { print NR + 0 }')
[ "$syft_scans" -eq 2 ] ||
  fail "$supply_workflow must contain exactly two pinned source-archive Syft scans"
require_ordered_text "$supply_workflow" \
  'name: Bootstrap pinned build tools' \
  'name: Select pinned Go for CodeQL' \
  'name: Initialize CodeQL' \
  'name: Build analyzed source' \
  'name: Analyze source'

for required_text_value in \
  "expected_codeql_go=\"\$RUNNER_TEMP/codeql-action-go-tracing/bin/go\"" \
  "expected_wrapper=\$(printf '#!/bin/bash\\n\\nexec %s \"\$@\"' \"\$bin_dir/go\")" \
  "[ \"\$actual_wrapper\" = \"\$expected_wrapper\" ]"; do
  require_text "$dev_script" "$required_text_value"
done
reject_text "$dev_script" '-exclude-generated'

for required_text_value in \
  'fail-on-severity: moderate' \
  'license-check: true' \
  'warn-only: false' \
  '  - Apache-2.0'; do
  require_text "$dependency_config" "$required_text_value"
done
reject_text "$dependency_config" 'allow-ghsas:'

for required_text_value in \
  'version: 2' \
  'package-ecosystem: gomod' \
  'vendor: true' \
  'package-ecosystem: github-actions' \
  'interval: weekly'; do
  require_text "$dependabot_config" "$required_text_value"
done

today=$(date -u '+%Y-%m-%d')
LC_ALL=C awk -v today="$today" '
function error(message) {
    print FILENAME ":" FNR ": " message > "/dev/stderr"
    failed = 1
}
function leap(year) {
    return (year % 400 == 0) || (year % 4 == 0 && year % 100 != 0)
}
function valid_date(value, parts, year, month, day, maximum) {
    if (value !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
        return 0
    }
    split(value, parts, "-")
    year = parts[1] + 0
    month = parts[2] + 0
    day = parts[3] + 0
    if (month < 1 || month > 12 || day < 1) {
        return 0
    }
    maximum = 31
    if (month == 4 || month == 6 || month == 9 || month == 11) {
        maximum = 30
    } else if (month == 2) {
        maximum = leap(year) ? 29 : 28
    }
    return day <= maximum
}
function finish_entry() {
    if (entry_state != 0) {
        error("suppression requires id, exact path, owner/reason statement, and expiry")
        entry_state = 0
    }
}
BEGIN {
    split("vulnerabilities misconfigurations secrets licenses", required, " ")
    entry_count = 0
}
/^(vulnerabilities|misconfigurations|secrets|licenses): \[\]$/ {
    finish_entry()
    category = $0
    sub(/:.*/, "", category)
    if (seen_category[category]++) {
        error("duplicate suppression category " category)
    }
    current_category = ""
    next
}
/^(vulnerabilities|misconfigurations|secrets|licenses):$/ {
    finish_entry()
    category = $0
    sub(/:$/, "", category)
    if (seen_category[category]++) {
        error("duplicate suppression category " category)
    }
    current_category = category
    next
}
/^  - id: / {
    finish_entry()
    if (current_category == "") {
        error("suppression entry is outside a category")
        next
    }
    current_id = substr($0, 9)
    if (current_id !~ /^[A-Za-z0-9][A-Za-z0-9._:-]*$/) {
        error("invalid suppression identifier")
    }
    if (seen_id[current_id]++) {
        error("duplicate suppression identifier " current_id)
    }
    key = current_category SUBSEP current_id
    if (seen_entry[key]++) {
        error("duplicate suppression " current_category "/" current_id)
    }
    entry_state = 1
    next
}
/^    paths:$/ {
    if (entry_state != 1) {
        error("suppression paths are out of order")
        next
    }
    entry_state = 2
    next
}
/^      - "/ {
    if (entry_state != 2 && entry_state != 3) {
        error("suppression path is out of order")
        next
    }
    if (substr($0, length($0), 1) != "\"") {
        error("suppression path must be double quoted")
        next
    }
    path = substr($0, 10, length($0) - 10)
    if (path !~ /^[A-Za-z0-9_.\/-]+$/ || path ~ /(^|\/)\.\.?(\/|$)/ ||
        path ~ /^\// || path ~ /\/\//) {
        error("suppression path must be one exact repository-relative path")
    }
    path_key = current_category SUBSEP current_id SUBSEP path
    if (seen_path[path_key]++) {
        error("duplicate suppression path " path)
    }
    entry_state = 3
    next
}
/^    statement: / {
    if (entry_state == 1 || entry_state == 2) {
        error("suppression requires at least one exact path before statement")
        next
    }
    if (entry_state != 3) {
        error("suppression statement is out of order")
        next
    }
    statement = substr($0, 16)
    separator = index(statement, "; reason=")
    if (separator == 0) {
        error("suppression statement requires owner and reason")
    } else {
        owner = substr(statement, 7, separator - 7)
        reason = substr(statement, separator + 9)
        if (substr(statement, 1, 6) != "owner=" ||
            owner != "info@ardur.ai" || reason == "") {
            error("suppression statement requires owner=info@ardur.ai; reason=nonempty")
        }
    }
    entry_state = 4
    next
}
/^    expired_at: / {
    if (entry_state != 4) {
        error("suppression expiry is out of order")
        next
    }
    expiry = substr($0, 17)
    if (!valid_date(expiry)) {
        error("suppression expiry is not a calendar date")
    } else if (expiry <= today) {
        error("suppression is expired or expires today: " current_id)
    }
    entry_state = 0
    entry_count++
    next
}
/^[[:space:]]*$/ { next }
{ error("unsupported suppression syntax") }
END {
    finish_entry()
    for (index_value in required) {
        if (!seen_category[required[index_value]]) {
            error("missing suppression category " required[index_value])
        }
    }
    if (failed) {
        exit 1
    }
    print "veer-suppressions active=" entry_count " status=passed"
}
' "$trivy_ignore" || fail 'suppression policy verification failed'

LC_ALL=C awk -F '\t' -v today="$today" '
function error(message) {
    print FILENAME ":" FNR ": " message > "/dev/stderr"
    failed = 1
}
function leap(year) {
    return (year % 400 == 0) || (year % 4 == 0 && year % 100 != 0)
}
function valid_date(value, parts, year, month, day, maximum) {
    if (value !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
        return 0
    }
    split(value, parts, "-")
    year = parts[1] + 0
    month = parts[2] + 0
    day = parts[3] + 0
    if (month < 1 || month > 12 || day < 1) {
        return 0
    }
    maximum = 31
    if (month == 4 || month == 6 || month == 9 || month == 11) {
        maximum = 30
    } else if (month == 2) {
        maximum = leap(year) ? 29 : 28
    }
    return day <= maximum
}
NR == 1 {
    if ($0 != "id\trule\tscope\towner\texpires\treason") {
        error("unexpected gosec-suppression header")
    }
    next
}
{
    if (NF != 6) {
        error("expected six tab-separated fields")
        next
    }
    if ($1 !~ /^VEER-SEC-[0-9][0-9][0-9]$/) {
        error("invalid suppression ID")
    }
    if ($2 !~ /^G[0-9][0-9][0-9]$/) {
        error("invalid gosec rule")
    }
    if ($3 !~ /^([A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+[.]go$/ || $3 ~ /(^|\/)\.\.?(\/|$)/) {
        error("invalid suppression scope")
    }
    if ($4 != "info@ardur.ai") {
        error("suppression owner must be info@ardur.ai")
    }
    if (!valid_date($5)) {
        error("suppression expiry is not a calendar date")
    } else if ($5 <= today) {
        error("gosec suppression is expired or expires today: " $1)
    }
    if (length($6) < 20) {
        error("suppression reason is too short")
    }
    if (seen[$1]++) {
        error("duplicate suppression ID " $1)
    }
    count++
}
END {
    if (count == 0) {
        error("gosec suppression registry must not be empty while annotations exist")
    }
    if (failed) {
        exit 1
    }
    print "veer-gosec-registry active=" count " status=passed"
}
' "$gosec_suppressions" || fail 'gosec suppression registry verification failed'

{
  find "$repo_root" \
    \( \
    -path "$repo_root/.git" -o \
    -path "$repo_root/.tools" -o \
    -path "$repo_root/vendor" \
    \) -prune -o \
    -type f -name '*.go' \
    -exec grep -EHn -- '#nosec|//[[:space:]]*nolint|//lint:ignore' {} + || true
} | LC_ALL=C awk -F '\t' -v registry="$gosec_suppressions" -v root="$repo_root" '
function error(message) {
    print "gosec annotations: " message > "/dev/stderr"
    failed = 1
}
BEGIN {
    while ((getline registry_line < registry) > 0) {
        registry_row++
        if (registry_row == 1) {
            continue
        }
        split(registry_line, fields, "\t")
        registered_rule[fields[1]] = fields[2]
        registered_scope[fields[1]] = fields[3]
        registered[fields[1]] = 1
        registered_count++
    }
    close(registry)
}
{
    first_colon = index($0, ":")
    remainder = substr($0, first_colon + 1)
    second_colon = index(remainder, ":")
    source_file = substr($0, 1, first_colon - 1)
    source_line = substr(remainder, second_colon + 1)
    relative_file = substr(source_file, length(root) + 2)

    if (source_line ~ /\/\/[[:space:]]*nolint/ || source_line ~ /\/\/lint:ignore/) {
        error(relative_file ": ungoverned lint suppression is forbidden")
        next
    }
    marker = index(source_line, "#nosec")
    if (marker == 0) {
        next
    }
    annotation = substr(source_line, marker)
    split(annotation, tokens, /[[:space:]]+/)
    identifier = tokens[4]
    sub(/:$/, "", identifier)
    if (tokens[1] != "#nosec" || tokens[2] !~ /^G[0-9][0-9][0-9]$/ ||
        tokens[3] != "--" || identifier !~ /^VEER-SEC-[0-9][0-9][0-9]$/ ||
        index(annotation, identifier ": ") == 0) {
        error(relative_file ": malformed #nosec annotation")
        next
    }
    if (!(identifier in registered)) {
        error(relative_file ": unregistered #nosec annotation " identifier)
        next
    }
    if (registered_rule[identifier] != tokens[2]) {
        error(relative_file ": annotation rule differs from registry for " identifier)
    }
    if (registered_scope[identifier] != relative_file) {
        error(relative_file ": annotation scope differs from registry for " identifier)
    }
    annotation_count[identifier]++
}
END {
    for (identifier in registered) {
        if (annotation_count[identifier] != 1) {
            error(identifier " must appear in exactly one source annotation; found " (annotation_count[identifier] + 0))
        }
    }
    if (failed) {
        exit 1
    }
    print "veer-gosec-annotations matched=" registered_count " status=passed"
}
' || fail 'gosec suppression annotation verification failed'

require_text "$repo_root/go.mod" 'go 1.27.1'
require_text "$repo_root/go.mod" 'github.com/go-jose/go-jose/v4 v4.1.5'
require_text "$repo_root/vendor/modules.txt" '# github.com/go-jose/go-jose/v4 v4.1.5'
require_regular_file "$repo_root/vendor/github.com/go-jose/go-jose/v4/LICENSE"
require_text "$repo_root/go.mod" 'go.yaml.in/yaml/v3 v3.0.5'
require_text "$repo_root/vendor/modules.txt" '# go.yaml.in/yaml/v3 v3.0.5'
require_regular_file "$repo_root/vendor/go.yaml.in/yaml/v3/LICENSE"
require_text "$supply_chain_doc" 'Second-person approval is not a protected-branch requirement.'
require_text "$supply_chain_doc" 'enabled with zero required approving reviews and last-push approval disabled'
require_text "$supply_chain_doc" "direct pushes to \`main\` remain prohibited."
reject_text "$supply_chain_doc" 'One independent latest-head approval'

(
  cd -- "$repo_root"
  "$repo_root/.tools/bin/go" run -mod=vendor -trimpath ./hack/branchprotection <"$branch_policy"
) || fail 'branch protection policy verification failed'

(
  cd -- "$repo_root"
  "$repo_root/.tools/bin/go" run -mod=vendor -trimpath ./hack/workflowpolicy \
    . \
    .github/workflows/bootstrap.yml \
    .github/workflows/dco.yml \
    .github/workflows/supply-chain.yml
) || fail 'workflow policy verification failed'

printf '%s\n' \
  'veer-supply-chain workflows=3 scanners=vuln,misconfig,secret,license coverage_floor=80.0 sbom_retention_days=30 status=passed'
