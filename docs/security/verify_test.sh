#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
fixture_base=${TMPDIR:-/tmp}
fixture_root=$(mktemp -d "$fixture_base/veer-security-verify.XXXXXX")

case "$fixture_root" in
  "$fixture_base"/veer-security-verify.*) ;;
  *)
    printf '%s\n' "security threat-model fixture setup failed: unsafe temporary path $fixture_root" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -rf -- "$fixture_root"
}
trap cleanup 0 1 2 15

fail() {
  printf '%s\n' "security threat-model fixture failed: $*" >&2
  exit 1
}

fixture_count=0
new_fixture() {
  fixture_count=$((fixture_count + 1))
  test_root="$fixture_root/case-$fixture_count"
  mkdir -p "$test_root"
  cp -R "$repo_root/docs" "$test_root/docs"
}

rewrite_threat_field() {
  threat_id=$1
  field_number=$2
  replacement=$3
  ledger="$test_root/docs/security/threats.tsv"
  rewritten="$test_root/threats.tsv"

  LC_ALL=C awk -F '\t' -v OFS='\t' -v id="$threat_id" \
    -v field="$field_number" -v value="$replacement" '
      $1 == id { $field = value }
      { print }
    ' "$ledger" >"$rewritten"
  mv "$rewritten" "$ledger"
}

expect_rejection() {
  case_name=$1
  expected_text=$2

  set +e
  output=$("$test_root/docs/security/verify.sh" 2>&1)
  status=$?
  set -e

  [ "$status" -ne 0 ] || fail "$case_name was accepted"
  case "$output" in
    *"$expected_text"*) ;;
    *) fail "$case_name produced an unexpected failure: $output" ;;
  esac
}

"$script_dir/verify.sh" >/dev/null

new_fixture
rewrite_threat_field TM-001 9 '-'
expect_rejection 'missing high-risk mitigation' \
  'critical/high threat requires a mitigation and linked follow-up'

new_fixture
rewrite_threat_field TM-001 10 'OWN-UNDECLARED'
expect_rejection 'undeclared control owner' 'undeclared owner OWN-UNDECLARED'

new_fixture
rewrite_threat_field TM-001 5 'TB-99'
expect_rejection 'undeclared trust boundary' 'undeclared boundary TB-99'

new_fixture
rewrite_threat_field TM-001 6 'ACT-UNDECLARED'
expect_rejection 'undeclared attacker' 'undeclared attacker ACT-UNDECLARED'

new_fixture
class_ledger="$test_root/docs/security/data-classes.tsv"
rewritten_classes="$test_root/data-classes.tsv"
LC_ALL=C awk -F '\t' '$1 != "DC-PERSONAL" { print }' \
  "$class_ledger" >"$rewritten_classes"
mv "$rewritten_classes" "$class_ledger"
expect_rejection 'missing required data class' \
  'missing required data class DC-PERSONAL'

new_fixture
rewrite_threat_field TM-001 14 'docs/security/model.md:9999'
expect_rejection 'stale source citation' \
  'citation range is outside the target: docs/security/model.md:9999'

new_fixture
rewrite_threat_field TM-001 14 'docs/security/model.md:1-9999'
expect_rejection 'stale source citation range endpoint' \
  'citation range is outside the target: docs/security/model.md:1-9999'

new_fixture
rewrite_threat_field TM-001 14 'docs/security/../security/model.md:1'
expect_rejection 'citation parent traversal' \
  'unsafe citation path: docs/security/../security/model.md:1'

new_fixture
rewrite_threat_field TM-001 14 'docs/security/does-not-exist.md'
expect_rejection 'incomplete citation syntax' \
  'evidence must contain only complete repository documentation citations'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  !changed && index($0, "docs/architecture/overview.md:99-117") {
      sub(/docs\/architecture\/overview[.]md:99-117/, "docs/architecture/does-not-exist.md")
      changed = 1
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'malformed readable source citation' \
  'readable model contains malformed documentation citation'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  !changed && index($0, "docs/architecture/overview.md:99-117") {
      sub(/docs\/architecture\/overview[.]md:99-117/, "./docs/security/model.md:1-99999")
      changed = 1
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'prefixed readable source citation with stale range' \
  'citation range is outside the target: docs/security/model.md:1-99999'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  !changed && index($0, "docs/architecture/overview.md:99-117") {
      sub(/docs\/architecture\/overview[.]md:99-117/, "../docs/architecture/overview.md:99999")
      changed = 1
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'parent-prefixed readable source citation' \
  'readable model contains malformed documentation citation'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  !changed && index($0, "docs/architecture/overview.md:99-117") {
      sub(/docs\/architecture\/overview[.]md:99-117/, "xdocs/architecture/overview.md:99999")
      changed = 1
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'token-prefixed readable source citation' \
  'readable model contains malformed documentation citation'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  !changed && index($0, "docs/architecture/overview.md:99-117") {
      sub(/docs\/architecture\/overview[.]md:99-117/, "Docs/architecture/does-not-exist.md:99999")
      changed = 1
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'case-mutated readable source citation' \
  'readable model contains malformed documentation citation'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
ln -s architecture "$test_root/docs/alias"
LC_ALL=C awk '
  /^\| API and GitOps edge \|/ {
      sub(/docs\/architecture\/overview[.]md:5-24/, "docs/alias/overview.md:5-24")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'citation through an intermediate symbolic link' \
  'citation path contains a symbolic link: docs/alias/overview.md:5-24'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| High \| \*\*TM-001 / { next }
  { print }
' "$model" >"$rewritten_model"
printf '%s\n' '<!-- TM-001 is intentionally not a readable attacker-story row. -->' \
  >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'threat ID outside attacker-story table' \
  'threat ID is absent from the readable attacker-story table: TM-001'

new_fixture
rewrite_threat_field TM-001 3 'medium'
expect_rejection 'readable and ledger risk mismatch' \
  'ledger risk does not match readable priority for TM-001'

new_fixture
rewrite_threat_field TM-001 4 ''
expect_rejection 'threat without a protected asset' \
  'threat requires at least one asset'

new_fixture
rewrite_threat_field TM-001 5 ''
expect_rejection 'threat without a trust boundary' \
  'threat requires at least one trust boundary'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| High \| \*\*TM-001 / {
      sub(/Issues #22 and #28 \|$/, "Issue #9999 |")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'attacker story with unknown evidence work' \
  'unknown readable issue reference #9999'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| High \| \*\*TM-001 / {
      sub(/Issues #22 and #28 \|$/, "Issues #15, #22, and #28 |")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'attacker story and ledger evidence mismatch' \
  'ledger issue references do not match readable evidence for TM-001'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| High \| \*\*TM-001 / {
      sub(/OIDC, short lifetime, and token exclusion are accepted requirements only/, "Accept unsigned tokens and emit raw credentials")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'readable and ledger existing-controls mismatch' \
  'ledger existing controls do not match readable attacker story for TM-001'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| High \| \*\*TM-001 / {
      sub(/Strict issuer\/audience\/algorithm\/signature\/time\/JWKS validation, human\/workload separation, raw-token canaries, and negative corpus/, "Accept unsigned tokens and emit raw credentials")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'readable and ledger mitigation mismatch' \
  'ledger mitigation does not match readable attacker story for TM-001'

new_fixture
rewrite_threat_field TM-014 6 'ACT-MEMBER'
expect_rejection 'attacker story and ledger actor mismatch' \
  'ledger attackers do not match readable actor set for TM-014'

new_fixture
rewrite_threat_field TM-001 9 ' '
expect_rejection 'whitespace-only high-risk mitigation' 'empty required field 9'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| DC-PERSONAL \|/ { next }
  { print }
' "$model" >"$rewritten_model"
printf '%s\n' '<!-- DC-PERSONAL is intentionally not a readable data-class row. -->' \
  >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'data class outside classification table' \
  'data class is absent from readable model: DC-PERSONAL'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| OWN-SECURITY \|/ { next }
  { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '<!--' \
  '### Control owners' \
  '| ID | Accountable surface | Live verification work |' \
  '| --- | --- | --- |' \
  '| OWN-SECURITY | fake surface | fake verification |' \
  '-->' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'owner outside control-owner table' \
  'undeclared owner OWN-SECURITY'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| OWN-SECURITY \|/ {
      sub(/Issues #14 and #28 \|$/, "Issue #9999 |")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'control owner with unknown verification work' \
  'unknown readable issue reference #9999'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { print; skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'required section with empty body' \
  'has no visible section content: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
printf '%s\n' '<!-- ### Workspace isolation assumptions -->' \
  >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'required heading hidden in a comment' \
  'is missing visible heading: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '<!-- first hidden block' \
  '--> <!-- second hidden block' \
  '### Workspace isolation assumptions' \
  'This heading remains inside the second comment.' \
  '-->' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'chained comment transitions cannot expose a heading' \
  'is missing visible heading: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '```text <!-- -->' \
  '### Workspace isolation assumptions' \
  'This heading remains inside the fenced code block.' \
  '```' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'comment text in a fence opener cannot expose a heading' \
  'is missing visible heading: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '<pre title="<!-- -->">' \
  '### Workspace isolation assumptions' \
  'This heading remains inside the raw HTML block.' \
  '</pre>' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'comment text in an HTML opener cannot expose a heading' \
  'is missing visible heading: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '<pre>' \
  '### Workspace isolation assumptions' \
  'This content is raw HTML, not a rendered Markdown section.' \
  '</pre>' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'required heading hidden in a raw HTML block' \
  'is missing visible heading: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '<custom-element title=">">' \
  '### Workspace isolation assumptions' \
  'This heading is raw HTML content, not Markdown structure.' \
  '</custom-element>' \
  '' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'required heading hidden by quoted HTML attribute' \
  'is missing visible heading: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '<pre title="</pre>">' \
  '### Workspace isolation assumptions' \
  'This heading remains inside the raw preformatted HTML element.' \
  '</pre>' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'quoted raw-HTML close tag cannot expose a heading' \
  'is missing visible heading: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '   ```text' \
  '### Workspace isolation assumptions' \
  '   ```' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'required heading hidden in an indented fence' \
  'is missing visible heading: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| OWN-SECURITY \|/ { next }
  { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '   ```text' \
  '### Control owners' \
  '| ID | Accountable surface | Live verification work |' \
  '| --- | --- | --- |' \
  '| OWN-SECURITY | fake surface | fake verification |' \
  '   ```' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'owner table hidden in an indented fence' \
  'undeclared owner OWN-SECURITY'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| OWN-SECURITY \|/ { next }
  { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '<pre>' \
  '### Control owners' \
  '| ID | Accountable surface | Live verification work |' \
  '| --- | --- | --- |' \
  '| OWN-SECURITY | fake surface | fake verification |' \
  '</pre>' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'owner table hidden in a raw HTML block' \
  'undeclared owner OWN-SECURITY'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| A-01 \|/ {
      sub(/`docs\/architecture\/overview[.]md:26-45`/, "No source evidence retained")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'protected asset without source citation' \
  'protected asset lacks a complete source citation: A-01'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| API and GitOps edge \|/ {
      sub(/`docs\/architecture\/overview[.]md:5-24`; `docs\/architecture\/0002-alpha-implementation-stack[.]md:72-87`/, "No source evidence retained")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'component without source citation' \
  'component row lacks a complete source citation'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '   ````text' \
  '   ```' \
  '### Workspace isolation assumptions' \
  '   ````' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'shorter marker cannot close an indented fence' \
  'is missing visible heading: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" { skip = 1; next }
  $0 == "### Provider credential flow and blast radius" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
printf '%s\n' \
  '   ```text' \
  '   ~~~' \
  '### Workspace isolation assumptions' \
  '   ```' >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'mismatched marker cannot close an indented fence' \
  'is missing visible heading: ### Workspace isolation assumptions'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
required_source='https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html'
LC_ALL=C awk -v source="$required_source" '
  index($0, source) { next }
  { print }
' "$model" >"$rewritten_model"
printf '%s\n' "<!-- $required_source -->" >>"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'required source hidden in a comment' \
  'is missing exact primary reference destination: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  { sub(/Issue #13 controls bootstrap/, "Issue #9999 controls bootstrap"); print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'unknown issue reference in readable prose' \
  'unknown readable issue reference #9999'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| OWN-RECONCILIATION \|/ {
      sub(/Issues #29 through #37/, "Issues #29 through #999999999")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'readable issue range exceeds the inventory work bound' \
  'readable issue range exceeds offline inventory bound #29 through #999999999'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
required_source='https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html'
LC_ALL=C awk -v source="$required_source" '
  index($0, source) { next }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'missing AWS source-identity reference' \
  'is missing exact primary reference destination: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
required_source='https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html'
LC_ALL=C awk -v source="$required_source" '
  { sub(source, source "-broken"); print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'primary source URL accepted as a prefix' \
  'is missing exact primary reference destination: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "| ID | Asset | Required property | Evidence |" { in_assets = 1; print; next }
  in_assets && $0 == "| --- | --- | --- | --- |" { in_assets = 0; next }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'protected-assets table without delimiter' \
  'canonical assets row appears before a valid delimiter'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "| ID | Class | Examples | At rest | In transit | Access | Logging | Retention | Disposal | Owner | Verification |" {
      in_classes = 1
      print
      next
  }
  in_classes && $0 == "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |" { in_classes = 0; next }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'data-class table without delimiter' \
  'canonical classes row appears before a valid delimiter'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| TB-01 \|/ {
      sub(/OWN-IDENTITY \|$/, "OWN-DOES-NOT-EXIST |")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'undeclared trust-boundary verification owner' \
  'undeclared trust-boundary owner OWN-DOES-NOT-EXIST for TB-01'

new_fixture
rewrite_threat_field TM-001 11 'https://github.com/ArdurAI/veer/issues/0'
expect_rejection 'zero issue target' \
  'follow_up must contain exact Veer issue URLs'

new_fixture
rewrite_threat_field TM-001 11 'https://github.com/ArdurAI/veer/issues/9999'
expect_rejection 'unknown issue target' \
  'follow_up must contain exact Veer issue URLs'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| A-01 \|/ { print "| A-01 | | | |"; next }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'empty protected-asset cells' \
  'invalid required cells in canonical assets row'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| ACT-NET \|/ { print "| ACT-NET | | |"; next }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'empty attacker cells' \
  'invalid required cells in canonical attackers row'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| ACT-NET \|/ { sub(/ACT-NET/, "ACT--") }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
ledger="$test_root/docs/security/threats.tsv"
rewritten="$test_root/threats.tsv"
LC_ALL=C awk -F '\t' -v OFS='\t' '
  $6 == "ACT-NET" { $6 = "ACT--" }
  { print }
' "$ledger" >"$rewritten"
mv "$rewritten" "$ledger"
expect_rejection 'malformed canonical attacker identifier' \
  'undeclared attacker ACT--'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| TB-01 \|/ { print "| TB-01 | | | |"; next }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'empty trust-boundary cells' \
  'invalid required cells in canonical boundaries row'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| OWN-SECURITY \|/ { print "| OWN-SECURITY | | |"; next }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'empty control-owner cells' \
  'invalid required cells in canonical owners row'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| High \| \*\*TM-001 / {
      print "| High | **TM-001 — placeholder.** | | | | | |"
      next
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'empty attacker-story cells' \
  'invalid required cells in canonical threats row'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| DC-PERSONAL \|/ { print "| DC-PERSONAL | Personal | | | | | | | | | |"; next }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'empty data-class cells' \
  'invalid required cells in canonical classes row'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| DC-CREDENTIAL \|/ {
      sub(/Raw values exist only in process memory or an external secret manager; Veer persists opaque references versions and non-secret destination metadata; every unavoidable store is encrypted/, "Persist plaintext credentials at rest")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'readable and ledger at-rest handling mismatch' \
  'ledger at-rest rule does not match readable data class for DC-CREDENTIAL'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| DC-CREDENTIAL \|/ {
      sub(/Raw session material only until operation completion expiry revocation cancellation or lost ownership; references follow ProviderConnection lifetime and independent rotation/, "Retain raw credentials forever")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'readable and ledger retention handling mismatch' \
  'ledger retention rule does not match readable data class for DC-CREDENTIAL'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| DC-PERSONAL \|/ {
      sub(/\| OWN-IDENTITY \|/, "| OWN-IDENTITY and OWN-NONEXISTENT |")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'data class with an additional undeclared owner' \
  'readable data class has invalid control owner: DC-PERSONAL'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| DC-PERSONAL \|/ {
      sub(/Issues #22, #27, #28, and #63 \|$/, "Issue #14 |")
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'data-class readable and ledger verification mismatch' \
  'ledger verification does not match readable data class for DC-PERSONAL'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |" {
      print "| Priority | Scenario and capability gain | Preconditions | Impact | Existing controls | Mitigation | Proof |"
      next
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'attacker-story table with renamed columns' \
  'unexpected canonical threats table header'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Assumptions and unresolved evidence" { skip = 1; next }
  $0 == "## Attack surface, mitigations, and attacker stories" { skip = 0 }
  !skip { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'missing assumptions and unresolved evidence section' \
  'is missing visible heading: ### Assumptions and unresolved evidence'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" {
      print "| ID | Conflicting responsibility | Alternate work |"
      print "| --- | --- | --- |"
      print "| OWN-FAKE | Conflicting contract | Issue #14 |"
      print ""
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'additional table inside a canonical section' \
  'unexpected table in canonical owners section'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  $0 == "### Workspace isolation assumptions" {
      print "#### Alternate ownership"
      print ""
      print "| ID | Conflicting responsibility | Alternate work |"
      print "| --- | --- | --- |"
      print "| OWN-FAKE | Conflicting contract | Issue #14 |"
      print ""
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'nested heading cannot end a canonical section' \
  'unexpected table in canonical owners section'

new_fixture
model="$test_root/docs/security/threat-model.md"
rewritten_model="$test_root/threat-model.md"
LC_ALL=C awk '
  /^\| Build and release path \|/ {
      print
      print "| Component | Security-relevant responsibility | Source evidence |"
      print "| --- | --- | --- |"
      print "| Conflicting component | Alternate security contract | `docs/security/model.md:1` |"
      next
  }
  { print }
' "$model" >"$rewritten_model"
mv "$rewritten_model" "$model"
expect_rejection 'adjacent duplicate canonical table header' \
  'duplicate canonical components table header'

new_fixture
model="$test_root/docs/security/threat-model.md"
printf '%s\n' \
  '' \
  '### Control owners' \
  '| ID | Conflicting responsibility | Alternate work |' \
  '| --- | --- | --- |' \
  '| OWN-FAKE | Conflicting contract | Issue #14 |' >>"$model"
expect_rejection 'duplicate canonical control-owner section' \
  'duplicate visible heading: ### Control owners'

new_fixture
model="$test_root/docs/security/threat-model.md"
printf '%s\n' \
  '' \
  ' ### Control owners ###' \
  '| ID | Conflicting responsibility | Alternate work |' \
  '| --- | --- | --- |' \
  '| OWN-FAKE | Conflicting contract | Issue #14 |' >>"$model"
expect_rejection 'indented ATX duplicate canonical section' \
  'duplicate visible heading: ### Control owners'

new_fixture
ledger="$test_root/docs/security/threats.tsv"
rewritten="$test_root/threats.tsv"
LC_ALL=C awk '
  NR > 1 { print previous }
  { previous = $0 }
  END { if (NR > 0) printf "%s", previous }
' "$ledger" >"$rewritten"
mv "$rewritten" "$ledger"
expect_rejection 'missing terminal newline' \
  'docs/security/threats.tsv must end with a newline'

printf 'security threat-model negative fixtures passed (%s cases)\n' "$fixture_count"
