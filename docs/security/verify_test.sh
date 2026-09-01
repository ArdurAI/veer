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

printf '%s\n' 'security threat-model negative fixtures passed'
