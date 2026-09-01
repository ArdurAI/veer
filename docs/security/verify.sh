#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
docs_root=$(CDPATH='' cd -- "$repo_root/docs" && pwd -P)
model_file="$script_dir/threat-model.md"
threat_file="$script_dir/threats.tsv"
class_file="$script_dir/data-classes.tsv"
summary_file="$script_dir/model.md"
issue_inventory_file="$script_dir/issue-inventory.txt"

fail() {
  printf '%s\n' "security threat-model verification failed: $*" >&2
  exit 1
}

validate_regular_file() {
  checked_file=$1
  [ -f "$checked_file" ] || fail "missing ${checked_file#"$repo_root/"}"
  [ ! -L "$checked_file" ] || fail "${checked_file#"$repo_root/"} must not be a symbolic link"
  record_count=$(LC_ALL=C awk 'END { print NR + 0 }' "$checked_file")
  newline_count=$(wc -l <"$checked_file" | LC_ALL=C awk '{ print $1 }')
  [ "$record_count" -eq "$newline_count" ] ||
    fail "${checked_file#"$repo_root/"} must end with a newline"
}

write_visible_markdown() {
  source_file=$1
  destination_file=$2
  LC_ALL=C awk '
    function fence_transition(line, stripped, marker, marker_length, tail) {
        stripped = line
        sub(/^[ ]?[ ]?[ ]?/, "", stripped)
        marker = substr(stripped, 1, 1)
        if (marker != "`" && marker != "~") {
            return 0
        }
        marker_length = 0
        while (substr(stripped, marker_length + 1, 1) == marker) {
            marker_length++
        }
        if (marker_length < 3) {
            return 0
        }
        tail = substr(stripped, marker_length + 1)
        if (!in_fence) {
            in_fence = 1
            opening_marker = marker
            opening_length = marker_length
            return 1
        }
        if (marker == opening_marker && marker_length >= opening_length &&
            tail ~ /^[[:space:]]*$/) {
            in_fence = 0
            opening_marker = ""
            opening_length = 0
            return 1
        }
        return 0
    }
    function html_transition(line, stripped, lower, tag) {
        stripped = line
        sub(/^[ ]?[ ]?[ ]?/, "", stripped)
        lower = tolower(stripped)
        if (in_html_literal) {
            if (index(lower, html_close)) {
                in_html_literal = 0
                html_close = ""
            }
            return 1
        }
        if (in_html_until_blank) {
            if (line ~ /^[[:space:]]*$/) {
                in_html_until_blank = 0
            }
            return 1
        }
        if (in_processing_instruction) {
            if (index(line, "?>")) {
                in_processing_instruction = 0
            }
            return 1
        }
        if (in_declaration) {
            if (index(line, ">")) {
                in_declaration = 0
            }
            return 1
        }
        if (in_cdata) {
            if (index(line, "]]>") ) {
                in_cdata = 0
            }
            return 1
        }
        if (lower ~ /^<(pre|script|style|textarea)([[:space:]>]|$)/) {
            tag = lower
            sub(/^</, "", tag)
            sub(/[[:space:]>].*$/, "", tag)
            html_close = "</" tag ">"
            if (!index(lower, html_close)) {
                in_html_literal = 1
            }
            return 1
        }
        if (substr(stripped, 1, 9) == "<![CDATA[") {
            if (!index(stripped, "]]>") ) {
                in_cdata = 1
            }
            return 1
        }
        if (substr(stripped, 1, 2) == "<?") {
            if (!index(stripped, "?>")) {
                in_processing_instruction = 1
            }
            return 1
        }
        if (stripped ~ /^<![A-Z]/) {
            if (!index(stripped, ">")) {
                in_declaration = 1
            }
            return 1
        }
        if (substr(lower, 1, 1) == "<") {
            tag = lower
            sub(/^<\//, "", tag)
            sub(/^</, "", tag)
            sub(/[[:space:]\/>].*$/, "", tag)
            if (tag in block_tag ||
                lower ~ /^<\/?[a-z][a-z0-9-]*([[:space:]][^>]*)?\/?>[[:space:]]*$/) {
                in_html_until_blank = 1
                return 1
            }
        }
        return 0
    }
    BEGIN {
        tags = "address article aside base basefont blockquote body caption center col colgroup dd details dialog dir div dl dt fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend li link main menu menuitem nav noframes ol optgroup option p param search section summary table tbody td tfoot th thead title tr track ul"
        tag_count = split(tags, tag_values, " ")
        for (tag_index = 1; tag_index <= tag_count; tag_index++) {
            block_tag[tag_values[tag_index]] = 1
        }
    }
    {
        line = $0
        if (in_fence) {
            fence_transition(line)
            print ""
            next
        }
        if (in_html_literal || in_html_until_blank || in_processing_instruction ||
            in_declaration || in_cdata) {
            html_transition(line)
            print ""
            next
        }
        if (in_comment) {
            if (index(line, "-->")) {
                in_comment = 0
            }
            print ""
            next
        }
        if (index(line, "<!--")) {
            comment_tail = substr(line, index(line, "<!--") + 4)
            if (!index(comment_tail, "-->")) {
                in_comment = 1
            }
            print ""
            next
        }
        if (fence_transition(line) || html_transition(line)) {
            print ""
            next
        }
        print line
    }
  ' "$source_file" >"$destination_file"
}

visible_markdown_has() {
  required_content=$1
  match_mode=$2
  visible_file=$3
  LC_ALL=C awk -v required="$required_content" -v mode="$match_mode" '
    (mode == "exact" && $0 == required) ||
    (mode == "contains" && index($0, required)) { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$visible_file"
}

visible_section_has_content() {
  required_heading=$1
  visible_file=$2
  LC_ALL=C awk -v required="$required_heading" '
    function heading_level(line, level) {
        if (line !~ /^##+ /) {
            return 0
        }
        level = 1
        while (substr(line, level + 1, 1) == "#") {
            level++
        }
        return level
    }
    $0 == required {
        in_section = 1
        target_level = heading_level($0)
        next
    }
    in_section {
        current_level = heading_level($0)
        if (current_level > 0 && current_level <= target_level) {
            exit
        }
        if (current_level == 0 && $0 !~ /^[[:space:]]*$/) {
            found_content = 1
        }
    }
    END { exit found_content ? 0 : 1 }
  ' "$visible_file"
}

require_visible_section() {
  required_heading=$1
  checked_file=$2
  visible_file=$3
  visible_markdown_has "$required_heading" exact "$visible_file" ||
    fail "${checked_file#"$repo_root/"} is missing visible heading: $required_heading"
  visible_section_has_content "$required_heading" "$visible_file" ||
    fail "${checked_file#"$repo_root/"} has no visible section content: $required_heading"
}

require_visible_text() {
  required_text=$1
  checked_file=$2
  visible_file=$3
  visible_markdown_has "$required_text" contains "$visible_file" ||
    fail "${checked_file#"$repo_root/"} is missing visible text: $required_text"
}

require_primary_reference() {
  required_destination=$1
  visible_file=$2
  LC_ALL=C awk -v required="$required_destination" '
    $0 == "### Primary references" { in_references = 1; next }
    in_references && /^##+ / { exit }
    in_references && /^- \[/ {
        destination = $0
        sub(/^.*\]\(/, "", destination)
        sub(/\)[[:space:]]*$/, "", destination)
        if (destination == required) {
            found = 1
        }
    }
    END { exit found ? 0 : 1 }
  ' "$visible_file" ||
    fail "${model_file#"$repo_root/"} is missing exact primary reference destination: $required_destination"
}

for checked_file in \
  "$model_file" \
  "$threat_file" \
  "$class_file" \
  "$summary_file" \
  "$issue_inventory_file"; do
  validate_regular_file "$checked_file"
done

LC_ALL=C awk '
  !/^https:\/\/github[.]com\/ArdurAI\/veer\/issues\/[1-9][0-9]*$/ {
      print FILENAME ":" FNR ": invalid issue inventory entry" > "/dev/stderr"
      failed = 1
      next
  }
  seen[$0]++ {
      print FILENAME ":" FNR ": duplicate issue inventory entry " $0 > "/dev/stderr"
      failed = 1
  }
  { rows++ }
  END {
      if (rows == 0) {
          print FILENAME ": issue inventory has no entries" > "/dev/stderr"
          failed = 1
      }
      if (failed) {
          exit 1
      }
  }
' "$issue_inventory_file" || fail 'issue inventory contract is invalid'

verification_tmp_base=${TMPDIR:-/tmp}
verification_tmp=$(mktemp -d "$verification_tmp_base/veer-security-verify.XXXXXX") ||
  fail 'cannot create verification workspace'
case "$verification_tmp" in
  "$verification_tmp_base"/veer-security-verify.*) ;;
  *) fail "unsafe verification workspace: $verification_tmp" ;;
esac
cleanup() {
  rm -rf -- "$verification_tmp"
}
trap cleanup 0 1 2 15

visible_model_file="$verification_tmp/threat-model.visible.md"
visible_summary_file="$verification_tmp/model.visible.md"
write_visible_markdown "$model_file" "$visible_model_file"
write_visible_markdown "$summary_file" "$visible_summary_file"

for required_heading in \
  '## Overview' \
  '## Threat model, trust boundaries, and assumptions' \
  '### Workspace isolation assumptions' \
  '### Provider credential flow and blast radius' \
  '### Data classification' \
  '### Unsupported deployment modes' \
  '## Attack surface, mitigations, and attacker stories' \
  '### Review and maintenance' \
  '## Severity calibration'; do
  require_visible_section "$required_heading" "$model_file" "$visible_model_file"
done

for required_source in \
  'https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html' \
  'https://datatracker.ietf.org/doc/html/rfc9700' \
  'https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html' \
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html' \
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html' \
  'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html' \
  'https://kubernetes.io/docs/concepts/security/multi-tenancy/' \
  'https://kubernetes.io/docs/concepts/security/service-accounts/' \
  'https://www.postgresql.org/docs/18/ddl-rowsecurity.html'; do
  require_primary_reference "$required_source" "$visible_model_file"
done

require_visible_text \
  '[formal threat model and data classification](threat-model.md)' \
  "$summary_file" \
  "$visible_summary_file"
require_visible_text \
  "[\`threats.tsv\`](threats.tsv)" \
  "$model_file" \
  "$visible_model_file"
require_visible_text \
  "[\`data-classes.tsv\`](data-classes.tsv)" \
  "$model_file" \
  "$visible_model_file"
require_visible_text \
  "[\`issue-inventory.txt\`](issue-inventory.txt)" \
  "$model_file" \
  "$visible_model_file"

LC_ALL=C awk -F '\t' -v issue_inventory="$issue_inventory_file" '
function trim(value) {
    sub(/^[[:space:]]+/, "", value)
    sub(/[[:space:]]+$/, "", value)
    return value
}
function error(message) {
    print FILENAME ":" FNR ": " message > "/dev/stderr"
    failed = 1
}
function valid_links(value, values, count, link_index) {
    count = split(value, values, ",")
    if (count < 1) {
        return 0
    }
    for (link_index = 1; link_index <= count; link_index++) {
        if (values[link_index] !~ /^https:\/\/github[.]com\/ArdurAI\/veer\/issues\/[1-9][0-9]*$/ ||
            !(values[link_index] in known_issue)) {
            return 0
        }
    }
    return 1
}
function valid_issue_work(value, work, range_values, range_count, range_start, range_end,
                          issue_number, remaining, issue_url) {
    work = trim(value)
    if (work !~ /^[Ii]ssues? /) {
        return 0
    }
    sub(/^[Ii]ssues? /, "", work)
    if (work ~ /^#[1-9][0-9]* through #[1-9][0-9]*$/) {
        range_count = split(work, range_values, " through ")
        if (range_count != 2) {
            return 0
        }
        range_start = substr(range_values[1], 2) + 0
        range_end = substr(range_values[2], 2) + 0
        if (range_start > range_end) {
            return 0
        }
        for (issue_number = range_start; issue_number <= range_end; issue_number++) {
            issue_url = "https://github.com/ArdurAI/veer/issues/" issue_number
            if (!(issue_url in known_issue)) {
                return 0
            }
        }
        return 1
    }
    if (work !~ /^#[1-9][0-9]*(, #[1-9][0-9]*)*(,? and #[1-9][0-9]*)?$/) {
        return 0
    }
    remaining = work
    while (match(remaining, /#[1-9][0-9]*/)) {
        issue_number = substr(remaining, RSTART + 1, RLENGTH - 1)
        issue_url = "https://github.com/ArdurAI/veer/issues/" issue_number
        if (!(issue_url in known_issue)) {
            return 0
        }
        remaining = substr(remaining, RSTART + RLENGTH)
    }
    return 1
}
function valid_evidence(value, values, count, citation_index) {
    count = split(value, values, ";")
    if (count < 1) {
        return 0
    }
    for (citation_index = 1; citation_index <= count; citation_index++) {
        if (values[citation_index] !~ /^docs\/[A-Za-z0-9_.\/-]+:[1-9][0-9]*(-[1-9][0-9]*)?$/) {
            return 0
        }
    }
    return 1
}
function valid_readable_row(line, expected_columns, cells, count, cell_index, value) {
    count = split(line, cells, "|")
    if (count != expected_columns + 2 || trim(cells[1]) != "" || trim(cells[count]) != "") {
        return 0
    }
    for (cell_index = 2; cell_index < count; cell_index++) {
        value = trim(cells[cell_index])
        if (value == "" || value == "-") {
            return 0
        }
    }
    return 1
}
function valid_delimiter_row(line, expected_columns, cells, count, cell_index, value) {
    count = split(line, cells, "|")
    if (count != expected_columns + 2 || trim(cells[1]) != "" || trim(cells[count]) != "") {
        return 0
    }
    for (cell_index = 2; cell_index < count; cell_index++) {
        value = trim(cells[cell_index])
        if (value !~ /^:?-{3,}:?$/) {
            return 0
        }
    }
    return 1
}
function finish_table() {
    if (table != "" && !table_delimiter_seen) {
        error("canonical " table " table is missing a valid delimiter")
    }
    table = ""
    table_columns = 0
    table_delimiter_seen = 0
}
BEGIN {
    while ((getline inventory_entry < issue_inventory) > 0) {
        known_issue[inventory_entry] = 1
    }
    close(issue_inventory)
}
FNR == NR {
    if ($0 ~ /^##+ /) {
        finish_table()
        section = $0
    }
    if (section == "### Protected assets" &&
        $0 == "| ID | Asset | Required property | Evidence |") {
        table = "assets"
        table_columns = 4
        table_delimiter_seen = 0
        next
    }
    if (section == "### Actors and realistic starting capabilities" &&
        $0 == "| ID | Actor and starting capability | Capability not assumed |") {
        table = "attackers"
        table_columns = 3
        table_delimiter_seen = 0
        next
    }
    if (section == "### Trust boundaries" &&
        $0 == "| ID | Crossing and transferred authority | Required enforcement | Verification owner |") {
        table = "boundaries"
        table_columns = 4
        table_delimiter_seen = 0
        next
    }
    if (section == "### Control owners" &&
        $0 == "| ID | Accountable surface | Live verification work |") {
        table = "owners"
        table_columns = 3
        table_delimiter_seen = 0
        next
    }
    if (section == "## Attack surface, mitigations, and attacker stories" &&
        $0 ~ /^\| Priority \| Scenario and capability gain \|/) {
        table = "threats"
        table_columns = 7
        table_delimiter_seen = 0
        next
    }
    if (table != "" && valid_delimiter_row($0, table_columns, delimiter_cells)) {
        if (table_delimiter_seen) {
            error("duplicate delimiter in canonical " table " table")
        }
        table_delimiter_seen = 1
        next
    }
    if (table == "assets" && $0 ~ /^\| A-[0-9][0-9] \|/) {
        if (!table_delimiter_seen) {
            error("canonical assets row appears before a valid delimiter")
            next
        }
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical assets row")
            next
        }
        asset_id = trim(cells[2])
        if (assets[asset_id]++) {
            error("duplicate protected-asset row " asset_id)
        }
        next
    }
    if (table == "attackers" &&
        $0 ~ /^\| ACT-[A-Z0-9]+(-[A-Z0-9]+)* \|/) {
        if (!table_delimiter_seen) {
            error("canonical attackers row appears before a valid delimiter")
            next
        }
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical attackers row")
            next
        }
        attacker_id = trim(cells[2])
        if (attackers[attacker_id]++) {
            error("duplicate attacker row " attacker_id)
        }
        next
    }
    if (table == "boundaries" && $0 ~ /^\| TB-[0-9][0-9] \|/) {
        if (!table_delimiter_seen) {
            error("canonical boundaries row appears before a valid delimiter")
            next
        }
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical boundaries row")
            next
        }
        boundary_id = trim(cells[2])
        if (boundaries[boundary_id]++) {
            error("duplicate trust-boundary row " boundary_id)
        }
        boundary_owner[boundary_id] = trim(cells[5])
        next
    }
    if (table == "owners" && $0 ~ /^\| OWN-[A-Z]+(-[A-Z]+)* \|/) {
        if (!table_delimiter_seen) {
            error("canonical owners row appears before a valid delimiter")
            next
        }
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical owners row")
            next
        }
        owner_id = trim(cells[2])
        if (owners[owner_id]++) {
            error("duplicate control-owner row " owner_id)
        }
        if (!valid_issue_work(trim(cells[4]))) {
            error("invalid live verification work for control owner " owner_id)
        }
        next
    }
    if (table == "threats" &&
        $0 ~ /^\| (Critical|High|Medium|Low) \| \*\*TM-[0-9][0-9][0-9] /) {
        if (!table_delimiter_seen) {
            error("canonical threats row appears before a valid delimiter")
            next
        }
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical threats row")
            next
        }
        match($0, /TM-[0-9][0-9][0-9]/)
        threat_id = substr($0, RSTART, RLENGTH)
        if (model_threat[threat_id]++) {
            error("duplicate readable attacker-story row " threat_id)
        }
        model_risk[threat_id] = tolower(trim(cells[2]))
        next
    }
    if (table != "" && $0 ~ /^\|/) {
        error("unexpected row in canonical " table " table")
        next
    }
    if (table != "" && $0 !~ /^\|/) {
        finish_table()
    }
    next
}
FNR == 1 {
    finish_table()
    for (boundary_id in boundary_owner) {
        if (!(boundary_owner[boundary_id] in owners)) {
            error("undeclared trust-boundary owner " boundary_owner[boundary_id] " for " boundary_id)
        } else {
            used_owners[boundary_owner[boundary_id]] = 1
        }
    }
    expected = "id\tstride\trisk\tassets\tboundary\tattacker\tscenario\texisting_controls\tmitigation\towner\tfollow_up\tverification\tresidual_risk\tevidence"
    if ($0 != expected) {
        error("unexpected threat ledger header")
    }
    stride["Spoofing"] = 1
    stride["Tampering"] = 1
    stride["Repudiation"] = 1
    stride["Information disclosure"] = 1
    stride["Denial of service"] = 1
    stride["Elevation of privilege"] = 1
    risks["critical"] = 1
    risks["high"] = 1
    risks["medium"] = 1
    risks["low"] = 1
    next
}
NF != 14 {
    error("expected 14 tab-separated threat fields")
    next
}
{
    rows++
    if ($1 !~ /^TM-[0-9][0-9][0-9]$/) {
        error("invalid threat ID " $1)
    }
    if (seen[$1]++) {
        error("duplicate threat ID " $1)
    }
    if (!($1 in model_threat)) {
        error("threat ID is absent from the readable attacker-story table: " $1)
    }
    if (!($2 in stride)) {
        error("invalid STRIDE category " $2)
    }
    if (!($3 in risks)) {
        error("invalid risk " $3)
    }
    if (($1 in model_threat) && $3 != model_risk[$1]) {
        error("ledger risk does not match readable priority for " $1)
    }
    asset_count = split($4, asset_refs, "|")
    for (asset_index = 1; asset_index <= asset_count; asset_index++) {
        if (!(asset_refs[asset_index] in assets)) {
            error("undeclared asset " asset_refs[asset_index])
        }
        used_assets[asset_refs[asset_index]] = 1
    }
    boundary_count = split($5, boundary_refs, "|")
    for (boundary_index = 1; boundary_index <= boundary_count; boundary_index++) {
        if (!(boundary_refs[boundary_index] in boundaries)) {
            error("undeclared boundary " boundary_refs[boundary_index])
        }
        used_boundaries[boundary_refs[boundary_index]] = 1
    }
    if (!($6 in attackers)) {
        error("undeclared attacker " $6)
    }
    used_attackers[$6] = 1
    for (field_index = 7; field_index <= 14; field_index++) {
        if (trim($field_index) == "" || trim($field_index) == "-") {
            error("empty required field " field_index)
        }
    }
    if (!($10 in owners)) {
        error("undeclared owner " $10)
    }
    used_owners[$10] = 1
    if (!valid_links($11)) {
        error("follow_up must contain exact Veer issue URLs")
    }
    if (!valid_links($12)) {
        error("verification must contain exact Veer issue URLs")
    }
    if (($3 == "critical" || $3 == "high") &&
        (trim($9) == "-" || trim($11) == "-")) {
        error("critical/high threat requires a mitigation and linked follow-up")
    }
    if (!valid_evidence($14)) {
        error("evidence must contain only complete repository documentation citations")
    }
}
END {
    if (rows == 0) {
        error("threat ledger has no rows")
    }
    for (asset in assets) {
        if (!(asset in used_assets)) {
            error("declared asset is not covered by a threat: " asset)
        }
    }
    for (boundary in boundaries) {
        if (!(boundary in used_boundaries)) {
            error("declared boundary is not covered by a threat: " boundary)
        }
    }
    for (attacker in attackers) {
        if (!(attacker in used_attackers)) {
            error("declared attacker has no threat coverage: " attacker)
        }
    }
    for (owner in owners) {
        if (!(owner in used_owners)) {
            error("declared owner has no threat accountability: " owner)
        }
    }
    for (model_id in model_threat) {
        if (!(model_id in seen)) {
            error("readable model references missing threat ledger row: " model_id)
        }
    }
    if (failed) {
        exit 1
    }
}
' "$visible_model_file" "$threat_file" || fail 'threat ledger contract is invalid'

LC_ALL=C awk -F '\t' -v issue_inventory="$issue_inventory_file" '
function trim(value) {
    sub(/^[[:space:]]+/, "", value)
    sub(/[[:space:]]+$/, "", value)
    return value
}
function error(message) {
    print FILENAME ":" FNR ": " message > "/dev/stderr"
    failed = 1
}
function valid_links(value, values, count, link_index) {
    count = split(value, values, ",")
    if (count < 1) {
        return 0
    }
    for (link_index = 1; link_index <= count; link_index++) {
        if (values[link_index] !~ /^https:\/\/github[.]com\/ArdurAI\/veer\/issues\/[1-9][0-9]*$/ ||
            !(values[link_index] in known_issue)) {
            return 0
        }
    }
    return 1
}
function valid_issue_work(value, work, range_values, range_count, range_start, range_end,
                          issue_number, remaining, issue_url) {
    work = trim(value)
    if (work !~ /^[Ii]ssues? /) {
        return 0
    }
    sub(/^[Ii]ssues? /, "", work)
    if (work ~ /^#[1-9][0-9]* through #[1-9][0-9]*$/) {
        range_count = split(work, range_values, " through ")
        if (range_count != 2) {
            return 0
        }
        range_start = substr(range_values[1], 2) + 0
        range_end = substr(range_values[2], 2) + 0
        if (range_start > range_end) {
            return 0
        }
        for (issue_number = range_start; issue_number <= range_end; issue_number++) {
            issue_url = "https://github.com/ArdurAI/veer/issues/" issue_number
            if (!(issue_url in known_issue)) {
                return 0
            }
        }
        return 1
    }
    if (work !~ /^#[1-9][0-9]*(, #[1-9][0-9]*)*(,? and #[1-9][0-9]*)?$/) {
        return 0
    }
    remaining = work
    while (match(remaining, /#[1-9][0-9]*/)) {
        issue_number = substr(remaining, RSTART + 1, RLENGTH - 1)
        issue_url = "https://github.com/ArdurAI/veer/issues/" issue_number
        if (!(issue_url in known_issue)) {
            return 0
        }
        remaining = substr(remaining, RSTART + RLENGTH)
    }
    return 1
}
function valid_readable_row(line, expected_columns, cells, count, cell_index, value) {
    count = split(line, cells, "|")
    if (count != expected_columns + 2 || trim(cells[1]) != "" || trim(cells[count]) != "") {
        return 0
    }
    for (cell_index = 2; cell_index < count; cell_index++) {
        value = trim(cells[cell_index])
        if (value == "" || value == "-") {
            return 0
        }
    }
    return 1
}
function valid_delimiter_row(line, expected_columns, cells, count, cell_index, value) {
    count = split(line, cells, "|")
    if (count != expected_columns + 2 || trim(cells[1]) != "" || trim(cells[count]) != "") {
        return 0
    }
    for (cell_index = 2; cell_index < count; cell_index++) {
        value = trim(cells[cell_index])
        if (value !~ /^:?-{3,}:?$/) {
            return 0
        }
    }
    return 1
}
function finish_table() {
    if (table != "" && !table_delimiter_seen) {
        error("canonical " table " table is missing a valid delimiter")
    }
    table = ""
    table_columns = 0
    table_delimiter_seen = 0
}
BEGIN {
    while ((getline inventory_entry < issue_inventory) > 0) {
        known_issue[inventory_entry] = 1
    }
    close(issue_inventory)
}
FNR == NR {
    if ($0 ~ /^##+ /) {
        finish_table()
        section = $0
    }
    if (section == "### Control owners" &&
        $0 == "| ID | Accountable surface | Live verification work |") {
        table = "owners"
        table_columns = 3
        table_delimiter_seen = 0
        next
    }
    if (section == "### Data classification" &&
        $0 == "| ID | Class | Central rule | Retention boundary | Owner and verification |") {
        table = "classes"
        table_columns = 5
        table_delimiter_seen = 0
        next
    }
    if (table != "" && valid_delimiter_row($0, table_columns, delimiter_cells)) {
        if (table_delimiter_seen) {
            error("duplicate delimiter in canonical " table " table")
        }
        table_delimiter_seen = 1
        next
    }
    if (table == "owners" && $0 ~ /^\| OWN-[A-Z]+(-[A-Z]+)* \|/) {
        if (!table_delimiter_seen) {
            error("canonical owners row appears before a valid delimiter")
            next
        }
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical owners row")
            next
        }
        owner_id = trim(cells[2])
        if (owners[owner_id]++) {
            error("duplicate control-owner row " owner_id)
        }
        if (!valid_issue_work(trim(cells[4]))) {
            error("invalid live verification work for control owner " owner_id)
        }
        next
    }
    if (table == "classes" && $0 ~ /^\| DC-[A-Z][A-Z-]* \|/) {
        if (!table_delimiter_seen) {
            error("canonical classes row appears before a valid delimiter")
            next
        }
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical classes row")
            next
        }
        class_id = trim(cells[2])
        if (class_seen[class_id]++) {
            error("duplicate readable data-class row " class_id)
        }
        model_class[class_id] = trim(cells[3])
        owner_and_work = trim(cells[6])
        owner_separator = index(owner_and_work, "; ")
        if (!owner_separator) {
            error("readable data class has invalid owner and verification: " class_id)
        } else {
            owner_id = substr(owner_and_work, 1, owner_separator - 1)
            owner_work = substr(owner_and_work, owner_separator + 2)
            if (owner_id !~ /^OWN-[A-Z]+(-[A-Z]+)*$/) {
                error("readable data class has invalid control owner: " class_id)
            } else {
                model_class_owner[class_id] = owner_id
            }
            if (!valid_issue_work(owner_work)) {
                error("readable data class has invalid verification work: " class_id)
            }
        }
        next
    }
    if (table != "" && $0 ~ /^\|/) {
        error("unexpected row in canonical " table " table")
        next
    }
    if (table != "" && $0 !~ /^\|/) {
        finish_table()
    }
    next
}
FNR == 1 {
    finish_table()
    expected = "id\tname\texamples\tat_rest\tin_transit\taccess\tlogging\tretention\tdisposal\towner\tverification"
    if ($0 != expected) {
        error("unexpected data-class ledger header")
    }
    required["DC-CREDENTIAL"] = "Credential"
    required["DC-AUDIT"] = "Audit"
    required["DC-PERSONAL"] = "Personal"
    required["DC-CONFIGURATION"] = "Configuration"
    required["DC-OPERATIONAL"] = "Operational"
    next
}
NF != 11 {
    error("expected 11 tab-separated data-class fields")
    next
}
{
    rows++
    if (!($1 in required)) {
        error("unexpected data class " $1)
    } else if ($2 != required[$1]) {
        error("unexpected name for " $1)
    }
    if (seen[$1]++) {
        error("duplicate data class " $1)
    }
    if (!($1 in model_class)) {
        error("data class is absent from readable model: " $1)
    } else if ($2 != model_class[$1]) {
        error("ledger name does not match readable data class for " $1)
    }
    for (field_index = 1; field_index <= 10; field_index++) {
        if (trim($field_index) == "" || trim($field_index) == "-") {
            error("data class " $1 " has empty handling field " field_index)
        }
    }
    if (!($10 in owners)) {
        error("undeclared data-class owner " $10)
    } else if (($1 in model_class_owner) && $10 != model_class_owner[$1]) {
        error("ledger owner does not match readable data class for " $1)
    }
    if (!valid_links($11)) {
        error("data-class verification must contain exact Veer issue URLs")
    }
}
END {
    for (class_id in required) {
        if (!(class_id in seen)) {
            error("missing required data class " class_id)
        }
    }
    if (rows != 5) {
        error("expected exactly five required data classes")
    }
    for (model_id in model_class) {
        if (!(model_id in seen)) {
            error("readable model references missing data-class ledger row: " model_id)
        }
    }
    if (failed) {
        exit 1
    }
}
' "$visible_model_file" "$class_file" || fail 'data-class ledger contract is invalid'

model_citations_file="$verification_tmp/model-citations.txt"
all_citations_file="$verification_tmp/all-citations.txt"
unique_citations_file="$verification_tmp/unique-citations.txt"

LC_ALL=C awk '
function error(column) {
    print FILENAME ":" FNR ": malformed documentation citation at column " column > "/dev/stderr"
    failed = 1
}
function token_character(character) {
    return character ~ /[A-Za-z0-9_.\/:\-]/
}
{
    search_from = 1
    while (search_from <= length($0)) {
        candidate = substr($0, search_from)
        relative_start = index(candidate, "docs/")
        if (!relative_start) {
            break
        }
        citation_start = search_from + relative_start - 1
        if (citation_start > 2 && substr($0, citation_start - 2, 2) == "./") {
            citation_start -= 2
        }
        preceding = citation_start > 1 ? substr($0, citation_start - 1, 1) : ""
        if (preceding != "" && token_character(preceding)) {
            search_from = citation_start + 5
            continue
        }
        candidate = substr($0, citation_start)
        if (!match(candidate, /^(\.\/)?docs\/[A-Za-z0-9_.\/-]+:[1-9][0-9]*(-[1-9][0-9]*)?/)) {
            error(citation_start)
            search_from = citation_start + 5
            continue
        }
        matched_length = RLENGTH
        citation = substr(candidate, RSTART, matched_length)
        following = substr(candidate, matched_length + 1, 1)
        if (following != "" && token_character(following)) {
            error(citation_start)
            search_from = citation_start + matched_length
            continue
        }
        sub(/^\.\//, "", citation)
        if (!seen[citation]++) {
            print citation
        }
        search_from = citation_start + matched_length
    }
}
END {
    if (failed) {
        exit 1
    }
}
' "$visible_model_file" >"$model_citations_file" ||
  fail 'readable model contains malformed documentation citation'

cp "$model_citations_file" "$all_citations_file"
LC_ALL=C awk -F '\t' '
  FNR > 1 {
      citation_count = split($14, citations, ";")
      for (citation_index = 1; citation_index <= citation_count; citation_index++) {
          print citations[citation_index]
      }
  }
' "$threat_file" >>"$all_citations_file"
LC_ALL=C sort -u "$all_citations_file" >"$unique_citations_file"

while IFS= read -r citation; do
  citation_path=${citation%:*}
  citation_location=${citation##*:}
  case "$citation_location" in
    *-*)
      citation_start=${citation_location%-*}
      citation_end=${citation_location#*-}
      ;;
    *)
      citation_start=$citation_location
      citation_end=$citation_location
      ;;
  esac
  case "$citation_path" in
    docs/*)
      case "/$citation_path/" in
        */../* | */./* | *//*) fail "unsafe citation path: $citation" ;;
      esac
      ;;
    *) fail "unsafe citation path: $citation" ;;
  esac
  citation_file="$repo_root/$citation_path"
  [ -f "$citation_file" ] || fail "citation target does not exist: $citation"
  [ ! -L "$citation_file" ] || fail "citation target must not be a symbolic link: $citation"
  citation_dir=$(CDPATH='' cd -- "$(dirname -- "$citation_file")" && pwd -P)
  case "$citation_dir/" in
    "$docs_root"/*) ;;
    *) fail "citation target resolves outside docs: $citation" ;;
  esac
  line_count=$(wc -l <"$citation_file" | LC_ALL=C awk '{ print $1 }')
  [ "$citation_start" -ge 1 ] &&
    [ "$citation_end" -ge "$citation_start" ] &&
    [ "$citation_end" -le "$line_count" ] ||
    fail "citation range is outside the target: $citation"
done <"$unique_citations_file"

printf '%s\n' 'security threat-model verification passed'
