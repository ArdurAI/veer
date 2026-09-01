#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
docs_root=$(CDPATH='' cd -- "$repo_root/docs" && pwd -P)
model_file="$script_dir/threat-model.md"
threat_file="$script_dir/threats.tsv"
class_file="$script_dir/data-classes.tsv"
summary_file="$script_dir/model.md"

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

visible_markdown_has() {
  required_content=$1
  match_mode=$2
  checked_file=$3
  LC_ALL=C awk -v required="$required_content" -v mode="$match_mode" '
    {
        line = $0
        if (in_comment) {
            if (index(line, "-->")) {
                in_comment = 0
            }
            next
        }
        if (index(line, "<!--")) {
            comment_tail = substr(line, index(line, "<!--") + 4)
            if (!index(comment_tail, "-->")) {
                in_comment = 1
            }
            next
        }
        if (line ~ /^[ ]?[ ]?[ ]?```/ || line ~ /^[ ]?[ ]?[ ]?~~~/) {
            in_fence = !in_fence
            next
        }
        if (!in_fence &&
            ((mode == "exact" && line == required) ||
             (mode == "contains" && index(line, required)))) {
            found = 1
        }
    }
    END { exit found ? 0 : 1 }
  ' "$checked_file"
}

require_visible_heading() {
  required_heading=$1
  checked_file=$2
  visible_markdown_has "$required_heading" exact "$checked_file" ||
    fail "${checked_file#"$repo_root/"} is missing visible heading: $required_heading"
}

require_visible_text() {
  required_text=$1
  checked_file=$2
  visible_markdown_has "$required_text" contains "$checked_file" ||
    fail "${checked_file#"$repo_root/"} is missing visible text: $required_text"
}

for checked_file in "$model_file" "$threat_file" "$class_file" "$summary_file"; do
  validate_regular_file "$checked_file"
done

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
  require_visible_heading "$required_heading" "$model_file"
done

for required_source in \
  'https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html' \
  'https://datatracker.ietf.org/doc/html/rfc9700' \
  'https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html' \
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html' \
  'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html' \
  'https://kubernetes.io/docs/concepts/security/multi-tenancy/' \
  'https://kubernetes.io/docs/concepts/security/service-accounts/' \
  'https://www.postgresql.org/docs/18/ddl-rowsecurity.html'; do
  require_visible_text "$required_source" "$model_file"
done

require_visible_text '[formal threat model and data classification](threat-model.md)' "$summary_file"
require_visible_text "[\`threats.tsv\`](threats.tsv)" "$model_file"
require_visible_text "[\`data-classes.tsv\`](data-classes.tsv)" "$model_file"

LC_ALL=C awk -F '\t' '
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
        if (values[link_index] !~ /^https:\/\/github[.]com\/ArdurAI\/veer\/issues\/[0-9][0-9]*$/) {
            return 0
        }
    }
    return 1
}
function valid_evidence(value, values, count, citation_index) {
    count = split(value, values, ";")
    if (count < 1) {
        return 0
    }
    for (citation_index = 1; citation_index <= count; citation_index++) {
        if (values[citation_index] !~ /^docs\/[A-Za-z0-9_.\/-]+:[0-9][0-9]*(-[0-9][0-9]*)?$/) {
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
FNR == NR {
    if (in_model_comment) {
        if (index($0, "-->")) {
            in_model_comment = 0
        }
        next
    }
    if (index($0, "<!--")) {
        comment_tail = substr($0, index($0, "<!--") + 4)
        if (!index(comment_tail, "-->")) {
            in_model_comment = 1
        }
        next
    }
    if ($0 ~ /^[ ]?[ ]?[ ]?```/ || $0 ~ /^[ ]?[ ]?[ ]?~~~/) {
        in_model_fence = !in_model_fence
        next
    }
    if (in_model_fence) {
        next
    }
    if ($0 ~ /^##+ /) {
        section = $0
        table = ""
    }
    if (section == "### Protected assets" &&
        $0 == "| ID | Asset | Required property | Evidence |") {
        table = "assets"
        table_columns = 4
        next
    }
    if (section == "### Actors and realistic starting capabilities" &&
        $0 == "| ID | Actor and starting capability | Capability not assumed |") {
        table = "attackers"
        table_columns = 3
        next
    }
    if (section == "### Trust boundaries" &&
        $0 == "| ID | Crossing and transferred authority | Required enforcement | Verification owner |") {
        table = "boundaries"
        table_columns = 4
        next
    }
    if (section == "### Control owners" &&
        $0 == "| ID | Accountable surface | Live verification work |") {
        table = "owners"
        table_columns = 3
        next
    }
    if (section == "## Attack surface, mitigations, and attacker stories" &&
        $0 ~ /^\| Priority \| Scenario and capability gain \|/) {
        table = "threats"
        table_columns = 7
        next
    }
    if (table != "" && $0 ~ /^\| ---/) {
        separator_count = split($0, separator_cells, "|")
        if (separator_count != table_columns + 2) {
            error("unexpected column count in canonical " table " separator")
        }
        next
    }
    if (table == "assets" && $0 ~ /^\| A-[0-9][0-9] \|/) {
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
    if (table == "attackers" && $0 ~ /^\| ACT-[A-Z0-9-][A-Z0-9-]* \|/) {
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
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical boundaries row")
            next
        }
        boundary_id = trim(cells[2])
        if (boundaries[boundary_id]++) {
            error("duplicate trust-boundary row " boundary_id)
        }
        next
    }
    if (table == "owners" && $0 ~ /^\| OWN-[A-Z-][A-Z-]* \|/) {
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical owners row")
            next
        }
        owner_id = trim(cells[2])
        if (owners[owner_id]++) {
            error("duplicate control-owner row " owner_id)
        }
        next
    }
    if (table == "threats" &&
        $0 ~ /^\| (Critical|High|Medium|Low) \| \*\*TM-[0-9][0-9][0-9] /) {
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
        table = ""
        table_columns = 0
    }
    next
}
FNR == 1 {
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
' "$model_file" "$threat_file" || fail 'threat ledger contract is invalid'

LC_ALL=C awk -F '\t' '
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
        if (values[link_index] !~ /^https:\/\/github[.]com\/ArdurAI\/veer\/issues\/[0-9][0-9]*$/) {
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
FNR == NR {
    if (in_model_comment) {
        if (index($0, "-->")) {
            in_model_comment = 0
        }
        next
    }
    if (index($0, "<!--")) {
        comment_tail = substr($0, index($0, "<!--") + 4)
        if (!index(comment_tail, "-->")) {
            in_model_comment = 1
        }
        next
    }
    if ($0 ~ /^[ ]?[ ]?[ ]?```/ || $0 ~ /^[ ]?[ ]?[ ]?~~~/) {
        in_model_fence = !in_model_fence
        next
    }
    if (in_model_fence) {
        next
    }
    if ($0 ~ /^##+ /) {
        section = $0
        table = ""
    }
    if (section == "### Control owners" &&
        $0 == "| ID | Accountable surface | Live verification work |") {
        table = "owners"
        table_columns = 3
        next
    }
    if (section == "### Data classification" &&
        $0 == "| ID | Class | Central rule | Retention boundary | Owner and verification |") {
        table = "classes"
        table_columns = 5
        next
    }
    if (table != "" && $0 ~ /^\| ---/) {
        separator_count = split($0, separator_cells, "|")
        if (separator_count != table_columns + 2) {
            error("unexpected column count in canonical " table " separator")
        }
        next
    }
    if (table == "owners" && $0 ~ /^\| OWN-[A-Z-][A-Z-]* \|/) {
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical owners row")
            next
        }
        owner_id = trim(cells[2])
        if (owners[owner_id]++) {
            error("duplicate control-owner row " owner_id)
        }
        next
    }
    if (table == "classes" && $0 ~ /^\| DC-[A-Z][A-Z-]* \|/) {
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical classes row")
            next
        }
        class_id = trim(cells[2])
        if (class_seen[class_id]++) {
            error("duplicate readable data-class row " class_id)
        }
        model_class[class_id] = trim(cells[3])
        if (!match(cells[6], /OWN-[A-Z-][A-Z-]*/)) {
            error("readable data class lacks a control owner: " class_id)
        } else {
            model_class_owner[class_id] = substr(cells[6], RSTART, RLENGTH)
        }
        next
    }
    if (table != "" && $0 ~ /^\|/) {
        error("unexpected row in canonical " table " table")
        next
    }
    if (table != "" && $0 !~ /^\|/) {
        table = ""
        table_columns = 0
    }
    next
}
FNR == 1 {
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
' "$model_file" "$class_file" || fail 'data-class ledger contract is invalid'

LC_ALL=C awk '
{
    remaining = $0
    while (match(remaining, /docs\/[A-Za-z0-9_.\/-]+:[0-9][0-9]*(-[0-9][0-9]*)?/)) {
        citation = substr(remaining, RSTART, RLENGTH)
        if (!seen[citation]++) {
            print citation
        }
        remaining = substr(remaining, RSTART + RLENGTH)
    }
}
' "$model_file" "$threat_file" |
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
  done

printf '%s\n' 'security threat-model verification passed'
