#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
docs_root=$(CDPATH='' cd -- "$repo_root/docs" && pwd -P)
model_file="$script_dir/threat-model.md"
model_inventory_file="$script_dir/model-inventory.tsv"
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
    function is_escaped(line, position, slash_count) {
        slash_count = 0
        position--
        while (position > 0 && substr(line, position, 1) == "\\") {
            slash_count++
            position--
        }
        return slash_count % 2 == 1
    }
    function spaces(count, value, space_index) {
        value = ""
        for (space_index = 0; space_index < count; space_index++) {
            value = value " "
        }
        return value
    }
    function matching_tick_end(line, opening_index, opening_length,
                               scan_index, run_length) {
        scan_index = opening_index + opening_length
        while (scan_index <= length(line)) {
            if (substr(line, scan_index, 1) != "`") {
                scan_index++
                continue
            }
            run_length = 1
            while (substr(line, scan_index + run_length, 1) == "`") {
                run_length++
            }
            if (run_length == opening_length) {
                return scan_index + run_length - 1
            }
            scan_index += run_length
        }
        return 0
    }
    function rendered_contract_text(line, character_index, visible, character,
                                    run_length, closing_index) {
        visible = ""
        character_index = 1
        while (character_index <= length(line)) {
            if (in_comment) {
                if (substr(line, character_index, 3) == "-->") {
                    visible = visible "   "
                    character_index += 3
                    in_comment = 0
                } else {
                    visible = visible " "
                    character_index++
                }
                continue
            }
            character = substr(line, character_index, 1)
            if (inline_tick_count) {
                if (character == "`") {
                    run_length = 1
                    while (substr(line, character_index + run_length, 1) == "`") {
                        run_length++
                    }
                    visible = visible spaces(run_length)
                    if (run_length == inline_tick_count) {
                        inline_tick_count = 0
                    }
                    character_index += run_length
                } else {
                    visible = visible " "
                    character_index++
                }
                continue
            }
            if (substr(line, character_index, 4) == "<!--") {
                visible = visible "    "
                in_comment = 1
                character_index += 4
                continue
            }
            if (character == "`" && !is_escaped(line, character_index)) {
                run_length = 1
                while (substr(line, character_index + run_length, 1) == "`") {
                    run_length++
                }
                closing_index = matching_tick_end(line, character_index, run_length)
                if (closing_index) {
                    visible = visible substr(line, character_index,
                        closing_index - character_index + 1)
                    character_index = closing_index + 1
                } else {
                    visible = visible spaces(run_length)
                    inline_tick_count = run_length
                    character_index += run_length
                }
                continue
            }
            visible = visible character
            character_index++
        }
        return visible
    }
    function has_rendered_raw_html(line) {
        return line ~ /<\/?[A-Za-z][A-Za-z0-9-]*([[:space:]\/>]|$)/ ||
            line ~ /<!\[CDATA\[|<\?|<![A-Z]/
    }
    function has_entity_reference(line) {
        return line ~ /&(#([xX][0-9A-Fa-f]+|[0-9]+)|[A-Za-z][A-Za-z0-9]+);/
    }
    function has_list_contained_heading(line, candidate, list_seen, matched_length) {
        candidate = line
        sub(/^[[:space:]]*/, "", candidate)
        while (candidate != "") {
            if (match(candidate, /^>[[:space:]]*/)) {
                matched_length = RLENGTH
            } else if (match(candidate, /^[-+*][[:space:]]+/)) {
                matched_length = RLENGTH
                list_seen = 1
            } else if (match(candidate, /^[0-9]+[.)][[:space:]]+/)) {
                matched_length = RLENGTH
                list_seen = 1
            } else {
                break
            }
            candidate = substr(candidate, matched_length + 1)
            sub(/^[[:space:]]*/, "", candidate)
        }
        return list_seen && candidate ~ /^#+([[:space:]]|$)/
    }
    function normalize_atx_heading(line, normalized, leading_spaces, hashes, content) {
        normalized = line
        leading_spaces = 0
        while (leading_spaces < 3 && substr(normalized, 1, 1) == " ") {
            normalized = substr(normalized, 2)
            leading_spaces++
        }
        if (substr(normalized, 1, 1) == " ") {
            return line
        }
        hashes = 0
        while (substr(normalized, hashes + 1, 1) == "#") {
            hashes++
        }
        if (hashes < 1 || hashes > 6) {
            return line
        }
        content = substr(normalized, hashes + 1)
        if (content != "" && substr(content, 1, 1) !~ /^[[:space:]]$/) {
            return line
        }
        sub(/^[[:space:]]+/, "", content)
        sub(/[[:space:]]+#+[[:space:]]*$/, "", content)
        sub(/[[:space:]]+$/, "", content)
        gsub(/[[:space:]]+/, " ", content)
        normalized = substr(normalized, 1, hashes)
        return content == "" ? normalized : normalized " " content
    }
    {
        line = $0
        if (in_fence) {
            fence_transition(line)
            print ""
            next
        }
        if (!in_comment && !inline_tick_count && fence_transition(line)) {
            print ""
            next
        }
        line = rendered_contract_text(line)
        if (line ~ /^[[:space:]]*>/) {
            print FILENAME ":" FNR ": rendered blockquotes are forbidden in verified Markdown" > "/dev/stderr"
            failed = 1
        }
        if (has_list_contained_heading(line)) {
            print FILENAME ":" FNR ": rendered list-contained headings are forbidden in verified Markdown" > "/dev/stderr"
            failed = 1
        }
        if (has_rendered_raw_html(line)) {
            print FILENAME ":" FNR ": rendered raw HTML is forbidden in verified Markdown" > "/dev/stderr"
            failed = 1
            print ""
            next
        }
        if (has_entity_reference(line)) {
            print FILENAME ":" FNR ": entity references are forbidden in verified Markdown" > "/dev/stderr"
            failed = 1
        }
        normalized = normalize_atx_heading(line)
        print normalized
    }
    END {
        if (inline_tick_count) {
            print FILENAME ": unterminated inline code span in verified Markdown" > "/dev/stderr"
            failed = 1
        }
        exit failed ? 1 : 0
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

require_markdown_link() {
  required_label=$1
  required_destination=$2
  checked_file=$3
  visible_file=$4
  required_link="[$required_label]($required_destination)"
  LC_ALL=C awk -v required="$required_link" '
    function is_escaped(line, position, slash_count) {
        slash_count = 0
        position--
        while (position > 0 && substr(line, position, 1) == "\\") {
            slash_count++
            position--
        }
        return slash_count % 2 == 1
    }
    function is_image_opener(line, position) {
        return position > 1 && substr(line, position - 1, 1) == "!" &&
            !is_escaped(line, position - 1)
    }
    {
        line = $0
        for (character_index = 1; character_index <= length(line); character_index++) {
            if (!code_tick_count &&
                substr(line, character_index, length(required)) == required &&
                !is_escaped(line, character_index) &&
                !is_image_opener(line, character_index)) {
                found = 1
            }
            if (substr(line, character_index, 1) != "`" ||
                is_escaped(line, character_index)) {
                continue
            }
            run_length = 1
            while (substr(line, character_index + run_length, 1) == "`") {
                run_length++
            }
            if (!code_tick_count) {
                code_tick_count = run_length
            } else if (run_length == code_tick_count) {
                code_tick_count = 0
            }
            character_index += run_length - 1
        }
    }
    END { exit found ? 0 : 1 }
  ' "$visible_file" ||
    fail "${checked_file#"$repo_root/"} is missing unescaped Markdown link: $required_link"
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
  "$model_inventory_file" \
  "$threat_file" \
  "$class_file" \
  "$summary_file" \
  "$issue_inventory_file"; do
  validate_regular_file "$checked_file"
done

LC_ALL=C awk '
  function issue_number_is_supported(issue_number) {
      return length(issue_number) < 10 ||
          (length(issue_number) == 10 && issue_number <= 2147483647)
  }
  !/^https:\/\/github[.]com\/ArdurAI\/veer\/issues\/[1-9][0-9]*$/ {
      print FILENAME ":" FNR ": invalid issue inventory entry" > "/dev/stderr"
      failed = 1
      next
  }
  {
      issue_number = $0
      sub(/^.*\//, "", issue_number)
      if (!issue_number_is_supported(issue_number)) {
          print FILENAME ":" FNR ": issue inventory entry exceeds supported issue number" > "/dev/stderr"
          failed = 1
          next
      }
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
write_visible_markdown "$model_file" "$visible_model_file" ||
  fail 'formal threat model contains unsupported rendered markup'
write_visible_markdown "$summary_file" "$visible_summary_file" ||
  fail 'security summary contains unsupported rendered markup'

LC_ALL=C awk '
  function trim(value) {
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      return value
  }
  function setext_level(line, stripped, leading_spaces) {
      stripped = line
      leading_spaces = 0
      while (leading_spaces < 3 && substr(stripped, 1, 1) == " ") {
          stripped = substr(stripped, 2)
          leading_spaces++
      }
      if (substr(stripped, 1, 1) == " ") {
          return 0
      }
      if (stripped ~ /^=+[[:space:]]*$/) {
          return 1
      }
      if (stripped ~ /^-+[[:space:]]*$/) {
          return 2
      }
      return 0
  }
  function record_heading(heading) {
      if (seen[heading]++) {
          print FILENAME ":" FNR ": duplicate visible heading: " heading > "/dev/stderr"
          failed = 1
      }
  }
  {
      if ($0 ~ /^##+ /) {
          record_heading($0)
      }
      level = setext_level($0)
      setext_text = trim(previous_line)
      if (level && setext_text != "") {
          record_heading((level == 1 ? "# " : "## ") setext_text)
      }
      previous_line = $0
  }
  END { exit failed ? 1 : 0 }
' "$visible_model_file" || fail 'readable model contains duplicate canonical sections'

LC_ALL=C awk -v issue_inventory="$issue_inventory_file" '
  function validate_issue(number, issue_url) {
      issue_url = "https://github.com/ArdurAI/veer/issues/" number
      if (!(issue_url in known_issue)) {
          print FILENAME ":" FNR ": unknown readable issue reference #" number > "/dev/stderr"
          failed = 1
      }
  }
  BEGIN {
      while ((getline inventory_entry < issue_inventory) > 0) {
          known_issue[inventory_entry] = 1
          inventory_number = inventory_entry
          sub(/^.*\//, "", inventory_number)
          if (length(inventory_number) > max_issue_digits) {
              max_issue_digits = length(inventory_number)
          }
          known_issue_count++
      }
      close(issue_inventory)
  }
  {
      issue_token_remaining = $0
      while (match(issue_token_remaining, /#[0-9][A-Za-z0-9_-]*/)) {
          issue_token = substr(issue_token_remaining, RSTART, RLENGTH)
          if (issue_token !~ /^#[1-9][0-9]*$/) {
              print FILENAME ":" FNR ": malformed readable issue reference " issue_token > "/dev/stderr"
              failed = 1
          }
          issue_token_remaining = substr(issue_token_remaining, RSTART + RLENGTH)
      }
      remaining = $0
      while (match(remaining, /#[1-9][0-9]* through #[1-9][0-9]*/)) {
          range = substr(remaining, RSTART, RLENGTH)
          split(range, endpoints, " through ")
          range_start_text = substr(endpoints[1], 2)
          range_end_text = substr(endpoints[2], 2)
          if (length(range_start_text) > max_issue_digits ||
              length(range_end_text) > max_issue_digits) {
              print FILENAME ":" FNR ": readable issue range exceeds offline inventory bound " range > "/dev/stderr"
              failed = 1
          } else {
              range_start = range_start_text + 0
              range_end = range_end_text + 0
          }
          if (length(range_start_text) <= max_issue_digits &&
              length(range_end_text) <= max_issue_digits &&
              range_start > range_end) {
              print FILENAME ":" FNR ": invalid readable issue range " range > "/dev/stderr"
              failed = 1
          } else if (length(range_start_text) <= max_issue_digits &&
              length(range_end_text) <= max_issue_digits &&
              range_end - range_start + 1 > known_issue_count) {
              print FILENAME ":" FNR ": readable issue range exceeds offline inventory bound " range > "/dev/stderr"
              failed = 1
          } else if (length(range_start_text) <= max_issue_digits &&
              length(range_end_text) <= max_issue_digits) {
              for (issue_number = range_start; issue_number <= range_end; issue_number++) {
                  validate_issue(issue_number)
              }
          }
          remaining = substr(remaining, RSTART + RLENGTH)
      }
      remaining = $0
      while (match(remaining, /#[1-9][0-9]*/)) {
          issue_number = substr(remaining, RSTART + 1, RLENGTH - 1)
          validate_issue(issue_number)
          remaining = substr(remaining, RSTART + RLENGTH)
      }
  }
  END { exit failed ? 1 : 0 }
' "$visible_model_file" || fail 'readable model references issues outside the offline inventory'

for required_heading in \
  '## Overview' \
  '### Components and source evidence' \
  '### Effective resources and capabilities' \
  '## Threat model, trust boundaries, and assumptions' \
  '### Protected assets' \
  '### Security objectives' \
  '### Actors and realistic starting capabilities' \
  '### Trust boundaries' \
  '### Control owners' \
  '### Workspace isolation assumptions' \
  '### Provider credential flow and blast radius' \
  '### Data classification' \
  '### Unsupported deployment modes' \
  '### Assumptions and unresolved evidence' \
  '## Attack surface, mitigations, and attacker stories' \
  '### Residual risk that cannot be relabeled as mitigation' \
  '### Review and maintenance' \
  '## Severity calibration' \
  '### Primary references'; do
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

require_markdown_link \
  'formal threat model and data classification' \
  'threat-model.md' \
  "$summary_file" \
  "$visible_summary_file"
require_markdown_link \
  'model-inventory.tsv' \
  'model-inventory.tsv' \
  "$model_file" \
  "$visible_model_file"
require_markdown_link \
  'threats.tsv' \
  'threats.tsv' \
  "$model_file" \
  "$visible_model_file"
require_markdown_link \
  'data-classes.tsv' \
  'data-classes.tsv' \
  "$model_file" \
  "$visible_model_file"
require_markdown_link \
  'issue-inventory.txt' \
  'issue-inventory.txt' \
  "$model_file" \
  "$visible_model_file"

LC_ALL=C awk -F '\t' -v issue_inventory="$issue_inventory_file" \
  -v model_inventory="$model_inventory_file" '
function trim(value) {
    sub(/^[[:space:]]+/, "", value)
    sub(/[[:space:]]+$/, "", value)
    return value
}
function error(message) {
    print FILENAME ":" FNR ": " message > "/dev/stderr"
    failed = 1
}
function inventory_error(message) {
    print model_inventory ":" inventory_line_number ": " message > "/dev/stderr"
    failed = 1
}
function valid_links(value, record_id, role, values, count, link_index, issue_key) {
    count = split(value, values, ",")
    if (count < 1) {
        return 0
    }
    for (link_index = 1; link_index <= count; link_index++) {
        if (values[link_index] !~ /^https:\/\/github[.]com\/ArdurAI\/veer\/issues\/[1-9][0-9]*$/ ||
            !(values[link_index] in known_issue)) {
            return 0
        }
        issue_key = record_id SUBSEP values[link_index]
        if (role == "follow_up") {
            ledger_follow_up[issue_key] = 1
        } else if (role == "verification") {
            ledger_verification[issue_key] = 1
        } else {
            return 0
        }
    }
    return 1
}
function record_model_issue(record_id, issue_url, role, issue_key) {
    if (record_id == "") {
        return 1
    }
    issue_key = record_id SUBSEP issue_url
    if (role == "follow_up") {
        if (issue_key in model_follow_up) {
            return 0
        }
        model_follow_up[issue_key] = 1
        return 1
    }
    if (role == "verification") {
        if (issue_key in model_verification) {
            return 0
        }
        model_verification[issue_key] = 1
        return 1
    }
    return 0
}
function valid_issue_work(value, record_id, role, work, range_values, range_count,
                          range_start_text, range_end_text, range_start, range_end,
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
        range_start_text = substr(range_values[1], 2)
        range_end_text = substr(range_values[2], 2)
        if (length(range_start_text) > max_issue_digits ||
            length(range_end_text) > max_issue_digits) {
            return 0
        }
        range_start = range_start_text + 0
        range_end = range_end_text + 0
        if (range_start > range_end ||
            range_end - range_start + 1 > known_issue_count) {
            return 0
        }
        for (issue_number = range_start; issue_number <= range_end; issue_number++) {
            issue_url = "https://github.com/ArdurAI/veer/issues/" issue_number
            if (!(issue_url in known_issue) || !record_model_issue(record_id, issue_url, role)) {
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
        if (!(issue_url in known_issue) || !record_model_issue(record_id, issue_url, role)) {
            return 0
        }
        remaining = substr(remaining, RSTART + RLENGTH)
    }
    return 1
}
function valid_role_evidence(value, record_id, separator, follow_up_work, verification_work) {
    if (substr(value, 1, 11) != "Follow-up: ") {
        return 0
    }
    value = substr(value, 12)
    separator = index(value, "; verification: ")
    if (!separator) {
        return 0
    }
    follow_up_work = substr(value, 1, separator - 1)
    verification_work = substr(value, separator + 16)
    if (follow_up_work == "" || verification_work == "") {
        return 0
    }
    return valid_issue_work(follow_up_work, record_id, "follow_up") &&
        valid_issue_work(verification_work, record_id, "verification")
}
function record_readable_attackers(value, threat_id, remaining, relative_start, prefix,
                                   preceding, candidate, attacker_id, matched_length,
                                   following, attacker_key, found) {
    remaining = value
    while ((relative_start = index(remaining, "ACT-")) > 0) {
        prefix = substr(remaining, 1, relative_start - 1)
        preceding = length(prefix) > 0 ? substr(prefix, length(prefix), 1) : ""
        if (preceding ~ /[A-Za-z0-9_-]/) {
            return 0
        }
        candidate = substr(remaining, relative_start)
        if (!match(candidate, /^ACT-[A-Z0-9]+(-[A-Z0-9]+)*/)) {
            return 0
        }
        attacker_id = substr(candidate, RSTART, RLENGTH)
        matched_length = RLENGTH
        following = substr(candidate, matched_length + 1, 1)
        if (following ~ /[A-Za-z0-9_-]/ || !(attacker_id in attackers)) {
            return 0
        }
        attacker_key = threat_id SUBSEP attacker_id
        model_attacker[attacker_key] = 1
        found = 1
        remaining = substr(candidate, matched_length + 1)
    }
    return found
}
function has_complete_citation(value) {
    return value ~ /(^|[^A-Za-z0-9_.\/:\-])(\.\/)?docs\/[A-Za-z0-9_.\/-]+:[1-9][0-9]*(-[1-9][0-9]*)?([^A-Za-z0-9_.\/:\-]|$)/
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
function valid_gfm_delimiter_row(line, cells, candidate, count, cell_index, value) {
    candidate = trim(line)
    if (candidate !~ /\|/) {
        return 0
    }
    sub(/^\|/, "", candidate)
    sub(/\|$/, "", candidate)
    count = split(candidate, cells, "|")
    if (count < 2) {
        return 0
    }
    for (cell_index = 1; cell_index <= count; cell_index++) {
        value = trim(cells[cell_index])
        if (value !~ /^:?-{3,}:?$/) {
            return 0
        }
    }
    return 1
}
function markdown_heading_level(line, level) {
    level = 0
    while (substr(line, level + 1, 1) == "#") {
        level++
    }
    return level
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
        inventory_number = inventory_entry
        sub(/^.*\//, "", inventory_number)
        if (length(inventory_number) > max_issue_digits) {
            max_issue_digits = length(inventory_number)
        }
        known_issue_count++
    }
    close(issue_inventory)
    required_component["API and GitOps edge"] = 1
    required_component["Identity and policy"] = 1
    required_component["PostgreSQL state store"] = 1
    required_component["Reconciliation queue and worker"] = 1
    required_component["Credential broker and provider adapters"] = 1
    required_component["Audit, telemetry, and archive"] = 1
    required_component["Migration, backup, and recovery tooling"] = 1
    required_component["Build and release path"] = 1
    required_component_count = 8
    for (required_asset_index = 1; required_asset_index <= 9; required_asset_index++) {
        required_asset[sprintf("A-%02d", required_asset_index)] = 1
    }
    required_asset_count = 9
    required_attacker["ACT-NET"] = 1
    required_attacker["ACT-MEMBER"] = 1
    required_attacker["ACT-TENANT"] = 1
    required_attacker["ACT-WORKLOAD"] = 1
    required_attacker["ACT-PROVIDER"] = 1
    required_attacker["ACT-PLATFORM"] = 1
    required_attacker["ACT-SUPPLY"] = 1
    required_attacker_count = 7
    for (required_boundary_index = 1; required_boundary_index <= 13; required_boundary_index++) {
        required_boundary[sprintf("TB-%02d", required_boundary_index)] = 1
    }
    required_boundary_count = 13
    required_owner["OWN-SECURITY"] = 1
    required_owner["OWN-IDENTITY"] = 1
    required_owner["OWN-CREDENTIALS"] = 1
    required_owner["OWN-DATA"] = 1
    required_owner["OWN-RECONCILIATION"] = 1
    required_owner["OWN-PROVIDERS"] = 1
    required_owner["OWN-OPERATIONS"] = 1
    required_owner["OWN-SUPPLY-CHAIN"] = 1
    required_owner_count = 8
    for (required_threat_index = 1; required_threat_index <= 21; required_threat_index++) {
        required_threat[sprintf("TM-%03d", required_threat_index)] = 1
    }
    inventory_line_number = 1
    inventory_status = getline inventory_line < model_inventory
    expected_inventory_header = "kind\tid_or_name\tdescription\trequirement_or_exclusion\taccountability_or_evidence"
    if (inventory_status <= 0) {
        inventory_error("model inventory is empty or unreadable")
    } else if (inventory_line != expected_inventory_header) {
        inventory_error("unexpected model inventory header")
    }
    while ((inventory_status = getline inventory_line < model_inventory) > 0) {
        inventory_line_number++
        inventory_field_count = split(inventory_line, inventory_fields, "\t")
        if (inventory_field_count != 5) {
            inventory_error("expected 5 tab-separated model inventory fields")
            continue
        }
        inventory_kind = trim(inventory_fields[1])
        inventory_id = trim(inventory_fields[2])
        inventory_description_value = trim(inventory_fields[3])
        inventory_requirement_value = trim(inventory_fields[4])
        inventory_accountability_value = trim(inventory_fields[5])
        if (inventory_kind == "" || inventory_id == "" ||
            inventory_description_value == "" || inventory_requirement_value == "" ||
            inventory_accountability_value == "") {
            inventory_error("model inventory fields must be nonempty")
            continue
        }
        inventory_key = inventory_kind SUBSEP inventory_id
        if (model_inventory_seen[inventory_key]++) {
            inventory_error("duplicate model inventory row " inventory_kind "/" inventory_id)
        }
        inventory_kind_rows[inventory_kind]++
        model_inventory_description[inventory_key] = inventory_description_value
        model_inventory_requirement[inventory_key] = inventory_requirement_value
        model_inventory_accountability[inventory_key] = inventory_accountability_value
        if (inventory_kind == "component") {
            if (!(inventory_id in required_component)) {
                inventory_error("unexpected model inventory component " inventory_id)
            }
            if (inventory_requirement_value != "-" ||
                !has_complete_citation(inventory_accountability_value)) {
                inventory_error("invalid model inventory component contract " inventory_id)
            }
        } else if (inventory_kind == "asset") {
            if (!(inventory_id in required_asset)) {
                inventory_error("unexpected model inventory asset " inventory_id)
            }
            if (inventory_requirement_value == "-" ||
                !has_complete_citation(inventory_accountability_value)) {
                inventory_error("invalid model inventory asset contract " inventory_id)
            }
        } else if (inventory_kind == "attacker") {
            if (!(inventory_id in required_attacker)) {
                inventory_error("unexpected model inventory attacker " inventory_id)
            }
            if (inventory_requirement_value == "-" || inventory_accountability_value != "-") {
                inventory_error("invalid model inventory attacker contract " inventory_id)
            }
        } else if (inventory_kind == "boundary") {
            if (!(inventory_id in required_boundary)) {
                inventory_error("unexpected model inventory boundary " inventory_id)
            }
            if (inventory_requirement_value == "-" ||
                !(inventory_accountability_value in required_owner)) {
                inventory_error("invalid model inventory boundary contract " inventory_id)
            }
        } else if (inventory_kind == "owner") {
            if (!(inventory_id in required_owner)) {
                inventory_error("unexpected model inventory owner " inventory_id)
            }
            if (inventory_requirement_value != "-" ||
                !valid_issue_work(inventory_accountability_value, "", "")) {
                inventory_error("invalid model inventory owner contract " inventory_id)
            }
        } else {
            inventory_error("unexpected model inventory kind " inventory_kind)
        }
    }
    if (inventory_status < 0) {
        inventory_error("cannot read model inventory")
    }
    close(model_inventory)
    if (inventory_kind_rows["component"] != required_component_count ||
        inventory_kind_rows["asset"] != required_asset_count ||
        inventory_kind_rows["attacker"] != required_attacker_count ||
        inventory_kind_rows["boundary"] != required_boundary_count ||
        inventory_kind_rows["owner"] != required_owner_count) {
        inventory_error("model inventory kind counts do not match the canonical baseline")
    }
    for (inventory_required_id in required_component) {
        if (!("component" SUBSEP inventory_required_id in model_inventory_seen)) {
            inventory_error("missing model inventory component " inventory_required_id)
        }
    }
    for (inventory_required_id in required_asset) {
        if (!("asset" SUBSEP inventory_required_id in model_inventory_seen)) {
            inventory_error("missing model inventory asset " inventory_required_id)
        }
    }
    for (inventory_required_id in required_attacker) {
        if (!("attacker" SUBSEP inventory_required_id in model_inventory_seen)) {
            inventory_error("missing model inventory attacker " inventory_required_id)
        }
    }
    for (inventory_required_id in required_boundary) {
        if (!("boundary" SUBSEP inventory_required_id in model_inventory_seen)) {
            inventory_error("missing model inventory boundary " inventory_required_id)
        }
    }
    for (inventory_required_id in required_owner) {
        if (!("owner" SUBSEP inventory_required_id in model_inventory_seen)) {
            inventory_error("missing model inventory owner " inventory_required_id)
        }
    }
}
FNR == NR {
    if ($0 ~ /^##+ /) {
        current_heading_level = markdown_heading_level($0)
        leaves_canonical_section = canonical_section_table == "" ||
            current_heading_level <= canonical_section_level
        finish_table()
        section = $0
        if (leaves_canonical_section) {
            canonical_section_table = ""
            canonical_section_level = 0
            canonical_header_seen = 0
            if (section == "### Components and source evidence") {
                canonical_section_table = "components"
            } else if (section == "### Protected assets") {
                canonical_section_table = "assets"
            } else if (section == "### Actors and realistic starting capabilities") {
                canonical_section_table = "attackers"
            } else if (section == "### Trust boundaries") {
                canonical_section_table = "boundaries"
            } else if (section == "### Control owners") {
                canonical_section_table = "owners"
            } else if (section == "## Attack surface, mitigations, and attacker stories") {
                canonical_section_table = "threats"
            }
            if (canonical_section_table != "") {
                canonical_section_level = current_heading_level
            }
        }
    }
    if (canonical_header_seen && table == "" &&
        canonical_section_table != "" && $0 ~ /^\|/) {
        error("unexpected table in canonical " canonical_section_table " section")
        next
    }
    if (section == "### Components and source evidence" &&
        $0 == "| Component | Security-relevant responsibility | Source evidence |") {
        if (canonical_header_seen) {
            error("duplicate canonical components table header")
            next
        }
        table = "components"
        table_columns = 3
        table_delimiter_seen = 0
        canonical_header_seen = 1
        next
    }
    if (section == "### Protected assets" &&
        $0 == "| ID | Asset | Required property | Evidence |") {
        if (canonical_header_seen) {
            error("duplicate canonical assets table header")
            next
        }
        table = "assets"
        table_columns = 4
        table_delimiter_seen = 0
        canonical_header_seen = 1
        next
    }
    if (section == "### Actors and realistic starting capabilities" &&
        $0 == "| ID | Actor and starting capability | Capability not assumed |") {
        if (canonical_header_seen) {
            error("duplicate canonical attackers table header")
            next
        }
        table = "attackers"
        table_columns = 3
        table_delimiter_seen = 0
        canonical_header_seen = 1
        next
    }
    if (section == "### Trust boundaries" &&
        $0 == "| ID | Crossing and transferred authority | Required enforcement | Verification owner |") {
        if (canonical_header_seen) {
            error("duplicate canonical boundaries table header")
            next
        }
        table = "boundaries"
        table_columns = 4
        table_delimiter_seen = 0
        canonical_header_seen = 1
        next
    }
    if (section == "### Control owners" &&
        $0 == "| ID | Accountable surface | Live verification work |") {
        if (canonical_header_seen) {
            error("duplicate canonical owners table header")
            next
        }
        table = "owners"
        table_columns = 3
        table_delimiter_seen = 0
        canonical_header_seen = 1
        next
    }
    if (section == "## Attack surface, mitigations, and attacker stories" &&
        $0 ~ /^\| Priority \| Scenario and capability gain \|/) {
        if (canonical_header_seen) {
            error("duplicate canonical threats table header")
            next
        }
        expected_header = "| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Follow-up and verification |"
        if ($0 != expected_header) {
            error("unexpected canonical threats table header")
            next
        }
        table = "threats"
        table_columns = 7
        table_delimiter_seen = 0
        canonical_header_seen = 1
        next
    }
    if (table != "" && valid_delimiter_row($0, table_columns, delimiter_cells)) {
        if (table_delimiter_seen) {
            error("duplicate delimiter in canonical " table " table")
        }
        table_delimiter_seen = 1
        next
    }
    if (table == "components" && $0 ~ /^\|/) {
        if (!table_delimiter_seen) {
            error("canonical components row appears before a valid delimiter")
            next
        }
        if (!valid_readable_row($0, table_columns, cells)) {
            error("invalid required cells in canonical components row")
            next
        }
        component_name = trim(cells[2])
        if (!(component_name in required_component)) {
            error("unexpected canonical component " component_name)
        }
        if (components[component_name]++) {
            error("duplicate canonical component " component_name)
        }
        component_rows++
        inventory_key = "component" SUBSEP component_name
        if (trim(cells[3]) != model_inventory_description[inventory_key]) {
            error("canonical component description does not match model inventory: " component_name)
        }
        if (trim(cells[4]) != model_inventory_accountability[inventory_key]) {
            error("canonical component evidence does not match model inventory: " component_name)
        }
        if (!has_complete_citation(trim(cells[4]))) {
            error("component row lacks a complete source citation")
        }
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
        if (!(asset_id in required_asset)) {
            error("unexpected canonical asset " asset_id)
        }
        if (assets[asset_id]++) {
            error("duplicate protected-asset row " asset_id)
        }
        asset_rows++
        inventory_key = "asset" SUBSEP asset_id
        if (trim(cells[3]) != model_inventory_description[inventory_key]) {
            error("canonical asset description does not match model inventory: " asset_id)
        }
        if (trim(cells[4]) != model_inventory_requirement[inventory_key]) {
            error("canonical asset required property does not match model inventory: " asset_id)
        }
        if (trim(cells[5]) != model_inventory_accountability[inventory_key]) {
            error("canonical asset evidence does not match model inventory: " asset_id)
        }
        if (!has_complete_citation(trim(cells[5]))) {
            error("protected asset lacks a complete source citation: " asset_id)
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
        if (!(attacker_id in required_attacker)) {
            error("unexpected canonical attacker " attacker_id)
        }
        if (attackers[attacker_id]++) {
            error("duplicate attacker row " attacker_id)
        }
        attacker_rows++
        inventory_key = "attacker" SUBSEP attacker_id
        if (trim(cells[3]) != model_inventory_description[inventory_key]) {
            error("canonical attacker capability does not match model inventory: " attacker_id)
        }
        if (trim(cells[4]) != model_inventory_requirement[inventory_key]) {
            error("canonical attacker exclusion does not match model inventory: " attacker_id)
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
        if (!(boundary_id in required_boundary)) {
            error("unexpected canonical boundary " boundary_id)
        }
        if (boundaries[boundary_id]++) {
            error("duplicate trust-boundary row " boundary_id)
        }
        boundary_rows++
        boundary_owner[boundary_id] = trim(cells[5])
        inventory_key = "boundary" SUBSEP boundary_id
        if (trim(cells[3]) != model_inventory_description[inventory_key]) {
            error("canonical boundary crossing does not match model inventory: " boundary_id)
        }
        if (trim(cells[4]) != model_inventory_requirement[inventory_key]) {
            error("canonical boundary enforcement does not match model inventory: " boundary_id)
        }
        if (trim(cells[5]) != model_inventory_accountability[inventory_key]) {
            error("canonical boundary owner does not match model inventory: " boundary_id)
        }
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
        if (!(owner_id in required_owner)) {
            error("unexpected canonical owner " owner_id)
        }
        if (owners[owner_id]++) {
            error("duplicate control-owner row " owner_id)
        }
        owner_rows++
        inventory_key = "owner" SUBSEP owner_id
        if (trim(cells[3]) != model_inventory_description[inventory_key]) {
            error("canonical owner surface does not match model inventory: " owner_id)
        }
        if (trim(cells[4]) != model_inventory_accountability[inventory_key]) {
            error("canonical owner accountability does not match model inventory: " owner_id)
        }
        if (!valid_issue_work(trim(cells[4]), "", "")) {
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
        story_contract = trim(cells[3])
        story_prefix = "**" threat_id " — "
        if (substr(story_contract, 1, length(story_prefix)) != story_prefix) {
            error("invalid readable scenario prefix for " threat_id)
        } else {
            story_contract = substr(story_contract, length(story_prefix) + 1)
            story_close_position = index(story_contract, ".** ")
            if (!story_close_position) {
                error("invalid readable scenario boundary for " threat_id)
            } else {
                model_scenario[threat_id] = substr(story_contract, 1, story_close_position - 1)
                model_capability_gain[threat_id] = substr(story_contract, story_close_position + 4)
                if (model_scenario[threat_id] == "" || model_capability_gain[threat_id] == "") {
                    error("empty readable scenario contract for " threat_id)
                }
            }
        }
        model_prerequisites[threat_id] = trim(cells[4])
        model_impact[threat_id] = trim(cells[5])
        model_existing_controls[threat_id] = trim(cells[6])
        model_mitigation[threat_id] = trim(cells[7])
        if (!record_readable_attackers(trim(cells[3]), threat_id)) {
            error("invalid or undeclared actor set in readable attacker story " threat_id)
        }
        if (!valid_role_evidence(trim(cells[8]), threat_id)) {
            error("invalid follow-up or verification work for readable attacker story " threat_id)
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
    if (table == "" && canonical_section_table != "" && $0 ~ /^\|/) {
        error("unexpected table in canonical " canonical_section_table " section")
    } else if (table == "" && canonical_section_table != "" &&
               valid_gfm_delimiter_row($0, alternate_delimiter_cells)) {
        error("unexpected table in canonical " canonical_section_table " section")
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
    expected = "id\tstride\trisk\tassets\tboundary\tattackers\tscenario\tcapability_gain\tprerequisites\timpact\texisting_controls\tmitigation\towner\tfollow_up\tverification\tresidual_risk\tevidence"
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
NF != 17 {
    error("expected 17 tab-separated threat fields")
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
    } else {
        used_stride[$2] = 1
    }
    if (!($3 in risks)) {
        error("invalid risk " $3)
    }
    if (($1 in model_threat) && $3 != model_risk[$1]) {
        error("ledger risk does not match readable priority for " $1)
    }
    if (($1 in model_threat) && $7 != model_scenario[$1]) {
        error("ledger scenario does not match readable attacker story for " $1)
    }
    if (($1 in model_threat) && $8 != model_capability_gain[$1]) {
        error("ledger capability gain does not match readable attacker story for " $1)
    }
    if (($1 in model_threat) && $9 != model_prerequisites[$1]) {
        error("ledger prerequisites do not match readable attacker story for " $1)
    }
    if (($1 in model_threat) && $10 != model_impact[$1]) {
        error("ledger impact does not match readable attacker story for " $1)
    }
    if (($1 in model_threat) && $11 != model_existing_controls[$1]) {
        error("ledger existing controls do not match readable attacker story for " $1)
    }
    if (($1 in model_threat) && $12 != model_mitigation[$1]) {
        error("ledger mitigation does not match readable attacker story for " $1)
    }
    if (trim($4) == "") {
        error("threat requires at least one asset")
    }
    asset_count = split($4, asset_refs, "|")
    for (asset_index = 1; asset_index <= asset_count; asset_index++) {
        asset_id = asset_refs[asset_index]
        asset_key = $1 SUBSEP asset_id
        if (!(asset_id in assets)) {
            error("undeclared asset " asset_id)
        }
        if (ledger_asset[asset_key]++) {
            error("duplicate asset " asset_id " for " $1)
        }
        used_assets[asset_id] = 1
    }
    if (trim($5) == "") {
        error("threat requires at least one trust boundary")
    }
    boundary_count = split($5, boundary_refs, "|")
    for (boundary_index = 1; boundary_index <= boundary_count; boundary_index++) {
        boundary_id = boundary_refs[boundary_index]
        boundary_key = $1 SUBSEP boundary_id
        if (!(boundary_id in boundaries)) {
            error("undeclared boundary " boundary_id)
        }
        if (ledger_boundary[boundary_key]++) {
            error("duplicate boundary " boundary_id " for " $1)
        }
        used_boundaries[boundary_id] = 1
    }
    attacker_count = split($6, attacker_refs, "|")
    for (attacker_index = 1; attacker_index <= attacker_count; attacker_index++) {
        attacker_id = attacker_refs[attacker_index]
        attacker_key = $1 SUBSEP attacker_id
        if (attacker_id !~ /^ACT-[A-Z0-9]+(-[A-Z0-9]+)*$/) {
            error("invalid attacker " attacker_id)
        }
        if (!(attacker_id in attackers)) {
            error("undeclared attacker " attacker_id)
        }
        if (ledger_attacker[attacker_key]++) {
            error("duplicate attacker " attacker_id " for " $1)
        }
        used_attackers[attacker_id] = 1
    }
    attacker_mismatch = 0
    for (attacker_id in attackers) {
        attacker_key = $1 SUBSEP attacker_id
        if ((attacker_key in model_attacker) != (attacker_key in ledger_attacker)) {
            attacker_mismatch = 1
        }
    }
    if (attacker_mismatch) {
        error("ledger attackers do not match readable actor set for " $1)
    }
    for (field_index = 7; field_index <= 17; field_index++) {
        if (trim($field_index) == "" || trim($field_index) == "-") {
            error("empty required field " field_index)
        }
    }
    if (!($13 in owners)) {
        error("undeclared owner " $13)
    }
    used_owners[$13] = 1
    if (!valid_links($14, $1, "follow_up")) {
        error("follow_up must contain exact Veer issue URLs")
    }
    if (!valid_links($15, $1, "verification")) {
        error("verification must contain exact Veer issue URLs")
    }
    follow_up_mismatch = 0
    verification_mismatch = 0
    for (issue_url in known_issue) {
        issue_key = $1 SUBSEP issue_url
        if ((issue_key in model_follow_up) != (issue_key in ledger_follow_up)) {
            follow_up_mismatch = 1
        }
        if ((issue_key in model_verification) != (issue_key in ledger_verification)) {
            verification_mismatch = 1
        }
    }
    if (follow_up_mismatch) {
        error("ledger follow-up references do not match readable follow-up work for " $1)
    }
    if (verification_mismatch) {
        error("ledger verification references do not match readable verification work for " $1)
    }
    if (($3 == "critical" || $3 == "high") &&
        (trim($12) == "-" || trim($14) == "-")) {
        error("critical/high threat requires a mitigation and linked follow-up")
    }
    if (!valid_evidence($17)) {
        error("evidence must contain only complete repository documentation citations")
    }
}
END {
    if (rows == 0) {
        error("threat ledger has no rows")
    }
    if (component_rows == 0) {
        error("readable model has no canonical component rows")
    }
    if (component_rows != required_component_count) {
        error("readable model must contain exactly " required_component_count " canonical components")
    }
    for (component_name in required_component) {
        if (!(component_name in components)) {
            error("missing canonical component " component_name)
        }
    }
    if (asset_rows != required_asset_count) {
        error("readable model must contain exactly " required_asset_count " canonical assets")
    }
    for (required_asset_id in required_asset) {
        if (!(required_asset_id in assets)) {
            error("missing canonical asset " required_asset_id)
        }
    }
    if (attacker_rows != required_attacker_count) {
        error("readable model must contain exactly " required_attacker_count " canonical attackers")
    }
    for (required_attacker_id in required_attacker) {
        if (!(required_attacker_id in attackers)) {
            error("missing canonical attacker " required_attacker_id)
        }
    }
    if (boundary_rows != required_boundary_count) {
        error("readable model must contain exactly " required_boundary_count " canonical boundaries")
    }
    for (required_boundary_id in required_boundary) {
        if (!(required_boundary_id in boundaries)) {
            error("missing canonical boundary " required_boundary_id)
        }
    }
    if (owner_rows != required_owner_count) {
        error("readable model must contain exactly " required_owner_count " canonical owners")
    }
    for (required_owner_id in required_owner) {
        if (!(required_owner_id in owners)) {
            error("missing canonical owner " required_owner_id)
        }
    }
    for (required_threat_id in required_threat) {
        if (!(required_threat_id in seen)) {
            error("missing required threat " required_threat_id)
        }
    }
    for (stride_category in stride) {
        if (!(stride_category in used_stride)) {
            error("missing STRIDE category coverage: " stride_category)
        }
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
function valid_links(value, record_id, values, count, link_index, issue_key) {
    count = split(value, values, ",")
    if (count < 1) {
        return 0
    }
    for (link_index = 1; link_index <= count; link_index++) {
        if (values[link_index] !~ /^https:\/\/github[.]com\/ArdurAI\/veer\/issues\/[1-9][0-9]*$/ ||
            !(values[link_index] in known_issue)) {
            return 0
        }
        issue_key = record_id SUBSEP values[link_index]
        ledger_issue[issue_key] = 1
    }
    return 1
}
function record_model_issue(record_id, issue_url, issue_key) {
    if (record_id == "") {
        return 1
    }
    issue_key = record_id SUBSEP issue_url
    if (issue_key in model_issue) {
        return 0
    }
    model_issue[issue_key] = 1
    return 1
}
function valid_issue_work(value, record_id, work, range_values, range_count,
                          range_start_text, range_end_text, range_start, range_end,
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
        range_start_text = substr(range_values[1], 2)
        range_end_text = substr(range_values[2], 2)
        if (length(range_start_text) > max_issue_digits ||
            length(range_end_text) > max_issue_digits) {
            return 0
        }
        range_start = range_start_text + 0
        range_end = range_end_text + 0
        if (range_start > range_end ||
            range_end - range_start + 1 > known_issue_count) {
            return 0
        }
        for (issue_number = range_start; issue_number <= range_end; issue_number++) {
            issue_url = "https://github.com/ArdurAI/veer/issues/" issue_number
            if (!(issue_url in known_issue) || !record_model_issue(record_id, issue_url)) {
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
        if (!(issue_url in known_issue) || !record_model_issue(record_id, issue_url)) {
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
function valid_gfm_delimiter_row(line, cells, candidate, count, cell_index, value) {
    candidate = trim(line)
    if (candidate !~ /\|/) {
        return 0
    }
    sub(/^\|/, "", candidate)
    sub(/\|$/, "", candidate)
    count = split(candidate, cells, "|")
    if (count < 2) {
        return 0
    }
    for (cell_index = 1; cell_index <= count; cell_index++) {
        value = trim(cells[cell_index])
        if (value !~ /^:?-{3,}:?$/) {
            return 0
        }
    }
    return 1
}
function markdown_heading_level(line, level) {
    level = 0
    while (substr(line, level + 1, 1) == "#") {
        level++
    }
    return level
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
        inventory_number = inventory_entry
        sub(/^.*\//, "", inventory_number)
        if (length(inventory_number) > max_issue_digits) {
            max_issue_digits = length(inventory_number)
        }
        known_issue_count++
    }
    close(issue_inventory)
}
FNR == NR {
    if ($0 ~ /^##+ /) {
        current_heading_level = markdown_heading_level($0)
        leaves_canonical_section = canonical_section_table == "" ||
            current_heading_level <= canonical_section_level
        finish_table()
        section = $0
        if (leaves_canonical_section) {
            canonical_section_table = ""
            canonical_section_level = 0
            canonical_header_seen = 0
            if (section == "### Control owners") {
                canonical_section_table = "owners"
            } else if (section == "### Data classification") {
                canonical_section_table = "classes"
            }
            if (canonical_section_table != "") {
                canonical_section_level = current_heading_level
            }
        }
    }
    if (canonical_header_seen && table == "" &&
        canonical_section_table != "" && $0 ~ /^\|/) {
        error("unexpected table in canonical " canonical_section_table " section")
        next
    }
    if (section == "### Control owners" &&
        $0 == "| ID | Accountable surface | Live verification work |") {
        if (canonical_header_seen) {
            error("duplicate canonical owners table header")
            next
        }
        table = "owners"
        table_columns = 3
        table_delimiter_seen = 0
        canonical_header_seen = 1
        next
    }
    if (section == "### Data classification" &&
        $0 == "| ID | Class | Examples | At rest | In transit | Access | Logging | Retention | Disposal | Owner | Verification |") {
        if (canonical_header_seen) {
            error("duplicate canonical classes table header")
            next
        }
        table = "classes"
        table_columns = 11
        table_delimiter_seen = 0
        canonical_header_seen = 1
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
        if (!valid_issue_work(trim(cells[4]), "")) {
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
        model_class_examples[class_id] = trim(cells[4])
        model_class_at_rest[class_id] = trim(cells[5])
        model_class_in_transit[class_id] = trim(cells[6])
        model_class_access[class_id] = trim(cells[7])
        model_class_logging[class_id] = trim(cells[8])
        model_class_retention[class_id] = trim(cells[9])
        model_class_disposal[class_id] = trim(cells[10])
        owner_id = trim(cells[11])
        if (owner_id !~ /^OWN-[A-Z]+(-[A-Z]+)*$/) {
            error("readable data class has invalid control owner: " class_id)
        } else {
            model_class_owner[class_id] = owner_id
        }
        if (!valid_issue_work(trim(cells[12]), class_id)) {
            error("readable data class has invalid verification work: " class_id)
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
    if (table == "" && canonical_section_table != "" && $0 ~ /^\|/) {
        error("unexpected table in canonical " canonical_section_table " section")
    } else if (table == "" && canonical_section_table != "" &&
               valid_gfm_delimiter_row($0, alternate_delimiter_cells)) {
        error("unexpected table in canonical " canonical_section_table " section")
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
    if (($1 in model_class) && $3 != model_class_examples[$1]) {
        error("ledger examples do not match readable data class for " $1)
    }
    if (($1 in model_class) && $4 != model_class_at_rest[$1]) {
        error("ledger at-rest rule does not match readable data class for " $1)
    }
    if (($1 in model_class) && $5 != model_class_in_transit[$1]) {
        error("ledger in-transit rule does not match readable data class for " $1)
    }
    if (($1 in model_class) && $6 != model_class_access[$1]) {
        error("ledger access rule does not match readable data class for " $1)
    }
    if (($1 in model_class) && $7 != model_class_logging[$1]) {
        error("ledger logging rule does not match readable data class for " $1)
    }
    if (($1 in model_class) && $8 != model_class_retention[$1]) {
        error("ledger retention rule does not match readable data class for " $1)
    }
    if (($1 in model_class) && $9 != model_class_disposal[$1]) {
        error("ledger disposal rule does not match readable data class for " $1)
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
    if (!valid_links($11, $1)) {
        error("data-class verification must contain exact Veer issue URLs")
    }
    issue_mismatch = 0
    for (issue_url in known_issue) {
        issue_key = $1 SUBSEP issue_url
        if ((issue_key in model_issue) != (issue_key in ledger_issue)) {
            issue_mismatch = 1
        }
    }
    if (issue_mismatch) {
        error("ledger verification does not match readable data class for " $1)
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
function citation_delimiter(character) {
    return character == "" || character ~ /^[[:space:]]$/ ||
        character == "`" || character == ")" || character == "]" ||
        character == "}" || character == ";" || character == "," ||
        character == "." || character == "!"
}
function external_url_docs_occurrence(line, docs_start, prefix) {
    prefix = substr(line, 1, docs_start - 1)
    return prefix ~ /(^|[^A-Za-z0-9+.-])[Hh][Tt][Tt][Pp][Ss]?:\/\/[^[:space:]<>()]*\/$/
}
{
    search_from = 1
    while (search_from <= length($0)) {
        candidate = substr($0, search_from)
        relative_start = index(tolower(candidate), "docs/")
        if (!relative_start) {
            break
        }
        docs_start = search_from + relative_start - 1
        if (external_url_docs_occurrence($0, docs_start)) {
            search_from = docs_start + 5
            continue
        }
        if (substr($0, docs_start, 5) != "docs/") {
            error(docs_start)
            search_from = docs_start + 5
            continue
        }
        citation_start = docs_start
        if (citation_start > 2 && substr($0, citation_start - 2, 2) == "./") {
            citation_start -= 2
        }
        preceding = citation_start > 1 ? substr($0, citation_start - 1, 1) : ""
        if (preceding != "" && token_character(preceding)) {
            error(citation_start)
            search_from = docs_start + 5
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
        if (!citation_delimiter(following)) {
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
      citation_count = split($17, citations, ";")
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
  citation_cursor=$repo_root
  citation_remaining=$citation_path
  while [ -n "$citation_remaining" ]; do
    case "$citation_remaining" in
      */*)
        citation_component=${citation_remaining%%/*}
        citation_remaining=${citation_remaining#*/}
        ;;
      *)
        citation_component=$citation_remaining
        citation_remaining=''
        ;;
    esac
    citation_cursor="$citation_cursor/$citation_component"
    [ ! -L "$citation_cursor" ] ||
      fail "citation path contains a symbolic link: $citation"
  done
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
