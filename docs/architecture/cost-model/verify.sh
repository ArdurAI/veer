#!/bin/sh
set -eu

script_dir=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")"
    pwd
)
tmp_file=
expected_summary_file=
actual_summary_file=

# Remove only the files allocated by mktemp for this invocation.
cleanup() {
    for allocated_file in \
        "$tmp_file" \
        "$expected_summary_file" \
        "$actual_summary_file"
    do
        if [ -n "$allocated_file" ]; then
            rm -f -- "$allocated_file"
        fi
    done
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

tmp_file=$(mktemp "${TMPDIR:-/tmp}/veer-cost-model.XXXXXX")
expected_summary_file=$(mktemp \
    "${TMPDIR:-/tmp}/veer-cost-summary-expected.XXXXXX")
actual_summary_file=$(mktemp \
    "${TMPDIR:-/tmp}/veer-cost-summary-actual.XXXXXX")

LC_ALL=C awk -f "$script_dir/calculate.awk" \
    "$script_dir/sources.tsv" \
    "$script_dir/profiles.tsv" \
    "$script_dir/inputs.tsv" >"$tmp_file"

diff -u "$script_dir/expected.tsv" "$tmp_file"

LC_ALL=C awk -F '\t' '
function money(value, formatted, parts, whole, grouped) {
    formatted = sprintf("%.2f", value + 0)
    split(formatted, parts, ".")
    whole = parts[1]
    grouped = ""
    while (length(whole) > 3) {
        grouped = "," substr(whole, length(whole) - 2) grouped
        whole = substr(whole, 1, length(whole) - 3)
    }
    return whole grouped "." parts[2]
}

NR == 1 {
    next
}

$1 == "developer" {
    label = "Developer"
    estimate = "USD " money($2) " cloud infrastructure"
}

$1 == "small" {
    label = "Small production"
    estimate = "USD " money($2)
}

$1 == "target" {
    label = "Target-scale qualification"
    estimate = "USD " money($2)
}

{
    if (label == "") {
        print "unmapped cost-summary profile " $1 > "/dev/stderr"
        exit 1
    }
    printf "| %s | %s | USD %s | USD %s |\n", \
        label, estimate, money($3), money($4)
    label = ""
    estimate = ""
}
' "$script_dir/expected.tsv" >"$expected_summary_file"

LC_ALL=C awk '
/^\| Developer \|/ ||
/^\| Small production \|/ ||
/^\| Target-scale qualification \|/
' "$script_dir/../0001-alpha-operational-bounds.md" >"$actual_summary_file"

diff -u "$expected_summary_file" "$actual_summary_file"
printf '%s\n' 'cost model verification passed'
