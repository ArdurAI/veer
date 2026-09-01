#!/bin/sh
set -eu

script_dir=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")"
    pwd
)
tmp_file=$(mktemp "${TMPDIR:-/tmp}/veer-cost-model.XXXXXX")

# Remove only the file allocated by mktemp for this invocation.
cleanup() {
    rm -f "$tmp_file"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

LC_ALL=C awk -f "$script_dir/calculate.awk" \
    "$script_dir/sources.tsv" \
    "$script_dir/profiles.tsv" \
    "$script_dir/inputs.tsv" >"$tmp_file"

diff -u "$script_dir/expected.tsv" "$tmp_file"
printf '%s\n' 'cost model verification passed'
