#!/bin/sh
set -eu

script_dir=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")"
    pwd
)
architecture_dir=$(dirname -- "$script_dir")
repo_root=$(
    unset CDPATH
    cd -- "$architecture_dir/../.."
    pwd
)
versions_file="$script_dir/versions.tsv"
adr_file="$architecture_dir/0002-alpha-implementation-stack.md"

expected_header='component	role	version	verified_on	compatibility_url	release_url'
actual_header=$(sed -n '1p' "$versions_file")
if [ "$actual_header" != "$expected_header" ]; then
    printf '%s\n' 'versions.tsv has an unexpected header' >&2
    exit 1
fi

LC_ALL=C awk -F '\t' '
NR == 1 {
    next
}

NF != 6 {
    print FILENAME ":" NR ": expected 6 tab-separated fields" > "/dev/stderr"
    failed = 1
    next
}

$1 !~ /^[a-z][a-z0-9-]*$/ {
    print FILENAME ":" NR ": invalid component identifier " $1 > "/dev/stderr"
    failed = 1
}

seen[$1]++ {
    print FILENAME ":" NR ": duplicate component " $1 > "/dev/stderr"
    failed = 1
}

$3 !~ /^[0-9]+\.[0-9]+(\.[0-9]+)?$/ {
    print FILENAME ":" NR ": version is not exact: " $3 > "/dev/stderr"
    failed = 1
}

$4 !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ {
    print FILENAME ":" NR ": invalid verification date " $4 > "/dev/stderr"
    failed = 1
}

$5 !~ /^https:\/\// || $6 !~ /^https:\/\// {
    print FILENAME ":" NR ": evidence URLs must use HTTPS" > "/dev/stderr"
    failed = 1
}

END {
    split("go postgresql pgx sqlc goose", required, " ")
    for (required_index in required) {
        if (!seen[required[required_index]]) {
            print FILENAME ": missing required component " required[required_index] > "/dev/stderr"
            failed = 1
        }
    }
    if (failed) {
        exit 1
    }
}
' "$versions_file"

tab=$(printf '\t')
LC_ALL=C awk -F '\t' 'NR > 1 { print $1 "\t" $3 }' "$versions_file" |
while IFS="$tab" read -r component version
do
    if ! grep -Fq "| \`$component\` | \`$version\` |" "$adr_file"; then
        printf '%s\n' \
            "$adr_file: missing pin for $component $version" >&2
        exit 1
    fi
done

for heading in \
    '### Runtime and framework alternatives' \
    '### Relational-store alternatives' \
    '### Queue alternatives' \
    '### Migration-tool alternatives' \
    '### Module-boundary alternatives' \
    '## Benchmark and qualification assumptions'
do
    if ! grep -Fqx "$heading" "$adr_file"; then
        printf '%s\n' "$adr_file: missing required section $heading" >&2
        exit 1
    fi
done

if ! grep -Fq \
    '[Alpha implementation stack](docs/architecture/0002-alpha-implementation-stack.md)' \
    "$repo_root/README.md"
then
    printf '%s\n' 'README.md does not link ADR 0002' >&2
    exit 1
fi

if ! grep -Fq '[ADR 0002](0002-alpha-implementation-stack.md)' \
    "$architecture_dir/overview.md"
then
    printf '%s\n' 'architecture overview does not link ADR 0002' >&2
    exit 1
fi

printf '%s\n' 'stack decision verification passed'
