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
action_lock="$repo_root/.github/actions-lock.tsv"
go_bin="$repo_root/.tools/go/bin/go"

fail() {
  printf '%s\n' "veer-online-sources: $*" >&2
  exit 1
}

git_bin=$(command -v git) || fail 'git is required'
command -v awk >/dev/null 2>&1 || fail 'awk is required'
command -v diff >/dev/null 2>&1 || fail 'diff is required'
command -v mktemp >/dev/null 2>&1 || fail 'mktemp is required'
[ -f "$action_lock" ] && [ ! -L "$action_lock" ] ||
  fail 'action lock must be a regular non-symlink file'
[ -x "$go_bin" ] && [ ! -L "$go_bin" ] ||
  fail 'checksum-pinned Go is not installed as a regular executable'
[ -d "$repo_root/vendor" ] && [ ! -L "$repo_root/vendor" ] ||
  fail 'vendor must be a physical directory'

temp_base=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
temp_base=${temp_base%/}
case "$temp_base" in
  /*) ;;
  *) fail "temporary base must be absolute: $temp_base" ;;
esac
[ -d "$temp_base" ] && [ ! -L "$temp_base" ] ||
  fail "temporary base must be a physical directory: $temp_base"
task_tmp=$(mktemp -d "$temp_base/veer-online-sources.XXXXXX")
case "$task_tmp" in
  "$temp_base"/veer-online-sources.*) ;;
  *) fail "unsafe temporary directory: $task_tmp" ;;
esac
cleanup() {
  if [ -d "$task_tmp/modcache" ]; then
    chmod -R u+w "$task_tmp/modcache" || true
  fi
  rm -rf -- "$task_tmp"
}
trap cleanup 0 1 2 15

unset ALL_PROXY HTTPS_PROXY HTTP_PROXY NO_PROXY all_proxy https_proxy http_proxy no_proxy \
  GH_TOKEN GITHUB_TOKEN GIT_ASKPASS SSH_ASKPASS SSH_AUTH_SOCK \
  GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE GIT_CEILING_DIRECTORIES \
  GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_PREFIX GIT_CONFIG_SYSTEM \
  GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS \
  GIT_EXEC_PATH || true
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_GLOBAL=/dev/null
GIT_TERMINAL_PROMPT=0
GCM_INTERACTIVE=never
export GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL GIT_TERMINAL_PROMPT GCM_INTERACTIVE

LC_ALL=C awk -F '\t' '
NR == 1 {
    if ($0 != "action\tsha\tversion\tsource_url") {
        print FILENAME ": unexpected action-lock header" > "/dev/stderr"
        failed = 1
    }
    next
}
NF != 4 {
    print FILENAME ":" FNR ": expected four tab-separated fields" > "/dev/stderr"
    failed = 1
    next
}
{
    if ($1 !~ /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*$/ ||
        $1 ~ /(^|\/)\.\.?($|\/)/) {
        print FILENAME ":" FNR ": invalid action path " $1 > "/dev/stderr"
        failed = 1
    }
    if (length($2) != 40 || $2 !~ /^[0-9a-f]+$/) {
        print FILENAME ":" FNR ": invalid action SHA" > "/dev/stderr"
        failed = 1
    }
    if ($3 !~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/) {
        print FILENAME ":" FNR ": invalid release tag" > "/dev/stderr"
        failed = 1
    }
    split($1, action_path, "/")
    expected_url = "https://github.com/" action_path[1] "/" action_path[2] "/releases/tag/" $3
    if ($4 != expected_url) {
        print FILENAME ":" FNR ": source URL is not canonical for " $1 "@" $3 > "/dev/stderr"
        failed = 1
    }
    if (seen[$1]++) {
        print FILENAME ":" FNR ": duplicate action " $1 > "/dev/stderr"
        failed = 1
    }
    count++
}
END {
    if (count != 8) {
        print FILENAME ": expected eight action locks, found " count > "/dev/stderr"
        failed = 1
    }
    exit failed ? 1 : 0
}
' "$action_lock" || fail 'action-lock structure is invalid'

tab=$(printf '\t')
resolved_count=0
while IFS="$tab" read -r action expected_sha version _; do
  [ "$action" != action ] || continue
  owner=${action%%/*}
  remainder=${action#*/}
  repository_name=${remainder%%/*}
  repository="$owner/$repository_name"
  remote_refs=$(
    "$git_bin" -c credential.helper= -c core.askPass= -c http.extraHeader= \
      ls-remote --exit-code "https://github.com/$repository.git" \
      "refs/tags/$version" "refs/tags/$version^{}"
  ) || fail "cannot resolve $repository release tag $version"
  direct_sha=$(printf '%s\n' "$remote_refs" |
    LC_ALL=C awk -v ref="refs/tags/$version" '$2 == ref { print $1 }')
  peeled_sha=$(printf '%s\n' "$remote_refs" |
    LC_ALL=C awk -v ref="refs/tags/$version^{}" '$2 == ref { print $1 }')
  resolved_sha=${peeled_sha:-$direct_sha}
  [ -n "$resolved_sha" ] || fail "$repository release tag $version has no commit"
  [ "$resolved_sha" = "$expected_sha" ] ||
    fail "$action release tag $version resolves to $resolved_sha, expected $expected_sha"
  resolved_count=$((resolved_count + 1))
done <"$action_lock"
[ "$resolved_count" -eq 8 ] || fail "resolved $resolved_count action locks, expected 8"

mkdir -p "$task_tmp/gopath" "$task_tmp/modcache" "$task_tmp/go-build" \
  "$task_tmp/go-tmp" "$task_tmp/telemetry"
chmod 0700 "$task_tmp/telemetry"
printf '%s\n' off >"$task_tmp/telemetry/mode"
(
  cd -- "$repo_root"
  GOENV=off \
    GOPATH="$task_tmp/gopath" \
    GOMODCACHE="$task_tmp/modcache" \
    GOCACHE="$task_tmp/go-build" \
    GOTMPDIR="$task_tmp/go-tmp" \
    GOWORK=off \
    GOTOOLCHAIN=local \
    GOFLAGS='' \
    GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org \
    GOPRIVATE='' \
    GONOPROXY='' \
    GONOSUMDB='' \
    GOINSECURE='' \
    GOVCS='*:off' \
    TEST_TELEMETRY_DIR="$task_tmp/telemetry" \
    "$go_bin" mod download all
  GOENV=off \
    GOPATH="$task_tmp/gopath" \
    GOMODCACHE="$task_tmp/modcache" \
    GOCACHE="$task_tmp/go-build" \
    GOTMPDIR="$task_tmp/go-tmp" \
    GOWORK=off \
    GOTOOLCHAIN=local \
    GOFLAGS='' \
    GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org \
    GOVCS='*:off' \
    TEST_TELEMETRY_DIR="$task_tmp/telemetry" \
    "$go_bin" mod verify
  GOENV=off \
    GOPATH="$task_tmp/gopath" \
    GOMODCACHE="$task_tmp/modcache" \
    GOCACHE="$task_tmp/go-build" \
    GOTMPDIR="$task_tmp/go-tmp" \
    GOWORK=off \
    GOTOOLCHAIN=local \
    GOFLAGS='' \
    GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org \
    GOVCS='*:off' \
    TEST_TELEMETRY_DIR="$task_tmp/telemetry" \
    "$go_bin" mod vendor -o "$task_tmp/vendor"
)
diff -ru "$repo_root/vendor" "$task_tmp/vendor" ||
  fail 'committed vendor differs from checksum-authenticated module source'

printf '%s\n' \
  "veer-online-sources action_locks=$resolved_count vendor=authenticated status=passed"
