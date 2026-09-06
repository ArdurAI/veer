#!/bin/sh
set -eu

fail() {
  printf '%s\n' "veer-dco: $*" >&2
  exit 1
}

usage() {
  printf '%s\n' 'Usage: ./hack/verify-dco.sh BASE_COMMIT HEAD_COMMIT' >&2
}

validate_object_id() {
  object_label=$1
  object_id=$2
  case "$object_id" in
    '' | *[!0-9A-Fa-f]*) fail "$object_label must be a full hexadecimal object ID" ;;
  esac
  object_length=${#object_id}
  if [ "$object_length" -ne 40 ] && [ "$object_length" -ne 64 ]; then
    fail "$object_label must be a full 40- or 64-character object ID"
  fi
}

[ "$#" -eq 2 ] || {
  usage
  exit 2
}

base_input=$1
head_input=$2
validate_object_id base "$base_input"
validate_object_id head "$head_input"

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || fail 'not inside a Git repository'
cd -- "$repo_root"

base_commit=$(git rev-parse --verify "$base_input^{commit}" 2>/dev/null) ||
  fail "base commit is unavailable: $base_input"
head_commit=$(git rev-parse --verify "$head_input^{commit}" 2>/dev/null) ||
  fail "head commit is unavailable: $head_input"

commit_count=$(git rev-list --count "$base_commit..$head_commit") ||
  fail 'cannot enumerate the pull-request commit range'
[ "$commit_count" -gt 0 ] || fail 'pull-request commit range is empty'

failed=0
for commit in $(git rev-list --reverse --topo-order "$base_commit..$head_commit"); do
  author_identity=$(git show -s --format='%an <%ae>' "$commit") ||
    fail "cannot read author identity for $commit"

  if git show -s --format=%B "$commit" |
    git -c trailer.separators=: interpret-trailers --parse |
    LC_ALL=C VEER_DCO_EXPECTED_AUTHOR="$author_identity" awk '
      BEGIN {
        expected = ENVIRON["VEER_DCO_EXPECTED_AUTHOR"]
      }
      {
        key = $0
        sub(/:.*/, "", key)
        value = $0
        sub(/^[^:]*:[[:space:]]*/, "", value)
        if (tolower(key) == "signed-off-by" &&
            tolower(value) == tolower(expected)) {
          found = 1
        }
      }
      END { exit found ? 0 : 1 }
    '; then
    short_commit=$(git rev-parse --short=12 "$commit")
    printf '%s\n' "veer-dco commit=$short_commit status=passed"
  else
    short_commit=$(git rev-parse --short=12 "$commit")
    printf '%s\n' \
      "veer-dco commit=$short_commit status=failed expected=Signed-off-by: $author_identity" >&2
    failed=1
  fi
done

[ "$failed" -eq 0 ] || fail 'one or more commits lack an author-matching DCO sign-off'
printf '%s\n' "veer-dco commits=$commit_count status=passed"
