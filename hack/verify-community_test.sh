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
temp_dir=

fail() {
  printf '%s\n' "veer-community-test: $*" >&2
  exit 1
}

cleanup() {
  if [ -n "$temp_dir" ] && [ -d "$temp_dir" ]; then
    rm -rf -- "$temp_dir"
  fi
}

trap cleanup 0
trap 'exit 1' HUP INT TERM

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/veer-community-test.XXXXXX")
fixture_root="$temp_dir/repository"

for relative_path in \
  .github/workflows/dco.yml \
  CODE_OF_CONDUCT.md \
  CONTRIBUTING.md \
  GOVERNANCE.md \
  LICENSE \
  README.md \
  SECURITY.md \
  docs/development.md \
  hack/verify-community.sh \
  hack/verify-community_test.sh \
  hack/verify-dco.sh \
  hack/verify-dco_test.sh; do
  destination="$fixture_root/$relative_path"
  mkdir -p -- "$(dirname -- "$destination")"
  cp "$repo_root/$relative_path" "$destination"
done

if ! "$fixture_root/hack/verify-community.sh" >"$temp_dir/baseline.log" 2>&1; then
  sed -n '1,120p' "$temp_dir/baseline.log" >&2
  fail 'canonical policy fixture unexpectedly failed'
fi

assert_rejects_append() {
  case_name=$1
  relative_path=$2
  contradictory_text=$3
  destination="$fixture_root/$relative_path"

  printf '\n%s\n' "$contradictory_text" >>"$destination"
  set +e
  "$fixture_root/hack/verify-community.sh" >"$temp_dir/$case_name.log" 2>&1
  status=$?
  set -e
  cp "$repo_root/$relative_path" "$destination"

  [ "$status" -ne 0 ] || fail "$case_name unexpectedly passed"
}

assert_rejects_append \
  contributing-contradiction \
  CONTRIBUTING.md \
  'For documentation-only commits, a Signed-off-by trailer is optional.'
assert_rejects_append \
  readme-contradiction \
  README.md \
  'Documentation-only commits do not require DCO sign-off.'
assert_rejects_append \
  development-contradiction \
  docs/development.md \
  'The DCO check is optional for documentation-only commits.'
assert_rejects_append \
  dco-verifier-drift \
  hack/verify-dco.sh \
  '# unreviewed verifier change'

printf '%s\n' 'veer-community-tests cases=5 status=passed'
