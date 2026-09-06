#!/bin/sh
set -eu

script_dir=$(
  unset CDPATH
  cd -- "$(dirname -- "$0")"
  pwd -P
)
verifier="$script_dir/verify-dco.sh"
temp_dir=

fail() {
  printf '%s\n' "veer-dco-test: $*" >&2
  exit 1
}

cleanup() {
  if [ -n "$temp_dir" ] && [ -d "$temp_dir" ]; then
    rm -rf -- "$temp_dir"
  fi
}

trap cleanup 0
trap 'exit 1' HUP INT TERM

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/veer-dco-test.XXXXXX")
repo_dir="$temp_dir/repository"
mkdir -p -- "$repo_dir"
git -C "$repo_dir" init --quiet --initial-branch=main
git -C "$repo_dir" config user.name 'Veer DCO Test'
git -C "$repo_dir" config user.email 'veer-dco-test@example.invalid'
git -C "$repo_dir" config commit.gpgsign false
git -C "$repo_dir" config core.hooksPath /dev/null

printf '%s\n' base >"$repo_dir/payload.txt"
git -C "$repo_dir" add payload.txt
git -C "$repo_dir" commit --quiet --signoff -m 'test: establish base'
base_commit=$(git -C "$repo_dir" rev-parse HEAD)

assert_passes() {
  case_name=$1
  shift
  if ! (cd -- "$repo_dir" && "$verifier" "$@") >"$temp_dir/$case_name.log" 2>&1; then
    sed -n '1,120p' "$temp_dir/$case_name.log" >&2
    fail "$case_name unexpectedly failed"
  fi
}

assert_fails() {
  case_name=$1
  shift
  if (cd -- "$repo_dir" && "$verifier" "$@") >"$temp_dir/$case_name.log" 2>&1; then
    fail "$case_name unexpectedly passed"
  fi
}

git -C "$repo_dir" switch --quiet --create signed "$base_commit"
printf '%s\n' signed >"$repo_dir/payload.txt"
git -C "$repo_dir" add payload.txt
git -C "$repo_dir" commit --quiet --signoff -m 'test: signed contribution'
signed_head=$(git -C "$repo_dir" rev-parse HEAD)
assert_passes signed "$base_commit" "$signed_head"

git -C "$repo_dir" config trailer.separators '='
assert_passes configured-separator "$base_commit" "$signed_head"
git -C "$repo_dir" config --unset trailer.separators

git -C "$repo_dir" switch --quiet --create unsigned "$base_commit"
printf '%s\n' unsigned >"$repo_dir/payload.txt"
git -C "$repo_dir" add payload.txt
git -C "$repo_dir" commit --quiet -m 'test: unsigned contribution'
unsigned_head=$(git -C "$repo_dir" rev-parse HEAD)
assert_fails unsigned "$base_commit" "$unsigned_head"

git -C "$repo_dir" switch --quiet --create mismatched "$base_commit"
printf '%s\n' mismatched >"$repo_dir/payload.txt"
git -C "$repo_dir" add payload.txt
git -C "$repo_dir" commit --quiet -m 'test: mismatched contribution' \
  -m 'Signed-off-by: Another Person <another@example.invalid>'
mismatched_head=$(git -C "$repo_dir" rev-parse HEAD)
assert_fails mismatched "$base_commit" "$mismatched_head"

git -C "$repo_dir" switch --quiet --create author-backslash "$base_commit"
printf '%s\n' author-backslash >"$repo_dir/payload.txt"
git -C "$repo_dir" add payload.txt
git -C "$repo_dir" \
  -c 'user.name=Domain\User' \
  -c user.email=user@example.invalid \
  commit --quiet --signoff -m 'test: preserve author backslash'
author_backslash_head=$(git -C "$repo_dir" rev-parse HEAD)
assert_passes author-backslash "$base_commit" "$author_backslash_head"

git -C "$repo_dir" switch --quiet --create stripped-backslash "$base_commit"
printf '%s\n' stripped-backslash >"$repo_dir/payload.txt"
git -C "$repo_dir" add payload.txt
git -C "$repo_dir" \
  -c 'user.name=Domain\User' \
  -c user.email=user@example.invalid \
  commit --quiet -m 'test: reject stripped author backslash' \
  -m 'Signed-off-by: DomainUser <user@example.invalid>'
stripped_backslash_head=$(git -C "$repo_dir" rev-parse HEAD)
assert_fails stripped-backslash "$base_commit" "$stripped_backslash_head"

git -C "$repo_dir" switch --quiet --create mixed "$base_commit"
printf '%s\n' mixed-signed >"$repo_dir/payload.txt"
git -C "$repo_dir" add payload.txt
git -C "$repo_dir" commit --quiet --signoff -m 'test: first mixed contribution'
printf '%s\n' mixed-unsigned >"$repo_dir/payload.txt"
git -C "$repo_dir" add payload.txt
git -C "$repo_dir" commit --quiet -m 'test: second mixed contribution'
mixed_head=$(git -C "$repo_dir" rev-parse HEAD)
assert_fails mixed "$base_commit" "$mixed_head"

assert_fails empty "$base_commit" "$base_commit"
assert_fails abbreviated deadbeef "$signed_head"

printf '%s\n' 'veer-dco-tests cases=9 status=passed'
