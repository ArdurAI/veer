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

fail() {
  printf '%s\n' "veer-community: $*" >&2
  exit 1
}

require_regular_file() {
  relative_path=$1
  file="$repo_root/$relative_path"
  if [ ! -f "$file" ] || [ -L "$file" ]; then
    fail "$relative_path must be a regular non-symlink file"
  fi
}

require_text() {
  relative_path=$1
  expected_text=$2
  grep -Fq -- "$expected_text" "$repo_root/$relative_path" ||
    fail "$relative_path is missing required policy text: $expected_text"
}

require_exact_line() {
  relative_path=$1
  expected_line=$2
  grep -Fqx -- "$expected_line" "$repo_root/$relative_path" ||
    fail "$relative_path is missing an exact normative policy statement: $expected_line"
}

reject_text() {
  relative_path=$1
  rejected_text=$2
  if grep -Fq -- "$rejected_text" "$repo_root/$relative_path"; then
    fail "$relative_path contains stale or placeholder policy text: $rejected_text"
  fi
}

sha256_file() {
  file=$1
  sha256_stream <"$file"
}

sha256_stream() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{ print $1 }'
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{ print $1 }'
    return
  fi
  fail 'neither shasum nor sha256sum is available'
}

community_policy_sha() {
  for relative_path in \
    CODE_OF_CONDUCT.md \
    CONTRIBUTING.md \
    GOVERNANCE.md \
    LICENSE \
    README.md \
    SECURITY.md \
    docs/development.md; do
    policy_file_sha=$(sha256_file "$repo_root/$relative_path")
    printf '%s  %s\n' "$policy_file_sha" "$relative_path"
  done | sha256_stream
}

for required_path in \
  LICENSE \
  README.md \
  CONTRIBUTING.md \
  CODE_OF_CONDUCT.md \
  GOVERNANCE.md \
  SECURITY.md \
  .github/workflows/dco.yml \
  docs/development.md \
  hack/verify-community.sh \
  hack/verify-community_test.sh \
  hack/verify-dco.sh \
  hack/verify-dco_test.sh; do
  require_regular_file "$required_path"
done

expected_license_sha=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30
actual_license_sha=$(sha256_file "$repo_root/LICENSE")
[ "$actual_license_sha" = "$expected_license_sha" ] ||
  fail "LICENSE is not the canonical Apache-2.0 text: got $actual_license_sha"

expected_community_policy_sha=780b26d1d93977f5546ec3934654c08c76bde532bb5de192c96072fee65646f5
actual_community_policy_sha=$(community_policy_sha)
[ "$actual_community_policy_sha" = "$expected_community_policy_sha" ] ||
  fail "community policy differs from its reviewed canonical form: got $actual_community_policy_sha"

require_text README.md '[Apache License 2.0](LICENSE)'
require_text README.md 'Developer Certificate of Origin 1.1'
require_exact_line README.md 'The authoritative contribution policy is [CONTRIBUTING.md](CONTRIBUTING.md).'
reject_text README.md 'An open-source license has not yet been selected.'

require_text CONTRIBUTING.md 'Developer Certificate of Origin 1.1'
require_text CONTRIBUTING.md 'Signed-off-by: Your Name <your.email@example.com>'
require_text CONTRIBUTING.md 'SPDX identifier'
require_text CONTRIBUTING.md "\`Apache-2.0\`"

dco_required_statement="Every commit in a pull request requires an author-matching \`Signed-off-by\` trailer."
require_exact_line CONTRIBUTING.md "$dco_required_statement"
require_exact_line docs/development.md 'The authoritative contribution policy is [CONTRIBUTING.md](../CONTRIBUTING.md).'

require_text GOVERNANCE.md 'maintainer-led consensus'
require_text GOVERNANCE.md 'ArdurAI retains final authority'
require_text GOVERNANCE.md "\`Apache-2.0\`"

require_text CODE_OF_CONDUCT.md 'Contributor Covenant'
require_text CODE_OF_CONDUCT.md 'version 2.1'
require_text CODE_OF_CONDUCT.md 'info@ardur.ai'
reject_text CODE_OF_CONDUCT.md '[INSERT CONTACT METHOD]'

require_text SECURITY.md 'private GitHub vulnerability report'
require_text SECURITY.md 'info@ardur.ai'
require_text SECURITY.md 'acknowledgment within two business days'
require_text SECURITY.md 'initial severity and scope assessment within five business days'
require_text SECURITY.md 'Coordinated disclosure'

expected_dco_workflow_sha=d91ce24e44672a241220b4f0e82c5ce317996a6a64caa71876c880d9c50cf977
actual_dco_workflow_sha=$(sha256_file "$repo_root/.github/workflows/dco.yml")
[ "$actual_dco_workflow_sha" = "$expected_dco_workflow_sha" ] ||
  fail "DCO workflow differs from its reviewed canonical form: got $actual_dco_workflow_sha"

expected_dco_verifier_sha=1d547b0598b71585e5719a82f31c97603848bf7a77edc77ea098b8cb42bb59a8
actual_dco_verifier_sha=$(sha256_file "$repo_root/hack/verify-dco.sh")
[ "$actual_dco_verifier_sha" = "$expected_dco_verifier_sha" ] ||
  fail "DCO verifier differs from its reviewed canonical form: got $actual_dco_verifier_sha"

printf '%s\n' \
  'veer-community license=Apache-2.0 policy_bundle=canonical dco=1.1 dco_workflow=canonical dco_verifier=canonical governance=maintainer-led conduct=2.1 vulnerability_reporting=private status=passed'
