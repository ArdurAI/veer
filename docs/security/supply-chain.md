# Software-supply-chain controls

## Scope and boundary

This control set implements issue
[#15](https://github.com/ArdurAI/veer/issues/15) for source review and CI. It
does not implement release packaging, binary reproducibility, runtime image
signing, deployment admission, or consumer verification; issue
[#66](https://github.com/ArdurAI/veer/issues/66) owns those release controls.
Veer remains a reference-contract repository without deployable API or worker
binaries.

The design follows the
[NIST Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final),
[SLSA 1.2 specification](https://slsa.dev/spec/v1.2/), and GitHub's
[immutable action guidance](https://docs.github.com/en/actions/how-tos/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions).
Those sources guide the control design; passing these checks is not a SLSA
level claim.

## Required evidence

| Control | Pull-request evidence | Default-branch evidence |
| --- | --- | --- |
| Offline source build | Clean checksum-pinned bootstrap and network-disabled `./hack/dev check` | Same clean-checkout result on `main` |
| Concurrency and coverage | Complete race suite and an 80.0% aggregate statement floor | Same required workflow on every change |
| Supported hosts | Linux `amd64` through the clean lane plus Linux `arm64`, macOS `arm64`, and macOS Intel matrix jobs | Latest successful matrix run |
| Static analysis | golangci-lint, gosec 2.29.0 over all compiled Go source including checked-in generated files, and CodeQL for Go using the repository-pinned Go 1.27.1 toolchain | CodeQL result retained by GitHub code scanning |
| Dependency risk | GitHub dependency review rejects moderate-or-higher advisories and licenses outside the reviewed allowlist; the clean hosted lane regenerates `vendor/` from `go.sum`-authenticated modules | Dependabot alerts, security updates, and weekly Go/Actions updates |
| Repository risk | Trivy 0.74.0 scans vulnerability, misconfiguration, secret, and license categories | Weekly scan plus GitHub secret scanning and push protection |
| Workflow integrity | actionlint plus the offline immutable-action and least-privilege verifier; the clean hosted lane resolves every recorded release tag to its locked action SHA | Repository Actions policy requires full-SHA references |
| Inventory | Checksum-pinned Syft generates an SPDX JSON source/dependency SBOM from the exact source archive, retained for 30 days | GitHub provenance and SBOM attestations bind that same `main` source archive |
| Review and merge | Exact-head DCO and all protected status checks | No mandatory second-person approval; resolved conversations and exact-head required checks remain mandatory |

The platform matrix intentionally uses GitHub's standard hosted runner labels,
not larger runners. Standard GitHub-hosted Actions are free for public
repositories, but each additional platform consumes runner capacity and roughly
one bootstrap download set. If the repository becomes private, GitHub-hosted
minute and storage charges must be reviewed before retaining the same matrix.
The offline workflow policy binds every governed job to its exact runner and
timeout and binds the platform strategy to the three documented label/runner
pairs, so one Linux runner cannot impersonate all protected platform contexts.

## Immutable inputs

[`tools/manifest.tsv`](../../tools/manifest.tsv) pins each developer tool by
version, platform-specific URL, archive member, and SHA-256. The manifest
includes actionlint, gosec, and Syft, so local workflow/static security checks
and hosted SBOM generation do not execute mutable tool downloads.

`.github/actions-lock.tsv` separately records the full commit SHA, release
annotation, and canonical upstream release URL for every external GitHub
Action. The offline verifier rejects an unknown action, a changed SHA, a tag, a
branch, a floating version, an unrelated source URL, an unused lock, or a
checkout that retains credentials. The clean hosted lane independently asks the
canonical Git repository for each release tag, peels annotated tags, and
requires the result to equal the locked runtime SHA. Pinning the outer composite
action also freezes its checked-in nested action references; reviewers must
still inspect those references when updating the outer action.

## Suppression lifecycle

The default `.trivyignore.yaml` contains no exceptions. A future Trivy
exception must use its structured category and include fields in this exact
order:

```yaml
vulnerabilities:
  - id: CVE-2099-0001
    paths:
      - "path/to/exact/source.file"
    statement: owner=info@ardur.ai; reason=bounded false positive with linked evidence
    expired_at: 2099-01-01
```

The verifier rejects missing or duplicate IDs, missing owner/reason, malformed
calendar dates, expiry today or earlier, unknown syntax, and absent scanner
categories. Every exception must include at least one exact, quoted,
repository-relative `paths` entry; broad exceptions and wildcard paths are
rejected. PURL-scoped exceptions are not accepted until the verifier gains an
equally strict package-identity contract.

The CodeQL job bootstraps the pinned toolchain, copies that verified Go
distribution under `RUNNER_TEMP`, and puts only the staged binary on `PATH`
before initialization. This keeps the downloaded standard-library source
outside the repository source root, so CodeQL does not attribute toolchain code
to Veer. The private build entry point requires a canonical staged root under
`RUNNER_TEMP`, rejects roots inside the checkout, and verifies the temporary
CodeQL wrapper delegates exactly to that staged binary before using it inside
the same offline, vendored build environment as `./hack/dev build`. This
prevents both source-root contamination and a successful untraced build from
producing misleading CodeQL evidence.

Default-branch workflow runs use unique concurrency groups and are not
automatically canceled by concurrency. This preserves the source-provenance
step across overlapping pushes; users with write access can still cancel runs
manually. Manually dispatched checks do not run source provenance. Pull-request
runs continue to cancel obsolete work.

Gosec exceptions are declared in `.github/gosec-suppressions.tsv` and linked
one-to-one to a source annotation. Every entry fixes the gosec rule and source
file, names `info@ardur.ai` as the owner, records a non-empty rationale, and
expires on a calendar date. CI rejects an unknown, duplicate, orphaned,
mis-scoped, or expired entry; gosec additionally requires both a rule ID and
justification. The current G115 entries preserve bounded `uint32` protocol
fields or a capacity counter, the G101 entries identify public vocabulary that
resembles secret names, and G118 records the bounded revocation lifecycle that
must finish cleanup after its caller stops waiting. G304 records the explicitly
configured, identity-checked private reference-token file; G705 records bounded
JSON problem output with a safe request-ID grammar and `nosniff`. `nolint` and
`lint:ignore` remain prohibited, as do unregistered `#nosec` annotations. Gosec scans
checked-in generated Go files rather than trusting a self-declared generated
header to remove compiled code from analysis. GitHub dependency-review advisory
allowlists remain prohibited.

## Permissions and attestations

Every workflow defaults to `contents: read`. DCO alone receives `checks: write`
to publish the trusted-base exact-head result. CodeQL alone receives
`security-events: write`. Only the default-branch source-attestation job
receives `id-token: write` and `attestations: write`; pull-request jobs cannot
mint attestations. That privileged job installs only Syft, directly from the
platform artifact whose SHA-256 is committed in `tools/manifest.tsv`; it does not
run the broader development toolchain.

The attested subject is a `git archive` of the exact `main` SHA. The workflow
generates its SPDX JSON SBOM from that tar, then signs provenance and SBOM
attestations for the same subject. This establishes GitHub-hosted
source-snapshot provenance. Before either archive is created, both the workflow
step and offline policy reject `export-ignore` and `export-subst` in every
repository `.gitattributes` file; a reviewed tracked file therefore cannot be
omitted or rewritten by archive attributes. Both archive-producing steps also
reject mode-160000 Git submodule entries because `git archive` would otherwise
retain only an empty directory, not the bound commit identity or its source.
This does not claim a reproducible binary, image signature, or deployable
release. Those claims require issue [#66](https://github.com/ArdurAI/veer/issues/66)'s
artifact build, signing, publication, and consumer verification boundary.

The pinned Syft 1.51.1 `file:` source was compared directly with an exact
extraction of the same tar. Both sources produced the same dependency PURLs,
including Veer's root Go module and go-jose v4.1.5; only the root subject record
differed. The tar input therefore retains subject alignment without dropping
the source dependency inventory. Update checks are disabled during generation,
so the checksum-pinned binary does not replace itself or consult a mutable
installer before attestation.

## Protected repository settings

The auditable desired branch rule is
`.github/branch-protection.json`. After the installing pull request merges, an
owner must apply it and read it back from GitHub. The same live verification is
required for:

- GitHub secret scanning and push protection enabled;
- Dependabot vulnerability alerts and security updates enabled;
- GitHub Actions restricted to immutable full-SHA references; and
- a successful CodeQL analysis on the exact default-branch commit.

Every required status check is associated with GitHub Actions app ID `15368`,
read from the exact-head check runs before this policy was recorded. The legacy
`contexts` field is intentionally omitted because GitHub's
[update branch protection API](https://docs.github.com/en/rest/branches/branch-protection#update-branch-protection)
models it as an alternative to the fine-grained `checks` representation. Each
`checks` entry prevents another status producer from satisfying a protected
context name.

Second-person approval is not a protected-branch requirement. An authorized
maintainer can merge their own pull request after the exact-head checks succeed
and applicable conversations are resolved. The pull-request review rule remains
enabled with zero required approving reviews and last-push approval disabled, so
direct pushes to `main` remain prohibited. This owner-selected policy removes
protection against a single compromised or mistaken maintainer; app-bound CI,
administrator enforcement, conversation resolution, and force-push/deletion
bans remain the compensating controls.

The rule keeps `main` writable through validated merges with `lock_branch` set
to `false`. Its `allow_fork_syncing` value is therefore also `false`: GitHub
only applies fork syncing when a branch is locked and normalizes the flag to
the effective disabled value on an unlocked branch. This does not prevent a
fork from syncing while `main` remains unlocked.

The bootstrap change cannot require its own not-yet-existing checks before it
merges. That one-time ordering constraint does not permit later bypass: the
rule is applied only after the exact merged SHA has produced every named check,
and subsequent pull requests must satisfy the protected rule.
