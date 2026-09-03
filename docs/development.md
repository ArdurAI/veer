# Local development

Veer's development entrypoint makes a clean checkout reproducible without
root access, a cloud account, private services, or private credentials.

## Golden path

From the repository root, run:

```sh
./hack/dev bootstrap
./hack/dev check
```

`bootstrap` uses unauthenticated HTTPS to fetch public release artifacts from
Go and GitHub. It validates every download against the SHA-256 digest in
[`tools/manifest.tsv`](../tools/manifest.tsv) before extracting or executing
it. It never invokes a remote install script and does not modify system or user
tool directories.

`check` requires the prepared repository-local toolchain. It disables Go
toolchain switching, inherited Go workspaces, per-user Go configuration, Go
telemetry, module proxies, checksum-database calls, and version control
downloads. It also removes inherited tar and ShellCheck defaults plus common
AWS, Google Cloud, and Azure credential variables from child processes. No
check needs a cloud API, database, queue, cluster, container runtime, or
private credential.

## Supported hosts and prerequisites

Bootstrap supports these host combinations:

| Operating system | Architectures |
| --- | --- |
| macOS | `amd64`, `arm64` |
| Linux | `amd64`, `arm64` |

The clean host must provide POSIX `sh`, `awk`, `curl`, `date`, `diff`, `git`,
`grep`, `head`, `mktemp`, `sed`, `sort`, `tar`, `uname`, `wc`, `xargs`, and either
`shasum` or `sha256sum`. These are base utilities on supported macOS and common
Linux development or CI images. No package manager or administrator access is
required.

Windows is not supported directly for the alpha. Use a supported Linux
environment such as WSL 2; native Windows support requires a separate decision
and CI lane.

## Pinned toolchain

The artifact manifest is the source of truth for every supported platform:

| Tool | Version | Purpose |
| --- | --- | --- |
| Go | 1.27.0 | Build and unit-test runtime |
| golangci-lint | 2.13.2 | Go static analysis |
| sqlc | 1.31.1 | Typed code generation from reviewed SQL |
| goose | 3.27.3 | SQL migration execution |
| shfmt | 3.14.0 | Shell formatting |
| ShellCheck | 0.11.0 | Shell static analysis |
| rumdl | 0.2.62 | Markdown linting |
| Vacuum | 0.30.1 | OpenAPI structural validation and linting |

Run `./hack/dev versions` to verify and print the installed versions. A changed
manifest invalidates the prepared-state marker, so subsequent commands stop
with an instruction to rerun bootstrap.

## Commands

| Command | Behavior |
| --- | --- |
| `./hack/dev bootstrap` | Validate the full platform matrix, download or reuse verified artifacts, install them under `.tools/`, and verify versions. |
| `./hack/dev check` | Run every required fast gate in order and stop on the first failure. |
| `./hack/dev format` | Rewrite existing regular, non-symlink Go and shell files using the pinned formatters. |
| `./hack/dev lint` | Run ShellCheck and golangci-lint. |
| `./hack/dev build` | Compile every Go package with path trimming. |
| `./hack/dev test` | Run all fast Go unit tests once. |
| `./hack/dev api` | Validate OpenAPI, hierarchy/control/admission schema examples, expected-failure instances, and Veer-specific HTTP, evolution, defaulting, and conversion invariants without remote references. |
| `./hack/dev docs` | Lint Markdown and verify checked-in architecture, cost, stack, and security evidence, including negative contract fixtures. |
| `./hack/dev versions` | Verify and report every installed tool version. |

The aggregate command emits machine-readable lines such as
`veer-check step=test status=passed duration_seconds=1`. These give local and
CI logs a stable step name, outcome, and duration without printing environment
variables or credentials.

## Network, disk, and CI cost safeguards

- Only `bootstrap` needs public network access. Verified downloads are cached
  in `.tools/downloads/`; repeated bootstrap runs reuse them after checking
  their digest.
- Each manifest row is bound to the selected tool's exact upstream repository,
  release version, platform artifact name, archive format, and binary member.
  Tar archives may contain only canonical, uniquely addressed regular files
  and directories, at most 20,000 members, and at most 512 MiB of expanded
  file data. The compressed download cap remains 100 MiB per artifact.
- On a macOS/arm64 clean run verified on 2026-09-01, the download cache was
  exactly 176,834,836 bytes and `.tools/` occupied approximately 851 MiB after
  one full check. Other platforms may differ. The whole directory is ignored
  by Git and can be removed to reclaim local space.
- The bootstrap CI job uses a fresh checkout to prove the clean-host path. Its
  runner is bounded to 15 minutes and has no service containers, cloud login,
  or paid third-party API calls.
- Fast gates use repository-local Go, golangci-lint, and XDG caches but run
  with `GOENV=off`, `GOWORK=off`, `GOPROXY=off`, `GOVCS=*:off`, and
  `GOTOOLCHAIN=local`.
- API validation runs Vacuum with a repository-owned configuration, update
  checks disabled, remote references disabled, extension-reference traversal
  enabled, and HTTP, private-network, and insecure TLS access denied. The
  pinned binary validates in-schema positive examples and bounded
  expected-failure hierarchy, control, and admission instances. Veer's
  standard-library semantic tests also freeze the six-stage admission manifest,
  sparse-write/canonical default split, deterministic default fixtures, version
  hub, negative contract mutations, and document size, nesting, and traversal
  bounds.
- Bootstrap clears `TAR_OPTIONS` and `GZIP`; lint clears `SHELLCHECK_OPTS` and
  passes `--norc`. Archive behavior and ShellCheck policy therefore do not
  inherit user or CI defaults.
- The pinned Go process uses `.tools/cache/go-telemetry` with mode `off`, and
  every command verifies the reported mode and directory before invoking Go.
  This prevents collection and upload without changing the developer's global
  preference; see the primary [Go telemetry documentation](https://go.dev/doc/telemetry).
- Deleted worktree paths and source symlinks are never passed to write-mode
  formatters; source symlinks are not a supported way to include Veer code.

## Troubleshooting

### The manifest changed

If a command reports `tool manifest changed`, rerun:

```sh
./hack/dev bootstrap
```

Do not edit `.tools/state/manifest.sha256`; it is generated only after a
successful install and version verification.

### A checksum does not match

Bootstrap deletes a mismatched cached artifact and retries the approved public
release URL. If the new download still differs, stop. Verify the release digest
at its primary source and update all affected manifest rows in a reviewed pull
request; never substitute the observed digest merely to make bootstrap pass.

### A download is unavailable

Confirm that HTTPS access to `go.dev` and `github.com` is allowed. Bootstrap
uses no proxy credentials or repository token. If an organization requires an
authenticated artifact mirror, that mirror needs a separate trust, credential,
retention, and cost decision before it can become a supported source.

### A check tries to reach the network

That is a defect. `check` deliberately disables Go's network resolution. Do
not work around it by adding credentials or enabling a module proxy; report the
failing step and command output.

## Updating a pin

1. Verify the new release and compatibility at the upstream primary source.
2. Update all four platform rows and their upstream SHA-256 digests in
   `tools/manifest.tsv` in one pull request. The URL, format, and member must
   continue to match the tool-specific platform contract enforced by
   `./hack/dev bootstrap`, and the file must retain its terminal newline.
3. Synchronize every declaration of the changed version:
   - the pinned-tool table in this guide for every tool;
   - `.go-version` and the `go` directive in `go.mod` for Go;
   - `docs/architecture/stack-evaluation/versions.tsv` and ADR 0002 for Go,
     sqlc, or goose.
   Search the repository for the previous version to find deliberate prose and
   source-link references that also need review. Bootstrap and local checks
   reject drift among the machine-readable pins and this guide; the stack
   verifier rejects drift between its manifest and ADR 0002.
4. Run `./hack/dev bootstrap`, `./hack/dev versions`, and
   `./hack/dev check` from a clean tool directory.
5. Let the clean-bootstrap CI lane exercise the same commands on Linux.

If a legitimate upstream archive grows beyond the member or expanded-size
budget, review its contents and disk-cost impact before changing the bound.
Do not raise a limit merely to make bootstrap pass.

Never use a floating tag, `@latest`, a curl-to-shell installer, or an
unverified binary. Issue #15 owns the broader software-supply-chain gates,
negative fixtures, SBOM retention, and protected-branch policy; this command
contract is their reproducible foundation.
