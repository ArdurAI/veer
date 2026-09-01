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
toolchain switching, module proxies, checksum-database calls, and version
control downloads. It also removes common AWS, Google Cloud, and Azure
credential variables from child processes. No check needs a cloud API,
database, queue, cluster, container runtime, or private credential.

## Supported hosts and prerequisites

Bootstrap supports these host combinations:

| Operating system | Architectures |
| --- | --- |
| macOS | `amd64`, `arm64` |
| Linux | `amd64`, `arm64` |

The clean host must provide POSIX `sh`, `awk`, `curl`, `date`, `diff`, `git`,
`grep`, `mktemp`, `sed`, `tar`, `uname`, `xargs`, and either `shasum` or
`sha256sum`. These are base utilities on supported macOS and common Linux
development or CI images. No package manager or administrator access is
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

Run `./hack/dev versions` to verify and print the installed versions. A changed
manifest invalidates the prepared-state marker, so subsequent commands stop
with an instruction to rerun bootstrap.

## Commands

| Command | Behavior |
| --- | --- |
| `./hack/dev bootstrap` | Validate the full platform matrix, download or reuse verified artifacts, install them under `.tools/`, and verify versions. |
| `./hack/dev check` | Run every required fast gate in order and stop on the first failure. |
| `./hack/dev format` | Rewrite tracked and unignored new Go and shell files using the pinned formatters. |
| `./hack/dev lint` | Run ShellCheck and golangci-lint. |
| `./hack/dev build` | Compile every Go package with path trimming. |
| `./hack/dev test` | Run all fast Go unit tests once. |
| `./hack/dev docs` | Lint Markdown and verify checked-in architecture and cost evidence. |
| `./hack/dev versions` | Verify and report every installed tool version. |

The aggregate command emits machine-readable lines such as
`veer-check step=test status=passed duration_seconds=1`. These give local and
CI logs a stable step name, outcome, and duration without printing environment
variables or credentials.

## Network, disk, and CI cost safeguards

- Only `bootstrap` needs public network access. Verified downloads are cached
  in `.tools/downloads/`; repeated bootstrap runs reuse them after checking
  their digest.
- On a macOS/arm64 clean run verified on 2026-09-01, the download cache was
  exactly 157,327,393 bytes and `.tools/` occupied approximately 769 MiB after
  one full check. Other platforms may differ. The whole directory is ignored
  by Git and can be removed to reclaim local space.
- The bootstrap CI job uses a fresh checkout to prove the clean-host path. Its
  runner is bounded to 15 minutes and has no service containers, cloud login,
  or paid third-party API calls.
- Fast gates use repository-local Go, golangci-lint, and XDG caches but run
  with `GOPROXY=off`, `GOVCS=off`, and `GOTOOLCHAIN=local`.

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
   `tools/manifest.tsv` in one pull request.
3. Run `./hack/dev bootstrap`, `./hack/dev versions`, and
   `./hack/dev check` from a clean tool directory.
4. Let the clean-bootstrap CI lane exercise the same commands on Linux.

Never use a floating tag, `@latest`, a curl-to-shell installer, or an
unverified binary. Issue #15 owns the broader software-supply-chain gates,
negative fixtures, SBOM retention, and protected-branch policy; this command
contract is their reproducible foundation.
