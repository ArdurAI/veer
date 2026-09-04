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

## Vendored Go dependencies

Runtime Go module source is committed under `vendor/`. Normal format, lint,
build, and test commands force `-mod=vendor` while module proxy, checksum
database, and version-control downloads remain disabled. A clean checkout can
therefore compile and test without module-network access, a repository token,
or proxy credentials.

The current runtime dependency is
[`github.com/go-jose/go-jose/v4` v4.1.4](https://github.com/go-jose/go-jose/releases/tag/v4.1.4),
selected for OIDC JWT signature and JWK handling. The committed version is
Apache-2.0 licensed, requires Go 1.24 or newer, and has no non-standard-library
module dependencies. [ADR 0008](architecture/0008-oidc-authentication-and-principals.md)
defines the surrounding trust, parsing, network, redaction, and error boundary.

`./hack/dev bootstrap` still downloads only the checksum-pinned tools in
`tools/manifest.tsv`; it never resolves application modules. Dependency updates
are a separate, explicitly online maintenance operation: review the primary
release and license, change `go.mod`/`go.sum`, regenerate `vendor/`, inspect the
result, and then rerun the complete network-disabled check. Do not work around a
missing or inconsistent vendor tree by enabling a module proxy in an ordinary
check.

## Commands

| Command | Behavior |
| --- | --- |
| `./hack/dev bootstrap` | Validate the full platform matrix, download or reuse verified artifacts, install them under `.tools/`, and verify versions. |
| `./hack/dev check` | Run every required fast gate in order and stop on the first failure. |
| `./hack/dev format` | Rewrite existing regular, non-symlink Go and shell files using the pinned formatters. |
| `./hack/dev lint` | Run ShellCheck and golangci-lint. |
| `./hack/dev build` | Compile every Go package with path trimming. |
| `./hack/dev test` | Run all fast Go unit tests once. |
| `./hack/dev api` | Validate OpenAPI, hierarchy/control/admission/authorization/audit/reconciliation projections, schema examples, expected-failure instances, runtime vocabulary drift, operation action annotations, and Veer-specific HTTP and evolution invariants without remote references. |
| `./hack/dev docs` | Lint Markdown and verify checked-in architecture, cost, stack, and security evidence, including negative contract fixtures. |
| `./hack/dev versions` | Verify and report every installed tool version. |

The aggregate command emits machine-readable lines such as
`veer-check step=test status=passed duration_seconds=1`. These give local and
CI logs a stable step name, outcome, and duration without printing environment
variables or credentials.

Authorization contract changes must update the domain registry, the root
`x-veer-authorization` projection, affected
`x-veer-authorization-action` operation annotations, PolicySpec fixtures, and
[ADR 0009](architecture/0009-deterministic-hierarchical-authorization.md) in
one reviewed change. `go test ./api/openapi` cross-binds the OpenAPI vocabulary,
role matrix, reservations, inheritance, and PolicySpec semantics to the runtime
package. The OpenAPI document remains a reference contract and does not prove
that an API route or worker invokes authorization.

Credential-broker contract changes must keep
[`ADR 0010`](architecture/0010-provider-neutral-credential-broker.md), the
`internal/core/domain/credential` constants and constructors, the split
`SecretResolver` and `SessionIssuer` ports, the
`internal/core/service/credentialbroker` surface, and the formal threat-model
status in one reviewed change. Focused tests must cover exact Workspace,
Environment, ProviderConnection, operation, target-generation, action, and
recipient binding; generation/version rotation; expiry and refresh boundaries;
ordered overlapping clock clamping, fresh zero/rollback and sequence-saturation
failure, later recovery, and the raw resolver-return source-TTL anchor;
the exact one-hour source-reuse cutoff plus timer-free cleanup-capable
acquisition/rotation/lifecycle, sweep, and close paths; TTL borrow-deferred versus
explicit-invalidation immediate destruction; private source ownership across the
post-`Resolve` settlement gap; destroy-before-cancel ordering, including joined
concurrent invalidators, for connection invalidation, broker close, rotation
cutover, and last-waiter source/rotation abandonment; Operation termination that
destroys a matching pending rotation source without destroying the shared
current-generation source; local epochs and tombstones; capacity and
single-flight behavior; and credential serialization canaries. They must also
prove durable-budget claim settlement truth independently from local
publication, priority partitioning, local-first cancellation and revocation,
closed revocation-result aggregation, and the handle-only `Lease.Close`
boundary. They must exercise all eleven classified failures, shared-state
`Broker` and `Lease` copies, lease reservation across rotation commit and late
cancellation, exactly-once cleanup of every valid unpublished issuer result,
joining or pending old-flight cleanup, the broker-wide 16-call revocation queue,
generation-wide tombstoning when current-generation revoke cancels a pending
rotation, and expiry evidence through the exact provider expiry. Capacity tests
must prove that material and disposal slots remain charged through `Destroy` and that
connection high-water state and terminal Operation tombstones are not evicted to
admit new identities. These are deterministic contract checks: they use
injected time and test doubles, make no cloud or paid-service request, and do
not establish runtime worker enforcement or distributed revocation.

Issue #25 does not change the public transport. `./hack/dev api` must continue
to report exactly four paths, seven operations, and 81 schemas. Adding broker
material, a backend location, or session state to OpenAPI is a contract failure,
not a required projection update.

Audit or privileged-administration contract changes must keep
[`ADR 0011`](architecture/0011-tamper-evident-audit-and-privileged-administration.md),
the `internal/core/domain/audit`, `internal/core/domain/authentication`, and
`internal/core/domain/administration` constants and registries, the
ledger-owned `StrongAuthenticationVerifier` and `Clock`, the root
`x-veer-audit` projection, and the formal threat-model status in one reviewed
change. Focused tests must cover canonical event and segment bounds, exact
vocabulary order, operation-timeline correlations, actor/authentication
compatibility, stream scope, chain and export verification, trusted terminal
checkpoints, retention boundaries and holds, exact administrator identity,
sealed action/target pairs, exactly-once verifier invocation with exact
credential/request forwarding, strong-authentication age and replay, rejected
verifier outputs, trusted-clock issuance and overlap behavior, one-use grant
lifecycle, clock regression, expiry equality, and redaction/serialization
canaries. They must also prove that callers cannot inject verifier output or
issuance time and that an internally valid hash-chain prefix does not establish
tail completeness without a separately trusted expected head.
These are deterministic reference checks: they make no database, archive,
signing, cloud, or paid-service call and do not establish durable, cross-node,
atomic, API, or worker enforcement. The root projection adds no public path,
operation, or schema; `./hack/dev api` must still report exactly four paths,
seven operations, and 81 schemas.

Reconciliation reliability changes must keep
[`ADR 0012`](architecture/0012-reconciliation-reliability-and-fencing.md), the
`internal/core/domain/reconciliation` constants and closed registries, the
fixed idempotency projection in `x-veer-evolution`, the root
`x-veer-reconciliation` projection, the cost worksheet, and the formal threat
model in one reviewed change. Focused tests must cover all eight crash
boundaries, fixed non-sliding 24-hour replay at equality, unresolved
reservations, capacity-bounded active-call and cross-key cleanup ordering,
bounded response/key state, and stale completion rejection after safe
reclamation; separate logical-effect and
physical-attempt identity; immutable plan reuse and capability-qualified safe
supersession; signed fence exhaustion; renew-without-fence-increment; strict RPC
margin, retry-proof expiry, and live-lease dispatch recheck; failed and unknown
maintenance;
duplicate delivery takeover by a newer fence; exact one-use attempt preparation
and dispatch authority; exact work-to-lease plan binding; cancel-pending
projection through the existing six Operation phases; pre-dispatch finite
unknown-outcome observation with a sealed deadline, exact-current completion,
source-attempt-versioned same-millisecond late-result suppression, logical-
effect-based replanning, completed-effect admission rejection, and exactly-once
quarantine; qualified reverse-order compensation with sealed schedule progress;
recovery chronology; 90-day tombstone eligibility; and full queue-request
pre-reservation. Property, fuzz,
redaction, and serialization tests must
keep untrusted evidence bounded and opaque runtime authority out of diagnostics.

These are provider-free, process-local reference checks. They make no database,
queue, provider, cloud, or paid-service call and do not establish durable state,
worker enforcement, cross-node coordination, or exactly-once provider
execution. The root projection adds no public path, operation, or schema;
`./hack/dev api` must remain at exactly four paths, seven operations, and 81
schemas.

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
