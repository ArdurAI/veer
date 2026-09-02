# ADR 0006: Control, execution, and evidence contracts

- Status: Accepted
- Date: 2026-09-02
- Owners: Veer maintainers
- Decision scope: Issue [#19](https://github.com/ArdurAI/veer/issues/19)

## Context

Veer needs stable provider-neutral representations for control resources,
asynchronous work, capability discovery, quota observations, and estimated
cost before admission, persistence, or provider code can safely depend on
them. Absence, `null`, zero, and `false` cannot stand in for unavailable
evidence: each would let a caller confuse an unknown provider fact with a
known safe value.

Provider credentials are a separate trust boundary. Public resources may
identify a credential reference, but they must never contain secret material,
provider-native credential documents, backend locations, or caller tokens.
Policy content is also intentionally deferred until the authorization issue
defines actions, roles, inheritance, inputs, and deterministic decisions.

## Decision

### Control-resource ownership

The `v1alpha1` hierarchy adds two control resources:

```text
Workspace
├── Policy
└── Environment
    ├── ProviderConnection
    └── Application
        └── Component
```

A Policy is parented directly by its Workspace. A ProviderConnection is
parented by an Environment and inherits that Environment's immutable
Workspace ID. This makes the two scopes required for provider execution part
of retained placement rather than a provider-adapter convention. Sharing one
credential authority across Environments is not selected for the alpha.

The complete-snapshot ceiling becomes 64,001 records: one Workspace, 1,000
Environments, 10,000 Applications, 50,000 Components, 2,500 Policies, and 500
ProviderConnections. This is the ADR 0001 target-scale qualification boundary,
not an unbounded product quota.

Policy and ProviderConnection use the common immutable resource envelope and
the existing server-derived `metadata.workspaceId` and `metadata.parent`
rules. Their write schemas omit both fields. RESTRICT deletion and immutable
placement apply exactly as they do to the four workload resource kinds.

### Policy and provider connection

`PolicySpec` is a closed empty object. The resource establishes stable
identity, Workspace ownership, lifecycle, and conditions without choosing a
policy language early. Issue
[#23](https://github.com/ArdurAI/veer/issues/23) owns policy actions, roles,
inheritance, inputs, outputs, and decision versions.

`ProviderConnectionSpec` contains only a bounded provider identifier and a
`CredentialReference`. The reference contains an opaque `referenceId` and an
opaque `version`. It is an identifier for later trusted resolution, not a
secret-manager URL, path, credential value, access token, password, access
key, kubeconfig, arbitrary header map, or provider-native document.

`ProviderConnectionStatus` contains the common observed generation and
conditions plus bounded capability and quota observations. Capability and
quota names are unique and sorted so equivalent evidence has one canonical
ordering.

### Explicit evidence states

Every provider capability has a state of `Supported`, `Unsupported`, or
`Unknown`. Every quota check has a state of `WithinLimit`, `Exceeded`, or
`Unknown`. Each carries a bounded name, source, observation timestamp, and
safe reason.

Known quota states require canonical non-negative decimal `requested` and
`available` values. `WithinLimit` requires requested to be less than or equal
to available; `Exceeded` requires requested to be greater than available.
`Unknown` forbids both values. The comparison uses decimal arithmetic over the
canonical strings and never binary floating point.

Every cost estimate has a state of `Known` or `Unknown` and always identifies
currency, region, source, observation timestamp, confidence, and a safe
reason. A known estimate requires a canonical non-negative decimal amount and
`Low`, `Medium`, or `High` confidence. An unknown estimate forbids an amount
and requires `Unknown` confidence. A known amount of zero is therefore
distinct from unknown cost.

The alpha schemas prove shape, required members, bounds, closed objects, and
the tagged-union presence rules. Pure domain validation proves decimal
comparison, canonical ordering, and aggregate invariants. Issue
[#42](https://github.com/ArdurAI/veer/issues/42) owns units, hard-versus-soft
quota policy, evidence freshness windows, actual-cost references, attribution,
provider-call budgets, and approval behavior for stale or unknown evidence.

### Operation lifecycle

Operation remains a standalone durable receipt rather than a desired-state
resource. It carries immutable Workspace ownership and may carry an
Environment, ProviderConnection, and cost estimate. Provider-bound operations
require both the Environment and ProviderConnection references; control-only
operations carry neither.

The phase vocabulary is exactly `Pending`, `Waiting`, `Running`, `Succeeded`,
`Failed`, and `Canceled`. The `v1alpha1` cancellation wire spelling is
`Canceled`.

A generic reader that encounters an unrecognized phase treats the operation
as nonterminal, authorizes no automated mutation or provider side effect, and
surfaces the unsupported state while continuing only bounded polling. Veer's
typed domain validator rejects an unrecognized phase from persistence. The
OpenAPI transition manifest freezes this behavior as
`nonterminal-no-side-effects`.

Allowed phase changes are:

| Current phase | Allowed next phase |
| --- | --- |
| `Pending` | `Waiting`, `Running`, `Succeeded`, `Failed`, `Canceled` |
| `Waiting` | `Pending`, `Running`, `Succeeded`, `Failed`, `Canceled` |
| `Running` | `Waiting`, `Succeeded`, `Failed`, `Canceled` |
| `Succeeded`, `Failed`, `Canceled` | exact idempotent replay only |

`Pending` means queued without an active execution lease; it is not limited to
an operation's first phase. A `Waiting` operation may return to `Pending` when
a dependency or retry becomes schedulable. A `Running` operation must first
move to `Waiting` before it can be requeued, preserving the observable fact
that active execution stopped. The graph is intentionally not transitive, so a
direct `Running` to `Pending` transition remains invalid.

An exact replay returns the existing value. Every material transition requires
an injected, non-regressing millisecond timestamp and a new injected resource
version. Identity, ownership, generation, and creation time remain immutable.
Persistence, delivery, fencing, compensation, and uncertain provider outcomes
remain issue [#29](https://github.com/ArdurAI/veer/issues/29).

Standalone Operation storage uses the pinned v1-compatible internal JSON
profile from ADR 0004 and rejects representations above 4,096 encoded bytes.
Construction, validation, transition, decoding, and encoding enforce the same
ceiling.

### Condition lifecycle

The existing six-field Condition wire shape remains unchanged. A condition is
identified by `type`; sets are bounded, unique, and sorted by that identity.
`True`, `False`, and `Unknown` may transition among one another.

`lastTransitionAt` advances only when status changes. A reason, message, or
observed-generation refresh with the same status preserves it. Observed
generation cannot regress or exceed the owning resource generation. Transition
time is injected, normalized to UTC milliseconds, and cannot regress. Exact
updates are no-ops.

Issue [#35](https://github.com/ArdurAI/veer/issues/35) owns durable condition
history, severity, drift, operation correlation, and concurrent status-write
behavior.

### Enforcement boundaries

This decision adds schemas and provider-free domain oracles. It adds no HTTP
route, server, database, queue, policy evaluator, credential broker, provider
SDK, provider call, or generated code.

- Issue [#20](https://github.com/ArdurAI/veer/issues/20) owns admission order,
  defaulting, field-path errors, immutable-field mapping, and conversion.
- Issue [#21](https://github.com/ArdurAI/veer/issues/21) owns the reference
  server, lifecycle handlers, filtering, pagination, and idempotency harness.
- Issue [#25](https://github.com/ArdurAI/veer/issues/25) owns credential
  resolution, short-lived sessions, rotation, refresh, and revocation.
- Issue [#38](https://github.com/ArdurAI/veer/issues/38) owns provider
  interfaces and concrete capability names.
- Issue [#30](https://github.com/ArdurAI/veer/issues/30) owns transactional
  persistence, scoped indexes, and atomic hierarchy enforcement.

### Observability and cost safeguards

Domain errors expose stable classes through `errors.Is` but never interpolate
credential references, provider names, capability names, resource IDs,
messages, amounts, or source values. Later adapters can count bounded error
classes; high-cardinality identifiers remain governed log or trace fields and
never metric labels.

All validation is deterministic, CPU- and memory-bounded, and uses no network,
database, queue, provider API, credential backend, randomness, or paid service.
Decimal strings are bounded before parsing, observation collections are
bounded before indexing, and hierarchy snapshots are rejected before
allocation above the qualification ceiling.

## Consequences

- Callers can distinguish unsupported, exceeded, known zero, and unavailable
  evidence without interpreting omission or sentinel numeric values.
- Environment-scoped ProviderConnections reduce credential blast radius and
  give every provider-bound operation stable Workspace and Environment keys.
- One `Canceled` spelling avoids ambiguous cancellation aliases.
- Closed Policy intent prevents this schema issue from choosing an
  authorization language before its action and decision model exists.
- Schema and domain validators deliberately overlap as independent drift
  oracles where JSON Schema cannot express prior-state comparisons.

## Alternatives considered

### Workspace-wide ProviderConnections

Rejected for the alpha because a single credential authority could span
Environment isolation boundaries. Supporting deliberate sharing later needs
explicit authorization, blast-radius, rotation, and deletion semantics.

### Embedded credentials or backend paths

Rejected because public resources, fixtures, plans, logs, and errors must not
become secret-bearing channels or reveal secret-store topology.

### Boolean capability and quota values

Rejected because false cannot distinguish unsupported, exceeded, stale, and
unavailable evidence.

### Numeric JSON amounts

Rejected because binary floating-point and exponent aliases do not provide one
stable representation for equality, comparison, persistence, or audit.

### Omitted unknown values

Rejected because omission conflates unavailable evidence with a producer bug
or an older representation and makes conservative admission impossible.

## Evidence

The executable evidence includes canonical Policy, ProviderConnection, and
Operation fixtures; positive and expected-failure schema instances; secret
field rejection; complete operation and condition transition matrices;
known-zero-versus-unknown cost; known and unknown capability and quota cases;
ordering properties; and bounded fuzz execution.

```sh
go test ./internal/core/domain/condition ./internal/core/domain/operation \
  ./internal/core/domain/control ./internal/core/domain/hierarchy
go test -race ./internal/core/domain/condition ./internal/core/domain/operation \
  ./internal/core/domain/control ./internal/core/domain/hierarchy
go test -count=100 ./internal/core/domain/condition \
  ./internal/core/domain/operation ./internal/core/domain/control
./hack/dev api
./hack/dev check
```
