# ADR 0005: Resource hierarchy and ownership

- Status: Accepted
- Date: 2026-09-02
- Owners: Veer maintainers
- Decision scope: Issue [#18](https://github.com/ArdurAI/veer/issues/18)

## Context

Veer's common resource envelope supplies stable identity and an immediate
parent reference, but a single resource cannot prove that its parent exists,
belongs to the same Workspace, has the required kind, or does not form a
cycle. The first operable alpha needs those rules before admission, storage,
authorization, and reconciliation build on the hierarchy.

The model must not use display names, paths, provider fields, or recursive
database lookups as ownership keys. It must also remain executable without a
database, provider account, network call, or generated transport type.

## Decision

### Kind registry and edges

The `v1alpha1` hierarchy contains exactly six resource kinds. Control-resource
semantics are recorded by
[ADR 0006](0006-control-execution-and-evidence.md):

| Kind | Required parent | Ownership rule |
| --- | --- | --- |
| `Workspace` | none | `metadata.workspaceId == metadata.id` |
| `Environment` | `Workspace` | inherit the resolved parent's Workspace ID |
| `Application` | `Environment` | inherit the resolved parent's Workspace ID |
| `Component` | `Application` | inherit the resolved parent's Workspace ID |
| `Policy` | `Workspace` | inherit the resolved parent's Workspace ID |
| `ProviderConnection` | `Environment` | inherit the resolved parent's Workspace ID |

The registry is closed for this version. A new kind or edge changes both the
domain registry and the independently checked OpenAPI hierarchy manifest.
Display names, labels, spec fields, and status fields are deliberately absent
from graph records and never participate in ownership or authorization keys.

### Server-derived ownership

Every read representation carries required, read-only
`metadata.workspaceId`. A Workspace derives it from its own server-issued ID.
A child derives it from the resolved parent's retained Workspace ID. Clients
cannot supply `workspaceId` or `parent` through create or replace schemas.

The domain exposes a sealed placement value whose fields are private. Root and
child derivation validate issued opaque IDs and parent relationships before
the placement can construct a resource. The construction input contains only
display name, labels, resource version, creation time, spec, and status; it
cannot override ID, kind, parent, API version, or Workspace ownership.

The common resource constructor remains a low-level boundary for
already-admitted server values. It validates and retains `workspaceId` but
does not infer graph relationships by itself.

### Complete-snapshot validation

The provider-free reference model validates a complete retained view of one
Workspace. Before allocating an index, it rejects more than 64,001 records:
one Workspace plus the 1,000 Environment, 10,000 Application, 50,000
Component, 2,500 Policy, and 500 ProviderConnection target maxima in ADR 0001.
Within that ceiling it builds bounded indexes and performs iterative traversal
in `O(V + E)` time and `O(V)` memory:

1. Validate the requested Workspace ID, record versions and kinds, scoped ID
   uniqueness, and each record's Workspace ownership.
2. Require exactly the self-owned Workspace root and reject a root parent or a
   child without a parent.
3. Resolve every child parent inside the same snapshot.
4. Detect self, two-node, and longer cycles iteratively before evaluating edge
   kinds.
5. Enforce the six allowed parent-kind edges and build a direct-child index.

Record order does not affect the result. A parent outside the supplied
snapshot is an orphan even if a caller claims the same Workspace ID. A record
with a foreign Workspace ID fails before it can become an authorization or
storage key. Scoped uniqueness is sufficient for this reference model;
durable issuance and atomic create/delete races belong to the store.

### Immutable placement and deletion

ID, kind, parent, and Workspace ID are immutable after creation. Transition
validation compares only those stable placement fields; it does not confuse a
display-name change with reparenting.

Deletion uses RESTRICT semantics. A retained resource with any direct child
cannot be deleted. In a valid tree, every descendant implies a direct child,
so this prevents orphan creation while allowing leaf-first deletion. A
retained child continues to block deletion regardless of future lifecycle
state until a later lifecycle decision explicitly defines tombstones,
finalizers, or cascade behavior.

### Transport and enforcement boundaries

OpenAPI publishes six closed schema families and a reviewed
`x-veer-hierarchy` manifest. Workspace read schemas require root metadata;
Environment, Application, Component, Policy, and ProviderConnection read
schemas require child metadata. Write schemas omit server-owned placement
fields. The workload child specs and Policy spec are closed empty objects until
their owning roadmap issues adopt fields; ProviderConnection intent remains a
provider identifier and credential reference only.

JSON Schema proves individual document shape. The hierarchy package proves
cross-resource parent existence, ownership equality, edge kinds, cycles,
immutability, and deletion restriction.
[ADR 0007](0007-deterministic-admission-and-version-conversion.md) defines
request admission order, stable external error codes, JSON Pointer mapping,
defaulting, and version-hub conversion for issue
[#20](https://github.com/ArdurAI/veer/issues/20). Issue
[#30](https://github.com/ArdurAI/veer/issues/30) must enforce equivalent
scoped indexed reads and create/delete decisions atomically in persistence.

This issue adds no routes. The existing Workspace operations remain the
representative HTTP surface until a separate route decision defines child
addressing and parent selection.

### Observability and cost

Hierarchy errors are stable sentinels suitable for `errors.Is`. Their messages
classify the failure but do not embed IDs, display names, specs, status, label
values, or provider data. A later adapter can count rejections with
low-cardinality class labels; request or resource identifiers may appear only
as separately governed bounded log or trace fields, never metric labels.

Validation rejects an over-limit snapshot before allocating its indexes and
uses no recursion, network, database, queue, provider API, or paid service. The
full snapshot is the deterministic reference and test oracle, not a
prescription to load every tenant resource on each production request. Indexed
persistence in issue #30 must preserve these semantics within the alpha
latency and cost budgets.

### Version evidence

All six kinds remain byte-stable through the common canonical `v1alpha1`
envelope. [ADR 0007](0007-deterministic-admission-and-version-conversion.md)
adds a versionless internal hub and semantic round trips for each kind's spec
and status commands. Sparse Workspace omission may normalize to canonical
explicit `false`; equivalence is measured after defaulting, not by source
presence. This does not claim compatibility with a second public version.

## Consequences

- Authorization and storage layers receive one stable Workspace ownership key
  without trusting names or repeatedly traversing ancestors.
- Orphans, cross-Workspace references, wrong-kind edges, and cycles fail
  before they can enter a valid snapshot.
- Reparenting and Workspace transfer require a future explicit versioned
  operation; ordinary updates cannot perform them accidentally.
- RESTRICT deletion requires callers to delete leaves first but avoids hidden
  cascades and ambiguous partial failure.
- OpenAPI and domain registries remain independent drift oracles and therefore
  intentionally duplicate the six-kind table.

## Alternatives considered

### Caller-supplied Workspace ownership

Rejected because an untrusted ownership key can create cross-Workspace
confusion before authorization or persistence has a trustworthy scope.

### Derive ownership by walking ancestors only

Rejected as the retained authorization key because it makes every scoped
lookup depend on graph traversal and parent availability. Parent traversal is
still used to validate the stored key.

### Names or path prefixes as ownership keys

Rejected because display names are mutable and non-unique, while route shape
is a transport concern rather than stable identity.

### Reparent or transfer in ordinary replacement

Rejected because ownership changes require explicit authorization, conflict,
audit, and persistence semantics that do not exist in this issue.

### Cascade deletion

Deferred because safe cascade needs lifecycle ordering, finalizers, retry and
partial-failure semantics, audit evidence, and atomic persistence decisions.

### JSON-Schema-only validation

Rejected because one document schema cannot prove parent existence,
cross-record equality, cycles, previous-state immutability, or descendants.

## Deferred decisions

- Concrete Environment, Application, and Component spec fields.
- Child HTTP route topology and the external parent-selection surface.
- Global versus Workspace-local durable ID issuance.
- Tombstone, finalizer, and cascade exceptions from issue #36.
- Atomic hierarchy reads and create/delete race closure from issue #30.

## Evidence

The evidence includes positive and negative schema fixtures, complete and
multi-Workspace graph matrices, transition and deletion tests, canonical
fixtures for all six kinds, order-invariance property tests, and bounded fuzz
execution:

```sh
go test ./internal/core/domain/resource ./internal/core/domain/hierarchy
go test -race ./internal/core/domain/resource ./internal/core/domain/hierarchy
go test -count=100 ./internal/core/domain/resource ./internal/core/domain/hierarchy
go test -run '^$' -fuzz '^FuzzSnapshot$' -fuzztime=10000x ./internal/core/domain/hierarchy
./hack/dev api
./hack/dev check
```
