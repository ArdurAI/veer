# ADR 0004: Common resource envelope

- Status: Accepted
- Date: 2026-09-02
- Owners: Veer maintainers
- Decision scope: Issue [#17](https://github.com/ArdurAI/veer/issues/17)

## Context

Veer's API conventions define the meaning of identity, generation, resource
version, timestamps, desired state, and observed state. The control-plane core
also needs one implementation that preserves those meanings without depending
on generated HTTP types, a database, ambient time, or a particular identifier
generator.

The implementation must make stable identity and revision behavior testable
before later issues add concrete resource hierarchies, admission, storage, and
the reference server. It also needs a deterministic representation for
semantic spec comparison and fixtures. Ordinary JSON Schema cannot constrain
object member order, and adopting a public signing format now would conflate
deterministic internal bytes with a cryptographic canonicalization contract.

## Decision

### Envelope and ownership

Every implemented resource contains these fields:

| Field | Meaning | Change owner |
| --- | --- | --- |
| `apiVersion` | Resource representation version | Immutable after creation |
| `kind` | Concrete resource kind | Immutable after creation |
| `metadata.id` | Stable opaque identity | Server-issued and immutable |
| `metadata.displayName` | Human-readable name | Desired-state client |
| `metadata.parent` | Immediate parent's stable ID | Server-owned and immutable |
| `metadata.labels` | Bounded caller metadata | Desired-state client |
| `metadata.generation` | Desired-spec revision | Domain transition |
| `metadata.resourceVersion` | Complete observable revision | Persistence boundary |
| `metadata.createdAt` | Creation instant | Server-issued and immutable |
| `metadata.updatedAt` | Last persisted-change instant | Persistence boundary |
| `spec` | Desired state | Desired-state client after admission |
| `status` | Observed state | Authorized controller |

`metadata.parent` is absent only for a root resource. It is an opaque ID rather
than a display name or a version-dependent path. It is read-only and has no
domain transition, so the common envelope cannot reparent a resource. Issue
[#18](https://github.com/ArdurAI/veer/issues/18) owns allowed parent kinds,
root and child rules, orphan and cycle checks, and immutable hierarchy
admission.

The domain package stores envelope state privately and returns copies. Callers
cannot mutate an ID, parent, labels map, spec map or slice, status map or slice,
generation, resource version, or timestamp through an alias. Concrete
identifier and resource-version allocation remains injected; this ADR does not
select UUID, ULID, sequence, or database issuance semantics.

### Transition semantics

Creation starts at generation `1`, with equal creation and update timestamps.
The following copy-returning transitions are defined:

- A rename or label change preserves ID, parent, creation time, spec, status,
  and generation.
- A semantic change to an already-defaulted spec increments generation exactly
  once. Generation overflow fails without returning partial state.
- A status change preserves the complete spec and generation. Every status type
  implements the common observation interface and exposes its outer and
  condition observations; every observation must be non-negative and no
  greater than the resource generation. A status without observation fields
  returns an empty sequence.
- Every persisted observable change receives a different injected resource
  version and a non-regressing update timestamp.
- An exact canonical no-op returns the original resource and consumes neither
  a resource version nor an update timestamp.

Issue [#20](https://github.com/ArdurAI/veer/issues/20) owns defaulting,
semantic admission, immutable-field validation, and version conversion. The
spec supplied to the envelope is therefore already admitted and defaulted.
Issues [#26](https://github.com/ArdurAI/veer/issues/26) and
[#30](https://github.com/ArdurAI/veer/issues/30) own atomic version issuance
and persistence.

### Internal canonical JSON profile

The common envelope uses a dependency-free internal JSON profile for equality,
round trips, and storage fixtures:

- output is UTF-8 JSON with no insignificant whitespace or trailing newline;
- envelope order is `apiVersion`, `kind`, `metadata`, `spec`, `status`;
- metadata order is `id`, `displayName`, optional `parent`, optional `labels`,
  `generation`, `resourceVersion`, `createdAt`, `updatedAt`;
- map and nested object keys are encoded in the deterministic lexical order
  provided by Go's pinned `encoding/json` implementation;
- array order is preserved;
- JSON numbers are signed 64-bit integers in canonical decimal form;
- timestamps are UTC RFC 3339 with exactly three fractional digits;
- an empty labels map normalizes to an omitted `labels` field and a root omits
  `parent`; explicit `null` is rejected for both optional fields;
- retained `spec` and `status` bytes advance through at most one typed
  encode/decode normalization step and must then reach a fixed point. Absent,
  `null`, empty object, and empty array values remain distinct only when the
  concrete type represents that distinction; unstructured maps preserve it,
  while typed `omitempty` fields can normalize empty or zero values to absence.
  Custom JSON unmarshalers cannot consume structured object or array values at
  typed boundaries, so they cannot override exact-name and unknown-field
  enforcement; scalar custom types remain supported. The `case:ignore` and
  `embed` JSON tag options are also rejected there. Raw-message capture is
  isolated to the resource envelope; explicit unstructured interface values
  remain the deliberate payload seam;
  and
- both decode input and encoded output are bounded to 262,144 bytes, 64 levels,
  and 50,000 JSON values. Duplicate keys and unknown typed fields fail.

This profile is an internal alpha representation, not RFC 8785, a public
cross-language wire guarantee, or an input to signatures, audit integrity, or
ETag derivation. A future integrity use must adopt and review a purpose-built
cross-language canonicalization contract.

## Consequences

- Domain tests can prove identity and revision behavior without storage,
  queues, cloud credentials, randomness, or wall-clock sleeps.
- Canonical comparison avoids generation churn for equivalent admitted specs
  and exact no-op writes, reducing later database, audit, queue, and reconcile
  work.
- Sorting makes encoding cost `O(n log n)` in object-key count. The resource,
  depth, node, and label bounds cap that work and its memory footprint.
- The domain package does not log resource content. Service adapters can count
  rejected transitions by error class and attach existing request/resource IDs
  without copying spec, status, label values, or provider data into telemetry.
- Concrete resource schemas remain responsible for typed spec/status fields;
  generated transport values do not become domain values.

## Alternatives considered

### Mutable exported structs

Rejected because map and slice aliases could change desired state without a
generation increment and identity fields could be overwritten during rename.

### Generate IDs and versions in the domain package

Rejected because uniqueness and atomic persistence cannot be proven without
the storage boundary, and the current API promises opacity rather than a UUID
or ULID format.

### Represent parent as a kind-and-ID object

Deferred because the common hierarchy is fixed and issue #18 owns parent
reference and hierarchy semantics. A stable ID is sufficient for the shared
envelope and does not make display names authorization keys.

### Claim RFC 8785 canonical JSON

Rejected for this boundary because RFC 8785's number and interoperability
requirements are broader than Veer's current signed-int64 resource contract.
The alpha needs deterministic internal equality, not a cryptographic public
serialization standard.

## Evidence

The implementation is covered by a root golden fixture bound to the checked-in
OpenAPI Workspace example, a parented domain golden, transition tables,
fixed-seed property tests, and Go fuzz seeds. The evidence commands are:

```sh
go test ./internal/core/domain/resource
go test -race ./internal/core/domain/resource
go test -count=100 ./internal/core/domain/resource
go test -run '^$' -fuzz '^FuzzCanonicalRoundTrip$' -fuzztime=10000x ./internal/core/domain/resource
./hack/dev api
./hack/dev check
```
