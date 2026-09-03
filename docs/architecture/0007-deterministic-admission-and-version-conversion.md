# ADR 0007: Deterministic admission and version conversion

- Status: Accepted
- Date: 2026-09-02
- Owners: Veer maintainers
- Decision scope: Issue [#20](https://github.com/ArdurAI/veer/issues/20)

## Context

Veer has a strict `v1alpha1` transport contract, a common immutable resource
envelope, a closed six-kind hierarchy, and provider-neutral control types. It
still needs one pure boundary that turns an untrusted create, replace, or
status body into validated canonical domain intent. Without that boundary,
defaulting can change generation meaning, map iteration can change which error
a caller sees, and a future version can leak transport representation details
into persistence and reconciliation.

OpenAPI must distinguish sparse client intent from a canonical returned value.
A JSON Schema `default` is an annotation; it does not apply the value. Making a
defaulted field required also leaves no omission case for the implementation to
exercise. Admission therefore needs an executable copy-returning default step
and a separate canonical schema.

The boundary must be testable without an HTTP server, authentication provider,
database, queue, policy engine, credential backend, provider SDK, network,
randomness, or ambient time. A rejection must not partially mutate retained
state or trigger downstream work.

## Decision

### Ordered pure pipeline

Create, replace, and status commands run exactly these stages, in this order:

| Order | Stage | Responsibility |
| ---: | --- | --- |
| 1 | `schema` | Bound bytes and JSON work, reject duplicate or unknown members, enforce the selected source schema, and reject unsupported versions or kinds. |
| 2 | `semantic` | Enforce value, ordering, uniqueness, status, and observation invariants without mutating the source value. |
| 3 | `immutable` | Compare source-visible immutable identity on replacement or status commands. Server-owned fields remain excluded by the schema stage. |
| 4 | `reference` | Validate placement against the supplied read-only hierarchy snapshot, including parent existence, kind, and Workspace ownership. |
| 5 | `default` | Copy the validated source value and materialize source-version defaults. |
| 6 | `conversion` | Convert the fully defaulted source command into the internal versionless hub. |

The order is an external compatibility contract recorded by the root-only
`x-veer-admission` OpenAPI manifest. Authentication, authorization, policy,
quota decisions, idempotency persistence, and HTTP preconditions are service or
adapter boundaries; they are not hidden stages in this pure pipeline.

JSON `integer` fields follow Draft 2020-12 mathematical-value semantics, so
exact int64 spellings such as `1`, `1.0`, and `1e0` are equivalent on input;
fractional or out-of-range values fail in the schema stage. The hub retains the
resulting int64, and canonical persisted output remains the decimal-integer
profile defined by ADR 0004.

Semantic validation is default-aware but non-mutating. For example, an omitted
Workspace `suspendReconciliation` is interpreted as its effective value
`false` while checking source semantics. Semantic equality and generation
decisions happen only downstream on the converted hub value, after the actual
default step, so omission and explicit `false` cannot cause generation churn.

Each stage consumes caller values or defensive snapshots and either returns a
fresh value or one terminal error. Rejection leaves the raw body, current
record, hierarchy snapshot, and caller-owned maps or slices byte-for-byte or
value-for-value unchanged. The package owns no persistence, queue, callback,
provider, clock, or network port, so failure cannot create a partial side
effect.

### Sparse write and canonical Workspace specs

`WorkspaceCreate` and `WorkspaceReplace` continue to require the outer `spec`
object, but now reference `WorkspaceSpecWrite`. That closed source schema makes
`suspendReconciliation` optional, accepts only a Boolean when present, and
declares the default annotation `false`. Explicit `null` remains invalid.

Workspace read representations continue to reference `WorkspaceSpec`. The
canonical schema requires `suspendReconciliation` and carries no default
annotation. The executable default rule is:

```text
v1alpha1 Workspace /spec/suspendReconciliation: absent -> false
```

Defaulting is deterministic, copy-returning, and idempotent. Applying it twice
produces the same canonical value as applying it once, explicit `false` and
`true` are preserved, and the sparse source is never modified. The schema split
is a compatible widening of create and replace input; it does not make the
canonical response sparse.

### Stable terminal errors

Admission exposes only a stage, stable code, and optional field path. It returns
at most one error. When more than one candidate exists, selection is the first
failing stage. Every candidate path is then normalized to either its exact
bounded escaped RFC 6901 pointer or the empty whole-document form before
selection continues with the lexicographically first normalized path and then
the lexicographically first code. Implementations must not depend on Go map
iteration order or allocate an unbounded path merely to improve diagnostics.

`invalid-json` is a terminal syntax error. Once token structure is malformed,
admission stops without comparing duplicate candidates collected from the
parseable prefix or inspecting the unread tail.

`request-too-large`, `json-too-deep`, and `too-many-json-nodes` are terminal
structural work ceilings in fixed evaluation order: byte-size preflight first,
then depth and node checkpoints during traversal. The first ceiling crossed
ends inspection immediately; admission does not spend work searching the
unread tail for a lexicographically earlier error. The manifest array freezes
this evaluation order. Stage, pointer, and code precedence applies only to
candidates safely collected before a work ceiling is crossed.

The exact stage code vocabulary is:

| Stage | Codes |
| --- | --- |
| `schema` | `request-too-large`, `invalid-json`, `json-too-deep`, `too-many-json-nodes`, `duplicate-field`, `unknown-field`, `missing-field`, `invalid-type`, `invalid-value`, `unsupported-version`, `unsupported-kind` |
| `semantic` | `invalid-spec`, `invalid-status`, `invalid-order`, `duplicate-item`, `future-observation` |
| `immutable` | `immutable-field` |
| `reference` | `invalid-placement`, `parent-not-found`, `parent-kind-mismatch`, `workspace-mismatch` |
| `default` | `default-failed` |
| `conversion` | `conversion-failed` |

`request-too-large` maps to the existing `413 RequestTooLarge` response.
Schema, semantic, immutable, and reference client faults otherwise map to the
existing `400 ValidationFailure` response. Default and conversion failure mean
an invariant in reviewed code was violated and map to `500 InternalFailure`;
they are not caller-correctable validation failures.

When present, the path is an exact escaped RFC 6901 JSON Pointer. The empty
string means the whole document and is used for failures such as malformed JSON
that cannot identify one member. A pointer that cannot fit the existing
`FieldViolation.field` bounds also becomes empty before candidate ordering: it
is never truncated or converted to dot notation. A future HTTP adapter must
omit the field-violation array in that case because its schema requires a
nonempty field. Error text is fixed safe text and never embeds raw input, IDs,
display names, providers, credential references, or secret-bearing values.

### Internal version hub

The hub is internal and unversioned. `v1alpha1` remains both the only served
version and the persisted canonical envelope version. Admission converts only
spec and status commands; it does not relabel a stored resource envelope or
claim that the internal hub is an API version.

All six kinds participate: Workspace, Policy, Environment,
ProviderConnection, Application, and Component. Every supported source version
must provide source-specific schema, semantic, reference, default, and total
conversion behavior before it can be added to the manifest. An unsupported
version or kind fails in the schema stage.

Round trips preserve meaning after defaulting, not sparse source presence. The
defining Workspace case is:

```text
source omitted -> hub false -> canonical v1alpha1 explicit false -> equal hub
```

For the current single served version, evidence covers source-to-hub and
hub-to-canonical-source conversion for the spec and status of every kind. This
is a real representation boundary and future-version seam, but it is not a
claim that a second public version or a lossy conversion exists.

### OpenAPI and compatibility gates

The root `x-veer-admission` manifest independently freezes stage order, code
sets, response mappings, error selection, path behavior, failure effects,
default rules, and hub semantics. The verifier rejects an unknown, missing,
moved, reordered, or weakened member. It binds the served and storage version
to the existing transport contract and binds the kind order to the independent
six-kind registry.

The OpenAPI surface remains four paths and seven operations. There is one new
schema, increasing the exact schema count from 78 to 79; there is no route,
method, response, media type, dependency, generator, or runtime service added.
An exact 18-cell fixture matrix covers create, replace, and status schemas for
all six kinds. Separate fixtures prove omission, explicit Boolean values,
canonical output shape, `null`, missing `spec`, desired state on status,
server-owned metadata, unknown spec members, and unsupported identity values.

## Consequences

- Callers can omit one documented Workspace write member without receiving a
  sparse or ambiguous read representation.
- Defaulted semantic equality gives persistence and reconciliation one stable
  generation meaning.
- Stable stage, code, and pointer selection can be mapped by an HTTP adapter
  without exposing internal errors or data.
- A versionless hub prevents core behavior from depending on generated
  transport structs while keeping `v1alpha1` storage and response envelopes
  explicit.
- Copying adds bounded allocation work, but request byte, depth, node,
  collection, and snapshot ceilings cap it. No network or paid-service cost is
  introduced.
- The manifest intentionally duplicates implementation constants as an
  independent drift oracle. Every future code, kind, default, or version change
  must update both sides with migration and compatibility evidence.

## Alternatives considered

### Keep one required schema with a default annotation

Rejected because the omission case is invalid and JSON Schema validators do
not apply the annotation. Defaulting code would be unreachable for conforming
requests.

### Make the canonical read field optional

Rejected because callers and persistence would have two representations for
the same effective value and semantic equality could churn generation.

### Default in place before validation

Rejected because a failing request could mutate caller-owned input, defaults
could hide an invalid source representation, and later validation could observe
a value the client did not send.

### Convert before reference validation

Rejected because source versions may need distinct reference projections and a
future conversion could discard information needed to validate placement.

### Aggregate all admission errors

Rejected for the alpha because traversal and map order could change output,
the bounded Problem schema permits one field violation, and one deterministic
terminal error is sufficient for correction without reflecting excessive
untrusted input.

### Version the hub as `v1alpha1`

Rejected because it would make a transport representation the core model and
misstate same-version conversion as the future compatibility boundary.

## Deferred decisions

- A second served API version and its lossless or lossy conversion policy.
- Concrete workload and Policy spec fields and their source-version defaults.
- HTTP adapter wiring, route-level authorization, precondition, idempotency,
  and response rendering behavior from issue #21.
- Persistence migrations and atomic storage decisions from issue #30.
- Policy and quota admission owned by issues #23, #24, and #42.

## Evidence

The evidence includes exact manifest drift mutations; the 18-cell schema
compatibility matrix; pinned Vacuum positive and expected-failure validation;
default determinism, idempotence, and input-alias tests; stable stage, code, and
path selection; a six-stage failure side-effect oracle; and spec/status hub
round trips for every kind.

```sh
go test ./api/openapi ./internal/core/domain/model/... ./internal/core/domain/admission
go test -race ./api/openapi ./internal/core/domain/model/... ./internal/core/domain/admission
go test -count=100 ./internal/core/domain/model/... ./internal/core/domain/admission
./hack/dev api
./hack/dev docs
./hack/dev check
```
