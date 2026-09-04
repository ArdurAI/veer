# ADR 0011: Tamper-evident audit and privileged administration

- Status: Accepted
- Date: 2026-09-03
- Owners: Veer maintainers
- Decision scope: Issue [#27](https://github.com/ArdurAI/veer/issues/27)

## Context

Veer must make security-relevant activity attributable, ordered, reviewable,
and resistant to undetected alteration without turning credentials, identity
claims, request bodies, provider responses, or arbitrary error text into a
second data-leak path. API admission and asynchronous execution also need a
shared correlation vocabulary so a later implementation can reconstruct one
Operation timeline across request, authorization, Operation, and provider
attempt facts.

[ADR 0008](0008-oidc-authentication-and-principals.md) supplies bounded Human
and Workload principals but deliberately forbids generic principal
serialization. [ADR 0009](0009-deterministic-hierarchical-authorization.md)
supplies canonical policy and input versions and reserves `audit.export`,
`operation.quarantine`, and `work.redrive` from Workspace roles. A
`WorkspaceAdministrator` therefore cannot be treated as a platform
administrator. Strong authentication, scope, reason, expiry, and one-use
semantics must be explicit before any of those reserved actions can be wired.

[ADR 0001](0001-alpha-operational-bounds.md) already fixes 90 days of online
audit availability and 365 days of immutable encrypted archive retention. It
also requires future durable audit, archive, and recovery controls. This issue
does not implement those controls. The useful boundary now is a deterministic,
transport-independent reference contract that later persistence, HTTP,
worker, archive, key-management, and administrative adapters must satisfy.

## Decision

### Contract boundary

The audit domain lives in `internal/core/domain/audit` under contract version
`veer.audit.v1alpha1`. It owns bounded canonical events, safe references,
stream checkpoints, hash-chain records, verification segments, export
descriptors and manifests, and pure retention decisions. The privileged
administration domain lives in `internal/core/domain/administration` under
contract version `veer.administration.v1alpha1`. It owns exact administrator
bindings, sealed privileged targets, ledger-gated strong-authentication
verification, one-use grants, and a bounded process-local lifecycle ledger.

The OpenAPI root `x-veer-audit` manifest projects the exact versions, limits,
closed vocabularies, integrity and export rules, fixed retention, and
privileged-administration boundary. It is reference metadata only. This
decision adds no path, operation, component schema, server, or authorization
annotation; the OpenAPI document remains at four paths, seven operations, and
81 schemas.

The reference packages implement no persistence or external-I/O adapter. The
administration ledger synchronously invokes its injected strong-authentication
verifier boundary, but this decision adds no verifier implementation,
`StateStore` transaction, database table or migration, outbox record, queue
work, API or worker emission, query implementation, archive writer, S3 object,
KMS operation, signing key or signer, provider call, or runtime enforcement.
An in-memory value being valid does not prove that an event was durably
recorded, that all replicas share one sequence, or that audit data committed
atomically with state and outbox work.

### Canonical event

`EventInput` contains exactly these semantic fields:

| Field | Contract |
| --- | --- |
| `ID` | Stable server-issued event ID |
| `Stream` | One Workspace stream or the separate Platform stream |
| `Sequence` | Positive stream-local order; wall time never breaks a tie |
| `RecordedAt` | Injected UTC timestamp normalized to millisecond precision |
| `ClockState` | `Synchronized`, `Uncertain`, or `Regressed` |
| `Kind` | Closed event family |
| `Source` | Closed component class that observed the fact |
| `Actor` | Anonymous, pseudonymous principal, or opaque administrator reference |
| `AuthenticationMethod` | Closed method compatible with the actor kind |
| `Action` | One registered authorization action, required for every event |
| `Request` | Optional stable request reference |
| `Target` | Optional hierarchy-sealed authorization-target projection |
| `Decision` | Optional policy version, input digest, effect, and reason |
| `Operation` | Optional bounded Operation snapshot |
| `Attempt` | Optional provider-attempt ID and positive ordinal |
| `Elevation` | Optional privileged-grant lifecycle projection |
| `Outcome` | Closed result that can preserve an indeterminate provider outcome |

The canonical JSON starts with `contractVersion`, rejects unknown and
duplicate fields and alternate encodings, and is capped at 16,384 bytes before
archive compression. It has no arbitrary attribute map, message, request body,
response body, provider body, or error text.

A Human or Workload actor retains only its principal kind and existing
`prn1_` fingerprint. Exact issuer and subject remain private authorization
inputs and are not serialized into the event. An Administrator actor retains
only its opaque administrator ID. Anonymous attribution carries no pseudonym.
The allowed actor and method pairs are exact:

| Actor kind | Authentication method |
| --- | --- |
| `Anonymous` | `None` |
| `Human` | `OIDC` or `StrongOIDC` |
| `Workload` | `WorkloadOIDC` or `Internal` |
| `Administrator` | `StrongOIDC` |

`OperationRef` retains the Operation, Workspace, resource, optional
co-present Environment and ProviderConnection, generation, resource version,
phase, optional bounded reason, and update time. It deliberately excludes the
Operation message and cost estimate. `DecisionRef` retains only the canonical
authorization policy version, input digest, effect, and reason. A target,
Operation, elevation, and Workspace stream must agree on Workspace and every
other shared scope identifier. An Operation and authorization target always
match on Workspace and resource; Environment and ProviderConnection must also
match when the Operation carries that optional binding. When an elevation
event also carries an Operation or authorization target, every shared object,
Workspace, resource, Environment, and ProviderConnection ID must match. A
`PlatformAudit` elevation rejects either unrelated co-reference.

### Timeline vocabulary and correlation

Event kinds are ordered canonically as `Request`, `Authorization`,
`Operation`, `ProviderAttempt`, `Elevation`, `Export`, `Retention`, and
`Integrity`. Their minimum relationship rules are:

- `Request` requires a request reference.
- `Authorization` requires a decision reference.
- `Operation` requires an Operation reference.
- `ProviderAttempt` requires both Operation and attempt references and source
  `ProviderAdapter`.
- `Elevation` requires an elevation reference, source `Administration`, an
  Administrator actor, and `StrongOIDC`.
- an attempt reference is forbidden on every non-attempt event;
- an elevation reference is forbidden on every non-elevation event and must
  match the event actor, action, scope, and recorded time.

Sources are `API`, `Worker`, `Controller`, `ProviderAdapter`,
`Administration`, and `System`. Outcomes are `Accepted`, `Succeeded`,
`Denied`, `Failed`, `Canceled`, and `Indeterminate`. `Indeterminate` records
an unknown external result; it does not assert success, failure, or retry
safety.

[ADR 0012](0012-reconciliation-reliability-and-fencing.md) fixes the producer
side of that vocabulary. One `ProviderAttempt` event corresponds to each actual
or conservatively possibly dispatched physical attempt. A prepared attempt that
is proven never dispatched is `NoEffect` and produces no attempt event; after
owner or process loss, absent such proof, the single attempt is recorded as
`Indeterminate`. Provider retries use new attempt IDs and ordinals while
retaining the same logical-effect identity.

These references are sufficient for a future producer to join request,
authorization, Operation transitions, and every externally attempted provider
mutation, including retries, by stable IDs and sequence. No API or worker
currently emits this stream, so the repository does not yet demonstrate that
a deployed Operation timeline is complete.

### Streams, sequence, and integrity

Every event carrying a target or Operation reference uses the `Workspace`
stream for that exact Workspace. `WorkspaceAudit` and `Operation` elevation
events use that same matching Workspace stream. A `PlatformAudit` elevation
instead uses the separate `Platform` stream, which carries no Workspace ID.
Cross-Workspace and cross-kind stream references are rejected. The two stream
kinds cannot be merged to infer a global order.

Every stream begins at a stream-specific genesis checkpoint at sequence zero.
`Append` accepts only the next positive sequence in the same stream and binds
the canonical event to the previous digest. The chain digest uses SHA-256 over
domain-separated, unsigned-64-bit-length-framed values covering the contract
version, stream, sequence, predecessor, and complete canonical event. Its
text prefix is `ach1_`.

A segment contains at most 1,000 contiguous records and at most 16,640,512
canonical bytes. Construction and decoding preflight count and aggregate bytes
before record allocation and chain work. Given the correct predecessor,
verification detects mutation, deletion inside the presented range,
insertion, reordering, cross-stream substitution, or broken sequence.
`Segment` has strict canonical JSON marshal and unmarshal behavior. `Record` and
`Checkpoint` are intentionally runtime trust values without standalone wire
encodings. Runtime-only opaque values reject generic JSON, text, binary, and
Gob serialization with `ErrSerializationForbidden`; `ChainDigest` and
`ExportBodyDigest` expose their own typed canonical text forms.

A hash chain alone cannot prove that the presenter deleted a valid suffix. A
valid prefix remains internally valid. `VerifySegment` can detect tail
deletion only when its computed head is compared with an independently trusted
terminal checkpoint. The package cannot decide whether a caller-supplied
checkpoint is trustworthy, durable, fresh, replicated, or independent from
the event store. Those are requirements for the later persistence, archive,
and recovery boundaries, not properties of this reference library.

Strict canonical decoding and successful chain verification prove only the
accepted representation and its continuity relative to the supplied
predecessor and, when present, expected head. They do not prove that a
producer's original event or reference assertion was true, observed, or
authorized. `UnmarshalCanonicalEvent` can revalidate embedded structural and
cross-reference shapes, but it cannot re-derive historical hierarchy state or
producer authority. Issue [#24](https://github.com/ArdurAI/veer/issues/24) owns
runtime reauthorization; issues [#30](https://github.com/ArdurAI/veer/issues/30)
and [#31](https://github.com/ArdurAI/veer/issues/31) own authoritative storage
and atomic production with state and outbox work. ADR 0012 requires those future
transactions to commit Operation/work/attempt state, required audit evidence,
the integrity anchor, and successor outbox work together, while every external
provider call remains outside the database transaction.

### Clock handling

All contract times are injected and normalized to UTC milliseconds, with parsed
years restricted to `0001` through `9999`. Sequence, not `RecordedAt`, defines
event order. `ClockState` preserves whether the producer considered wall time
synchronized, uncertain, or regressed instead of rewriting uncertain time into
a false ordering claim.

`RetentionInput` contains exactly `RecordedAt`, `EvaluatedAt`,
`PreviousEvaluatedAt`, `ClockState`, and `Holds`. Its single `ClockState` is a
conservative combined quality signal for the recorded timestamp and current
evaluation observation; it may be `Synchronized` only when both are. A later
good clock therefore cannot legitimize an originally uncertain `RecordedAt`.
Evaluation fails safe for a zero, future, uncertain, or regressed time and
never returns a deletion-eligible result. The administration ledger owns one
explicitly configured clock for strong-authentication admission and grant
issuance and maintains one non-regressing process-local high-water mark. A
sequential rollback fails rather than extending or resurrecting authority;
overlapping samples are ordered by call start so a late older call cannot
manufacture a rollback. This remains local state and is not a distributed clock
oracle.

### Export verification

An export consists of a non-empty canonical segment body and a bounded
canonical manifest. `DescribeExport` binds the predecessor checkpoint,
inclusive sequence range, record count, terminal checkpoint, generated time,
clock state, external signature algorithm, key ID, and an `aeb1_`-prefixed
domain-separated SHA-256 body digest. The manifest is capped at 4,096 bytes,
the external signature at 512 bytes, and its non-secret key ID at 128 bytes.
The canonical descriptor field order is `contractVersion`, `stream`,
`range` with `first` then `last`, `eventCount`, `previousDigest`,
`terminalDigest`, `bodyDigest`, `generatedAt`, `clockState`,
`signatureAlgorithm`, and `keyId`. The flat manifest has the same order and
appends `signature`.

`Ed25519` is the only accepted signature-algorithm descriptor. The package
implements neither signing nor public-key parsing. A caller supplies a
`SignatureVerifier`; the strict canonical `ExportDescriptor` encoding is the
signature payload, and `ExportManifest` binds the resulting signature. Both
types have strict canonical JSON marshal and unmarshal behavior. `VerifyExport`
checks that signature, body digest, stream, predecessor, range, count, chain,
and an explicit trusted terminal checkpoint. The trusted checkpoint is
mandatory even when the signature is valid because the signer and body alone
cannot prove that a later valid stream suffix was not omitted.

The reference verifier makes no network request and does not select a key trust
store. Key distribution, rotation, revocation, signer isolation, archive
publication, download authorization, and export transport remain future
adapter and runtime decisions.

### Retention and holds

The fixed audit intervals are:

| Event age at evaluation | Disposition |
| --- | --- |
| Less than 90 days | `Online` |
| At least 90 days and less than 365 days | `Archive` |
| At least 365 days | `Expire` |
| Any age with a valid hold | `Held` |

Hold kinds are `Legal`, `Incident`, and `Security`; one evaluation accepts at
most 32. Only a successfully initialized `Expire` decision is eligible for
deletion. `EvaluateRetention` is a pure classification. It does not move,
archive, lock, retain, or delete a record, and it does not override the
immutable-object and legal-hold requirements in ADR 0001. A longer retention
or new convenience copy needs privacy, storage, and cost review; a shorter
retention needs a reviewed security decision.

### Platform administration and elevation

Platform administration is configured separately from Workspace Policy. A
platform `Administrator` binds one opaque server-issued ID to one exact Human
principal identity by kind, issuer, and subject. A fingerprint, group, email,
audience, Workspace role, or network location cannot establish that binding.
At most 64 administrators are accepted by one reference ledger.

The human-elevatable action set is exactly, and in canonical order:

1. `audit.export`
2. `operation.quarantine`
3. `work.redrive`

`audit.export` may target either the singleton `PlatformAudit` scope or one
resolved `WorkspaceAudit` scope. `operation.quarantine` and `work.redrive`
require a resolved `Operation` target whose retained resource and optional
co-present Environment and ProviderConnection bindings match the supplied
hierarchy. Callers cannot assert those scopes directly. No other authorization
action is human-elevatable in this contract.

An `ElevationRequest` binds a unique grant ID, the configured administrator
and exact matching principal, one eligible action, one sealed target, a
required trimmed reason of at most 256 runes, an optional case reference of at
most 128 runes, an injected request time, and a positive millisecond-aligned
duration no longer than 15 minutes. There is no renewal API.

The shared `BearerCredential` value is owned by
`internal/core/domain/authentication`; `internal/core/ports` preserves aliases
for transport and adapter compatibility. A ledger requires one
`StrongAuthenticationVerifier` and one trusted `Clock`; a future composition
root must install both because this issue supplies no adapter or runtime
endpoint. For each otherwise valid issuance attempt,
`Ledger.Issue(ctx, credential, request)` invokes that verifier exactly once
with the exact credential and immutable request. The verifier must revalidate
the request's exact principal and challenge against the deployment-defined
`auth_time`, `acr`, and `amr` policy. A normal OIDC Principal is not proof of
strong authentication.

The verifier returns only an inert proof ID, its authenticated-at time, and an
error. The ledger is the sole consumer and grant-issuance authority: callers
cannot construct a public strong-authentication receipt, supply verifier
output, or choose the issuance time. After successful verification the ledger
samples its configured clock, normalizes both times, and requires issuance to
be at or after the request and authentication instants and no more than five
minutes after authentication. The port returns only the closed
`strong-authentication-invalid` or `strong-authentication-unavailable`
non-context failures. No verifier adapter or middleware integration exists in
this issue.

Proof IDs cannot be replayed. The process-local ledger retains proof tombstones
and at most 1,000 grants and terminal tombstones. A grant is single-use and
bound to its exact action and target. Its irreversible states are `Active`,
`Consumed`, `Revoked`, and `Expired`; equality with the expiry instant is
expired. Consumption and revocation produce receipts that can be projected
into matching audit elevation events.

Bearer credential, administrator, request, grant, target, consumption, and
revocation values redact credential, identity, scope, reason, and case data
from generic formatting and reject applicable JSON, text, binary, and Gob
serialization. Verifier proof metadata remains internal to the ledger rather
than becoming a serializable capability. These protections limit accidental
generic output; a compromised process can still inspect authority available
inside its address space.

The ledger lock makes one process's grant transition race deterministic. It is
not durable, shared across nodes, or atomic with audit, state, Operation, or
queue changes. A restart forgets it. Authoritative compare-and-set,
cross-replica replay prevention, action execution, and audit emission must be
implemented by their owning runtime and persistence issues before any
privileged workflow is usable.

## Consequences

- Producers and exporters have one bounded vocabulary for attribution,
  Operation correlation, integrity, retention, and privilege lifecycle.
- Workspace and Platform streams separate tenant history from platform
  authority, at the cost of requiring an explicit cross-stream investigation
  view rather than pretending there is one total order.
- Canonical encoding and chained checkpoints make presented-range alteration
  detectable. Completeness still depends on a trusted independent checkpoint.
- Fixed retention and hold outcomes are testable without granting deletion or
  archive authority to the domain package.
- Strong authentication and a one-use grant become explicit preconditions for
  three reserved actions, but no reserved action becomes executable merely
  because the reference types exist.
- The reference implementation introduces no cloud resource, network call, or
  paid API. Durable storage, archive, key management, export transport, and
  operational verification retain the cost envelopes and review requirements
  of ADR 0001.

## Rejected alternatives

### One global tenant and platform stream

Rejected because it would widen query and sequence authority across
Workspaces, couple unrelated tenants, and make a Workspace reader depend on a
platform-wide disclosure boundary.

### Timestamp ordering

Rejected because clocks can regress, disagree, or be uncertain. Injected time
is retained as evidence; the contiguous stream sequence is authoritative.

### Hash chain without a trusted expected head

Rejected as a completeness claim. It detects changes inside a presented range
but accepts an internally valid prefix after suffix deletion.

### Serialize the complete principal or provider response

Rejected because audit would become a credential, personal-data, and
untrusted-payload sink. Stable pseudonyms and bounded typed references retain
the correlation needed by this contract.

### Let WorkspaceAdministrator perform platform recovery actions

Rejected because Workspace policy administration is tenant authority. Export,
quarantine, and redrive remain reserved and require separate configured Human
administration plus strong authentication.

### Treat the process-local ledger as enforcement

Rejected because process memory cannot prevent replay or double consumption
across replicas or restarts and cannot make a privileged effect atomic with
durable audit evidence.

## Evidence

Deterministic domain tests cover canonical event round trips and negative
shape matrices, actor/method and event/reference relationships, Workspace
scope agreement, Operation timeline fixtures, chain mutation/deletion/
reordering, valid-prefix behavior with and without a trusted expected head,
segment byte/count preflights, manifest/body/signature/checkpoint verification,
fixed retention boundaries, holds, unsafe clock outcomes, exact administrator
identity, sealed action/target combinations, exact verifier invocation and
credential/request forwarding, strong-authentication age and replay,
verifier-output rejection, trusted-clock issuance and overlap behavior,
one-use grant races, expiry equality, non-regressing time, retained tombstones,
and redaction/serialization canaries.

Ordinary local verification commands are:

```sh
go test ./internal/core/domain/audit ./internal/core/domain/administration \
  ./internal/core/ports
go test -race ./internal/core/domain/audit \
  ./internal/core/domain/administration
go test -count=100 ./internal/core/domain/audit \
  ./internal/core/domain/administration
go test ./api/openapi
./hack/dev api
./hack/dev docs
./hack/dev check
git diff --check
```

These checks prove only the reference contracts and checked-in projection.
Issues [#24](https://github.com/ArdurAI/veer/issues/24),
[#30](https://github.com/ArdurAI/veer/issues/30), and
[#31](https://github.com/ArdurAI/veer/issues/31) own runtime reauthorization,
durable administration and audit persistence, and atomic write integration.
Issue [#34](https://github.com/ArdurAI/veer/issues/34) owns queue quarantine
and redrive execution. Issue [#64](https://github.com/ArdurAI/veer/issues/64)
owns archive, recovery, checkpoint trust, and break-glass exercises. None is
implemented by this decision.
