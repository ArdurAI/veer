# ADR 0010: Provider-neutral process-local credential broker

- Status: Accepted
- Date: 2026-09-03
- Owners: Veer maintainers
- Decision scope: Issue [#25](https://github.com/ArdurAI/veer/issues/25)

## Context

Veer's public `ProviderConnection` contract already binds a provider identifier
and opaque, versioned credential reference to one Environment and its immutable
Workspace owner. Provider-bound Operations retain the same Workspace,
Environment, and ProviderConnection identities. Those retained values are
necessary but not sufficient to hand authority to a provider adapter: a stale
or substituted connection, unbounded credential, or serializable session could
turn the control plane into a confused deputy.

[ADR 0009](0009-deterministic-hierarchical-authorization.md) therefore reserves
`credential.resolve` to broker authority rather than any tenant role. The
formal threat model additionally requires operation and recipient binding,
bounded lifetime, independent rotation and revocation, memory-only credential
handling, and secret-canary evidence.

This issue precedes the runtime API/worker, persistence, deterministic plans,
provider interfaces, and concrete AWS or Kubernetes adapters. The useful
boundary now is consequently a provider-neutral, process-local reference
broker that can prove its domain and concurrency behavior without a database,
secret manager, provider SDK, network call, or real credential. It must not
claim the later runtime and destination controls merely because the local
contract exists.

## Decision

### Contract boundary

The credential domain lives in `internal/core/domain/credential` and uses
contract version `veer.credentials.v1alpha1`. It owns immutable binding values,
secret-bearing material wrappers, issued-session validation, digest framing,
and closed failure classes. The core-owned ports `SecretResolver` and
`SessionIssuer` split external source lookup from provider-session issuance.
The service in `internal/core/service/credentialbroker` composes those ports
while owning caches, limits, single-flight work, lineage epochs, terminal
tombstones, leases, refresh, rotation, and revocation.

The contract is provider neutral:

- `SecretResolver` receives one validated `SourceLookup` and returns bounded
  `SourceMaterial` for the exact opaque reference and version.
- `SessionIssuer` is registered for one exact `Recipient`; it receives the
  bounded source through the broker and returns one validated `IssuedSession`.
- `SessionIssuer.Revoke` attempts upstream invalidation for one exact request
  and issued session and returns a closed `RevocationResult`.
- an adapter receives only the resulting short-lived `SessionMaterial`, never
  the caller's OIDC or Bearer credential and never the source material;
- the broker request contains stable server-derived identifiers and a closed
  authorization action, not caller-supplied ownership or provider-native
  payloads; and
- invalid input and pre-dispatch lifecycle or timing state fails before resolver
  or issuer dispatch; completion-time state is revalidated before publication.

`Recipient` is an exact bounded identifier for the eventual consumer. It is not
a network destination, AWS account, Kubernetes cluster, role, service account,
or proof that the recipient is authorized. Issues
[#38](https://github.com/ArdurAI/veer/issues/38) and
[#39](https://github.com/ArdurAI/veer/issues/39) own the provider interface and
the broker-to-adapter execution boundary.

### Binding construction

`NewRequest` constructs the only valid `Request` from a complete hierarchy
snapshot, one typed ProviderConnection envelope supplied by the caller, a
`ResourceView` of the target, one validated provider-bound Operation, one
registered authorization `Action`, and one `Recipient`. Callers cannot directly
populate the private binding fields.

Construction proves all facts available in the current repository:

1. The ProviderConnection exists in the supplied complete Workspace snapshot,
   is parented by an Environment, and retains the same Workspace as that
   Environment.
2. The Operation's Workspace, Environment, and ProviderConnection IDs exactly
   match the supplied connection envelope.
3. The supplied target envelope belongs to the same Workspace and Environment,
   and its `ResourceView` generation matches the Operation generation.
4. The provider identifier and credential reference come from the typed
   ProviderConnection rather than the caller.
5. The action and recipient are closed, validated values.
6. The requested session duration is the fixed fifteen-minute alpha duration.

The hierarchy snapshot proves retained identities and ancestry; it contains no
ProviderConnection spec, ProviderConnection generation, or target generation.
`NewRequest` takes those revision values from the supplied typed envelopes and
proves that they agree with the retained hierarchy and Operation. The broker
then enforces the highest connection generation observed during its own
lifetime. Neither step proves that the first observed envelopes are the store's
latest values. Authoritative reload and runtime currentness belong to issues
[#24](https://github.com/ArdurAI/veer/issues/24) and
[#30](https://github.com/ArdurAI/veer/issues/30); the exact execution-time
binding and fencing semantics are fixed by
[ADR 0012](0012-reconciliation-reliability-and-fencing.md).

`SourceLookup` contains exactly the Workspace, Environment,
ProviderConnection, ProviderConnection generation, provider identifier,
credential reference ID, and credential reference version. `SourceDigest`
commits to all of those fields with domain-separated length framing.

`Request` adds the Operation ID, target resource ID and generation, action, and
recipient. `BindingDigest` commits to the complete request. Digests are stable
correlation and equality values, not credentials, authorization decisions,
signatures, or substitutes for authoritative state.

The request deliberately contains no principal, caller credential,
authorization header, Policy document, arbitrary attributes, provider-native
document, endpoint, or backend location. Runtime reauthorization and plan
binding remain issue [#24](https://github.com/ArdurAI/veer/issues/24) and issue
[#33](https://github.com/ArdurAI/veer/issues/33).

### Three independent revision values

Credential rotation preserves the distinctions established by the resource
contract:

| Value | Meaning | Broker use |
| --- | --- | --- |
| `metadata.generation` | Monotonic desired-spec lineage for one ProviderConnection | Orders accepted connection observations and rejects stale or conflicting lineage |
| `spec.credentialRef.version` | Opaque external version selector with no lexical or numeric ordering | Exact source-cache identity; a changed value proves a rotation only with a higher generation |
| `metadata.resourceVersion` | Opaque revision of the complete persisted resource, including status-only changes | Not part of source or session identity and never used to order credential rotation |

For one stable ProviderConnection ID, an exact generation and `SourceDigest`
replay is idempotent. A lower generation is stale. A different digest at the
same generation is conflicting input. A higher generation is accepted as a
credential rotation only when provider and reference ID remain unchanged and
the opaque reference version changes. Rebinding provider authority or a
reference identity in place is rejected by
`CheckProviderConnectionSpecTransition` with
`ErrProviderConnectionRebind`; callers must create a distinct
ProviderConnection instead.

This rule prevents a display-name, status, or resource-version update from
rotating credentials and prevents a same-generation race from changing the
resolved authority.

### Material handling

`SourceMaterial` and `SessionMaterial` have private owned byte storage and are
constructed only through `NewSourceMaterial` and `NewSessionMaterial`.
`IssuedSession` binds session material, issue and expiry instants, and the exact
`BindingDigest`. `NewIssuedSession` consumes and destroys the supplied
`SessionMaterial` on every path and owns an independent copy on success. A value
exposes raw bytes only to a synchronous `WithBytes` callback. It clones a
scratch buffer under lock, releases the lock before the callback, and clears the
scratch on return. The callback must not retain the slice, launch work that
outlives the call, or transfer it to another goroutine.

Every generic formatting path is no-panic and no-secret; constructed values
return a fixed redacted representation. Constructed non-nil credential values
and constructed `Broker`, `Lease`, and `Rotation` values and their copies reject
JSON, text, binary, and Gob serialization with the classified
`ErrSerializationForbidden`. Go's `encoding/json` emits its standard safe
`null` for a typed nil pointer without invoking a value-receiver marshaler; that
empty case is not support for serializing credential material. Error values
contain closed classifications only. Source and session material must not enter
public resources, Operations, plans, state, queues, fixtures, logs, traces,
metrics, errors, cost reports, or support output. Synthetic non-secret canary
strings are test inputs, not deployment credentials.

The direct diagnostic and encoding method contract is for constructed non-nil
`SourceMaterial`, `SessionMaterial`, and `IssuedSession` values and their copies.
Callers must not infer that every direct method call on an arbitrary nil pointer
is supported. Generic `fmt` and `slog` handling of typed nil values remains
no-panic and no-secret, and generic JSON can emit only the safe `null` described
above.

`Broker` and `Lease` contain pointers to private synchronized state. Copying a
constructed value therefore aliases the same state; it does not snapshot a
broker, create a second broker, or duplicate a lease. Concurrently closing an
original lease and its copy releases the one shared handle exactly once.

`Destroy` clears the wrapper's owned buffer and makes the value invalid. The
broker destroys owned material when it processes replacement, expiry, revocation,
cancellation, terminal close, failed validation, backend error, or shutdown. This is
best-effort exposure reduction, not a cryptographic memory-erasure claim: Go's
compiler, runtime, garbage collector, dependencies, kernel, crash handling, or
provider SDK may have made copies outside the wrapper's control.

### Time and size bounds

Credential validity, refresh, expiry, and cache-admission decisions use an
injected clock, and no expected-value oracle depends on ambient time. Ambient
wall time is limited to backend timeout enforcement and bounded failure or
deadlock-watchdog behavior in tests.

The broker assigns a saturating, broker-local observation sequence before each
`Clock.Now` call. An older valid sample from overlapping work that finishes out
of order clamps to the accepted time high-water. A later-started zero or
regressed sample advances the observation fence and fails closed with
`ErrUnavailable`; a subsequent non-regressed sample can recover. Sequence
saturation also fails closed. The one-hour source deadline remains anchored to
the raw sample taken immediately after `Resolve` returns, even when ordered
logical observation of that sample clamps to a newer high-water.

| Bound | Alpha value | Enforcement |
| --- | ---: | --- |
| Requested session lifetime | 15 minutes | Every request uses the fixed duration; callers cannot enlarge it |
| Minimum issuer lifetime | 5 minutes | A newly issued session with less remaining lifetime is rejected and destroyed |
| Maximum issuer lifetime | 15 minutes | A backend cannot return authority beyond the requested maximum |
| Refresh-ahead window | 3 minutes | A live lease becomes refresh-eligible at `expiresAt - 3m` |
| Minimum new-use lifetime | 2 minutes | A newly acquired use must retain at least this usable interval |
| Expiry skew | 30 seconds | Usability and lifetime checks subtract the fixed safety skew |
| Backend timeout | 10 seconds | Resolver and issuer calls receive a clean internal child context no longer than this bound or their flight's earlier deadline; each queued upstream revoke receives a fresh baggage-free context for this bound only after it acquires a revocation slot |
| Source reuse eligibility | 1 hour maximum | A source becomes ineligible for every new borrow exactly one hour after its material returns from `Resolve`, or earlier on lineage invalidation |
| Recipient provider and name | 64 bytes each | `NewRecipient` rejects either oversized identifier |
| Source material | 64 KiB maximum | Constructor rejects larger input without retaining it |
| Session material | 16 KiB maximum | Constructor and issuer validation reject larger output |

The one-hour source bound is a reuse and admission ceiling, not a hard physical
residency deadline. The broker has no background timer: an idle broker may keep
an ineligible source entry past that hour. A cleanup-capable, time-observing
acquisition, rotation, or lifecycle entry, or explicit `SweepExpired`, retires
it; `Stats`, `RegisterIssuer`, `Lease.Use`, and `Lease.Close` do not sweep.
Ordinary TTL retirement destroys the owned bytes immediately unless an existing
borrow is still using them; that borrow defers final destruction and the source
remains charged to capacity until release. Broker `Close` and explicit lineage
invalidation by rotation or revocation instead destroy the master buffer
immediately even with an active borrow; only a callback's scratch copy may
remain until that callback returns.

These are Veer-owned portability and exposure ceilings, not claims about a
particular backend. They deliberately fit established provider constraints:
AWS STS documents 900 seconds as the minimum `AssumeRole` duration in its
[official API reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html),
and AWS Secrets Manager documents a 65,536-byte encrypted secret-value maximum
in its [official quotas](https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html).
Kubernetes documents TokenRequest credentials as time-bound, with a one-hour
default for Pod-bound tokens, and separately documents that an individual
short-lived token has no central revocation record in its
[ServiceAccount administration reference](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/).
Those examples inform the conservative bounds and the honest
`RevocationExpiryBound` state; they do not make AWS or Kubernetes an implemented
backend.

An issued session is accepted only when its binding matches exactly, its issue
time is not in the future under the clock/skew rule, it retains at least the
five-minute issuer minimum, and it expires no later than the request's
fifteen-minute maximum. A new use additionally requires two minutes of usable
lifetime after applying the thirty-second skew. Existing work becomes eligible
for refresh three minutes before expiry; expiry is never extended by reusing a
cached handle.

### Process-local concurrency and lifecycle

The broker has hard process-local cardinality bounds:

| State | Maximum |
| --- | ---: |
| Cached source entries | 500 |
| Cached or shared session cells | 1,000 |
| Active lease handles | 1,000 |
| Tracked connection lineages | 500 |
| Tracked Operations, including terminal tombstones | 10,000 |
| Concurrent source resolutions | 32 |
| Registered session issuers | 16 exact recipients |
| Concurrent upstream revocations | 16 |

The `SourceDigest` is the source-cache and resolver single-flight key. Identical
concurrent source lookups share one resolver attempt. Workspace, Environment,
connection, generation, provider, reference ID, or reference-version changes
produce a different key and never coalesce.

The complete `BindingDigest` is the session issuance and refresh single-flight
key. It adds Operation, target generation, action, and recipient, so distinct
effects cannot share a session merely because they use the same source.
Capacity is reserved before backend dispatch; an over-limit request fails
without calling the resolver or issuer. Refresh pins its fallback replacement
slot. Rotation pins its source and session publication slots and reserves its
first waiter's lease entitlement before dispatch; every later waiter reserves
before joining the flight. An atomic cutover turns all surviving entitlements
into leases, so competing acquisition cannot consume them and a committed
rotation cannot later fail for lease capacity.
Material selected for replacement or eviction remains charged to its source or
session ceiling until out-of-lock `Destroy` completes. Failed issuance and
rotation reservations likewise remain charged through unpublished-session
cleanup and destruction; admission cannot reuse a still-live material slot.

Every source-resolution leader, including a rotation, creates a private,
synchronized source holder before backend dispatch. After `Resolve` returns, the
broker snapshots the provider tuple and backend-context result, then transfers
any non-nil material into that pre-registered holder before clock observation
and durable-budget settlement. If invalidation already won, holder publication
synchronously destroys the result and fails. Only a completion that still
passes its clock, lineage, lifecycle, and waiter checks may atomically transfer
the source from the holder into a cache entry or committed rotation.

Connection revocation, Operation termination, rotation cutover, and broker
shutdown serialize a short process-local invalidation phase. While holding the
broker state lock they detach affected state and capture cancellations; after
releasing that lock they synchronously destroy affected cached, retired, and
flight-private source buffers before publishing those cancellations. The
serialization gate is released before bounded upstream cleanup waits. Thus a
resolver or issuer awakened by cancellation cannot observe an affected master
source buffer as still valid. Concurrent invalidators of the same flight holder
join any destruction already in progress before they may publish cancellation,
and no material destruction runs while the central broker lock is held. This
does not erase a scratch copy already inside a `WithBytes` callback or forcibly
terminate a backend that ignores its context.

When the last waiter abandons a source-resolution or rotation flight, the same
holder-before-cancel rule applies and its capacity remains reserved until the
worker finishes cleanup. Operation termination is deliberately narrower than
connection invalidation: it invalidates that Operation's sessions and any
matching pending rotation's private source, but preserves the shared
current-generation source cache because another Operation on the same
connection may still use it.

An issuer registration is keyed by the exact provider and recipient name.
`RegisterIssuer` rejects a duplicate even when the implementation value is
identical. Registration cannot be replaced or removed while the broker remains
live, so active leases cannot observe a new issuance or revocation contract
under the same identity.

Each ProviderConnection has a generation high-water mark and local lineage
epoch. `Acquire` accepts an exact current replay but returns
`ErrCredentialRotationRequired` with no resolver or issuer call when it sees a
higher generation. `Rotate` is the only cutover path. It requires the same
Workspace, Environment, connection, provider, and reference ID, a strictly
higher connection generation, and a changed opaque reference version.

`Rotate` prepares and validates the new lineage and session before an atomic
cutover. Cutover advances the epoch, publishes the new source and session,
materializes every live waiter's pre-reserved lease, and invalidates the prior
source and sessions locally. Cancellation that wins before commit removes that
waiter's entitlement and may abandon the flight; commit that wins the race is
final, and the late-canceled waiter receives its committed `Rotation`. A
successful cutover joins prior resolver, issuer, and revocation cleanup within
its bounded wait, then returns a `Rotation` containing the new lease and the
aggregate prior-session revocation result. Cleanup uncertainty is reported as
`RevocationPending`; it does not roll back or ambiguously pair a usable new
credential with an error.

Ownership of every non-nil `SessionIssuer.Issue` result transfers to the broker,
including a result returned with an error. Every valid provider session that is
not published because issuance or rotation failed, became stale, was canceled,
observed a terminal or closed broker, or failed a completion-time clock check
receives exactly one queued, baggage-free upstream `Revoke` attempt before the
broker destroys it and completes the issuing waiter. Invalid output is simply
destroyed. Lifecycle and rotation completion join already-started source,
session, unpublished-session, and revocation cleanup when it finishes inside
their wait; otherwise they report `RevocationPending` while broker-owned cleanup
continues. Honest broker-owned cleanup still in progress may produce
`RevocationPending` with no error. Caller cancellation while waiting produces
`RevocationPending` with that context error. Completion of any older flight is
checked against its captured epoch and can never publish stale output.

Each Operation has a local epoch. `CancelOperation` or `CloseOperation`
increments it and installs a terminal tombstone for the remaining lifetime of
that broker instance before attempting upstream revocation. A stale in-flight
completion cannot remove the tombstone, publish a session, or make the
Operation usable again. Exact concurrent work has one shared completion, while
each caller still receives its own bounded handle lifecycle and context result.
`RevokeConnection` follows the same local-first rule at connection scope.

Connection high-water state and terminal Operation tombstones are safety state,
not evictable cache entries. Once either tracking ceiling is full, a request
that needs a new connection or Operation slot fails with `ErrCapacity` before
backend dispatch. In particular, evicting a terminal Operation merely to admit
new work could resurrect a canceled or closed identifier, so exhaustion of the
10,000-Operation table is deliberately fail-closed.

The upstream revocation states are exactly:

| Result | Meaning |
| --- | --- |
| `RevocationNotRequired` | No known issued session required an upstream attempt |
| `RevocationProviderConfirmed` | Every required issuer reported provider-confirmed revocation |
| `RevocationExpiryBound` | Immediate provider revocation is unavailable, but every affected session remains bounded by its expiry |
| `RevocationPending` | At least one required upstream result is unavailable or not established |

Aggregation precedence is `RevocationPending`, `RevocationExpiryBound`,
`RevocationProviderConfirmed`, then `RevocationNotRequired`. For a live session,
an issuer error, timeout, explicit `RevocationPending`,
`RevocationNotRequired`, or invalid result is unconfirmed and yields
`RevocationPending` with the service's closed `ErrUnavailable`; local
invalidation remains effective. For a pending or expiry-bounded result, the
broker captures `ExpiresAt`, destroys the local session, and then retains only
that maximum provider expiry against the affected connection and any tracked
Operation before publishing attempt completion. An exact repeated lifecycle
call makes no second provider call: it returns
`RevocationExpiryBound` while that non-secret evidence remains, then
`RevocationNotRequired` at the exact expiry when no other authority remains.
`Lease.Close` releases only that handle and never invalidates or revokes its
shared issued-session cell.

Resolver and issuer work uses the broker's clean internal timeout context rather
than a caller context carrying values, baggage, or credentials. Caller
cancellation stops that waiter and abandons shared source, issuance, or rotation
work only after its last waiter leaves. Source and rotation abandonment destroy
the private flight source before publishing cancellation; an ordinary issuance
flight releases its borrow of the shared connection source only when its worker
exits. Upstream revocation instead uses one broker-wide queue across overlapping
lifecycle batches. At most 16 calls hold a slot; each call acquires its slot
before starting its fresh baggage-free ten-second provider context. A lifecycle
caller waits under its own cancellable context and a separate ten-second
ceiling. It may return `RevocationPending` with no error for known broker-owned
cleanup, with its context error when that caller stops waiting, or with
`ErrUnavailable` when the provider attempt fails or is unconfirmed. The
broker-owned queued call and cleanup continue, and later repeats can join or
consume the recorded result. An adapter that
ignores context cancellation can run longer than ten seconds, so the timeout
bounds the context granted to it, not forced goroutine termination. Broker
shutdown prevents new work, cancels owned resolver and issuer flights, destroys
cached and leased material, and leaves no reusable handle.

Revoking the current generation while an uncommitted next-generation rotation
is in flight advances the connection's `revokedThrough` tombstone through that
pending target before canceling it. Exact current- and target-generation repeats
return `RevocationPending` while the canceled rotation and any late
next-generation `Issue` output remain in cleanup. After cleanup, an exact target
repeat is idempotent and returns only retained expiry-bound evidence or
`RevocationNotRequired`, never another provider call.

Epochs, tombstones, caches, and session handles are intentionally process
local. Restarting a broker loses them. They do not establish distributed
revocation, persistence, worker fencing, or cross-replica coordination.

### Frozen service surface

The exported `credentialbroker` surface is deliberately closed:

- `New(SecretResolver, SecretReadBudget, Clock) (*Broker, error)` constructs an
  empty broker; a nil `Clock` selects the wall clock.
- `RegisterIssuer(Recipient, SessionIssuer) error` installs one exact immutable
  provider-and-recipient-name registration.
- `Acquire(context.Context, Request) (*Lease, error)` reuses or proactively
  refreshes one exact binding; `Refresh` forces a replacement attempt, and
  `Rotate(context.Context, Request) (Rotation, error)` is the only
  connection-lineage cutover.
- `RevokeConnection`, `CancelOperation`, and `CloseOperation` each accept a
  context and `Request` and return `(RevocationResult, error)` after local-first
  invalidation. `Close(context.Context)` applies the same rule to the broker.
- `SweepExpired() error` performs deterministic opportunistic cleanup without a
  background timer, and `Stats() Stats` returns label-free counters.
- `Lease.ExpiresAt`, `Lease.Use`, and `Lease.Close` expose bounded session use;
  `Use` accepts `func(context.Context, []byte) error` and supplies a clean
  expiry-bounded context plus an ephemeral byte copy.
- `Rotation.Lease`, `Rotation.PriorRevocation`, and `Rotation.Valid` expose a
  committed cutover without a lease-plus-error ambiguity.

The service's closed `Failure` vocabulary is `ErrInvalid`, `ErrConflict`,
`ErrStale`, `ErrRevoked`, `ErrOperationTerminated`, `ErrExpired`, `ErrClosed`,
`ErrUnavailable`, `ErrCapacity`, `ErrCredentialRotationRequired`, and
`ErrSerializationForbidden`. `Classify` recognizes all eleven failures without
exposing backend error text.

### Cost-budget boundary

[ADR 0001](0001-alpha-operational-bounds.md) requires a version-aware
single-flight source cache, but the cache is not a cost control. Before every
Veer-issued paid secret-manager request, a durable budget port must atomically
claim one regional, profile, and accounting-window request. A confirmed
pre-dispatch failure releases the claim idempotently; an uncertain outcome
retains it.

The production ledger reserves 90 percent for general reads and 10 percent for
rotation, invalidation, and recovery. The partitions cannot borrow. General
exhaustion rejects general calls while preserving unused critical capacity;
100-percent exhaustion rejects every call before dispatch. Missing ledger state
or a last confirmed durable read older than two minutes fails cache misses and
refreshes closed without calling the paid service. A still-valid cache hit may
continue until its version-aware expiry or invalidation.

The exact port is `SecretReadBudget`. `Claim` receives the source lookup and
either `SecretReadGeneral` or `SecretReadCritical` priority and returns one
`SecretReadClaim`. The broker calls its `Settle` exactly once with
`SecretReadConsumed`, `SecretReadReleased`, or `SecretReadRetained`; uncertain
dispatch and settlement failure retain the claim. General cache misses use the
general partition, while explicit rotation uses the critical partition.

Budget settlement records provider-call truth independently from local
publication. Immediately after `Resolve` returns, the broker snapshots whether
the provider returned a valid source with `SecretReadConsumed` and no provider
error. That result is settled as consumed even when a concurrent lifecycle
transition, an expired backend context, a clock failure, or a failed holder
transfer prevents caching or issuance; the source is still destroyed and never
published. This separation prevents a paid, consumed read from being
incorrectly released merely because Veer later rejected its authority.

The process-local broker exercises this port with deterministic adapters. It
does not implement the durable ledger or make a real Secrets Manager request.
Production resolution remains ineligible until a durable implementation
satisfies the accepted 45,000/5,000 small-profile and 450,000/50,000
target-profile primary/recovery request caps.

### Explicit non-claims

This decision and implementation add no:

- HTTP route, API server, worker, database, queue, plan, audit event, or runtime
  authorization enforcement;
- public OpenAPI schema, path, operation, or authorization-vocabulary change;
- real secret-manager, AWS STS, Kubernetes TokenRequest, provider SDK, network,
  or paid-service call;
- provider lifecycle interface or broker-to-adapter wiring;
- provider destination, account, partition, region, endpoint, cluster,
  namespace, IAM, RBAC, or effective-capability verification;
- cross-process or distributed revocation, durable tombstone, worker fence, or
  guarantee that an already dispatched provider request stopped; or
- hard memory-zeroization guarantee.

The broker's process-local generation high-water is replay fencing after first
observation, not proof that the initial ProviderConnection or target envelope
was authoritative or current.

The OpenAPI baseline remains exactly four paths, seven operations, and 81
schemas. Issue [#24](https://github.com/ArdurAI/veer/issues/24) owns runtime
reauthorization, [ADR 0012](0012-reconciliation-reliability-and-fencing.md)
fixes the provider-free reliability contract, and issues
[#30](https://github.com/ArdurAI/veer/issues/30) through
[#37](https://github.com/ArdurAI/veer/issues/37) own durable execution,
adapters, fences, cancellation, and recovery. Issue
[#38](https://github.com/ArdurAI/veer/issues/38) owns provider interfaces,
issue [#39](https://github.com/ArdurAI/veer/issues/39) owns adapter execution
context, and issues [#45](https://github.com/ArdurAI/veer/issues/45) and
[#52](https://github.com/ArdurAI/veer/issues/52) own Kubernetes and AWS
destination identity.

## Consequences

- Provider credential handling gains a bounded, reviewable core contract before
  provider SDKs or deployment credentials exist.
- Stable bindings and generation/epoch checks prevent one process from
  publishing stale or cross-scope resolver and issuer results.
- The split port avoids exposing long-lived source material to adapters and
  keeps provider-specific issuance replaceable.
- Exact fixed bounds make memory, concurrency, timeout, and potential paid-call
  pressure measurable. At the maxima, retained raw wrapper capacity is bounded
  independently of Go object overhead; the broker must reject rather than
  allocate beyond its entry and lease ceilings.
- Process-local state keeps this issue independently testable but deliberately
  leaves replica coordination, durable revocation, destination proof, and live
  provider qualification to their dependency-ordered issues.

## Rejected alternatives

### Embed credentials or backend paths in ProviderConnection

Rejected because public resources, plans, queues, fixtures, telemetry, and
errors would become secret-bearing or reveal backend topology. The existing
opaque reference contract remains unchanged.

### Pass caller credentials to an adapter

Rejected because authentication authority is not provider authority and would
violate the reserved broker action and tenant boundary.

### Treat resourceVersion or reference version as an ordered generation

Rejected because both are opaque. Only ProviderConnection generation provides
monotonic desired-state lineage.

### Share a session by source reference alone

Rejected because two Operations, actions, targets, or recipients could then
reuse authority outside the approved effect. Session sharing requires the full
`BindingDigest`.

### Claim process-local revocation as distributed revocation

Rejected because another replica or an already-dispatched provider call cannot
observe an in-memory epoch or tombstone. Durable coordination and fencing are
separate runtime contracts.

### Add a production secret backend now

Rejected because no durable cost ledger, runtime configuration, provider
interface, destination verification, or provider qualification exists. A live
backend here would either violate ADR 0001 or smuggle downstream decisions into
issue #25.

## Evidence

The retained evidence covers binding construction, exact digest separation,
generation/revision confusion, in-place rebind rejection, size and lifetime
boundaries, redacted formatting, forbidden serialization, shared-state copies,
best-effort destroy, same-key single-flight, different-scope non-coalescing,
cache, reservation, disposal, and lease limits, resolver and issuer timeouts,
rotation commit/cancellation races, flight-source ownership across settlement,
provider settlement versus publication, destroy-before-cancel lifecycle and
last-waiter ordering, Operation-scoped rotation cleanup, the global revocation
queue, unpublished and old-flight cleanup, retained expiry evidence, idempotent
generation tombstones, refresh, terminal tombstones, stale-completion
suppression, shutdown, and secret canaries.

Ordinary verification commands are:

```sh
go test ./internal/core/domain/credential ./internal/core/ports
go test ./internal/core/service/credentialbroker
go test -race ./internal/core/domain/credential ./internal/core/ports \
  ./internal/core/service/credentialbroker
go test -count=100 ./internal/core/domain/credential ./internal/core/ports \
  ./internal/core/service/credentialbroker
./hack/dev api
./hack/dev docs
./hack/dev check
git diff --check
```

The documentation checks are deterministic checked-in contract verification;
they are not a security scan. No security scanner is required by this decision.
