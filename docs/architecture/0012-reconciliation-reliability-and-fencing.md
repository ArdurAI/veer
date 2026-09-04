# ADR 0012: Reconciliation reliability, idempotency, and fencing

- Status: accepted
- Date: 2026-09-04
- Accepted: 2026-09-04
- Decision owners: ArdurAI maintainers
- Scope: first operable alpha
- Tracking issue: [#29](https://github.com/ArdurAI/veer/issues/29)

## Context

Veer accepts desired state before asynchronous workers contact an external
provider. PostgreSQL is authoritative, while SQS Standard deliberately permits
duplicate and reordered delivery. A provider timeout, process loss, queue
visibility expiry, or database-fence loss can leave the external effect unknown.
No queue feature or local mutex can make that gap exactly once.

ADRs 0001, 0002, 0003, 0006, 0009, 0010, and 0011 already require atomic
accepted writes, a transactional outbox, generation-aware Operations,
execution-time authorization, provider-credential binding, and one audit event
per physical provider attempt. This decision fixes the remaining crash,
idempotency, plan, lease, cancellation, retry, compensation, retention, and cost
semantics without changing the public Operation phase vocabulary.

Veer promises at-least-once delivery with fenced ownership. It does not promise
exactly-once provider execution.

## Decision

### Prepared attempts and crash boundaries

Before any provider mutation, one bounded PostgreSQL transaction persists all
of the following or none of them:

- the current Operation and immutable plan revision and digest;
- the canonical logical-effect key;
- a unique physical attempt ID and positive ordinal;
- the desired generation;
- the current lease owner and positive signed fence; and
- the applicable work-state transition and required audit evidence.

The provider call occurs only after that preparation commits and never while a
database transaction is open. A later bounded transaction atomically writes the
applicable Operation, work, attempt, observation, integrity anchor, required
audit data, and either zero or one successor outbox record. Split writes or
eventual repair of state, audit, and outbox are not accepted alternatives.

Preparation alone is not a second `ProviderAttempt` audit event. Exactly one
such event is required for every actual or conservatively possibly dispatched
physical attempt. A provider call that is proven never to have begun is
`NoEffect`; after owner or process loss, a prepared or dispatched attempt
without definitive evidence is `Indeterminate`.

The complete recovery matrix is:

| Crash boundary | Required recovery |
| --- | --- |
| Before the accepted API transaction commits | No accepted work exists; ordinary request retry is allowed. |
| After API commit but before response | Resolve and replay the durable HTTP idempotency result. |
| Before outbox publication | Reclaim the durable outbox claim. |
| After publish but before receipt recording | Republish is allowed and may duplicate delivery. |
| Delivery before fence acquisition | No provider effect is allowed. |
| After attempt preparation but before definitive result commit | Record `Indeterminate` unless a live owner proves dispatch never began. |
| After result commit but before queue acknowledgement | Redelivery is a durable no-op. |
| Lease or fence loss during a dispatched call | Stop new calls; retain the old call as potentially effective and observe it. |

A queue acknowledgement occurs only after its durable result commits. Queue
visibility and receipt possession suppress duplicate load but never grant
provider authority. Every durable work key retains its exact plan digest and
may be claimed or completed only by a lease token for that same plan. A
wrong-plan token is rejected before creating or changing delivery state. An
active delivery may be reclaimed only by the exact work and lease binding under
a strictly newer fence; a completed delivery remains a terminal no-op.

### Worker transaction predicates

Every authoritative worker transition predicates the exact Workspace,
resource lineage, desired generation, Operation, plan digest, owner, and fence.
A stale worker may retain bounded non-authoritative attempt evidence, but cannot
change the current Operation, desired state, observed state, or current effect
projection.

The eventual `StateStore` adapter owns transaction isolation, compare-and-swap,
row locking, and database-time sampling. The reference package defines the
transition and cardinality oracle; it does not make an in-memory value durable.

### Immutable plan identity and replanning

Every immutable plan has an opaque record ID, a positive revision, and a
domain-separated semantic digest. The digest binds:

- the reconciliation contract and planner versions;
- Operation, Workspace, resource, desired generation, and optional retained
  Environment and ProviderConnection scope;
- defaulted desired intent and the authoritative observed-snapshot identity and
  version;
- pseudonymous actor identity and authorization policy/input digests;
- ProviderConnection and credential-reference IDs, generations, resource
  versions, and canonical evidence digests when the Operation is provider-bound;
- capability, quota, and cost evidence versions and digests; and
- completed effects and compensation lineage.

Secrets and provider-native request bodies are never plan inputs. Plan record
ID, revision, predecessor metadata, Operation status resource version, and
physical attempt identity do not alter semantic identity.

Within one Operation, identical semantic inputs reuse the existing digest and
create no new work. A same-generation material replan requires a fresh
authoritative observation, every prior physical attempt to be resolved, and one
definitive authoritative current-effect projection for every attempted logical
effect. `Prepared` and `Dispatched` attempts block replanning;
`Indeterminate` remains immutable resolved physical history but may proceed only
after observation has made the corresponding current effect `Applied` or
`NoEffect`. Each current projection must match the exact plan, effect, purpose,
compensation or cancellation identity and be no older than its business attempt
or captured observation target. It also names the unique physical attempt that
most recently established its current truth. The new immutable revision names
its predecessor and atomically supersedes the prior executable plan. Every
current `Applied` effect is carried forward, and attempt admission rejects every
effect in the selected plan's completed set even when a caller omits a current
projection, so an equivalent replan cannot repeat it.

Successful plan selection returns a process-local, copy-safe, one-use lineage
capability bound to the exact expected and replacement lease bindings. A
same-generation capability can be minted only by the complete replan check; a
forward-to-compensation capability additionally binds the complete validated
qualified inverse schedule before it exists. Therefore an arbitrary
compensation plan cannot replace the active forward-plan lease and strand its
known applied effects. A
new-generation capability binds an exact next generation, new Operation, and
revision one. Lease replacement consumes that capability, so an arbitrary
forward-looking `LeaseBinding` cannot bypass plan-lineage validation.

A new desired generation creates a new Operation and supersedes only old work
that is proven undispatched. A prepared, dispatched, or `Indeterminate` effect
from an earlier generation gates a conflicting newer-generation dispatch until
it becomes `Applied` or `NoEffect`, unless an adapter supplies bounded evidence
that is cryptographically bound to the exact prior and candidate effects and
qualifies safe supersession. A higher database fence cannot undo an external
effect.

Issue [#33](https://github.com/ArdurAI/veer/issues/33) owns executable plan-step
shape and canonical provider-neutral semantics. This ADR fixes the identity and
transition constraints that shape must satisfy.

### HTTP idempotency and provider-effect identity

HTTP idempotency is a fixed, non-sliding semantic window:

```text
expires_at = first successful reservation commit time + 24h
live       = database_time < expires_at
expired    = database_time >= expires_at
```

The scope is authenticated principal, HTTP method, and canonical target. The
fingerprint additionally binds canonical query and defaulted canonical body.
Matching replay returns the stored semantic status, response body, and semantic
headers without new generation, audit, outbox, queue reservation, or provider
work. Request correlation is fresh for each transport attempt.

Replay never moves expiry, cleanup lag never extends the window, and an exact
cutoff race has one transactional winner. An unresolved reservation cannot be
recycled merely because 24 hours elapsed. After expiry, reuse creates a fresh
key epoch and must pass current authentication, authorization, preconditions,
validation, uniqueness, and admission. Clock monotonicity is enforced per
ledger using an ordered PostgreSQL-time high-water. An older overlapping call
keeps its own valid sample and may advance that high-water; a fresh sample below
the high-water fails closed even when it addresses another key.

When the bounded reference ledger reaches record capacity, it reclaims only
completed rows at or beyond their exact expiry before rejecting new work. A
call registers its scoped key and ordered sample before competing for the
ledger transition; its active-call registry is bounded from the configured
capacity and excess registration fails closed. Reclamation cannot remove a row
while an earlier live call for that key may still require replay. Once no such
call exists, it removes the response row and compact epoch state together. A
later fresh key lifetime may restart at epoch one; a delayed completion still
cannot match because completion compares the complete immutable scope, key,
fingerprint, epoch, commit time, and expiry tuple. Unresolved reservations
remain charged and are never age-reclaimed.

Provider-effect identity is separate from HTTP idempotency. It binds Workspace,
resource lineage, generation, Operation, and bounded canonical semantic effect.
It stays stable across physical retries and equivalent plan revisions. Every
physical provider call has a new attempt ID and ordinal. The bounded current
effect projection records the source attempt ID as its compare-and-swap version;
a definitive observation that wins the exact-current transition replaces it
with the observation attempt ID.

Retain a bounded current ownership/effect projection for the provider object
lifetime and at least 90 days after deletion. Age alone does not permit removal:
all referencing Operations, outbox records, deliveries, redrive authority, and
unknown attempts must also be terminal or provably superseded. Detailed plans,
attempts, and effect history retain the 90-day online and 365-day archive
periods in ADRs 0001 and 0011. Issue
[#36](https://github.com/ArdurAI/veer/issues/36) owns the complete durable
tombstone and finalizer lifecycle.

### Lease, fence, visibility, and cost

Production uses one stable PostgreSQL lease row keyed by Workspace and resource
lineage. Generation, Operation, plan revision, and plan digest are bound
columns, not alternate lease keys. Ordinary acquisition and takeover require
the exact retained binding; an expired old binding cannot overwrite a newer
row. Moving to a new generation or same-generation plan revision requires an
explicit one-use plan-lineage capability and atomic compare-and-swap from the
exact expected binding to a strictly forward replacement: a new generation
starts at revision one, while a replan advances exactly one revision. Before a
new-generation capability is minted, the exact first mutation admission must
already bind and pass the authoritative older-effect and safe-supersession
checks. Without that proof, an unresolved predecessor keeps the old lease
binding available for observation instead of being stranded by replacement.
Its fence is a positive signed PostgreSQL `bigint`: it
increments only on acquisition, takeover, or successful binding replacement,
remains unchanged on renewal, never resets or reuses, and fails closed before
overflow. Equality with expiry loses ownership.

The store lease and SQS visibility interval are each 60 seconds. A stable
per-work digest selects a renewal target from the closed interval 15 through 20
seconds, and a healthy worker never waits longer than 20 seconds. An SQS
visibility change establishes a new interval from that successful call; it does
not add time to the prior deadline.

Immediately before a provider mutation, the worker must revalidate current
generation, plan, owner, fence, execution authorization, ProviderConnection and
credential binding, quota, and cost authority using PostgreSQL time. Dispatch is
allowed only when that validation and permit admission carry the same exact
canonical PostgreSQL-time sample. The resulting authority and permit are
copy-safe, process-local one-use capabilities bound to the exact prepared
attempt identity, effect, purpose, request fingerprint, plan, owner, and fence.
Attempt preparation itself consumes a separate one-use capability that binds
the atomic cancellation state plus exact retry, older-generation,
compensation, and observation-budget checks. A time-bounded retry proof remains
attached to the prepared attempt and must still be live at the exact dispatch
sample. An observation reservation's original deadline is bound into its permit,
attempt admission, prepared attempt, and dispatch identity. Both execution-time
authority and the final dispatch transition reject equality with or passage of
that deadline. Immediately before the provider call is marked dispatched, the
lease table atomically rechecks that the permit's exact row, owner, binding, fence,
and unexpired lease are still current; a surrender, takeover, or replacement
that wins first rejects the stale permit.
The authority time is at or after attempt preparation, and recovery resolution
time is at or after the latest preparation or dispatch boundary. Dispatch is
allowed only when:

```text
remaining lease time > provider RPC timeout + 10s
provider RPC deadline < lease expiry - 10s
```

A failed or unknown store renewal or visibility change cancels the local call,
stops new dispatch, and surrenders or lets expire the store fence. A previously
dispatched unresolved attempt becomes `Indeterminate`; transport uncertainty is
never treated as success.

At the conservative target boundary, 1,000 continuously active leases renewed
at the earliest 15-second stable interval produce about 66.67 PostgreSQL
updates per second and 178,560,000 updates per 744-hour month. Qualification
must measure WAL, indexes, vacuum, backups,
replication, lock wait, and failover rather than assuming those writes are free.

The prior 20,000,000 and 100,000,000 SQS request-unit caps were fully
partitioned. At the earliest 15-second cadence, a healthy 30-second small call
needs one visibility reset before completion, while a healthy 60-second target
call can need three resets at 15, 30, and 45 seconds. Worst-case visibility
renewal therefore adds 3,546,645 small-profile and 52,824,735 target-profile
requests, so the revised caps are 23,546,645 and 152,824,735. Admission
reserves every baseline and visibility unit before work is accepted. Retries,
redeliveries, empty polls, partial-batch retries, and the completion-versus-
renewal race each consume the appropriate partition.

At the reviewed first-tier `us-east-1` rate of USD 0.40 per million requests,
the new visibility partition adds about USD 1.42 small and USD 21.13 target per
month. ADR 0001 and its checked-in worksheet carry the authoritative rounded
totals and remaining headroom. This is a design envelope, not an AWS quote.

The 60/20 pairing is a qualification target, not an AWS availability guarantee.
After a renewal followed by process loss, nominal lease expiry plus a 20-second
long poll leaves about 40 seconds inside ADR 0001's two-minute fenced-
reacquisition objective.

### Concurrent cancellation and update precedence

PostgreSQL commit and compare-and-swap order decides cancellation, update, and
dispatch races; request arrival time does not. Cancellation committed before
attempt preparation prevents the call and may terminalize the Operation as
`Canceled`.

The cancellation comparison and the prepared-attempt write are one future
StateStore transition. The reference model represents its successful side as a
one-use attempt-admission capability; a forward or compensation attempt cannot
be constructed from a bare `Running` Operation after cancellation has
committed.

If preparation wins, the transaction records `CancelPending`. Outcome
observation and a separately prepared provider-cancel attempt are allowed when
supported, but new forward business steps, compensation, and blind retry are
forbidden. Provider cancellation has its own logical effect, physical attempt,
audit event, and potentially `Indeterminate` result. Its admission separately
binds the exact unresolved forward or compensation effect being canceled, so a
cancellation outcome cannot replace or reinterpret the original effect truth.
The first provider-cancel call may start from that unresolved target; retrying
the distinct cancellation effect requires its own `NoEffect` evidence or exact
live adapter-idempotency proof.

The public Operation phases remain exactly `Pending`, `Waiting`, `Running`,
`Succeeded`, `Failed`, and `Canceled`. This decision adds no `Conditions` field.
While the canceling owner remains active, the Operation is `Running` with
internal reason `CancelPending`; after ownership is released while work remains
unresolved, it is `Waiting` with that reason. `Canceled` means no further
forward execution, not rollback. It is allowed only after every dispatched
outcome and required cleanup or quarantine disposition is durable. Cancellation
targets only its exact Operation and never erases a newer generation or an older
external effect.

### Uncertain provider outcomes and retry

Durable effect truth is independent from retry eligibility:

- `Applied` proves the effect occurred;
- `NoEffect` proves it did not occur; and
- `Indeterminate` records that the external result is unknown.

An indeterminate Operation remains `Waiting` with internal reason
`ProviderOutcomeIndeterminate`. Observation uses the persisted logical effect
and expected external identity. Retry is permitted only after `NoEffect`, or
when an adapter contract supplies bounded evidence of durable idempotency for
the exact logical effect and request fingerprint through the retry instant.
Timeout, cancellation, connection loss, or queue redelivery alone never proves
retry safety.

Every unknown effect has a finite positive observation-attempt count and
deadline. A slot is consumed before preparing an observation and returns a
one-use permit bound to the exact effect, reservation time, count, budget
version, and deadline. Observation attempt admission requires and seals a
persisted `Indeterminate` target and consumes that permit. Completion accepts the
resolved physical observation plus the authoritative current logical effect and
must commit both the budget transition and returned effect projection in one
future StateStore compare-and-swap. A dispatched definitive result updates state
and time only when the current projection, including its source attempt ID,
still exactly equals the captured target. A concurrently advanced projection is
returned unchanged even when both attempts resolve in the same normalized
millisecond, so a late `NoEffect` observation cannot overwrite a newer retry
result. Recovery proving
that observation dispatch never began also leaves the target state and timestamp
unchanged. Observation attempts cannot be reduced directly to an effect
projection; they must pass through this exact-current transition while preserving
plan, purpose, compensation, and provider-cancellation identity. `Prepared` or
`Dispatched` work is not yet an observation-eligible resolved unknown, and an
observation may be dispatched only strictly before its original budget deadline.
If the caller abandons the reservation before an attempt is prepared, an exact
one-use release transition retires the in-flight binding without refunding the
used slot. Release and preparation race atomically: only the winner can proceed,
so later observations or exact-deadline quarantine cannot be stranded by a
failed preparation.
Exhaustion transitions exactly once to quarantine/manual recovery. The old
unknown effect continues to gate a conflicting newer generation, and each
conflicting prior projection requires exact safe-supersession evidence.

### Compensation

Compensation is a new immutable forward plan for the same still-nonterminal
correlated Operation; it is never rollback of committed desired state or
history. It may contain only confirmed `Applied` effects with adapter-qualified
inverses and preconditions, runs in strict reverse dependency order, and may
touch only Veer-owned resources under the current generation, execution
authorization, credential binding, and fence.

Before each compensation attempt is prepared, the complete qualified inverse
schedule and the exact `Applied` prefix are validated. The resulting opaque
one-step capability binds the plan, original effect, qualified inverse,
dependency order, schedule evidence, and position. A compensation attempt must
carry that exact next-step capability; an arbitrary inverse, a step from
another schedule, or an out-of-order prefix cannot authorize dispatch.

Each compensation effect has a distinct logical identity, physical attempts,
and audit evidence. An `Indeterminate` original or compensation result is never
automatically compensated. Failure or uncertainty remains visible as
`Waiting`, quarantine, or manual recovery and is never reported as successful
rollback.

## Executable reference contract

`internal/core/domain/reconciliation` implements a provider-free,
transport-free, process-local reference model with contract version
`veer.reconciliation.v1alpha1`. It includes:

- bounded, domain-separated evidence, plan, request, result, work, and logical-
  effect digests;
- immutable plan selection, one-use lease-replacement and attempt-admission
  capabilities, safe supersession, and sealed next-compensation-step oracles;
- fixed-window idempotency, duplicate-delivery, signed-fence lease, queue-budget,
  attempt, observation, cancellation, retention, and crash-recovery models;
- closed vocabularies and stable internal reasons without changing Operation
  phases; and
- forbidden generic serialization and redacted diagnostics for opaque runtime
  values.

The model receives PostgreSQL time and transaction facts as inputs. It cannot
prove that a caller obtained them from PostgreSQL, that evidence bytes were
truthful, or that an adapter is durably idempotent. Its typed values constrain
future integration; they do not grant provider authority by themselves. A
future StateStore transaction must supply the complete retained cancellation,
effect, generation, proof, and observation-budget snapshot when minting attempt
admission; supply exact resolved physical history plus the authoritative current
logical-effect set when selecting a replacement plan; durably compare-and-swap
attempt dispatch; and atomically commit observation-budget completion with the
returned exact-current effect projection. The process-local one-use cells only
make copied in-memory values converge.

The root-only OpenAPI `x-veer-reconciliation` projection makes the contract
version, closed vocabulary, limits, timing, cost partitions, and non-claims
discoverable. It adds no path, operation, component schema, or runtime claim.

## Security, privacy, and observability

Plan and effect inputs are untrusted. Constructors validate closed kinds,
bounds, scope, generation, and digest framing before retaining only safe
projections. Secrets, bearer tokens, provider-native bodies, raw request bodies,
raw responses, and arbitrary provider errors are excluded from plans, queue
work, diagnostics, and metrics.

Opaque values reject JSON, text, binary, and Gob serialization. Typed digests
are intentional bounded text scalars. Logs may use opaque request, Operation,
plan, work, delivery, and attempt IDs for correlation, but those IDs are not
metric dimensions. Metrics use bounded states, purposes, results, and static
operation names.

Future production must observe prepared/dispatched/indeterminate counts,
observation and quarantine age, lease renewal and takeover, stale-fence writes,
queue visibility extensions, request-unit reservations, completion races,
provider timeouts, WAL, vacuum, and projected monthly cost. It must not record
credential or provider payload content.

## Explicit non-claims and ownership

This decision and its reference package implement no:

- PostgreSQL schema, transaction, row lock, fence, idempotency row, outbox, or
  current-effect projection;
- SQS message, receipt, visibility heartbeat, DLQ, redrive, or cost-meter
  adapter;
- API route, HTTP middleware, worker loop, scheduler, or composition-root
  enforcement;
- provider adapter, provider request, observation, cancellation, compensation,
  or destination-identity verification; or
- cross-process durability, cross-node coordination, exactly-once provider
  execution, or automatic orphan cleanup.

Issues [#30](https://github.com/ArdurAI/veer/issues/30) and
[#31](https://github.com/ArdurAI/veer/issues/31) own durable StateStore and
transactional-outbox integration. Issue
[#32](https://github.com/ArdurAI/veer/issues/32) owns the SQS and developer queue
adapters. Issue [#33](https://github.com/ArdurAI/veer/issues/33) owns executable
planning. Issue [#34](https://github.com/ArdurAI/veer/issues/34) owns worker
scheduling, quarantine, and redrive. Issues
[#35](https://github.com/ArdurAI/veer/issues/35) through
[#37](https://github.com/ArdurAI/veer/issues/37) own status/drift, deletion, and
failure-recovery integration. Provider issues #38 through #57 own adapter-
specific truth and conformance.

## Rejected alternatives

- **Record attempts only after the provider returns.** This loses evidence in
  the external-call crash gap and cannot distinguish no effect from uncertainty.
- **Repair state, audit, and outbox later.** Split authority makes acknowledged
  state unverifiable and permits work without its required evidence.
- **Create a new Operation for observation-only replanning.** This fragments one
  accepted request timeline; immutable revisions preserve it without mutation.
- **Retain HTTP replay for 90 days.** It simplifies late replay but increases
  storage and privacy cost without replacing long-lived provider-effect proof.
- **Use per-Operation fences or queue visibility as ownership.** Old and new
  generations can overlap, and transport possession cannot reject stale writes.
- **Report cancellation immediately.** `Canceled` would be false while an
  unresolved external effect or required cleanup remained.
- **Blindly retry unknown outcomes.** This can duplicate provider resources or
  destructive effects.
- **Always compensate, or never compensate.** Unqualified deletion is unsafe;
  rejecting every proven inverse leaves avoidable partial effects. The selected
  bounded forward-plan model makes the proof obligation explicit.

## Verification

Deterministic tests must cover:

- 24-hour minus-one-millisecond, equality, and plus-one-millisecond boundaries,
  non-sliding replay, ledger-wide clock rollback, cross-key cleanup while an
  earlier call is live, bounded row-and-key state, stale completion after full
  reclamation, unresolved expiry, and two cutoff racers;
- every crash point and its only accepted recovery action;
- duplicate delivery during live visibility, exact work-to-lease plan binding,
  and stale resume after takeover;
- store and visibility success, failure, and unknown outcomes;
- strict RPC deadline plus ten-second margin, live-lease recheck at dispatch,
  surrender/replacement versus permit consumption, preparation/recovery
  chronology, timestamp overflow, signed fence exhaustion, qualified one-use
  forward binding replacement, and renewal without fence increment;
- an older prepared, dispatched, or indeterminate effect gating conflicting new
  generation work, with exact safe-supersession evidence;
- same-generation plan reuse and replan, completed-effect carry, compensation
  qualification, resolved physical history plus definitive current logical
  effects, source-attempt-versioned stale current-effect rejection, completed-
  effect admission rejection, sealed schedule progress, and reverse dependency
  order;
- one-use attempt admission covering cancellation, retry, generation, and
  observation; exact observation release versus preparation, finite deadline
  propagation through final dispatch, exact-current completion, stale-result and
  undispatched-result suppression, count/time exhaustion, and exactly-once
  quarantine;
- effect-evidence deletion at 90-day minus/equality with every residual
  reference and unknown state; and
- 1,000 synchronized leases through failover plus queue visibility-cost
  reservation, retries, partial batches, and completion races.

Ordinary local verification is:

```sh
go test ./internal/core/domain/reconciliation
go test -race ./internal/core/domain/reconciliation
go test -count=100 ./internal/core/domain/reconciliation
go test ./api/openapi
./hack/dev api
./hack/dev docs
./hack/dev check
git diff --check
```

These tests prove the pure reference contract and checked-in projection only.
The issue owners above must provide persistence, adapter, chaos, load, failover,
and operational evidence before Veer claims the runtime behavior.

## Primary references

- AWS documents Standard queues as
  [at-least-once delivery](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/standard-queues-at-least-once-delivery.html).
- AWS defines each SQS API action as a billable request in its
  [SQS pricing](https://aws.amazon.com/sqs/pricing/) documentation.
- AWS documents that
  [`ChangeMessageVisibility`](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ChangeMessageVisibility.html)
  starts the new visibility interval from the call time.
- PostgreSQL defines `bigint` as a signed eight-byte integer in its
  [numeric type documentation](https://www.postgresql.org/docs/current/datatype-numeric.html).
