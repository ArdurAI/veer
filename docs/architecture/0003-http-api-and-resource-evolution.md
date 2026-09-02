# ADR 0003: HTTP API and resource evolution conventions

- Status: accepted
- Date: 2026-09-01
- Accepted: 2026-09-01
- Decision owners: ArdurAI maintainers
- Scope: first operable alpha
- Tracking issue: [#16](https://github.com/ArdurAI/veer/issues/16)

## Decision

Veer's first-alpha control-plane contract is a versioned JSON HTTP API rooted
at `/api/v1alpha1`. The checked-in
[`veer-v1alpha1.json`](../../api/openapi/veer-v1alpha1.json) document uses
[OpenAPI 3.1.2](https://spec.openapis.org/oas/v3.1.2.html) and is the transport
source of truth. It defines a representative Workspace surface so routing,
media types, errors, correlation, concurrency, idempotency, pagination, status
writes, and deprecation are executable rather than prose-only conventions.

The API uses:

- `application/json` for successful request and response bodies;
- `application/problem+json` and
  [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html) for errors;
- lower camel case field names;
- UTC RFC 3339 timestamps with exactly millisecond precision;
- strong `ETag` response validators and required `If-Match` mutation
  preconditions;
- `Idempotency-Key` on every mutation;
- opaque, authenticated keyset pagination tokens;
- `Veer-Request-Id` as the bounded correlation header; and
- `Deprecation`, `Sunset`, and `Link` response fields for deprecated
  operations.

OpenAPI 3.2.0 is the latest published feature line as of this decision, but
3.1.2 is selected for the alpha. OpenAPI patch releases do not change the
minor-version feature set, and current Go generation tooling first provides
supported 3.1 behavior in
[`oapi-codegen` v2.8.0](https://github.com/oapi-codegen/oapi-codegen/releases/tag/v2.8.0).
Veer does not adopt a 3.2-only feature before its selected generator and
request-validation path support it. This issue does not introduce generated
runtime types; the first issue that does must pin its generator and runtime
dependencies and prove deterministic regeneration.

## Decision boundary

This decision specifies a transport contract. It does not claim that the
routes are running, that bearer-token validation exists, or that the
representative Workspace schema is the complete common resource
implementation.

- Issue [#17](https://github.com/ArdurAI/veer/issues/17) implements the common
  resource envelope, stable identity, serialization, and property tests.
- Issue [#20](https://github.com/ArdurAI/veer/issues/20) implements ordered
  validation, defaulting, immutable-field checks, references, and conversion.
- Issue [#22](https://github.com/ArdurAI/veer/issues/22) implements OIDC
  authentication and principal normalization.
- Issues [#23](https://github.com/ArdurAI/veer/issues/23) and
  [#24](https://github.com/ArdurAI/veer/issues/24) implement scoped
  authorization and policy decisions.
- Issues [#26](https://github.com/ArdurAI/veer/issues/26) and
  [#30](https://github.com/ArdurAI/veer/issues/30) implement persistence,
  idempotency, integrity, audit, and outbox transactions.

Generated transport values never become domain values. HTTP parsing,
representation, authentication middleware, and request validation remain in
the HTTP adapter. Core services receive explicit principal, command,
precondition, and idempotency values and return typed domain outcomes.

## Version and route model

The transport version appears once in the route prefix and once in resource
`apiVersion`:

```text
/api/v1alpha1/workspaces
/api/v1alpha1/workspaces/{workspaceId}
/api/v1alpha1/workspaces/{workspaceId}/status
/api/v1alpha1/operations/{operationId}
```

Resource names are plural nouns. Stable opaque identifiers are path segments;
display names never identify a resource and remain mutable. Nested routes are
used only when the parent is a real authorization or lifecycle boundary, not
to mirror storage joins.

Within one route version, Veer may add an optional request field, response
field, enum value with a documented unknown-value behavior, operation, or
problem type. It may not remove or rename a field, make an optional field
required, narrow an accepted value, change a field's meaning, change a status
code's retry class, or weaken a security precondition. Those are breaking
changes and require a new route version.

The `v1alpha1` label communicates prerelease maturity; it is not permission to
change an existing checked-in contract without a new version and migration
path. The repository may publish a newer alpha route while the old route
remains available through its stated sunset.

## Methods and successful writes

| Method | Contract |
| --- | --- |
| `GET` | Safe read. It has no idempotency or concurrency precondition header. |
| `POST` | Create or action. `Idempotency-Key` is required. |
| `PUT` | Complete replacement of the addressed writable subresource. `Idempotency-Key` and, except for create-by-name patterns, `If-Match` are required. |
| `PATCH` | Reserved for a future explicitly selected patch format. It is not accepted merely because an HTTP library supports it. |
| `DELETE` | Accept deletion intent. `Idempotency-Key` and `If-Match` are required. |

An accepted desired-state mutation returns `202 Accepted` with a bounded
receipt and relative operation `Location`. It means the desired state,
generation, idempotency result, integrity anchor, required audit data, and
outbox work committed atomically. It does not mean provider convergence or
deletion is complete. Synchronous status-only persistence returns `200` with a
bounded receipt and ETag. The receipt contains only resource identity, observed
generation, resource version, and update time; the caller reads the point
resource when it needs the full representation.

The accepted-mutation response binds `Location` to the receipt's `operationId`:
the header value is `/api/v1alpha1/operations/<operationId>`. This relationship
is declared by `x-veer-location-operation-id-pointer` so adapters and
conformance tests do not validate the header and body independently.

Only `application/json` is accepted for a request body. Missing or mismatched
`Content-Type` returns `415`. The maximum encoded request body, individual read
representation, or response page is 262,144 bytes. A collection page stops
before adding an item that would exceed the byte ceiling, even when fewer than
100 items have been selected. A write whose resulting canonical Workspace
representation cannot fit the same ceiling is rejected before commit. Non-read
receipts, status summaries, and problem bodies are capped at 1,024 bytes as established by
[ADR 0001](0001-alpha-operational-bounds.md). Oversized input is rejected
before JSON decoding, authentication-dependent allocation, persistence, or
audit payload construction.

## Representation rules

### Field names and timestamps

JSON field names use lower camel case. Acronyms are treated as words:
`apiVersion`, `resourceVersion`, and `requestId`, not `APIVersion`,
`resource_version`, or `requestID`.

Persisted and returned timestamps are UTC RFC 3339 strings with exactly three
fractional digits and a terminal `Z`, for example `2026-09-01T21:00:00.000Z`.
Clients may not depend on sub-millisecond precision. A timestamp with an
offset, missing fraction, leap-second value, or excess precision is rejected
where a client supplies it. Calendar validity is asserted in the schema
pattern, including Gregorian leap-year rules, and implementations also parse
the value before accepting it. The server compares parsed instants, never raw
timestamp text.

### Unknown fields

The server rejects an unknown request field at every declared object boundary
with `400 validation-failed` and an RFC 6901 JSON Pointer. This prevents a
misspelling or version mismatch from becoming silently ignored intent.
Free-form objects exist only where the schema opts in with a bounded value
schema, property count, key grammar, and size limit; `metadata.labels` is the
only such object in the baseline. The semantic verifier recognizes
`x-veer-free-form-map` only at the canonical `Labels` schema path; copying the
marker and schema-valued `additionalProperties` to any other object is rejected.

Clients must ignore an unknown response field while preserving every field
they forward without interpretation. A client that reads and writes a resource
must construct a declared write schema rather than round-trip the complete
read representation. The server still publishes a closed schema for each
exact contract revision so conformance tests detect an undocumented response
addition.

Server-owned fields are absent from write schemas or marked read-only in read
schemas. A client cannot set `id`, `generation`, `resourceVersion`, creation or
update timestamps, or status through a desired-state write.

Every schema value declared as `int64` also carries the explicit signed
64-bit maximum `9223372036854775807`; the format annotation alone does not
constrain JSON Schema validators.

## Generation, status, and resource version

`generation` and `resourceVersion` serve different consistency questions.

| Value | Meaning | Change rule | Client behavior |
| --- | --- | --- | --- |
| `generation` | Desired-spec revision for reconciliation | Starts at 1 and advances exactly once when the defaulted canonical spec changes semantically | Compare with `status.observedGeneration`; never use as an HTTP precondition |
| `resourceVersion` | Opaque revision of the complete observable resource | Changes on every persisted spec, metadata, status, lifecycle, or deletion write | Treat as opaque; use only through the returned strong ETag and `If-Match` |

A metadata-only write, status-only write, or exact idempotent replay does not
advance generation. A status write advances resourceVersion, carries its
observed generation, and cannot modify spec or metadata. A desired-spec change
racing a status write changes the ETag; the stale status writer receives `412`
and must reload, confirm its observed generation is still current, and retry
through the same bounded status schema.

Every point-resource `GET` and successful status response returns a strong
`ETag` containing the opaque resource version. Replacement, status, and delete
requests require that exact value in `If-Match`:

- missing `If-Match` returns `428 Precondition Required`;
- a syntactically invalid or weak validator returns `400`;
- a well-formed stale validator returns `412 Precondition Failed` and the
  current ETag when disclosure is authorized; and
- a current validator proceeds to authorization, admission, and the atomic
  store predicate.

Responses with both ETag and a resource version declare
`x-veer-etag-resource-version-pointer`. The adapter reads that JSON Pointer and
emits the body value wrapped as a strong quoted ETag. For a Workspace the
pointer is `/metadata/resourceVersion`; for operation and status receipts it is
`/resourceVersion`.

This follows the lost-update purpose of
[RFC 6585 section 3](https://www.rfc-editor.org/rfc/rfc6585.html#section-3)
and the conditional request semantics in
[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html). `409 Conflict` is not
used for a stale ETag; it remains available for a uniqueness, lifecycle,
policy, or idempotency-fingerprint conflict.

## Idempotency

Every `POST`, `PUT`, `PATCH`, and `DELETE` request requires an
`Idempotency-Key` between 16 and 128 visible characters from the checked-in
grammar. A key is untrusted input, not a credential or a place for personal
data. Raw keys are not log fields or metric dimensions; operational output
uses a bounded digest or the request ID.

The key is scoped to authenticated principal, HTTP method, and canonical
target. After request-size, media-type, authentication, authorization,
precondition syntax, schema, and semantic validation pass, Veer computes a
fingerprint over that scope plus canonical query and defaulted canonical body.
The transaction then:

1. reserves or loads the scoped key and fingerprint;
2. rejects the same key with a different fingerprint as
   `409 idempotency-key-reused`;
3. atomically commits the accepted mutation and its replayable response status,
   operation-semantic headers, and body; or
4. returns that stored semantic result for a matching replay without another
   generation, audit event, outbox record, queue claim, or provider attempt,
   while generating or echoing the current retry's `Veer-Request-Id`.

Request correlation is never replayed from the original attempt. It is not
part of the idempotency scope or fingerprint, and each retry's response, logs,
and traces use that retry's validated or server-generated request ID.

An outcome that failed before the idempotency transaction began is not cached.
An uncertain commit result must resolve the durable idempotency row before a
retry can execute. A record is retained for at least 24 hours; after expiry a
caller cannot rely on replay safety. Storage and lookup remain bounded by the
same principal and capacity admission limits as mutations.

The name and fault-tolerance intent align with the IETF HTTPAPI working-group
[`Idempotency-Key` draft](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/),
but that document is an expired Internet-Draft as of this decision, not an
Internet Standard. Veer's behavior above is therefore the controlling
contract. A future RFC requires a compatibility review rather than silently
changing this route version.

## Pagination

Collection reads use keyset pagination. `pageSize` defaults to 50 and is
bounded to 1 through 100. Results are ordered ascending by `(createdAt, id)`;
the stable ID breaks timestamp ties. Offset pagination is not exposed. The
count limit is secondary to the 262,144-byte encoded-page limit: page assembly
stops before the first item that would cross either limit and returns the
continuation token for that unconsumed item.

`nextPageToken` is an opaque, authenticated, URL-safe value no larger than
1,024 bytes. Before use, the server bounds its size and decoding work. Its
authenticated claims bind the principal, workspace scope, route, normalized
filter, ordering, last key, issue time, and 900-second expiry. A token cannot
be replayed across callers, scopes, routes, filters, or sort orders. Token
verification keys are versioned and rotated without making an expired token
valid again. Claims contain no credential, personal data, desired state, or
provider response body; encryption is additionally required if a selected
claim would disclose non-public topology.

A page sequence is deliberately not a database snapshot. Each request
reauthorizes and reads current state. Concurrent insertion or deletion may
change a later page, but a valid unchanged token and unchanged collection do
not duplicate or reorder items. Clients that require a historical snapshot
must use a future explicit export or audit API with its own retention and cost
contract.

## Errors and correlation

All error bodies use `application/problem+json`. The five RFC 9457 members are
used as follows:

- `type` is a stable `urn:veer:problem:<code>` identifier;
- `title` is a stable short summary fixed by the response-specific type;
- `status` repeats the HTTP status;
- `detail`, when present, is a bounded safe explanation for this occurrence;
  and
- `instance` is `urn:veer:request:<requestId>`, not the request path or a
  provider identifier.

Veer extensions are `code`, `requestId`, optional bounded `errors`, and
optional `retryAfterSeconds`. Field errors contain an RFC 6901 JSON Pointer,
stable code, and safe message. Raw tokens, credentials, SQL, stack traces,
provider bodies, connection strings, internal hostnames, and cross-workspace
identifiers are forbidden.

Field pointers accept arbitrary RFC 6901 member names, including spaces and
Unicode, while requiring `~0` and `~1` escapes for literal tilde and slash. A
pointer is capped at 96 code points and its encoded JSON string, including
quotes and escape expansion, is capped at 98 bytes. The server omits the
optional field violation if the exact pointer cannot fit that byte budget.

A problem response contains at most one field violation. Its pointer, code,
and message are capped at 96, 32, and 96 characters respectively; the
top-level title and detail are capped at 64 and 192 characters. Human-readable
diagnostic text uses a non-escaping printable-ASCII subset: control characters,
Unicode, quotes, reverse solidus, and the HTML-sensitive `&`, `<`, and `>` are
excluded. These grammar and length bounds keep the maximal declared envelope
within the 1,024-byte encoded response ceiling. Implementations still enforce
the encoded-byte limit after serialization and omit optional field violations
and detail before exceeding it.

Each reusable error response references a response-specific schema that fixes
`type`, HTTP `status`, and stable `code` with constants. This prevents a valid
generic Problem body from carrying a status or code that contradicts its HTTP
response component.

The shared `409 Conflict` response is a closed `oneOf` over four stable
identities: `idempotency-key-reused`, `uniqueness-conflict`,
`lifecycle-conflict`, and `policy-conflict`. The first covers a scoped key used
with different normalized intent; the other three cover current uniqueness,
lifecycle-transition, or policy-state invariants. Authentication and
authorization failures remain `401` and `403`, not policy conflicts.

The baseline includes validated examples for every issue-required class:

| Class | Status | Stable example code | Retry behavior |
| --- | ---: | --- | --- |
| Validation | `400` | `validation-failed` | Correct the request; no mutation occurred |
| Authentication | `401` | `authentication-required` | Obtain valid credentials; includes a bounded Bearer challenge with no error description or token material |
| Authorization | `403` | `authorization-denied` | Do not retry unchanged; cross-scope existence may instead be concealed as `404` |
| Conflict | `409` | `idempotency-key-reused` | Use the original request or a new key after resolving intent |
| Throttling | `429` | `rate-limited` | Honor bounded `Retry-After`, add jitter, and retain an overall deadline |
| Internal failure | `500` | `internal-failure` | Retry only when the operation is safe or protected by the same idempotency key |

`503` represents a system-wide admission, safety, or availability boundary and
also carries `Retry-After`. A server under resource-exhaustion attack may drop
work before constructing a problem body; RFC 6585 does not require a `429`
response when doing so would amplify the attack.

The `rate-limited` and `unavailable` problem refinements require
`retryAfterSeconds` between 1 and 86,400. Their response components declare
`x-veer-retry-after-body-pointer: /retryAfterSeconds`; the decimal Retry-After
header and body integer therefore carry the same bounded delay.

`Veer-Request-Id` is optional on requests, validated before use, at most 64
characters, and echoed on every response. The server generates a value when it
is absent. It is safe for bounded logs and traces but remains untrusted text;
it never grants identity, authorization, idempotency, or resource ownership.
Workspace, resource, actor, provider object, and request IDs are forbidden as
metric labels under the existing cardinality contract.

Every Problem requires both `requestId` and `instance`. The Problem-level
`x-veer-instance-request-id-template` fixes `instance` to
`urn:veer:request:{requestId}`, and every error response's
`x-veer-request-id-body-pointer` binds its `Veer-Request-Id` header to the body
`/requestId`. These relations make all three correlation surfaces identical.

Because OpenAPI response Header Objects do not have a native `required` flag,
Veer response components carry `x-veer-required-headers` as an executable
generator convention. `Veer-Request-Id` is always required; ETag, Location,
authentication challenge, and retry headers are required on their declared
responses. Successful responses additionally carry
`x-veer-required-header-sets`: when an operation is deprecated, `Deprecation`,
`Sunset`, and `Link` are emitted together as one conditional set. The pointer
and template extensions above define value equality after presence is known;
generated adapters fail closed if a declared pointer cannot be resolved.

## Deprecation and removal

A deprecated operation or representation returns all of:

- `Deprecation`, using the structured-field date defined by
  [RFC 9745](https://www.rfc-editor.org/rfc/rfc9745.html);
- `Sunset`, using the HTTP date defined by
  [RFC 8594](https://www.rfc-editor.org/rfc/rfc8594.html); and
- `Link` with `rel="deprecation"` to migration documentation and, when
  applicable, a sunset link.

`Sunset` is emitted only as an IMF-fixdate in GMT. Implementations parse and
round-trip the value before sending or accepting it so impossible calendar
dates, invalid clock fields, and a weekday that disagrees with the date are
rejected.

The deprecation date is no later than the first production response carrying
the deprecated behavior. Sunset is at least 90 days later. Removal cannot
occur before that date, and a breaking replacement uses a new route version.
The migration document identifies the replacement, behavioral differences,
client action, and last supported date. The headers are response metadata,
not an authorization or cache invalidation mechanism. The conditional trio is
encoded in each successful response component through
`x-veer-required-header-sets` so generated adapters cannot emit only part of
the lifecycle signal.

Security remediation may disable an unsafe operation sooner only when the
maintainers record the threat, blast radius, compensating behavior, customer
communication, and recovery path in a new decision. A security exception does
not authorize an undocumented incompatible schema change.

## Validation and generation contract

[`./hack/dev api`](../../hack/dev) performs two offline checks:

1. checksum-pinned Vacuum `0.30.1` parses and validates the OpenAPI 3.1.2
   document with remote references, update checks, plain HTTP, private-network
   access, and insecure TLS disabled; and
2. Go standard-library tests validate Veer's exact semantics and negative
   mutations.

The semantic verifier rejects:

- duplicate JSON keys, trailing documents, files above 1 MiB, nesting above
  64 levels, more than 50,000 JSON nodes, and more than 2,048 references;
- external or malformed `$ref` values;
- unversioned paths, anonymous root or operation security, duplicate operation
  IDs, unselected methods, server overrides, callbacks, or webhooks;
- mutation routes without idempotency, required ETag preconditions, an exact
  request schema, or their reviewed success response;
- request media type, response-specific problem status/code and conflict
  variants, problem correlation, mandatory header metadata, header/body
  bindings, shared response-header or example references, complete resource,
  status, receipt, and operation shapes, generation, resource-version,
  byte-bounded pagination, or deprecation drift;
- an object schema that silently accepts unknown properties; and
- missing or inconsistent validation, authentication, authorization,
  conflict, throttling, or internal-failure examples.

Future code generation uses only this reviewed document and a pinned
repository-local generator. Generated output is deterministic, formatted, and
either checked in with a regeneration diff gate or reproduced during the
build from already verified inputs. Generation may create transport structs
and `net/http` adapter interfaces; it may not generate or overwrite core
domain, persistence, policy, migration, or provider types.

## Security, observability, and cost effects

- Authentication is required by default in the contract. An anonymous route
  must override security explicitly and receive a separate threat and abuse
  review.
- Status writes are a distinct controller-authorized action and cannot carry
  desired spec or writable metadata.
- Conditional writes prevent lost updates but do not replace store
  serialization, workspace predicates, generation fences, current
  authorization, or provider ownership proofs.
- Strict request fields prevent ignored intent. Bounded problem details and
  correlation prevent raw upstream or secret-bearing data from becoming a
  response, log, trace, audit field, or metric label.
- Page size, body size, token lifetime, JSON traversal, response size, and
  retry headers are bounded. These limits constrain database work, memory,
  egress, log volume, and client retry amplification.
- Validation and contract tests make no network call and need no cloud
  credential or paid service. The only added local/CI artifact is the pinned
  validator downloaded during bootstrap.
- This decision adds no runtime service and no continuously billed resource to
  the cost worksheet. Runtime rate limiting, token signing, persistence,
  tracing, and ingress costs remain owned by their implementation issues and
  ADR 0001's existing envelopes.

## Alternatives considered

### OpenAPI 3.2.0 immediately

Rejected for the alpha baseline. It is the newest specification line, but Veer
does not need a 3.2-only feature and selecting it would narrow currently
supported Go generation paths. The contract can move through a reviewed new
route or tooling decision once end-to-end support is qualified.

### OpenAPI 3.0.x

Rejected. It has broader historical tooling support but lacks the full JSON
Schema 2020-12 alignment available in 3.1, which Veer uses for strict null,
constant, and schema semantics.

### Vendor media-type versioning

Rejected for the alpha. Combining URL and media-type versions creates two
independent negotiation dimensions and more cache, documentation, and support
states. URL versioning plus standard JSON and problem media types is explicit
for CLI, GitOps, and browser-independent clients.

### Offset pagination

Rejected. Large offsets make database work grow with page depth and concurrent
changes produce unstable pages. Bounded keyset tokens keep query work and
ordering explicit without promising a long-lived snapshot.

### `409` for every concurrency failure

Rejected. `428` and `412` preserve standard conditional-request meaning, while
`409` identifies a domain or idempotency conflict that a fresh representation
alone may not resolve.

### Accept unknown request fields

Rejected. Forward compatibility does not justify silently ignoring desired
state. A new client must select a route version whose declared fields the
server understands.

## Primary references

- [OpenAPI Specification 3.1.2](https://spec.openapis.org/oas/v3.1.2.html)
- [OpenAPI schema and dialect iterations](https://spec.openapis.org/oas/)
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
- [RFC 6585: Additional HTTP Status Codes](https://www.rfc-editor.org/rfc/rfc6585.html)
- [RFC 9457: Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457.html)
- [RFC 9745: The Deprecation HTTP Response Header Field](https://www.rfc-editor.org/rfc/rfc9745.html)
- [RFC 8594: The Sunset HTTP Header Field](https://www.rfc-editor.org/rfc/rfc8594.html)
- [RFC 8288: Web Linking](https://www.rfc-editor.org/rfc/rfc8288.html)
- [RFC 3339: Date and Time on the Internet](https://www.rfc-editor.org/rfc/rfc3339.html)
- [Expired IETF HTTPAPI Idempotency-Key draft](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/)
- [Vacuum v0.30.1 release](https://github.com/daveshanley/vacuum/releases/tag/v0.30.1)
- [`oapi-codegen` v2.8.0 release](https://github.com/oapi-codegen/oapi-codegen/releases/tag/v2.8.0)
