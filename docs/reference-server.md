# In-memory reference server

Veer's first executable control-plane slice is the loopback-only
`veer-reference-server`. It is a deterministic contract and authorization
harness for issues #21 and #24, not the production `veer-api` service.

## Proven boundary

The reference service implements create, get, replace, status replace, list,
and RESTRICT delete semantics for all six resource kinds:

- Workspace;
- Policy;
- Environment;
- ProviderConnection;
- Application; and
- Component.

Service tests cover valid and invalid hierarchy placement, generation and
resource-version changes, stale writes, keyed replays, idempotency conflicts,
concurrent writes, exact label filtering, stable `(createdAt, id)` ordering,
and opaque authenticated keyset pagination. The HTTP adapter exposes only the
four paths and seven operations already published in
[`veer-v1alpha1.json`](../api/openapi/veer-v1alpha1.json). Child-resource route
topology remains intentionally unselected.

The command opens a real `net/http` listener and handles interrupt-driven
graceful shutdown. It accepts only a literal IPv4 or IPv6 loopback address,
uses bounded header and connection timeouts, and requires a bearer credential
from a regular non-symlink token file with no group or world permissions.
Bearer syntax is parsed by Veer's fuzz-tested HTTP boundary; the reference
adapter reduces the configured credential to a per-process, randomly keyed
HMAC-SHA-256 digest immediately and compares fixed-size digests.

Before listening, the command creates one process-local Workspace, private
Human member directory, and WorkspaceAdministrator Policy. The HTTP handler is
bound to the policy-enforcing runtime rather than the raw lifecycle service.
That runtime reloads retained hierarchy and Policy resources, evaluates a
sealed target for get/replace/delete and Operation get, and evaluates every
retained list row before it can influence page size or a cursor. Workspace
create and status replacement remain reserved and return `403` without a
resource or Operation mutation.

Accepted mutations retain a bounded process-local admission record. Plan
construction replaces caller-supplied actor, decision, and Operation fields
with that record and current retained Operation. Immediately before a
process-local execution callback, the runtime reloads current membership,
PolicySet, and Operation, then requires exact actor, policy-version, and
authorization-input bindings. Non-delete execution also reloads the current
resource generation. Delete replay and execution use only the server-sealed
pre-delete targets retained with the admission because the resource has
already been tombstoned. Revocation, policy drift, or applicable generation
drift prevents the callback. Expired idempotency epochs replace their prior
admission instead of leaving the new Operation unplannable. This is executable
reference evidence, not a queue, worker, provider adapter, production OIDC
path, or cross-process authorization guarantee.

## Run locally

Create an ignored token file without putting the token in a command argument
or committed file:

```sh
umask 077
mkdir -p .tools
openssl rand -hex 32 > .tools/reference-token

go run ./cmd/veer-reference-server \
  --listen 127.0.0.1:8080 \
  --token-file .tools/reference-token
```

The token must use Veer's bounded RFC 6750 bearer-token character envelope.
The process logs only its loopback listener address. It never logs the token.
Send `SIGINT` or `SIGTERM` to drain and stop the listener.

## Evidence

Run the focused evidence set with:

```sh
go test ./internal/core/service/reference \
  ./internal/core/service/referenceauthorization \
  ./internal/adapters/store/memory \
  ./internal/adapters/referenceaccess \
  ./internal/transport/http \
  ./cmd/veer-reference-server \
  ./test/contract

go test -race ./internal/core/service/reference \
  ./internal/core/service/referenceauthorization \
  ./internal/adapters/store/memory \
  ./internal/adapters/referenceaccess \
  ./internal/transport/http \
  ./cmd/veer-reference-server \
  ./test/contract
```

The contract test validates the checked-in OpenAPI document, records its
SHA-256 digest, exercises deterministic black-box HTTP vectors, proves zero
database, queue, and provider calls, and compares the complete report with
[`reference-server-v1alpha1.golden.json`](../test/contract/testdata/reference-server-v1alpha1.golden.json).
The command test uses a real ephemeral TCP listener and proves authentication,
policy-filtered request handling, reserved-action denial, and graceful
shutdown. Authorization tests prove denied-mutation atomicity, per-row list
filtering, actor/decision Plan binding, policy drift, generation drift,
admission/revocation races, and effect/revocation exclusion.

## Explicit limitations

- State, replay results, Operations, and page-token state disappear on process
  restart. There is no database durability, rollback recovery, or cross-process
  concurrency guarantee.
- A successful mutation receipt proves reference-service acceptance only. It
  does not prove the atomic state, audit, integrity, and outbox transaction
  required for a production `202` response.
- The command is loopback-only and does not terminate TLS. Exposing it through
  a proxy, container port, tunnel, or public listener is unsupported.
- The bearer adapter is a fixed local verifier, not OIDC. The preseeded private
  member directory is process-local configuration rather than a membership
  API or durable identity store. Removing a member makes its retained Policy
  bindings inactive; new Policy writes still require every referenced member
  to exist.
- The execution callback serializes only this process's configured membership,
  policy mutations, and effect. It is not a distributed transaction or proof
  that an external provider call can be cancelled after dispatch.
- There is no provider execution, queue, worker, audit sink, telemetry export,
  persistent secret, cloud resource, or paid API call.

The local cost is bounded to one process's CPU and memory plus loopback I/O.
The copy-on-write store favors deterministic reviewability over performance;
it is not a capacity or production-cost model.
