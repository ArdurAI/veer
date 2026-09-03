# ADR 0009: Deterministic hierarchical authorization

- Status: Accepted
- Date: 2026-09-03
- Owners: Veer maintainers
- Decision scope: Issue [#23](https://github.com/ArdurAI/veer/issues/23)

## Context

[ADR 0008](0008-oidc-authentication-and-principals.md) establishes an
authenticated Human or Workload principal but grants it no membership, role,
or action. Veer also has a stable, server-derived Workspace and Environment
hierarchy. Authorization must join those facts without trusting display names,
caller-asserted ownership, a queue delivery, or provider-specific identity
claims.

The first-alpha contract needs one closed action vocabulary for planned API and
worker behavior, bounded Policy desired state, explicit role inheritance, and a
canonical decision that can be compared at request and execution time. The same
policy and normalized input must always produce the same result. Missing,
cross-Workspace, reserved, and insufficient authority must fail closed with
stable reasons.

## Decision

### Contract boundary

The version is `veer.authorization.v1alpha1`. The domain package owns the
executable reference evaluator, while the OpenAPI root
`x-veer-authorization` manifest projects the exact vocabulary and role matrix.
Each of the seven existing operations carries one scalar
`x-veer-authorization-action`. The OpenAPI document remains at four paths and
seven operations.

This is a pure reference contract, not runtime request enforcement. No API
server or worker currently invokes the evaluator. Route integration,
execution-time reauthorization, persistence, and audit emission remain work for
their owning issues. In particular, the documented `createWorkspace` operation
maps to `resource.create`, but Workspace creation is reserved and default
denied to every tenant role. Platform provisioning and bootstrap authority are
deferred to a separate governance decision.

### Membership, policy, and scopes

An authenticated principal is matched to a private Workspace member directory
by exact principal kind, issuer, and subject. Public Policy resources contain
only opaque `memberId` references; they never embed issuer, subject, group,
email, or workload claims.

`PolicySpec.bindings` is required, may be explicitly empty, and contains at
most 128 entries. Every entry has exactly `memberId`, `role`, and `scope`.
Bindings are unique and sorted lexicographically by this tuple:

```text
memberId, scope.kind, environmentId-or-empty, role
```

There are two scopes:

- `Workspace` omits `environmentId` and descends to the Workspace and all of
  its Environments.
- `Environment` requires a resolved Environment ID and descends only within
  that Environment.

Every referenced member and Environment must exist in the Policy's Workspace.
A resolved resource of the wrong kind is rejected. `WorkspaceAdministrator`
is valid only at Workspace scope and only for a Human member. Reference-stage
admission reports missing references as `reference-not-found` and wrong or
incompatible kinds as `reference-kind-mismatch`; neither is an `invalid-spec`
failure.

### Roles and inheritance

Inheritance is an explicit star, not a transitive job hierarchy. `Developer`,
`Operator`, and `WorkspaceAdministrator` each inherit `Viewer` and never inherit
one another.

| Role | Direct tenant grants |
| --- | --- |
| `Viewer` | List/get ordinary resources, plans, and operations; list permitted audit records |
| `Developer` | Create/replace/delete Applications and Components; preview their plans; cancel their operations |
| `Operator` | Create/replace/delete Environments and ProviderConnections; preview their plans; cancel or retry Environment, Application, Component, and ProviderConnection operations |
| `WorkspaceAdministrator` | List/get/create/replace/delete Policies; replace/delete the Workspace; list/get/preview Workspace and Policy plans; list/get/cancel Workspace and Policy operations; manage Workspace membership |

`membership.get` has one additional evaluator rule: a matched member may read
only its own membership object. That conditional rule is not published as an
unrestricted role grant.

### Complete action matrix

`ResourceKinds` below are hierarchy anchors. Empty means the object is
Workspace-scoped rather than anchored to a resource kind. All omitted role and
action combinations deny.

Every `*.list` action is defined as `per-retained-row` evaluation. A list
implementation must seal and evaluate each candidate retained row against that
row's Workspace policy state before including it in a response; a parent target
never authorizes its children, and an empty result does not create a synthetic
collection target. Pagination, filters, and counts cannot turn a denied row into
response data. Retained Plan, Operation, and resource-anchored Audit rows remain
unavailable until issue #24 adds their authoritative binding resolver.

| Actions | Object | Direct role and resource-kind grants |
| --- | --- | --- |
| `resource.list`, `resource.get` | `Resource` | Viewer: Application, Component, Environment, ProviderConnection, Workspace; WorkspaceAdministrator: Policy |
| `resource.create` | `Resource` | Developer: Application, Component; Operator: Environment, ProviderConnection; WorkspaceAdministrator: Policy; Workspace is reserved |
| `resource.replace`, `resource.delete` | `Resource` | Developer: Application, Component; Operator: Environment, ProviderConnection; WorkspaceAdministrator: Policy, Workspace |
| `resource.status.replace` | `Resource` | Reserved for controller authority |
| `plan.list`, `plan.get` | `Plan` | Viewer: Application, Component, Environment, ProviderConnection, Workspace; WorkspaceAdministrator: Policy, Workspace |
| `plan.preview` | `Plan` | Developer: Application, Component; Operator: Environment, ProviderConnection; WorkspaceAdministrator: Policy, Workspace |
| `operation.list`, `operation.get` | `Operation` | Viewer: Application, Component, Environment, ProviderConnection, Workspace; WorkspaceAdministrator: Policy, Workspace |
| `operation.cancel` | `Operation` | Developer: Application, Component; Operator: Application, Component, Environment, ProviderConnection; WorkspaceAdministrator: Policy, Workspace |
| `operation.retry` | `Operation` | Operator: Application, Component, Environment, ProviderConnection |
| `operation.quarantine` | `Operation` | Reserved for platform operations |
| `membership.list`, `membership.get`, `membership.create`, `membership.replace`, `membership.delete` | `Membership` | WorkspaceAdministrator: Workspace-wide; conditional self-only `membership.get` also applies |
| `audit.list` | `Audit` | Viewer: Application, Component, Environment, ProviderConnection, Workspace |
| `audit.export` | `Audit` | Reserved for privileged export workflows |
| `approval.approve`, `approval.reject`, `approval.override` | `Plan` | Reserved pending the approval decision |
| `work.publish`, `work.consume`, `work.redrive` | `Operation` | Reserved for narrow queue and operator identities |
| `reconcile.plan`, `reconcile.execute` | `Plan` | Reserved for narrow reconciler identities |
| `operation.transition` | `Operation` | Reserved for narrow worker identities |
| `credential.resolve` | `Resource` | Reserved for the credential broker |
| `provider.discover`, `provider.apply`, `provider.observe`, `provider.delete` | `Resource` | Reserved for provider adapters |
| `audit.append` | `Audit` | Reserved for append-only service identities |

The current transport projection is exact:

| Operation ID | Action | Tenant result under this matrix |
| --- | --- | --- |
| `listWorkspaces` | `resource.list` | Requires a matching scoped Viewer grant |
| `createWorkspace` | `resource.create` | Default denied; Workspace bootstrap is reserved |
| `getWorkspace` | `resource.get` | Requires a matching scoped Viewer grant |
| `replaceWorkspace` | `resource.replace` | Requires WorkspaceAdministrator |
| `deleteWorkspace` | `resource.delete` | Requires WorkspaceAdministrator |
| `replaceWorkspaceStatus` | `resource.status.replace` | Reserved for controller authority |
| `getOperation` | `operation.get` | Requires a matching scoped Viewer grant |

### Evaluation and canonical decisions

Evaluation accepts only a validated principal, a registered action, and a
hierarchy-sealed target. Public resolvers currently seal retained hierarchy
resources, server-derived create placements, and Workspace-scoped Membership or
Audit objects; callers cannot assert their Workspace or Environment ownership.
No public resolver for a retained Plan, Operation, or resource-anchored Audit
exists in this issue because a hierarchy snapshot cannot prove the separate
object-ID-to-resource binding. Those action-matrix entries remain fail closed.
Issue #24 must load the object by ID from authoritative persistence, derive its
immutable binding, and add the corresponding target-construction boundary before
runtime enforcement.

The immutable PolicySet binds the member directory and at most 2,500 ordered
Policy revisions, each with a desired-state generation. Its domain-separated
SHA-256 policy version uses the `azv1_` prefix. The input digest covers every
normalized principal field, action, and sealed target field and uses the
`azi1_` prefix. Exact identity claims are hashed into these digests but are not
exposed by them.

Decision precedence is fixed:

1. `CrossWorkspace`
2. `ReservedAction`
3. `NoMembership`
4. `NoRoleBinding`
5. `ScopeNotGranted`
6. `ActionNotGranted`
7. `RoleGranted`

The default effect is `Deny`; `Allow` is produced only by an exact grant or the
self-membership rule. A canonical decision contains exactly
`contractVersion`, `policyVersion`, `inputDigest`, `effect`, and `reason`, and
is capped at 1,024 encoded bytes. It contains no principal, member, target,
policy document, or arbitrary message. Identical normalized input and PolicySet
versions therefore produce byte-identical decisions.

### Bounds, signals, and operating cost

One Workspace has at most 500 members and 2,500 Policy resources; one Policy
has at most 128 bindings. Collections are copied, validated, sorted, or compiled
under those bounds. Evaluation is local and deterministic: it performs no
network request, provider call, database query, or paid service operation.

Future integration may count decisions by closed action, effect, and reason and
may correlate the bounded version/digest values. It must not put raw principal
claims, member IDs, target IDs, bearer credentials, or Policy documents in
logs, metrics, or traces. Such telemetry and route wiring are not implemented
by this decision.

## Consequences

- Default denial, explicit reservations, sealed targets, and exact membership
  matching prevent a caller from widening authority with names or asserted
  ownership.
- The fixed action and role registries make policy behavior reviewable and
  deterministic, at the cost of requiring a contract-version change for new
  semantics.
- Workspace-level grants intentionally descend into Environments. Operators
  must use Environment scopes when a grant must not cross Environment bounds.
- Workspace administration does not imply platform, worker, credential-broker,
  provider-adapter, approval, export, or redrive authority.
- An empty Policy binding set is valid and denies every otherwise valid tenant
  action except an exact self-membership read. A missing binding collection is
  invalid input.
- The OpenAPI projection documents required authorization but cannot be treated
  as evidence that an HTTP route or worker enforces it.

## Rejected alternatives

- Caller-supplied Workspace or Environment scope: ownership is resolved from
  the hierarchy instead.
- Display-name, email, group, or provider-role authorization: none is a stable
  Veer membership key.
- Transitive job-role inheritance: each non-Viewer role inherits Viewer only.
- Tenant-granted worker or controller actions: those actions remain reserved
  for separately authenticated service or privileged operational identities.
- An implicit first-user Workspace owner: Workspace provisioning remains
  default denied until platform governance defines a bootstrap authority.

## Verification

- Domain golden and negative tests cover deterministic decisions,
  cross-Workspace denial, reserved actions, role escalation, exact membership,
  scope descent, policy ordering, size bounds, and canonical serialization.
- OpenAPI tests bind the manifest vocabulary and role matrix to the exported
  domain registries, bind all seven operation annotations, and compare policy
  fixtures with `ValidatePolicySpec`.
- The pinned OpenAPI validator checks valid and expected-failure PolicySpec
  schema instances, including empty default-deny policy, scope shape, unknown
  role, duplicate entry, and undeclared identity claim cases.
- Ordinary local evidence is `go test ./api/openapi` and `./hack/dev api`; the
  complete repository gate remains `./hack/dev check`.
