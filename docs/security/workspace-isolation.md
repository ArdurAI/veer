# Workspace isolation evidence

Veer's process-local reference runtime treats production Workspaces as
mutually distrustful. Every tenant-owned read or write carries a stable opaque
Workspace ID; mutable display names are never accepted by the isolation,
storage, authorization, plan, audit, queue/worker, or provider-binding
contracts.

This document is the issue #26 isolation matrix. It records executable contract
evidence, not a claim that the deferred PostgreSQL, distributed worker, or
provider adapters already exist.

## Invariants

1. A missing or malformed scope fails before a store callback can observe or
   mutate state.
2. A mutation callback is bound to exactly one Workspace partition.
3. A read callback sees only an explicit, non-empty canonical scope set.
4. Canonical resources and Operations must carry the same Workspace ID as the
   partition from which they were loaded.
5. Root listing can cross Workspaces only through the runtime's explicit set of
   configured member directories. Child listing accepts exactly one scope.
6. Page tokens bind the canonical scope-set digest; a token cannot be replayed
   after widening or narrowing scope.
7. Queue data, Plans, audit references, and provider credential requests carry
   stable IDs and reject mismatched bindings. None of those artifacts grants
   execution authority.

## Isolation matrix

| Surface | Stable scope boundary | Negative evidence | Deferred production proof |
| --- | --- | --- | --- |
| Scope construction | `isolation.WorkspaceScope` and `WorkspaceScopeSet`; zero values are invalid | `TestWorkspaceScopeRejectsMissingAndMalformedIDs`; `TestWorkspaceScopeSetIsCanonicalAndOwnershipSafe` | None; this is the core value contract |
| Reference storage | `ReferenceStore.Update` requires one scope; `View` requires a non-empty scope set; memory state is partitioned by Workspace | `TestWorkspaceScopesFailClosedAndCannotCrossRead` proves callbacks are not invoked without scope, same resource IDs remain isolated, and a multi-scope identity collision fails closed | Composite foreign keys, query builders, runtime/database roles, forced RLS, and migration checks in issue #30 |
| CRUD and Operation reads | Create derives the root scope from the issued Workspace ID; addressed mutations and point reads require an explicit Workspace ID; loaded canonical ownership is rechecked | `TestWorkspaceScopeIsMandatoryAcrossCRUDListsAndOperations` rejects cross-scope get, replace, status replace, delete, Operation get, and foreign-parent create without changing the target | Durable transactions and tombstones in issue #30 |
| Lists and cursors | Workspace roots require an explicit scope set; child kinds require one scope; cursors bind a canonical scope digest | `TestWorkspaceScopeIsMandatoryAcrossCRUDListsAndOperations` rejects missing/duplicate scope and narrowed-scope token replay; `TestListFiltersUnauthorizedRowsBeforePagination` excludes an unconfigured Workspace before page shaping | Indexed durable pagination and query plans in issue #30 |
| Authorization | Policy targets resolve from stable hierarchy IDs and exact member directories; there is no display-name lookup | `TestEvaluateDefaultDenyScopeAndOrthogonalRoles`; `TestWorkspaceScopeRejectsMissingAndMalformedIDs`; the CRUD isolation test uses identical display names in two Workspaces | Durable membership and policy storage in issues #30 and #87 |
| Plans | `Plan` copies Workspace, resource, generation, Operation, decision, and provider bindings into its validated digest | `TestSameGenerationReplanRequiresDefinitiveAttemptsAndExactCarryForward` rejects prior attempts from another Plan/Workspace; `TestPlanBindsAdmissionAndExecutionRejectsPolicyDriftAndRevocation` reloads current scoped state | Executable step construction in issue #33 |
| Queue and worker authority | Work, lease, effect, attempt, and dispatch values are derived from one validated Plan and carry or digest its stable lineage | `TestDeliveryRequiresWorkAndLeaseFromTheSamePlan`; `TestAttemptPreparationDispatchAndOwnerLossAreFailClosed`; `TestDuplicateDeliveryNeverCreatesSecondAuthority` | Durable outbox/queue/worker implementations in issues #30, #31, and #32 |
| Audit | Workspace streams and every referenced target/Operation/elevation must agree on the stable Workspace ID | `TestProviderAttemptRequiresMatchingWorkspaceStream`; `TestOperationRequiresMatchingWorkspaceStream`; `TestReferenceStreamScopeIsExact`; `TestElevationCoReferencesMustMatchEverySharedScopeID` | Durable append-only sink and export controls in issues #30 and #88 |
| Provider adapter inputs | Credential requests seal Workspace, Environment, connection, target, Operation, action, and recipient bindings | `TestNewRequestRejectsUnsealedOrMismatchedInputs`; `TestValidateRequestRejectsEveryForgedBindingDimension`; `TestEveryBindingOnlyDimensionChangesOnlyBindingDigest` | Real broker/provider integration in issues #38, #39, #45, #52, and #87 |

The named tests live under `internal/` and run in the aggregate repository
checks. The reference HTTP contract is unchanged: child-resource routes remain
unselected, and the global Operation route performs bounded lookup by querying
each configured Workspace scope separately before authorization. No unscoped
storage view is exposed to that route.

## Residual risk and cost

The in-memory adapter holds one process-wide lock and copies one Workspace
partition per mutation. Explicit multi-Workspace root lists build a bounded
union under the same lock. This favors deterministic isolation evidence over
throughput; it does not establish production latency, memory, or database cost.

Issue #30 must preserve these fail-closed interfaces with parameterized scoped
queries, composite ownership constraints, a non-owner runtime role, forced RLS
as defense in depth, and atomic state/audit/outbox commits. Issues #31, #32,
and #33 must preserve the same stable scope through delivery and execution. Real
provider adapters remain blocked on their own dependency-ready issues.
