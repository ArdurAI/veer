# Roadmap

Veer's roadmap is organized around verifiable engineering boundaries rather
than calendar promises.

## Foundation

- Select the open-source license and contribution model.
- Record architecture decisions and API evolution rules.
- Establish formatting, linting, unit-test, security-scan, and release checks.
- Define the threat model and supported deployment boundary.

Exit criterion: contributors can build, test, and review the repository from a
clean checkout with no private services or credentials.

## Resource model

- Define versioned schemas for Workspace, Environment, Application, Component,
  Policy, ProviderConnection, Operation, and Condition.
- Implement validation, defaulting, identity, generations, and status.
- Build an in-memory reference server and contract-test harness.

Exit criterion: resource lifecycle semantics are deterministic and covered by
tests without calling a cloud provider.

## Reconciliation core

- Add durable desired-state and observed-state persistence.
- Implement queues, leases, idempotency, retries, cancellation, and deletion.
- Persist plans, policy decisions, conditions, and audit events.

Exit criterion: failure injection proves safe recovery from worker, queue, and
database interruptions.

## Kubernetes and AWS

- Implement provider identity and capability discovery.
- Add Kubernetes workload, service, configuration, and ingress components.
- Add foundational AWS network, identity, compute, and managed-service
  components incrementally.
- Enforce rate limits, quotas, cost metadata, and drift reporting.

Exit criterion: an application can be declared, planned, reconciled, observed,
updated, and deleted through least-privilege provider identities.

## GitOps and operations

- Add CLI and SDKs with stable machine-readable output.
- Add plan review, approval policy, and GitOps integration.
- Publish dashboards, alerts, backup procedures, and recovery exercises.
- Define versioning, upgrades, rollback, and release provenance.

Exit criterion: operators can run Veer using documented SLOs, recovery
objectives, and signed release artifacts.
