# Veer

Veer is a cloud-native application delivery control plane for teams operating
workloads across cloud infrastructure and Kubernetes.

It provides a consistent, declarative model for environments, applications,
infrastructure, identity, policy, and day-two operations. Provider-specific
details remain behind adapters so application teams can work with stable
platform concepts while operators retain control over security, cost, and
reliability.

## Status

Veer is in the pre-alpha foundation phase. APIs, storage formats, and
deployment topology are not yet stable.

## Development

A clean macOS or Linux checkout on `amd64` or `arm64` needs only standard host
utilities and these two commands:

```sh
./hack/dev bootstrap
./hack/dev check
```

Bootstrap installs Veer's checksum-verified toolchain under the ignored
`.tools/` directory. The aggregate check then runs formatting, lint, build,
unit-test, and documentation gates without cloud credentials or network
access. See the [local development guide](docs/development.md) for supported
hosts, individual commands, resource use, and troubleshooting.

## Design principles

- **Application focused:** expose the concepts application teams use rather
  than raw provider APIs.
- **Declarative:** persist desired state and reconcile it continuously.
- **Secure by default:** use least-privilege identities, explicit policy, and
  auditable actions.
- **Provider independent:** isolate cloud and cluster behavior behind typed
  adapters.
- **GitOps ready:** make every material change reviewable, reproducible, and
  observable.
- **Operationally honest:** surface drift, partial failure, cost, and provider
  limits instead of hiding them.

## Core model

| Concept | Purpose |
| --- | --- |
| Workspace | Administrative and policy boundary |
| Environment | Isolated runtime and infrastructure boundary |
| Application | Deployable product or service group |
| Component | Workload or managed-service unit |
| Policy | Authorization, security, and operational constraints |
| Provider connection | Environment-scoped reference to provider authority and observed capabilities |
| Reconciliation | Convergence from desired state to observed state |

## Initial scope

The first implementation slice targets AWS and Kubernetes:

1. Versioned resource schemas and validation.
2. A durable desired-state store with an append-only audit trail.
3. Policy-backed identity and authorization.
4. Kubernetes and AWS provider adapters.
5. Idempotent reconciliation with explicit plans, retries, and drift status.
6. A CLI and API suitable for automation and GitOps workflows.

## Documentation

- [Architecture overview](docs/architecture/overview.md)
- [Alpha operational bounds](docs/architecture/0001-alpha-operational-bounds.md)
- [Alpha implementation stack](docs/architecture/0002-alpha-implementation-stack.md)
- [HTTP API and resource evolution conventions](docs/architecture/0003-http-api-and-resource-evolution.md)
- [Common resource envelope](docs/architecture/0004-common-resource-envelope.md)
- [Resource hierarchy and ownership](docs/architecture/0005-resource-hierarchy-and-ownership.md)
- [Control, execution, and evidence contracts](docs/architecture/0006-control-execution-and-evidence.md)
- [Deterministic admission and version conversion](docs/architecture/0007-deterministic-admission-and-version-conversion.md)
- [OIDC authentication and principals](docs/architecture/0008-oidc-authentication-and-principals.md)
- [Deterministic hierarchical authorization](docs/architecture/0009-deterministic-hierarchical-authorization.md)
- [Provider-neutral process-local credential broker](docs/architecture/0010-provider-neutral-credential-broker.md)
- [OpenAPI v1alpha1 baseline](api/openapi/veer-v1alpha1.json)
- [Local development](docs/development.md)
- [Security model](docs/security/model.md)
- [Formal threat model and data classification](docs/security/threat-model.md)
- [Roadmap](docs/roadmap.md)

## License

An open-source license has not yet been selected. Public visibility alone does
not grant permission to copy, modify, or redistribute this repository. License
selection is required before the first source release or external contribution.
