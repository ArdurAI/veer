# Security regression suite

Status: executable evidence for issue #28 at the current `main` contract. This
report covers repository components that exist. It does not qualify future
production storage, queue, worker, provider-adapter, telemetry-export, or
support-bundle implementations.

## Public-route security matrix

[`TestPublicRouteSecurityMatrix`](../../test/security/security_regression_test.go)
derives the complete operation set from the validated OpenAPI artifact. The
test fails if a public operation is added without a matrix row. Its checked-in
result is
[`security-regression-v1alpha1.golden.json`](../../test/security/testdata/security-regression-v1alpha1.golden.json).

| Operation | Authenticated member | Authenticated outsider | Missing or invalid credential |
| --- | --- | --- | --- |
| `listWorkspaces` | `200`, own row returned; denied row removed before the one-item page | `200`, own row returned; denied row removed before the one-item page | `401` |
| `createWorkspace` | `403`, service-reserved tenant action | `403`, service-reserved tenant action | `401` |
| `getWorkspace` | `200` | `403` | `401` |
| `replaceWorkspace` | `202` | `403` | `401` |
| `deleteWorkspace` | Authorization passes; `409` protects the retained Policy child | `403` | `401` |
| `replaceWorkspaceStatus` | `403`, service-reserved tenant action | `403`, service-reserved tenant action | `401` |
| `getOperation` | `200` | `403` | `401` |

Workspace creation and status replacement intentionally have no tenant allow
case. The closed authorization matrix reserves both actions. Treating a `2xx`
response as required evidence would weaken the security contract. Their
positive path proves that a valid credential reaches the authorization layer;
their invariant is a tenant `403` for every value in the closed four-role
registry.

## Retained untrusted-input and fuzz corpus

The following fuzz targets run their seed corpus during ordinary `go test` and
remain available for time-bounded fuzzing:

| Boundary | Target | Retained input classes |
| --- | --- | --- |
| Public HTTP routes | `FuzzReferencePublicBoundary` | alternate token carrier, encoded path, duplicate JSON member, unknown credential-like field, trailing JSON, invalid UTF-8, depth bomb, webhook/remote-reference shape, oversized body, invalid credential |
| Bearer extraction | `FuzzExtractBearer`, `FuzzCredentialTrailerScrubbing` | header/query/cookie/trailer ambiguity, divergent query views, body and trailer aliasing, arbitrary casing |
| OIDC/JWKS | deterministic negative corpus in `internal/adapters/identity/oidc` | non-canonical JWT segments, duplicate members, forbidden remote key headers, claim failures, redirect/cookie response state, malformed and over-bound keys |
| Resource admission | `FuzzAdmitRaw` | every resource kind, duplicate and unknown fields, invalid Unicode, depth/node/byte bounds, trailing values |
| Closed domain values | fuzz targets under `internal/core/domain` | invalid sum types, identifiers, hierarchy, role/action vocabulary, operations, conditions, audit canonicalization, credentials, and reconciliation digests |

The public-boundary target sends malformed body seeds through the
member-authorized Workspace replacement route so they reach admission parsing.
It asserts panic freedom, bounded JSON responses, mandatory
no-store/nosniff/correlation headers, and bearer-canary absence. Every runtime
problem response must use a closed code/status pair, bind its request ID and
problem URNs, stay below 1,024 bytes, contain at most one field violation, and
respect the field-path and text bounds. The OpenAPI validator independently
rejects remote servers, remote references, and webhook expansion. No provider
response parser exists yet; provider-specific malicious-response corpora belong
with the adapters introduced by issues #38 and #41.

Run the public-boundary fuzzer for one minute with:

```sh
go test ./test/security -run '^$' -fuzz '^FuzzReferencePublicBoundary$' -fuzztime=1m
```

## Redaction report

| Surface named by issue #28 | Implemented evidence | Result |
| --- | --- | --- |
| Plans and reconciliation state | `TestOpaqueValuesRejectGenericSerializationAndRedactDiagnostics` covers plans, evidence, effects, attempts, leases, queue/idempotency state, proofs, and `slog` output | Secret and identity canaries absent; generic serialization rejected |
| Credential state | `TestCredentialValuesRedactAndRejectSerialization`, `FuzzSourceMaterialSafety`, and broker lease/lifecycle tests cover source/session material, requests, brokers, leases, rotation, errors, and destruction | Raw material remains callback-bounded; diagnostics redact; serialization rejected |
| Identity and bearer state | Identity diagnostic/serialization tests, bearer canary tests, OIDC negative corpus, and the route matrix cover principals, request carriers, challenges, problems, and headers | Raw token and identity claims absent from output; rejected request carriers scrubbed |
| Audit and privileged state | `TestOpaqueRuntimeValuesForbidLossyGenericSerialization` and `TestAdministrationDiagnosticsAndSerializationAreSafe` cover audit/elevation values, nested containers, errors, formatting, and `slog` | Canaries absent; opaque runtime values reject lossy serialization |
| HTTP errors | Route matrix and `FuzzReferencePublicBoundary` exercise every public route plus malformed/bounded input | Only closed problem codes and bounded field paths are returned; bearer, resource, operation, and identity canaries are absent from denied responses |
| Logs | Package redaction tests send every sensitive value through `fmt` and `slog` | Canaries absent from implemented logging surfaces |
| Traces | No tracer or trace exporter exists | Not applicable at this revision; issue #63 must add canaries with the first implementation |
| Metrics | No metrics registry or exporter exists | Not applicable at this revision; issue #63 must add label/value canaries and cardinality bounds |
| Support output | No support-bundle or diagnostic export exists | Not applicable at this revision; the implementing issue must add a closed allowlist and canary corpus |

This report proves current executable behavior only. A future component does
not inherit an “issue #28 passed” claim: its pull request must extend this
matrix, fuzz corpus, and redaction table before merge.

## Verification

```sh
go test ./test/security -count=1
go test ./internal/transport/http ./internal/adapters/identity/oidc \
  ./internal/core/domain/admission ./internal/core/domain/credential \
  ./internal/core/service/credentialbroker ./internal/core/domain/reconciliation \
  ./internal/core/domain/audit ./internal/core/domain/administration -count=1
./hack/dev security
./hack/dev check
./hack/dev race
./hack/dev coverage
```

The OAuth token restrictions are cross-checked against
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), and the retained
regression practice follows the verification intent of
[NIST SP 800-218 SSDF](https://csrc.nist.gov/pubs/sp/800/218/final).
