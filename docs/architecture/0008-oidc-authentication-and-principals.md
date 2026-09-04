# ADR 0008: OIDC authentication and principals

- Status: Accepted
- Date: 2026-09-02
- Owners: Veer maintainers
- Decision scope: Issue [#22](https://github.com/ArdurAI/veer/issues/22)

## Context

Veer's OpenAPI contract requires bearer authentication, while its core needs a
provider-neutral authenticated actor rather than an identity-provider SDK type.
The boundary must reject forged, replayed, misbound, ambiguous, and oversized
credentials without placing token or personal-claim material in generic logs,
errors, serialization, resources, queues, or audit payloads.

OIDC discovery, permissive JWT parsing, and provider-specific claim guesses
would make runtime network responses change Veer's trust anchors. Treating a
missing credential as a synthetic principal would also let later code confuse
absence with authenticated identity. This decision instead freezes explicit
configuration, bounded parsing, exact claim checks, and a closed outcome
taxonomy before routes or authorization are implemented.

## Decision

### Boundary and data flow

The bearer value is shared by ordinary authentication and privileged
administration, so the neutral `internal/core/domain/authentication` package
owns it. `internal/core/ports` retains type, constructor, error, and limit
aliases for existing transport and adapter call sites. Authentication then has
this one-way data flow:

```text
HTTP request
  -> internal/transport/http (carrier extraction and removal)
  -> internal/core/ports.NewBearerCredential (compatibility facade)
  -> internal/core/domain/authentication.BearerCredential (opaque shared value)
  -> internal/adapters/identity/oidc (signature, claim, and JWKS validation)
  -> internal/core/domain/identity.Principal (provider-neutral actor)
```

The transport accepts exactly one `Authorization` field-value. Its scheme is
ASCII case-insensitive `Bearer`, followed by one or more literal spaces and
exactly one RFC 6750 `b64token`. Horizontal tabs, leading or trailing
whitespace, multiple tokens, comma-combined values, authentication parameters,
and non-envelope bytes are invalid. The token is at most 8,192 bytes and the
complete field-value is at most 8,199 bytes; extra separator spaces consume the
same complete-value budget.

Every case variant of `Authorization` is removed from the in-memory request
before extraction returns, including invalid and duplicate cases. The exact
`access_token` query parameter and cookie name are rejected even when no
header is present. The URL raw query and `RequestURI` query suffix are inspected
independently with exact percent-decoded name semantics and without copying
values. A credential in either view, or disagreement between an available URL
view and the view in a nonempty `RequestURI`, is invalid. An empty `RequestURI`
is an unavailable second view rather than a disagreement. On query rejection,
both complete query views are cleared. Any already-materialized `Form` and
`PostForm` maps are cleared in place and replaced with non-nil empty maps. This
also clears aliases through the request and prevents a later `ParseForm` call
from reparsing the rejected query or consuming the body. On cookie rejection,
every case variant of the `Cookie` header is removed, so the rejected credential
cannot survive in ordinary downstream request or access-log formatting. This
intentionally discards the whole offending container, including unrelated
values, rather than reconstructing attacker-sized data.

An `Authorization` or `Cookie` trailer declaration is invalid whether it is
present as a case-insensitive token in a raw `Trailer` header or as a declared
key in `Request.Trailer`. Credential-capable declarations and any already
materialized values are removed before extraction returns, and that rejection
remains sticky across repeated extraction. Independently of declarations, a
body other than nil or `http.NoBody` is guarded when the request uses HTTP/1
chunked transfer coding or carries any raw `Trailer` header or nonempty
`Request.Trailer` map. Go's HTTP/2 server copies only predeclared terminal keys
into the handler request, so the metadata rule covers its materialization path
without wrapping every HTTP/2 body. The guard does not itself reject an
otherwise valid or absent credential. A wrapper preserves every `Read` and
`Close` result, and after each terminal `Read` (any non-nil error, including
`n > 0, io.EOF`) or `Close` it removes credential trailer values that Go may
materialize, including undeclared terminal fields accepted by Go's HTTP/1
chunked reader. Successful nonterminal reads do not rescan header maps.
Observing such a field latches the guard into an invalid state: it cannot
retract the extraction result that preceded body consumption, but every later
extraction is invalid. Unrelated trailer fields remain available. A body
outside the guard predicate retains its original object and behavior; a guarded
body is wrapped even when its declarations are absent or unrelated.

Whenever neither a forbidden query/cookie carrier, credential-capable trailer,
nor query-view disagreement is present, unrelated query parameters, cookies,
parsed forms, and trailer metadata remain untouched; rejecting `Authorization`
alone, including a malformed or duplicate field, does not discard them. Body
identity changes only for the trailer-capable guard described above. Request
bodies and multipart forms are never inspected for bearer credentials.

`ExtractBearer` must run on the original inbound `*http.Request` before any
`Clone`, `WithContext`, or retained body/request alias. Go's internal body reader
owns the original request pointer and can therefore populate its trailer map;
wrapping a pre-existing clone cannot scrub that hidden original surface without
reflection or unsafe coupling to `net/http`. This ordering is an HTTP adapter
obligation for issue #21. The in-place form clearing guarantee above applies to
the maps owned by the request passed at that supported boundary; it does not
claim to find copies retained before extraction.

A request with no accepted carrier returns an explicit absent result and no
principal. It does not call the authentication port, and the domain has no
anonymous `Principal` kind. A presented but malformed carrier returns the same
stable invalid classification used for a cryptographically rejected token.

### Configured trust anchors

Each accepted token class has a complete `TrustAnchor`; there are no implicit
defaults and no issuer-derived discovery request. The anchor contains:

- the exact HTTPS issuer identifier, with no user information, query, or
  fragment;
- the exact configured HTTPS JWKS URI, with no user information or fragment;
- one exact required audience;
- one explicit allowlist of one to eight asymmetric signature algorithms;
- one to eight accepted protected `typ` values;
- one required claim-name mapping for optional groups and, for workloads, the
  required workload identity claim name;
- an explicit maximum token lifetime and allowed clock skew; and
- explicit JWKS freshness, refresh-ahead, cooldown, fetch timeout, response
  byte, and key-count bounds.

The allowed algorithm vocabulary is `RS256`, `RS384`, `RS512`, `PS256`,
`PS384`, `PS512`, `ES256`, `ES384`, `ES512`, and `EdDSA`. Symmetric MACs,
`none`, encryption algorithms, and algorithms outside the configured subset
are rejected. RSA-PSS signatures require the JWA salt length equal to the
selected hash output; permissive auto-detected salt lengths are rejected. The
configured lifetime is a whole-second value from one second through 24 hours.
Clock skew is a whole-second value from zero through five minutes.

Human and Workload anchors are intentionally distinct configuration records.
A Human anchor forbids a workload-identity claim mapping. A Workload anchor
requires one, and authentication fails when that configured claim is absent or
invalid. Both kinds use the exact `(issuer, subject)` pair as logical identity;
they are never merged because an email, group, display name, or workload label
happens to match.

The application-facing API is
`oidc.NewAuthenticator([]TrustAnchor, client, clock)` with one to 16 anchors;
`oidc.NewVerifier` remains the single-anchor validation primitive. Construction
copies and validates every anchor and rejects overlapping classes whose exact
issuer and audience plus accepted type and algorithm sets could select the same
token. Same-issuer anchors with distinct audiences remain valid configuration.
For each request, bounded unverified header and `iss`/`aud` inspection is used
only to dispatch by exact issuer, audience membership, protected type, and
protected algorithm. Unknown or runtime-ambiguous classes are invalid without
a network request; this includes one token containing multiple configured
audiences that otherwise matches multiple anchors. Exactly one selected
verifier then repeats the structural checks and performs complete signature and
claim validation; routing data never establishes identity by itself.

### JWT access-token validation

Only a compact, single-signature JWS access token is accepted. The protected
header must contain bounded nonempty `alg`, `kid`, and `typ` strings. Embedded
or remote key-selection headers (`jwk`, `jku`, `x5c`, and `x5u`), critical or
detached-payload controls, noncanonical base64url, duplicate JSON members,
excessive nesting, and over-limit members or collections are rejected before
signature verification. A token never selects its own trust endpoint or
algorithm policy.

Validation binds all of the following in one configured anchor:

1. The protected algorithm is both supported and explicitly allowed.
2. The protected type is in the anchor's case-insensitive accepted set.
3. The signature verifies with a bounded, usable key from the anchor's JWKS.
4. `iss` exactly equals the configured issuer.
5. `sub` is present, nonempty, and within the domain bound.
6. `aud` is a bounded string or string array containing the exact configured
   audience; the normalized principal retains the canonical audience set.
7. `exp` and `iat` are required exact positive integer NumericDate seconds.
   Optional `nbf` is also an exact positive integer when present.
8. The token is active within configured skew, `exp` is after `iat`, and the
   issued lifetime does not exceed the configured maximum.
9. The configured groups claim, when present, is a bounded string array. A
   configured workload claim is a bounded string required only by Workload.

The resulting immutable principal contains the explicit Human or Workload
kind, exact issuer and subject, canonical sorted/deduplicated audiences and
groups, and the required Workload identity where applicable. A
domain-separated SHA-256 fingerprint supports bounded correlation, but exact
issuer-and-subject equality remains the logical-identity oracle. Authentication
does not grant Workspace membership, a role, or an action.

### JWKS fetch and rotation

The adapter fetches only the configured HTTPS JWKS URI with a bounded timeout,
at most a 1 MiB response, and at most 128 keys. Redirects are rejected. Client
cookie storage and sending are disabled, while response cookies are ignored.
A set is usable only after bounded parsing and key filtering; an empty or
malformed set never replaces a working cache.

A JWK is admitted only as a valid public verification key with a bounded,
nonempty `kid`. Its `use` is absent or exactly `sig`. Its `key_ops` is absent or
contains one to eight unique bounded operations including exact `verify`. An
explicit JWK `alg` must be both anchor-allowed and compatible with the key; an
omitted `alg` is accepted only when exactly one configured algorithm is
compatible. RSA moduli are 2,048 through 8,192 bits with an odd public exponent
of at least three. They must be odd, share no checked small factor or factor
with the public exponent, not be a perfect square, and be classified composite
by the fixed probable-prime oracle. RSA admission charges the cube of each
candidate modulus bit length against a per-response ceiling of four 8,192-bit
equivalents; exceeding the ceiling rejects the complete set before it can
replace the cache. EC keys bind P-256 to ES256, P-384 to ES384, and P-521 to
ES512. Ed25519 keys use a canonical on-curve encoding, reject the complete
eight-point small-order set, and bind only to EdDSA. Raw key material is bound
to the decoded verification key before use. A duplicate resolved
`(kid, algorithm)` rejects the complete set rather than selecting an
order-dependent winner.

Freshness is explicit and never exceeds 24 hours. Refresh-ahead is positive
and shorter than freshness; refresh cooldown is positive and at most one hour;
fetch timeout is positive and at most 30 seconds. Concurrent refreshes are
coalesced, a successful usable set replaces the cache atomically, and a failed
proactive refresh may use the prior set only while it is still fresh. Stale
keys are never accepted. Failed required or proactive attempts enter cooldown;
a successful ordinary or proactive refresh is governed by its new freshness
window and does not block a later required refresh solely because freshness is
shorter than cooldown. A completed fetch attempt ended by its owner's caller
cancellation or deadline also enters its applicable cooldown, preventing
disconnect-driven bypass; the canceling owner still receives the exact context
outcome. A live coalesced follower receives a token-free internal availability
result. Resolution may still use a fresh matching key; otherwise the stable
invalid/unavailable rules apply, and cooldown prevents immediate refetch.

An unknown `kid` or signature failure can trigger one anchor-wide
cooldown-limited refresh so legitimate rotation does not wait for ordinary
freshness expiry. Every reactive attempt enters cooldown, including a
successful fetch whose set still does not match. Repeating attacker-selected
key IDs cannot bypass that cooldown or grow a per-key cache. A successful
refresh that still cannot verify the token is invalid, not an availability
failure. If that reactive refresh fails while the prior key set remains fresh,
the submitted token is likewise invalid rather than turning a healthy verifier
into attacker-induced unavailability. A fetch failure is unavailable only when
no fresh usable set can make the decision.

### Safe outcomes and redaction

The authentication port has only these externally actionable failure classes:

| Class | Meaning | HTTP mapping owned by issue #21 |
| --- | --- | --- |
| `authentication-invalid` | A credential was presented but its carrier, JWS, signature, anchor binding, time, kind, or claims failed | `401` with the bounded invalid-token challenge |
| `authentication-unavailable` | No fresh usable trust data could be obtained or used for a non-context infrastructure reason | Retry-safe `503` behavior within the request deadline |
| Context cancellation or deadline | The caller's context ended first | Preserve the context outcome; do not relabel it or retry past the deadline |

Errors never wrap the submitted token, claim values, key ID, endpoint response,
or provider error text. Missing credentials are neither invalid nor
unavailable; they remain explicit absence for route policy to handle.
Invalid `TrustAnchor` input is a constructor/configuration failure and must stop
startup; it is not a per-request invalid or unavailable result.

The authentication domain owns the bearer credential, keeps its raw value
private, bounds construction, and exposes raw access through an accessor
intended only for verifier adapters. Ports aliases do not create another value
or ownership boundary. Ordinary OIDC verification and ledger-gated privileged
verification may consume the same type; neither contract makes the value
serializable or persistent. Its `Error`, `String`, and `GoString` methods
always return redacted fixed text; JSON and text marshaling fail. Principal
construction inputs, logical identity, workload identity, and principals
similarly block generic serialization and redact personal claims from
diagnostic formatting. Raw-token canaries cover success, parse failure,
alternative carriers, formatting, serialization, claim validation, and JWKS
failures.

### Dependency and offline build

Veer uses
[`github.com/go-jose/go-jose/v4` v4.1.4](https://github.com/go-jose/go-jose/releases/tag/v4.1.4)
for JOSE signature verification and JWK handling. It is Apache-2.0 licensed,
requires Go 1.24 or newer, and has no non-standard-library module dependency at
that version. Veer's selected Go 1.27.0 toolchain satisfies that requirement.

The exact source is committed under `vendor/`, and ordinary format, lint,
build, and test checks use `-mod=vendor` with module proxy, checksum database,
and version-control downloads disabled. `./hack/dev bootstrap` continues to
download only checksum-pinned development tools; it does not resolve Go
modules. Updating go-jose requires an explicit reviewed online maintenance
step, checksum and license review, regenerated vendor metadata, negative-token
tests, and the complete offline check.

## Consequences

- A deployment can support multiple providers and Human/Workload token classes
  without compiling provider-specific SDKs into the core model.
- Trust changes are reviewable configuration changes. Compromised configuration
  can still authorize the wrong issuer or endpoint and remains a high-impact
  operational trust anchor.
- An identity-provider compromise or stolen valid bearer token remains usable
  until expiry or provider-side revocation. Short lifetimes bound but cannot
  remove that residual risk.
- Reactive JWKS refresh reduces rotation delay, while global cooldown,
  coalescing, response bounds, and no-stale use limit attacker-driven network
  and memory work. An unavailable issuer can still reject new keys.
- An authenticator owns at most 16 independently bounded anchor caches. Cache
  memory and proactive or reactive JWKS traffic therefore scale linearly with
  configured token classes, even when anchors reuse an endpoint; unknown or
  ambiguous dispatch performs no fetch.
- Vendoring adds repository size and a deliberate dependency-update task, but
  normal checks remain reproducible and require no module network access or
  credentials.
- No cloud service or paid API is introduced by the library and contract tests.
  Production identity-provider and egress cost depends on the later deployment
  configuration and request volume.

## Alternatives considered

### OIDC discovery from the issuer

Rejected because discovery output would change the effective trust endpoint at
runtime. Exact issuer and JWKS URI are independent configured trust-anchor
fields.

### Accept ID tokens or opaque-token introspection

Rejected for this slice. The control-plane resource server accepts bounded JWT
access tokens only. ID-token client binding and introspection credentials add
different audiences, endpoints, caching, privacy, and availability boundaries.

### Infer Human or Workload from mutable claims

Rejected because provider conventions differ and mutable claim shape is not an
identity kind. The selected kind and workload claim mapping are explicit in the
trust anchor.

### Accept query, cookie, or form bearer tokens

Rejected because those carriers expand leakage, CSRF, parsing, and logging
surfaces. The `Authorization` field is the only supported bearer carrier.

### Fetch a key on every request or cache indefinitely

Rejected because the first makes authentication depend on per-request network
availability and attacker-controlled load, while the second misses key
rotation and revocation. Bounded shared freshness with cooldown-limited
reactive refresh gives an explicit middle ground.

### Implement JOSE primitives locally

Rejected because signature-format and JWK edge cases are security-sensitive.
The selected maintained library is pinned, vendored, license-compatible, and
dependency-minimal; Veer retains its own strict parsing, trust, claim, network,
and error boundaries around it.

## Deferred decisions

- Issue [#21](https://github.com/ArdurAI/veer/issues/21) owns routes, server,
  middleware wiring of issue #22's bounded authenticator, request ordering,
  response rendering, anonymous route policy, and exact
  `WWW-Authenticate`/`Retry-After` behavior. This issue adds no listening server
  or route.
- Issue [#23](https://github.com/ArdurAI/veer/issues/23) owns Workspace and
  Environment membership, roles, actions, default-deny authorization, and use
  of groups or Workload identity as policy input. Authentication alone grants
  no resource authority.
- Issue [#27](https://github.com/ArdurAI/veer/issues/27) owns the canonical
  audit event, persistence, integrity, query/export, and retention contract.
  This issue does not serialize a principal or raw claim as an audit payload.
- Browser authorization-code/PKCE login, device flow, token exchange,
  introspection, provider discovery, revocation polling, and proof-of-possession
  tokens need separate client, credential, replay, privacy, and availability
  decisions.

## Evidence

The executable evidence includes exact bearer-carrier tables, maximum-size and
duplicate-header cases, post-rejection request-surface and raw-token redaction
canaries, property and fuzz tests, principal canonicalization and alias tests,
Human/Workload negative matrices, multi-anchor overlap and exact-dispatch tests,
unknown/ambiguous zero-network checks, negative compact-JWT and claim corpora,
runtime-generated signed tokens, bounded JWKS fetch, redirect, rotation,
cooldown, and concurrency tests, canonical raw-to-typed EC, Ed25519, and RSA key
binding, exhaustive accepted low-order Ed25519 encodings, prime and cheaply
invalid RSA moduli, RSA work-budget boundaries, exact RSA-PSS salt-length
enforcement, and
invalid-versus-unavailable classification checks.

```sh
go test ./internal/core/domain/authentication ./internal/core/domain/identity \
  ./internal/core/ports \
  ./internal/transport/http ./internal/adapters/identity/oidc
go test -race ./internal/core/domain/authentication ./internal/core/domain/identity \
  ./internal/core/ports \
  ./internal/transport/http ./internal/adapters/identity/oidc
go test -count=100 ./internal/core/domain/authentication ./internal/core/domain/identity \
  ./internal/core/ports \
  ./internal/transport/http ./internal/adapters/identity/oidc
./hack/dev docs
./hack/dev check
```

Primary protocol references are
[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html),
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html),
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html),
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), and
[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).
