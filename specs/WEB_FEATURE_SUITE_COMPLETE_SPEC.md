---
spec_id: OMNIUS-WEB-COMPLETE
title: Complete Web Application Feature Suite
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Complete Web Application Feature Suite

This document combines the normative web feature-suite specifications, accepted ADRs, integration guidance, autonomous-agent handoff, and recommendation traceability. Individual files remain authoritative for stable paths and machine references.

## Contents
- `OMNIUS-025` — Web Application Architecture
- `OMNIUS-026` — Consumer Contract Generation
- `OMNIUS-027` — Frontend Capability SDK
- `OMNIUS-028` — Web Authentication and Authorization Integration
- `OMNIUS-029` — Realtime Browser Integration
- `OMNIUS-030` — Static Web Delivery
- `OMNIUS-031` — Frontend Data, State, Forms, Errors, and Uploads
- `OMNIUS-032` — Frontend Testing, Security, and Accessibility
- `OMNIUS-033` — Web Profiles, Generator, and Upgrades
- `OMNIUS-034` — Web Suite Roadmap, Acceptance, and Traceability
- `OMNIUS-ADR-0009` — Use React, TypeScript, and Vite for the Default Web Client
- `OMNIUS-ADR-0010` — Derive Frontend Integrations From Backend Consumer Contracts
- `OMNIUS-ADR-0011` — Separate Server, URL, Form, Realtime, and Client-Local State
- `OMNIUS-ADR-0012` — Default to Same-Origin Static Delivery and Keep SSR Out of the Baseline
- `OMNIUS-ADR-0013` — Use an Exact-Pinned, Constrained Orval Pipeline for OpenAPI Clients
- `OMNIUS-ADR-0014` — Use AsyncAPI 3.1 and JSON Schema for Browser-Facing Realtime Contracts

---

# Web Application Architecture

## 1. Purpose

This specification adds a first-class web-application capability to Omnius. A generated service can expose a browser application without forcing every product team to rediscover API clients, authentication bootstrap, authorization presentation, query caching, realtime synchronization, uploads, error handling, testing, static delivery, or deployment integration.

The architecture MUST remain backend-framework independent at the contract boundary and frontend-framework layered internally. The Rust service is authoritative for data, identity, authorization, validation, and enabled capabilities.

## 2. Default topology

The default `web` profile is a same-origin single deployment:

```text
Browser
  ├── GET / and application routes
  ├── GET /assets/*
  ├── /api/*
  ├── /ws
  └── /events
          │
          ▼
       Axum
  ├── Rust API and middleware
  ├── WebSocket/SSE transports
  └── Vite production output
```

Development uses the Vite development server and proxies API, WebSocket, and SSE namespaces to Axum. Production serves fingerprinted static assets and the SPA shell through `tower-http`.

A cross-origin API deployment MAY be configured, but same-origin session-cookie operation is the secure and ergonomic default.

## 3. Baseline technology decisions

The default browser implementation MUST use:

- React and TypeScript.
- Vite for development and production asset builds.
- TanStack Router for typed route and URL state.
- TanStack Query for remote/server-state caching and mutations.
- A generated Orval client sourced from the canonical OpenAPI artifact.
- React Hook Form with Zod for forms that benefit from schema-backed client validation.
- Zustand only when a durable client-local store is justified.
- WebSocket and SSE adapters built over a framework-neutral realtime core.
- Vitest, Testing Library, MSW, and Playwright for the test stack.

Exact versions and upgrade gates are specified in the dependency baseline and ADRs.

## 4. Repository topology

The generated service SHOULD begin with one physical `web-sdk` package with stable subpath exports. It MAY split into packages later without changing public semantics.

```text
contracts/
  openapi.json
  asyncapi.json
  permissions.json
  capabilities.json
  contract-manifest.json

packages/
  web-sdk/
    src/
      generated/
      client/
      auth/
      authorization/
      realtime/
      uploads/
      capabilities/
      react/
      testing/

web/
  src/
    routes/
    features/
    components/
    app/
```

The `web/` application owns product UI. `packages/web-sdk/` owns reusable integration. Generated files remain isolated below `generated/`.

## 5. Architectural invariants

1. Every browser-facing backend module MUST declare a frontend exposure contract.
2. Every module with no browser surface MUST explicitly declare `exposure: none` and a reason.
3. Consumer contracts MUST be deterministic and reproducible.
4. TypeScript API DTOs MUST derive from contracts emitted by Rust.
5. TanStack Query MUST own backend/server state.
6. Route and shareable filter state SHOULD live in the URL.
7. Zustand MUST NOT become a duplicate API cache.
8. Backend authorization MUST be enforced regardless of frontend rendering.
9. Session secrets MUST remain unavailable to browser JavaScript.
10. Realtime delivery MUST be treated as a synchronization hint, not an authoritative replacement for HTTP state.
11. Product UI MUST NOT import kit-internal generated paths directly; it imports public SDK exports.
12. The baseline MUST work without SSR or a JavaScript application server.
13. Adding or removing the web suite MUST be idempotent and preserve application-owned files.
14. A frontend build MUST be traceable to the contract hashes against which it was compiled.

## 6. Boundaries and extension points

The framework-neutral client layer owns:

- HTTP transport configuration.
- API error normalization.
- request IDs and correlation metadata.
- idempotency keys.
- pagination primitives.
- authentication mode integration.
- typed event parsing.
- realtime connection lifecycle.
- upload orchestration.
- runtime capability discovery.

The React layer owns:

- Query client integration.
- Router integration.
- providers and context.
- hooks and presentation guards.
- form adapters.
- component-testing helpers.

The product application owns:

- Visual design.
- feature-specific components.
- page composition.
- copy and localization.
- application-specific local state.
- semantic hooks that add real product meaning.

## 7. Explicit non-goals

The baseline does not prescribe:

- A component library or CSS system.
- A design system.
- React Server Components.
- server-side rendering.
- static-site generation.
- a Node.js production server.
- GraphQL as the primary browser API.
- a generic low-code page generator.
- automatic UI generation from every endpoint.
- client-side security enforcement.

Leptos, Next.js, TanStack Start, or other renderers MAY become future adapters through new ADRs and profiles.

## 8. Configuration

The web suite MUST define typed configuration for:

- public base path.
- API, WebSocket, and SSE paths.
- development proxy targets.
- static asset directory.
- SPA fallback.
- cache policy.
- source-map publication.
- CSP mode and nonce/hash handling.
- contract compatibility checks.
- enabled browser capabilities.
- permitted cross-origin deployments.

Unknown configuration keys MUST fail validation in production profiles.

## 9. Operational behavior

The web capability MUST participate in health, observability, and shutdown conventions already defined by the base bundle. It MUST expose:

- frontend build/version metadata.
- embedded contract hash metadata.
- asset-serving metrics.
- contract-mismatch diagnostics.
- WebSocket/SSE client-side telemetry boundaries that do not leak PII.
- a readiness failure when required static artifacts are absent in a production web profile.

## 10. Acceptance linkage

This specification is satisfied by `AC-WEB-001` through `AC-WEB-010` and by the profile-wide criteria in specification 34.

---

# Consumer Contract Generation

## 1. Purpose

The Rust service MUST expose complete, deterministic, machine-readable contracts before any generated frontend integration is considered stable. These contracts are the seam between backend capabilities and every consumer: browser applications, mobile clients, CLIs, test harnesses, documentation, and future framework adapters.

## 2. Required contract artifacts

A web-capable service MUST generate:

```text
contracts/
  openapi.json
  asyncapi.json
  permissions.json
  capabilities.json
  contract-manifest.json
```

`asyncapi.json` MAY be absent only when no asynchronous browser-facing channel is enabled. Its absence MUST be represented in the manifest rather than inferred from a missing build step.

### 2.1 OpenAPI

The OpenAPI document MUST include:

- Stable and unique `operationId` values.
- All request path, query, header, and cookie parameters.
- Request-body schemas.
- Successful and expected error response schemas.
- RFC 9457 problem details.
- Authentication schemes and operation-level requirements.
- pagination and idempotency metadata.
- deprecation metadata.
- examples for security-sensitive and structurally complex operations.
- route tags mapped to capability ownership.

The OpenAPI artifact MUST be generated from the same Rust types and route registrations used by the running service. A route exposed to the selected profile without a contract is a build failure unless explicitly classified as an operator-only route.

### 2.2 AsyncAPI

The AsyncAPI document MUST describe browser-facing WebSocket, SSE, and domain-event contracts using AsyncAPI 3.1 and JSON Schema-compatible payloads. It MUST define:

- channels and addresses.
- send/receive operations.
- protocol bindings.
- authentication requirements.
- message names and versions.
- event-envelope metadata.
- payload schemas.
- correlation and causation identifiers.
- replay/resume semantics where supported.

### 2.3 Permissions

`permissions.json` MUST contain a stable vocabulary, human-readable descriptions, resource/action metadata, deprecation state, and an optional grouping structure for UI use. Permission identifiers MUST originate from the backend authorization registry.

The file MUST NOT disclose policy internals, confidential relationship data, or permissions unavailable in the assembled profile.

### 2.4 Capabilities

`capabilities.json` MUST describe compiled browser-facing capabilities and their public contract surfaces. It MUST distinguish:

- compiled capability availability.
- runtime availability.
- authentication modes.
- route/channel locations.
- optional frontend exports.
- minimum compatible SDK version.
- feature-flag versus structural capability semantics.

A product feature flag MUST NOT be confused with a compiled capability.

### 2.5 Contract manifest

`contract-manifest.json` MUST include:

- manifest schema version.
- service-kit version.
- application version.
- build revision.
- generation timestamp or reproducible-build sentinel.
- SHA-256 for each contract.
- aggregate contract hash.
- enabled profile and modules.
- minimum and maximum supported client contract versions.
- generator versions.

The aggregate hash MUST be calculated from canonical bytes in a deterministic order.

## 3. Determinism

Contract generation MUST be reproducible. The generator MUST:

- sort maps, paths, operations, permissions, capabilities, and schemas deterministically.
- omit wall-clock timestamps in reproducible mode.
- normalize line endings.
- use stable schema naming.
- avoid nondeterministic hash-map iteration.
- produce byte-identical output for unchanged source and configuration.

The command surface MUST include:

```bash
cargo xtask contracts generate
cargo xtask contracts check
cargo xtask contracts diff --against <revision-or-artifact>
```

`check` MUST generate into a temporary directory and fail when committed output is stale.

## 4. Compatibility policy

Contract changes MUST be classified as:

- additive and backward compatible.
- behaviorally significant but schema compatible.
- deprecated.
- breaking.

CI MUST perform a semantic OpenAPI comparison and explicit checks for permission and event compatibility. A breaking change MUST require:

- an ADR or approved breaking-change record.
- a version increment.
- migration notes.
- a compatibility-window decision.
- updated contract fixtures and consumer tests.

Operation IDs, permission IDs, event names, event versions, and schema names are public identifiers. Renaming them is breaking unless an alias/deprecation path exists.

## 5. Generated TypeScript boundary

The TypeScript generator MUST consume only canonical artifacts under `contracts/`. It MUST NOT scrape a live server or infer APIs from frontend code.

Generated code MUST be isolated and marked as derived. Product code MUST NOT edit generated output. Generation MUST fail on:

- duplicate operation IDs.
- unsupported schemas.
- unknown authentication modes.
- invalid discriminated unions.
- unresolved references.
- missing expected error contracts.
- contract input outside the trusted repository path.

## 6. Runtime compatibility

The Rust service MUST expose a minimally sensitive metadata endpoint, normally `GET /api/_meta`, that reports:

- application and API versions.
- aggregate contract hash.
- public capability IDs.
- public transport locations.
- build revision.

The production frontend MUST embed the aggregate hash used at build time. A mismatch MUST be observable. The behavior MAY be warning, degraded mode, forced reload, or hard failure according to deployment policy, but silent mismatch is prohibited.

The endpoint MUST NOT disclose secrets, dependency versions that create unnecessary reconnaissance value, internal module configuration, or non-public authorization policy.

## 7. Contract ownership

Backend modules own the contract fragments they expose. The composition root owns final assembly and collision detection. Removing a module MUST remove its public contract only through an explicit compatibility-aware generator change.

## 8. Testing

Required tests include:

- byte-for-byte deterministic regeneration.
- JSON Schema validation of every artifact.
- generated TypeScript compilation.
- contract hash verification.
- route-to-OpenAPI coverage.
- event-to-AsyncAPI coverage.
- permission registry coverage.
- stale generated-output failure.
- additive and breaking diff fixtures.
- runtime metadata/frontend embedded-hash comparison.

## 9. Acceptance linkage

This specification is satisfied by `AC-WEB-011` through `AC-WEB-020`.

---

# Frontend Capability SDK

## 1. Purpose

The frontend capability SDK turns enabled backend modules into reusable, typed consumer primitives. It MUST reduce application code without hiding transport semantics, duplicating contracts, or forcing React into non-React consumers.

## 2. Layering

The SDK MUST have a framework-neutral core and a React adapter:

```text
contracts
    ↓
generated HTTP/event types
    ↓
client core
  ├── transport
  ├── errors
  ├── auth integration
  ├── pagination
  ├── idempotency
  ├── realtime
  ├── uploads
  └── capabilities
    ↓
React adapter
  ├── Query integration
  ├── Router integration
  ├── providers
  ├── hooks
  └── presentation guards
    ↓
product application
```

React-specific modules MUST depend on the core, never the reverse.

## 3. Package and export policy

The initial implementation SHOULD use one package with explicit subpath exports:

```text
@service/web-sdk/client
@service/web-sdk/auth
@service/web-sdk/authorization
@service/web-sdk/realtime
@service/web-sdk/uploads
@service/web-sdk/capabilities
@service/web-sdk/react
@service/web-sdk/testing
```

The package MUST expose only documented entry points. Product code MUST NOT import:

- internal generated directories.
- deep implementation paths.
- unversioned schema helpers.
- another package's private query keys.

The package MUST be tree-shakeable and MUST NOT install React as a runtime dependency of its framework-neutral entry points.

## 4. HTTP client generation

The baseline uses Orval to generate an exact-typed client and TanStack Query bindings from `contracts/openapi.json`. The implementation MUST follow ADR 0013:

- exact-pin the generator.
- run it against trusted repository-generated contracts only.
- run in an isolated CI/build environment without production secrets.
- disable unused generator surfaces.
- advisory-scan the package graph.
- compile and test generated output.
- review upgrades as code-generation supply-chain changes.

The generator SHOULD emit native `fetch`-based clients unless an ADR identifies a concrete need for another HTTP runtime.

## 5. Runtime client configuration

The SDK MUST provide one explicit client factory rather than hidden global mutation:

```ts
createServiceClient({
  baseUrl,
  credentials,
  headers,
  fetch,
  auth,
  onProblem,
  onContractMismatch,
})
```

It MUST support:

- same-origin relative URLs.
- alternate base URLs.
- injectable `fetch` for tests and non-browser runtimes.
- credentials policy.
- trace/request header propagation where allowed.
- authentication integration.
- abort signals and deadlines.
- normalized RFC 9457 errors.
- response request IDs.
- configurable retry behavior restricted by method/idempotency.
- observability hooks without request-body logging.

The SDK MUST NOT automatically retry non-idempotent operations without an idempotency key and explicit policy.

## 6. Generated versus semantic APIs

Every contracted operation MUST be callable through the generated client. Hand-written wrappers SHOULD exist only when they add semantic value, such as:

- `useCurrentSession`.
- `logoutEverywhere`.
- `useCurrentOrganization`.
- resumable upload orchestration.
- permission-aware route prerequisites.
- realtime-query synchronization.

Do not create one manual wrapper per endpoint merely to rename it.

## 7. Query integration

The React adapter MUST provide:

- a Query client factory with documented defaults.
- stable generated query keys.
- generated query and mutation options.
- cancellation through `AbortSignal`.
- standardized stale-time and retry classifications.
- problem-details error typing.
- SSR-neutral behavior even though SSR is not baseline.
- mutation invalidation hooks that can be extended by capabilities.

Query keys MUST derive from operation identity and normalized request parameters. Product code MUST be able to invalidate through exported key factories rather than string literals.

## 8. Capability adapters

A browser-facing module descriptor MUST declare some combination of:

- contract tags/operation IDs.
- event names.
- generated TypeScript exports.
- semantic utilities.
- React hooks.
- route prerequisites.
- query effects.
- testing fixtures.
- runtime metadata.

The machine-readable `frontend-capabilities.yaml` is normative for this mapping.

## 9. Error and support metadata

All expected API errors MUST become a common SDK error shape preserving:

- HTTP status.
- problem type.
- stable backend error code.
- title and detail safe for presentation.
- field violations.
- request ID.
- retryability classification.
- optional `Retry-After`.
- original typed error body where safe.

Unexpected parse/contract errors MUST be distinct from expected application problems.

## 10. Build and publishing

The SDK MUST:

- emit declarations.
- compile under strict TypeScript settings.
- preserve ESM semantics.
- declare browser/runtime support.
- avoid bundling duplicate React or Query runtimes.
- produce source maps according to policy.
- support workspace consumption before external publication.
- expose its generated-against contract hash.

Publishing outside the application workspace is optional. Internal workspace use is the default.

## 11. Acceptance linkage

This specification is satisfied by `AC-WEB-021` through `AC-WEB-030`.

---

# Web Authentication and Authorization Integration

## 1. Purpose

This specification integrates the base identity, session, JWT, OIDC, tenancy, and authorization capabilities into browser applications. It does not redesign backend identity.

## 2. Authentication modes

The SDK MUST support a declared authentication mode:

- `session` — same-origin opaque server-side session cookie; default for first-party web applications.
- `bearer` — externally supplied access token for mobile, public API, or separate-origin clients.
- `oidc-redirect` — browser authorization-code and PKCE flow terminating in a server-side session or approved token strategy.
- `none` — explicitly unauthenticated application.

Only compiled and configured modes may appear in capabilities metadata.

## 3. Session mode

In session mode:

- The session identifier MUST be stored in a `Secure`, `HttpOnly` cookie with an explicit `SameSite` policy.
- JavaScript MUST NOT receive, persist, or log the session secret.
- The API client MUST use the configured browser credentials policy.
- A session bootstrap endpoint MUST return the current public principal, session metadata, permission summary, and tenant context.
- Login and privilege elevation MUST rotate the server-side session identifier.
- Logout MUST clear client cache and realtime state in addition to revoking the server session.
- Expired or revoked sessions MUST produce a stable problem code.
- Tabs SHOULD converge after login/logout through a safe cross-tab signal that carries no credential.

The SDK MUST provide semantic primitives equivalent to:

```text
getSession
useSession
useCurrentPrincipal
login
logout
logoutAll
requireAuthenticated
requireAnonymous
```

## 4. CSRF and cross-origin controls

Cookie-authenticated unsafe methods MUST be protected by the backend's approved CSRF/cross-origin defense. The frontend adapter MUST:

- obtain and send any required anti-CSRF value without exposing the session identifier.
- avoid adding CSRF headers to untrusted origins.
- preserve same-origin defaults.
- treat CSRF rejection as a distinct typed problem.
- exercise negative tests for missing, stale, and cross-origin tokens.

CORS MUST NOT be enabled broadly merely to make development convenient. Vite development uses a proxy by default.

## 5. Bearer mode

The framework-neutral core MAY accept a token provider:

```ts
getAccessToken(): Promise<string | null>
```

The SDK MUST NOT prescribe local storage. Token persistence is a host-application security decision and MUST be documented by any profile that enables it.

Bearer integration MUST support:

- expiration-aware retrieval.
- one controlled refresh attempt.
- refresh single-flight.
- cancellation.
- logout/revocation.
- audience-specific clients.
- redacted diagnostics.

The SDK MUST prevent refresh loops.

## 6. OIDC browser flow

OIDC utilities MUST delegate authorization request construction, state, nonce, PKCE, token exchange, and account linking to the backend identity module unless an ADR explicitly chooses a public-client architecture.

The frontend MAY expose:

```text
beginOidcLogin(provider, returnTo)
completeOidcCallback
listLinkedIdentities
unlinkIdentity
```

`returnTo` values MUST be validated against approved same-origin locations.

## 7. Authorization presentation

The backend MUST include a public permission vocabulary and the principal's effective presentation permissions or claims suitable for UX decisions. The SDK MUST provide:

```text
can(permission, resourceContext?)
canAny(...)
canAll(...)
usePermission(...)
usePermissions(...)
RequirePermission
requirePermission
```

These controls hide, disable, redirect, or explain UI. They MUST NOT be described or tested as the security boundary.

Every protected backend operation MUST continue to authorize independently when invoked through HTTP, WebSockets, SSE-triggered commands, jobs, CLIs, or future adapters.

## 8. Tenant and organization context

When tenancy is enabled:

- Tenant context MUST be explicit in the session and/or selected route.
- The SDK MUST prevent accidental reuse of cached data across tenants by including tenant identity in appropriate query keys.
- Changing tenant MUST cancel or invalidate tenant-scoped queries, reset tenant-scoped local state, and re-establish realtime subscriptions.
- Tenant IDs MUST NOT be inferred solely from a mutable client store when the backend contract requires a route or header value.
- Cross-tenant authorization errors MUST retain the backend's generic disclosure policy.

## 9. Route prerequisites

Router helpers MAY enforce:

- authenticated-only routes.
- anonymous-only routes.
- tenant-required routes.
- permission-present routes.
- capability-present routes.

They MUST handle initial loading without flashing protected content and MUST avoid redirect loops. Deep links MUST preserve an approved return destination.

## 10. Cache and lifecycle behavior

On login, logout, principal change, privilege change, or tenant switch, the adapter MUST execute a defined cache policy. Sensitive per-principal queries MUST never remain visible to a subsequent principal in the same browser process.

Realtime session-revocation or permission-change events SHOULD trigger session revalidation rather than trusting event payloads as authority.

## 11. Testing

Required tests include:

- session bootstrap.
- login and logout.
- logout-all.
- CSRF rejection.
- session expiration.
- cross-tab logout.
- no credential in storage/logs.
- permission presentation.
- direct backend denial despite bypassing UI.
- tenant switch cache isolation.
- OIDC return-location validation.
- bearer refresh single-flight and loop prevention where bearer mode is enabled.

## 12. Acceptance linkage

This specification is satisfied by `AC-WEB-031` through `AC-WEB-040`.

---

# Realtime Browser Integration

## 1. Purpose

The realtime browser capability provides a typed, resilient consumer of the base WebSocket, SSE, and event-envelope modules. HTTP remains the source for reconstructing authoritative resource state unless an event contract explicitly guarantees otherwise.

## 2. Framework-neutral client

The SDK MUST expose a transport-neutral lifecycle:

```text
connect
disconnect
subscribe
unsubscribe
sendCommand          optional
connectionState
lastEventId
diagnostics
```

React hooks wrap this lifecycle but do not own transport correctness.

## 3. Typed messages

Message types MUST derive from AsyncAPI and shared JSON Schemas. The generated union MUST discriminate by stable event name and version. Unknown event types or versions MUST:

- not crash the connection loop.
- be observable.
- be ignored or routed to a compatibility handler according to policy.
- never be coerced into a known payload.

Runtime validation MUST be applied at the trust boundary when the selected generator/types do not inherently validate data.

## 4. Connection lifecycle

The client MUST implement:

- explicit states: idle, connecting, open, degraded, reconnecting, closed, unauthorized.
- exponential backoff with jitter and an upper bound.
- online/offline and visibility awareness without relying on them as perfect signals.
- cancellation and clean disposal.
- stable subscription identity.
- resubscription after reconnect.
- heartbeat/idle timeout behavior compatible with the server.
- authentication failure handling that does not create reconnect storms.
- observability hooks.

Backoff MUST reset only after a stable connection interval.

## 5. SSE

SSE support MUST address:

- `Last-Event-ID` or an equivalent resume cursor.
- named events.
- heartbeat comments.
- proxy buffering guidance.
- authentication constraints.
- browser-native versus fetch-stream implementation tradeoffs.
- cancellation.
- duplicate delivery.

If cookie authentication is sufficient, native `EventSource` MAY be used. If custom headers are required, the SDK MUST use an approved fetch-stream implementation and document browser support.

## 6. WebSockets

WebSocket support MUST address:

- URL derivation and approved protocols.
- origin checks on the server.
- upgrade-time authentication.
- post-upgrade session revalidation.
- maximum message size.
- command authorization.
- request/response correlation where commands are enabled.
- bounded client queues.
- slow or disconnected consumer behavior.
- graceful server drain/reconnect hints.

The browser MUST never assume a successful socket connection authorizes every subscription or command.

## 7. Query synchronization

Modules MAY declare event-to-query effects:

```yaml
event: organization.updated.v1
effects:
  - invalidate:
      operation_id: getOrganization
      parameters:
        id: "$message.data.organization_id"
  - invalidate:
      operation_id: listOrganizations
```

Supported effect types SHOULD include:

- invalidate.
- refetch.
- set/patch from a validated complete representation.
- remove.
- revalidate session.
- revalidate capabilities.

Invalidation is the default. Direct cache patching requires an event payload with a complete, version-compatible representation and conflict policy.

Effects MUST use generated query-key factories. They MUST include tenant and principal scope where applicable.

## 8. Ordering, replay, and duplicates

The client MUST tolerate at-least-once delivery and reconnect duplicates. When the event contract supplies sequence, revision, cursor, or occurred-at values, the SDK MAY use them to reject stale updates. It MUST NOT invent global ordering.

Missed-event recovery MUST be explicit:

- resumable stream.
- HTTP revalidation.
- full subscription snapshot.
- declared non-recoverable ephemeral semantics.

## 9. Multi-tab behavior

An optional cross-tab coordinator MAY avoid redundant connections. If implemented, it MUST:

- preserve correctness when leader election fails.
- carry no credentials.
- validate cross-tab messages.
- fall back to per-tab connections.
- shut down promptly.
- not be required for baseline correctness.

## 10. React integration

The React adapter SHOULD expose:

```text
RealtimeProvider
useRealtime
useConnectionState
useEvent
useSubscription
useRealtimeQuerySync
```

Hooks MUST unsubscribe on cleanup and avoid stale closure bugs. Handler exceptions MUST not terminate the connection manager.

## 11. Testing

Required tests include:

- typed message decoding.
- unknown-version behavior.
- reconnect with jitter under a fake clock.
- resubscription.
- unauthorized terminal state.
- session revocation.
- duplicate delivery.
- SSE resume.
- WebSocket command denial.
- query invalidation and safe patching.
- tenant switch.
- server drain.
- browser E2E across an actual Axum transport.

## 12. Acceptance linkage

This specification is satisfied by `AC-WEB-041` through `AC-WEB-050`.

---

# Static Web Delivery

## 1. Purpose

The `web-static` module allows the Rust service to serve the production browser application without a separate JavaScript server. It uses the existing Axum/Tower runtime and `tower-http` filesystem service rather than implementing file serving, range requests, or content metadata from scratch.

## 2. Route ownership

The composition root MUST reserve backend namespaces before installing the SPA fallback. At minimum:

```text
/api/*
/ws
/events
/_health/*
/_metrics
```

The exact list is generated from enabled modules.

The SPA fallback MUST:

- apply only to `GET` and `HEAD`.
- apply only after backend routes fail to match.
- never convert an API or transport 404 into `index.html`.
- reject path traversal and malformed paths.
- return the configured application shell.
- preserve a real 404 mode for deployments that do not use client routing.

## 3. Production artifacts

The production web build MUST emit:

- content-hashed JavaScript and CSS assets.
- an application shell.
- an asset manifest.
- embedded build revision.
- embedded aggregate contract hash.
- optional precompressed Brotli, gzip, or Zstandard variants supported by the selected server/browser policy.
- license notices required by dependencies.

The Rust build MAY embed the assets or copy them into the runtime image. The default SHOULD copy a directory into the final image to avoid recompiling Rust for every frontend-only change, unless single-binary distribution is an explicit profile goal.

Missing required production assets MUST fail startup or readiness; a production web profile MUST NOT silently expose only the API.

## 4. Cache policy

Default response policy:

```text
fingerprinted assets:
  Cache-Control: public, max-age=31536000, immutable

index.html and manifest-like bootstrap files:
  Cache-Control: no-cache

public runtime metadata:
  Cache-Control: no-store or short-lived according to deployment policy
```

ETags or equivalent validators SHOULD be enabled where supported. `index.html` MUST NOT be cached immutably because it selects the current asset graph.

## 5. Security headers

The module MUST integrate with the base HTTP security policy and define:

- Content-Security-Policy.
- `X-Content-Type-Options: nosniff`.
- frame-ancestor/clickjacking policy.
- referrer policy.
- permissions policy.
- HSTS at the appropriate TLS boundary.
- cross-origin opener/resource/embedder policies when application requirements permit.

CSP MUST avoid `unsafe-eval` in production. Inline scripts/styles require an explicit nonce/hash strategy or must be removed. Development CSP MAY be less strict for HMR but MUST be separate from production policy.

## 6. MIME, compression, and ranges

The implementation MUST use battle-tested serving middleware. It MUST:

- emit correct content types.
- negotiate only available precompressed variants.
- set `Vary` correctly.
- avoid double compression.
- support range requests where the underlying service safely supports them.
- avoid serving source files, environment files, contracts intended only for build use, or package metadata unintentionally.

## 7. Source maps

Source-map policy MUST be explicit:

- disabled.
- private and uploaded to an error-monitoring service.
- publicly served.

Production profiles SHOULD NOT publicly serve source maps by default. If maps are uploaded, the release identifier MUST match build metadata.

## 8. Development integration

Development MUST use Vite's development server with proxy rules for API and realtime paths. The generator MUST produce a single source of route-path configuration used by:

- Vite proxy configuration.
- SDK runtime configuration.
- Rust route assembly.
- browser E2E configuration.

HMR MUST remain a Vite concern. Axum MUST NOT attempt to implement HMR.

The development proxy MUST support:

- HTTP API requests.
- WebSocket upgrades.
- SSE streaming without buffering.
- secure-cookie development policy.
- configurable Rust target.
- IPv4/IPv6 host consistency.

## 9. Base path and reverse proxies

The module MUST support deployment at `/` and an explicitly configured public base path. Asset URLs, router base, API URLs, WebSocket URLs, and metadata endpoints MUST agree.

Trusted proxy configuration remains governed by the base HTTP specification. Static delivery MUST not broaden trust of forwarded headers.

## 10. Container build

The reference container SHOULD use:

1. A pinned Node/pnpm stage to install and build the web workspace.
2. A pinned Rust stage to compile the server.
3. A minimal non-root runtime image containing the server and web artifacts.

Build caches MUST not make lockfile changes invisible. Production dependency installation MUST be frozen. Secrets MUST use build-secret mechanisms and MUST not be copied into layers or client bundles.

## 11. Observability

Expose metrics for:

- static requests by status and asset class.
- bytes served.
- cache-control class.
- fallback count.
- missing-asset failures.
- contract mismatch reports.

Asset path labels MUST be normalized to avoid high cardinality.

## 12. Testing

Required tests include:

- asset serving.
- immutable cache headers.
- non-immutable shell.
- deep-link fallback.
- API 404 preservation.
- path traversal rejection.
- content type.
- precompressed negotiation.
- missing production build behavior.
- base-path deployment.
- CSP/security headers.
- Vite HTTP/WebSocket/SSE proxy.
- production container smoke test.

## 13. Acceptance linkage

This specification is satisfied by `AC-WEB-051` through `AC-WEB-060`.

---

# Frontend Data, State, Forms, Errors, and Uploads

## 1. State ownership

The generated application MUST use the following ownership model:

| State | Owner |
|---|---|
| Remote resources, lists, mutations, cache | TanStack Query |
| Route parameters, filters, pagination links, shareable UI state | TanStack Router/search parameters |
| Form drafts and validation state | React Hook Form or component-local form state |
| Authenticated principal/session resource | TanStack Query plus auth lifecycle helpers |
| Realtime connection manager | Framework-neutral SDK lifecycle |
| Ephemeral client-only state | Component state or optional Zustand |
| Durable server truth | Rust application and persistence modules |

Data fetched from the API MUST NOT be copied into Zustand as a routine pattern.

## 2. Query defaults

The SDK MUST define documented defaults for:

- retry classifications.
- mutation retry behavior.
- stale time.
- garbage collection.
- focus and reconnect refetch.
- offline behavior.
- cancellation.
- problem-details error handling.

Defaults MAY be overridden by operation metadata or product code. Authentication, validation, authorization, conflict, and not-found errors MUST not receive generic retry loops.

## 3. Pagination and collection utilities

The SDK MUST expose standard primitives for the backend's cursor-pagination convention:

- typed cursor parameters.
- finite queries.
- infinite-query options.
- next/previous cursor extraction.
- filter/sort normalization.
- reset-on-filter-change behavior.
- URL serialization.
- duplicate-item reconciliation policy.

Cursors MUST remain opaque to product code. Pagination utilities MUST preserve tenant and permission scope in query keys.

## 4. Idempotent mutations and concurrency

For operations marked idempotent-key capable, the SDK MUST support:

- cryptographically strong idempotency-key generation.
- caller-supplied keys for workflow recovery.
- stable reuse across one controlled retry sequence.
- no reuse across unrelated business actions.
- visibility in diagnostics without treating the key as a credential.

Optimistic-concurrency contracts such as ETags or version fields MUST have standard client helpers. Conflict responses MUST become typed problems suitable for refresh, merge, or user-directed resolution.

## 5. RFC 9457 problem handling

The application MUST have one normalized error pipeline. It MUST preserve:

- status.
- problem `type`.
- title.
- presentation-safe detail.
- stable application error code.
- field violations.
- request ID.
- retry-after metadata.
- conflict/current-version metadata where defined.
- underlying cause category.

The UI MUST be able to present the request ID for support without exposing stack traces or internal SQL/provider details.

Network errors, aborted requests, invalid responses, and contract mismatches MUST remain distinguishable from application problems.

## 6. Forms

React Hook Form is the default for nontrivial forms. Zod MAY provide client-side validation and transformation, but:

- Rust remains authoritative.
- Client schemas MUST derive from or be tested against contract schemas when they represent the same request.
- Client validation MUST not reject valid server inputs through drift.
- Server field violations MUST map back to controls.
- Global form errors MUST remain visible.
- submission MUST be cancellable or protected against double submission.
- accessibility semantics MUST be preserved.
- destructive actions SHOULD require deliberate confirmation proportional to risk.

Simple forms MAY use native/component-local state when a form library adds no value.

## 7. Local state

Zustand is optional. A new durable store requires a documented reason and ownership statement. Appropriate uses include:

- editor/workbench state not yet persisted.
- transient multi-step UI workflows.
- panel layout.
- local selection sets.
- safe local preferences.

Inappropriate uses include:

- lists fetched from the backend.
- the canonical user or organization record.
- a second permission cache.
- secrets or bearer tokens by default.
- data whose invalidation is already handled by TanStack Query.

Persisted local state MUST be versioned and migrated or discarded safely.

## 8. Uploads

The upload adapter MUST support the base object-storage and quarantine workflow. It MUST provide:

- metadata/initiation request.
- direct or proxied upload according to backend contract.
- streaming/progress where browser APIs permit.
- cancellation.
- multipart/resumable behavior when enabled.
- checksum support.
- completion/finalization.
- scan/quarantine status polling or realtime updates.
- retry semantics that do not duplicate objects.
- cleanup of abandoned uploads.
- typed rejection reasons.

A signed upload URL is a capability, not an authorization bypass. The backend MUST authorize initiation and completion. Object availability MUST remain false until required validation/scanning completes.

## 9. Feature flags and capabilities

The SDK MUST distinguish:

- structural compiled capabilities from `capabilities.json`.
- runtime provider availability.
- product feature flags.
- entitlements/permissions.

A capability check answers whether an integration exists. A feature flag answers whether behavior is enabled for a context. A permission answers whether the current principal may act. Product code MUST not conflate them.

## 10. Tenant-sensitive state

On tenant change:

- cancel in-flight tenant-scoped work where possible.
- invalidate or remove tenant-scoped queries.
- reset tenant-local form/store state.
- reconnect realtime subscriptions.
- update route state.
- prevent stale tenant content from flashing.

## 11. Testing

Required tests include:

- query retry classifications.
- cancellation.
- cursor pagination and URL round-trip.
- idempotency-key reuse boundaries.
- optimistic-concurrency conflict.
- RFC 9457 field mapping.
- form server-error mapping.
- Zustand absence from server-state paths.
- upload cancel/resume/finalize/quarantine.
- feature/capability/permission distinction.
- tenant switch isolation.

## 12. Acceptance linkage

This specification is satisfied by `AC-WEB-061` through `AC-WEB-068`.

---

# Frontend Testing, Security, and Accessibility

## 1. Test strategy

The suite MUST include:

1. Framework-neutral SDK unit tests.
2. React component/integration tests.
3. Contract generation and consumer compilation tests.
4. Browser E2E tests against the actual Rust service.
5. Security negative tests.
6. Accessibility checks.
7. performance and bundle-budget checks.
8. generator/profile fixtures.

Tests SHOULD favor observable behavior over implementation details.

## 2. Unit and component tests

Use Vitest and Testing Library for the React baseline. Tests MUST cover:

- provider composition.
- loading, empty, error, and success states.
- route prerequisites.
- session lifecycle.
- permissions presentation.
- query mutation and invalidation.
- forms and field errors.
- upload state.
- realtime cleanup.

Fake clocks MAY be used for backoff, token refresh, and timeout behavior, but tests MUST restore global state.

## 3. API mocking

MSW is the baseline browser/API mock layer. `@msw/source` MAY generate handlers from OpenAPI only after its compatibility with the pinned OpenAPI and MSW versions is proven.

Generated mocks MUST be treated as a convenience, not a substitute for E2E tests. They MUST:

- derive from trusted contracts.
- preserve expected error responses.
- allow scenario-specific overrides.
- fail on unhandled requests in tests except for explicit allowlists.
- avoid impossible states where practical.
- not contain production secrets.

Fixture builders SHOULD produce valid defaults with explicit overrides.

## 4. Browser E2E

Playwright tests MUST exercise a production-like build or the documented development topology against the actual Axum application and disposable infrastructure.

Required E2E scenarios include:

- unauthenticated and authenticated deep links.
- login/logout/session expiry.
- permission-denied UI plus direct API denial.
- tenant switching.
- pagination and filters.
- RFC 9457 rendering with request ID.
- upload workflow.
- WebSocket reconnect.
- SSE resume.
- realtime query invalidation.
- SPA fallback.
- asset caching.
- contract mismatch handling.

The suite MUST retain diagnostic traces/screenshots/videos on failure according to CI retention policy, with secret/PII controls.

## 5. Browser support

The project MUST declare a supported browser matrix and test at least:

- current Chromium.
- current Firefox.
- current WebKit/Safari-equivalent engine.

A lower compatibility tier MAY receive smoke tests only, but the distinction MUST be documented. Browser APIs used by uploads, streams, crypto, or cross-tab coordination require feature detection or an explicit support floor.

## 6. Web security

Security requirements include:

- no session credential in JavaScript-visible storage.
- no production secrets in Vite-exposed environment values.
- output encoding and safe React rendering.
- no unsafe HTML without a reviewed sanitizer and narrow API.
- production CSP without `unsafe-eval`.
- CSRF negative tests.
- clickjacking protections.
- safe redirect validation.
- dependency/advisory scanning.
- lockfile enforcement.
- source-map policy.
- upload content/type distrust.
- no client-side permission check presented as enforcement.
- redacted logs and browser telemetry.

Any `dangerouslySetInnerHTML` use MUST be isolated, reviewed, and tested.

## 7. Code-generation security

Code generators execute with developer/CI privileges and MUST be treated as supply-chain-sensitive build tools.

The Orval pipeline MUST:

- use an exact version.
- consume only a canonical repository path.
- reject URL input in the baseline task.
- run without production secrets.
- run in a constrained build job.
- disable unused output modes/plugins.
- scan advisories before update.
- produce reviewable diffs.
- compile generated output.
- require explicit approval for major/minor upgrade according to policy.

Generated mock or MCP features are excluded unless separately reviewed.

## 8. Accessibility

The default target is WCAG 2.2 AA for generated shells and reusable SDK UI helpers. Product applications remain responsible for their visual components, but the kit MUST not create barriers.

Requirements include:

- semantic landmarks.
- keyboard operation.
- visible focus.
- focus management after navigation/dialogs/errors.
- labels and descriptions.
- live-region strategy for asynchronous status.
- error summaries linked to controls.
- reduced-motion support.
- color-independent status communication.
- correct document title.
- skip navigation.
- accessible loading and empty states.

Automated axe checks MUST run on representative routes. Manual keyboard and screen-reader checks MUST be included in release criteria because automated tools are incomplete.

## 9. Performance

The suite MUST define initial budgets for:

- JavaScript entry size.
- route chunk size.
- CSS.
- number of startup requests.
- application-shell render.
- route transition.
- API waterfall depth.
- long tasks.

Budgets are configuration, not universal constants. CI MUST at minimum detect large regressions. Generated SDK modules MUST be tree-shakeable and avoid importing all capabilities into every route.

## 10. Supply chain and licensing

The Node workspace MUST use:

- a committed lockfile.
- frozen installs in CI.
- an approved package manager version.
- dependency advisory scanning.
- license/source policy where available.
- automated update PRs with tests.
- no lifecycle-script allow-all policy.
- provenance/SBOM integration with the base release process.

## 11. Acceptance linkage

This specification is satisfied by `AC-WEB-069` through `AC-WEB-076`.

---

# Web Profiles, Generator, and Upgrades

## 1. Purpose

Web capabilities MUST participate in the same module/profile/generator model as backend capabilities. Adding web support to an existing project is a supported migration, not a manual copy operation.

## 2. New modules

The extension defines these runtime modules:

- `consumer-contracts`
- `asyncapi-contracts`
- `web-sdk-core`
- `web-react`
- `web-auth`
- `web-authorization`
- `web-realtime`
- `web-uploads`
- `web-feature-flags`
- `web-tenancy`
- `web-static`
- `web-forms`
- `web-local-state`

`web-testing` remains a tooling module and MUST NOT appear in a runtime profile
or lifecycle selection. Its test harness runs separately from generated runtime
state.

Exact dependencies and application-template ownership are in the extension
module catalog. Runtime modules MUST be independently selectable only when
their dependency closure is valid. Provider-like choices MUST use existing
provider-slot/conflict mechanisms rather than ad hoc flags.

## 3. New profiles

The extension defines:

- `web-sdk-only` — contract and framework-neutral SDK without a served UI.
- `web` — authenticated browser application with static production delivery.
- `realtime-web` — authenticated web application with WebSocket/SSE integration.
- `saas-web` — SaaS profile plus organizations, uploads, feature flags, realtime, and web delivery.
- `full-reference-web` — reference/CI coverage of all compatible web modules.

Profiles MUST inherit base profiles rather than duplicate their entire runtime
module lists. Profiles MUST exclude `web-testing` and every other tooling
module.

## 4. Installed lifecycle commands

The lifecycle tool MUST be installed from the canonical repository at a full
immutable release revision:

```bash
REV=<full-lowercase-40-hex-revision>
OMNIUS_RELEASE_REVISION="$REV" cargo install --locked \
  --git https://github.com/bmanturner/omnius.git \
  --rev "$REV" \
  --bin cargo-service \
  omnius-generator
```

The installed CLI MUST support web transitions through the canonical surface:

```text
cargo service new <NAME> --profile web
cargo service add <MODULE>
cargo service remove <MODULE>
cargo service profile set <PROFILE>
cargo service update
cargo service doctor
cargo service diff
```

`cargo-service` is the only public lifecycle convention. Repository contract
generation remains a separate xtask concern and MUST NOT be exposed as a
project-owned lifecycle command.

## 5. Idempotency and ownership

Running the same lifecycle operation twice MUST produce no duplicate files,
dependencies, routes, scripts, or configuration.

The generator MUST distinguish:

- hashed kit-owned and derived files;
- deterministic managed regions;
- application-owned files, which are never overwritten or deleted;
- `Cargo.lock` as a semantically validated shared dependency lock.

Web/SDK/contract application templates MUST be embedded through an explicit
safe inventory. On first selection, the generator creates only missing regular
files and immediately records them as application-owned. Existing regular files
are preserved; symlinks and unsafe paths are refused. Removal and re-add MUST
preserve these application-owned files. Framework Rust, tooling, root `.sqlx`,
and framework migration SQL are forbidden template inventory entries.

## 6. Existing-project adoption

`profile set web` or an explicit web runtime-module addition MUST:

1. Validate exact schema-2 release identity and the current runtime selection.
2. Confirm required backend prerequisites.
3. Add extension runtime-module state without tooling modules.
4. Create missing package-manager workspace and lock policy files as
   application-owned templates.
5. Create missing deterministic contract scripts and SDK/product-shell assets.
6. Create missing development proxy and production static-delivery
   configuration.
7. Preserve every existing application-owned regular file.
8. Resolve and seal the exact Cargo lock/package graph once in a sibling stage.
9. Apply ordinary files, Cargo lock, and state through the durable transaction
   journal.

Conflicts, unsafe paths, dirty ownership, source overrides, or a mismatched
release MUST stop before mutation with a stable diagnostic.

## 7. Removal

Removing web runtime support MUST:

- remove only managed runtime registrations and matching trusted generated
  artifacts;
- preserve application-owned UI, SDK, contract, and configuration files in
  place;
- preserve backend data and migrations;
- explain remaining runtime dependencies;
- remove static routes only after proving no selected runtime module requires
  them;
- leave a clean, locked profile or abort without mutation.

## 8. Update strategy

`cargo service update` MUST support the approved one-way transition from at
least one prior released web-suite identity. Rehearsal fixtures MUST include:

- untouched generated project;
- project with application-owned routes/components;
- project with approved managed-region edits;
- project using web-sdk-only;
- project using saas-web;
- project with an intentionally stale contract;
- project with a dependency override.

Update MUST preserve unrelated application dependency records, bound the
package-graph change to the old/new service-kit closures, validate the
immutable Git source/revision, and write the sealed lock before schema-2 state.

## 9. Monorepo tooling

The baseline uses a pinned Node LTS, Corepack-compatible package-manager declaration, and pnpm workspace. The generator MUST create:

- root `package.json` with `packageManager`.
- `pnpm-workspace.yaml`.
- committed `pnpm-lock.yaml`.
- strict TypeScript configuration.
- scripts for check, generate, test, E2E, and build.
- CI frozen-install behavior.

Alternative package managers require an ADR and adapter rather than conditionals scattered through templates.

## 10. Profile verification

Every profile MUST be generated in a clean directory and run:

- Rust formatting/lint/test/build appropriate to the profile.
- frozen Node install where web is present.
- contract generation/check.
- strict TypeScript check.
- frontend unit tests.
- frontend production build.
- E2E smoke test.
- collision/ownership checks.
- advisory and license policy.

## 11. Acceptance linkage

This specification is satisfied by `AC-WEB-077` through `AC-WEB-080` plus the suite-wide criteria in specification 34.

---

# Web Suite Roadmap, Acceptance, and Traceability

## 1. Implementation phases

The machine task graph is normative. The conceptual phases are:

### W0 — Integration and compatibility

- Load extension catalogs.
- resolve and audit the Node dependency graph.
- prove the code-generation security controls.
- establish deterministic environment and toolchain pins.

### W1 — Consumer contract seam

- deterministic OpenAPI.
- AsyncAPI and event schemas.
- permissions and capabilities.
- aggregate manifest/hash.
- semantic compatibility checks.

### W2 — SDK foundation

- TypeScript workspace.
- Orval generated client.
- framework-neutral runtime.
- RFC 9457 errors, pagination, idempotency, contract mismatch.

### W3 — React application integration

- Query and Router.
- session/auth lifecycle.
- presentation authorization.
- forms, tenant state, feature flags, uploads.

### W4 — Realtime

- typed WS/SSE clients.
- reconnect, resume, session revalidation.
- query-effect integration.

### W5 — Delivery

- Vite development proxy.
- production asset build.
- Axum static service.
- cache and security policies.
- container integration.

### W6 — Verification

- unit/component/contract tests.
- actual-backend Playwright.
- security negative tests.
- accessibility.
- browser matrix.
- performance budgets.

### W7 — Generator and upgrades

- web modules/profiles.
- idempotent add/remove.
- managed ownership.
- prior-version upgrade rehearsal.

### W8 — Release evidence

- all profile builds.
- traceability.
- risk review.
- SBOM/provenance integration.
- release notes and operational runbook.

## 2. Scheduling against existing work

New tasks depend on existing task IDs. An agent MUST not begin a web task before its prerequisites are actually complete merely because the task file is present.

The first user-visible page is not a milestone ahead of deterministic contract export and SDK compilation.

## 3. Suite-level definition of done

The suite is complete only when all of the following hold:

- The original bundle and extension validate as one graph.
- No existing path or stable ID was overwritten.
- Every enabled HTTP operation is represented in OpenAPI.
- Every browser-facing asynchronous message is represented in AsyncAPI.
- Permissions and capabilities derive from backend registries.
- Contract output is deterministic and hashable.
- A semantic compatibility check exists.
- TypeScript clients compile from generated contracts.
- Product code contains no routine duplicate DTO declarations.
- TanStack Query owns server state.
- Route/search state uses Router conventions.
- Zustand is absent unless a client-local ownership rationale exists.
- Session cookies remain inaccessible to JavaScript.
- CSRF and direct authorization negative tests pass.
- Frontend permission helpers are documented as presentation only.
- Tenant changes isolate cache, routes, local state, and realtime.
- RFC 9457 errors preserve request IDs.
- Pagination, idempotency, concurrency, and upload utilities exist.
- WebSocket and SSE clients reconnect safely and resubscribe.
- Realtime events can invalidate or safely patch generated query keys.
- Vite development proxy works for HTTP, WS, and SSE.
- Axum serves production assets and deep links without swallowing API 404s.
- Asset and shell cache policies are correct.
- Production CSP and security headers are present.
- Vitest/Testing Library/MSW tests pass.
- Playwright tests the real Rust service.
- accessibility automated and manual gates are recorded.
- browser support and performance budgets are declared.
- web profiles generate, build, test, add, remove, and upgrade idempotently.
- dependency advisories, licenses, and code-generation risks are reviewed.
- recommendation traceability reports no unaccounted recommendation.

## 4. Traceability artifacts

The following are normative machine sources:

- `acceptance-criteria.yaml`
- `tasks.yaml`
- `module-catalog.yaml`
- `profiles.yaml`
- `frontend-capabilities.yaml`
- `risk-register.yaml`
- `recommendation-traceability.csv`
- `merge-plan.yaml`

The validator MUST reject unknown references, duplicate IDs, dependency cycles, profile requirement failures, path collisions, malformed examples, invalid schemas, stale hashes, and unresolved drafting markers.

## 5. Deviations

A deviation from an accepted ADR or normative MUST requires:

- an ADR amendment.
- rationale and alternatives.
- impact on public contracts.
- affected acceptance IDs.
- migration plan.
- updated machine artifacts.
- validation.

A package substitution is not a minor implementation detail when it changes generated API shape, runtime semantics, auth handling, or supply-chain exposure.

## 6. Release gate

The release report MUST list:

- exact Node, package-manager, TypeScript, browser-library, test-tool, and generator versions.
- dependency advisory status.
- generated profile matrix.
- contract aggregate hashes.
- breaking-change report.
- browser/a11y/performance results.
- known risks and accepted exceptions.
- SHA-256 manifest for the specification extension.

## 7. Acceptance linkage

All `AC-WEB-001` through `AC-WEB-080` MUST pass. No criterion may be silently waived; an accepted exception must name the criterion and expiry/review condition.

---

# Use React, TypeScript, and Vite for the Default Web Client

## Context

The service kit needs a browser implementation with broad ecosystem support, mature testing, straightforward static output, and no required JavaScript production server. The backend architecture must remain usable by other frontend frameworks.

## Decision

The default `web` profile uses React, TypeScript, and Vite.

- React provides the default UI runtime.
- TypeScript is mandatory under strict settings.
- Vite provides development HMR, proxying, and production static output.
- The framework-neutral SDK contains no React dependency.
- Product UI remains application-owned.
- No component library, CSS solution, or design system is selected here.

## Rationale

This combination is well understood, works with a static-production topology, and integrates with mature Router, Query, testing, and accessibility tooling. It does not require Axum to emulate frontend development infrastructure.

## Consequences

- A pinned Node LTS and package manager become build dependencies for web profiles.
- The release process must scan both Rust and Node dependency graphs.
- Alternative web frameworks require adapters and an ADR but can reuse the contracts and client core.
- SSR is not implied.

## Rejected alternatives

- A hand-written DOM client: too much infrastructure and poor ecosystem leverage.
- A mandatory JavaScript SSR server: unnecessary operational complexity for the baseline.
- Leptos as the sole default: attractive for all-Rust deployments but a smaller frontend ecosystem and weaker portability for non-Rust consumers.
- Framework-neutral product UI: tends to produce a lowest-common-denominator abstraction.

---

# Derive Frontend Integrations From Backend Consumer Contracts

## Context

Without a formal boundary, frontend projects routinely duplicate DTOs, hand-code fetch wrappers, invent incompatible error handling, and integrate backend modules inconsistently.

## Decision

The Rust composition root generates deterministic OpenAPI, AsyncAPI, permission, capability, and contract-manifest artifacts. TypeScript HTTP/event types and baseline client bindings derive from those artifacts.

Every browser-facing module declares its frontend exposure. Generated operation access is universal; hand-written hooks/utilities are added only when they provide semantic behavior.

## Consequences

- Stable operation, permission, event, and capability identifiers are public API.
- Contract generation and semantic diffing become CI gates.
- Generated code is kit-owned.
- The same client core can serve React, Expo, CLI, or other consumers.
- Backend route/event coverage must be verifiable.

## Rejected alternatives

- Manual SDKs as the default: high drift and repetitive maintenance.
- Inferring contracts from TypeScript: makes the backend depend on a consumer representation.
- Generating complete product UI: contracts do not contain enough product/design meaning.

---

# Separate Server, URL, Form, Realtime, and Client-Local State

## Context

Frontend boilerplates often introduce a global store that duplicates backend resources already cached by a server-state library. This creates conflicting sources of truth and difficult invalidation.

## Decision

- TanStack Query owns remote/server state.
- TanStack Router owns route and shareable URL state.
- React Hook Form or component state owns form state.
- The framework-neutral realtime client owns connection lifecycle.
- Component state or optional Zustand owns genuinely client-local state.
- Rust remains authoritative for durable state.

Zustand is optional and MUST NOT be used as a routine mirror of API resources, permissions, session records, or tenant resources.

## Consequences

- Query keys and invalidation are public SDK concepts.
- Tenant and principal changes require explicit cache isolation.
- Local persisted stores require versioning and ownership documentation.
- Semantic hooks may compose these systems but may not collapse them into one global store.

## Rejected alternatives

- Zustand/Redux for all data: duplicates Query behavior and invites drift.
- No server-state cache: loses mature concurrency, cancellation, retries, and invalidation.
- URL state in a global store: breaks shareability, navigation, and browser semantics.

---

# Default to Same-Origin Static Delivery and Keep SSR Out of the Baseline

## Context

A browser application can be deployed as static assets served by Axum, from a CDN, or behind a JavaScript SSR runtime. The default should minimize operational components while supporting secure first-party sessions.

## Decision

The default `web` profile:

- builds a Vite SPA.
- serves production assets from Axum using `tower-http`.
- uses same-origin API, session, WebSocket, and SSE paths.
- uses the Vite dev server with proxying in development.
- does not include SSR, React Server Components, or a Node production server.

Static CDN and separate-origin deployments are supported configuration variants. SSR requires a new adapter/profile and ADR.

## Consequences

- Cookie/CORS complexity is minimized in the default.
- SEO/content requirements that truly need server rendering are not solved by the baseline.
- The static service must implement correct fallback, cache, CSP, and asset behavior.
- A future Leptos or JavaScript SSR adapter can reuse contracts and client core.

## Rejected alternatives

- Always separate frontend and API origins: needless default CORS/cookie complexity.
- Mandatory SSR: adds runtime and deployment coupling many applications do not need.
- Custom Rust file server: duplicates hardened `tower-http` behavior.

---

# Use an Exact-Pinned, Constrained Orval Pipeline for OpenAPI Clients

## Context

The earlier design discussion considered `openapi-typescript`, `openapi-fetch`, and `openapi-react-query`. The maintainers subsequently deprecated the fetch and React Query packages. A maintained generator is still preferable to hand-writing endpoint clients.

Orval has broad OpenAPI client and TanStack Query generation support, but recent security advisories demonstrate that code generation from untrusted specifications is equivalent to executing a build-time supply-chain input.

## Decision

Use Orval as the baseline OpenAPI-to-TypeScript client/query generator, under these mandatory controls:

1. Exact version pin in the lockfile and package manifest.
2. Input restricted to the canonical repository-generated `contracts/openapi.json`.
3. No remote URL input in the baseline generation command.
4. Isolated generation job without production secrets or deploy credentials.
5. Disable unused mock, MCP, Zod, and plugin surfaces by default.
6. Dependency advisory scanning and explicit upgrade review.
7. Reviewable deterministic output.
8. strict TypeScript compilation and runtime integration tests.
9. An adapter boundary so the generator can be replaced without changing product code imports.
10. A Phase W0 compatibility and security experiment before implementation.

## Consequences

- Generated shape is not exposed directly as the only product API; public SDK subpaths insulate product code.
- Updating Orval is treated as a supply-chain-sensitive change.
- The deprecated openapi-fetch/openapi-react-query stack is not introduced.
- If Orval fails the W0 gate, the agent must record an ADR amendment and select another maintained contract generator rather than building a broad hand-written SDK.

## Rejected alternatives

- Deprecated openapi-fetch/openapi-react-query packages.
- Unconstrained code generation from URLs or user-supplied contracts.
- Hand-written clients for every endpoint.
- A custom generator before existing maintained options have been proven unsuitable.

---

# Use AsyncAPI 3.1 and JSON Schema for Browser-Facing Realtime Contracts

## Context

OpenAPI does not adequately describe asynchronous channels, protocol bindings, subscriptions, event direction, resume semantics, or versioned messages. The base kit already defines event envelopes and WebSocket/SSE transports.

## Decision

Browser-facing asynchronous contracts use AsyncAPI 3.1 with JSON Schema-compatible message payload definitions.

- OpenAPI remains authoritative for HTTP.
- AsyncAPI describes channels, operations, protocol bindings, security, event names/versions, and payloads.
- Shared schema generation MUST avoid divergent HTTP/event representations.
- TypeScript event unions derive from these artifacts.
- Runtime validation is applied at the browser trust boundary when needed.
- Event-to-query effects are separate machine metadata tied to stable event and operation IDs.

## Consequences

- Event names and versions become public compatibility identifiers.
- AsyncAPI validation and deterministic generation become CI gates.
- The contract does not promise ordering or replay unless the transport/module explicitly provides it.
- Realtime can be consumed by non-React clients.

## Rejected alternatives

- Encoding realtime behavior only in prose.
- Pretending OpenAPI callbacks fully describe interactive browser channels.
- Hand-maintained TypeScript event unions.
- Treating WebSocket payloads as untyped JSON.

---

# Integrating This Suite Into an Existing Specification Checkout

This extension assumes the original Omnius specification bundle is already present and implementation may already be underway. Integration is therefore additive and preserves every existing identifier.

## Non-destructive policy

The extension:

- Adds numbered specifications beginning with `25-`.
- Adds ADRs beginning with `adr/0009-`.
- Adds tasks `T130` through `T149`.
- Adds acceptance criteria in the `AC-WEB-*` namespace.
- Adds modules and profiles that do not reuse existing IDs.
- Places all machine-readable additions below `machine/extensions/web-application-suite/`.
- Does not replace canonical files such as `machine/module-catalog.yaml`, `machine/tasks.yaml`, or `AGENTS.md`.

The implementation agent MUST NOT renumber, rewrite, or mark existing requirements obsolete solely because this suite was added.

## Machine-catalog integration

`machine/extensions/web-application-suite/merge-plan.yaml` describes the canonical targets. There are two acceptable implementation approaches:

1. **Overlay-aware tooling:** make validators and generators read the base catalogs plus extension catalogs.
2. **Controlled canonical merge:** append the extension entries to the canonical catalogs through a deterministic migration command.

Whichever approach is selected MUST:

- Reject duplicate IDs.
- Preserve order deterministically.
- validate the merged module dependency graph and profiles.
- Record the extension version that was applied.
- Be idempotent.
- Avoid modifying application-owned source files.

Do not copy values manually between YAML files. Implement one repeatable merge or overlay mechanism and test it.

## Work already underway

Existing unblocked backend tasks continue normally. New web tasks become eligible only when their declared prerequisites are complete. Addition of this suite does not authorize broad refactoring.

When the suite reveals a genuine incompatibility:

1. Create an ADR amendment.
2. Add a narrowly scoped prerequisite task.
3. Update traceability.
4. Preserve completed behavior unless the amendment explicitly supersedes it.

## Recommended first integration commit

The first commit should contain only:

- The extension files.
- Validator execution in CI.
- Overlay or merge support for the machine catalogs.
- No React application implementation.

The first implementation milestone is deterministic consumer-contract export. The Vite application is intentionally downstream of that seam.

---

# Autonomous Agent Handoff — Web Application Feature Suite

You are extending an in-progress Omnius implementation. Read the original `AUTONOMOUS_AGENT_HANDOFF.md`, all accepted ADRs, this handoff, specifications `25` through `34`, and the extension machine catalogs before changing code.

## Governing rules

1. This suite is append-only. Preserve existing requirement, task, acceptance, module, and profile IDs.
2. Finish currently unblocked prerequisites rather than abandoning them to start visual frontend work.
3. Implement the backend-to-consumer contract seam before creating product UI.
4. Never hand-author a TypeScript duplicate of a schema already present in the canonical OpenAPI, AsyncAPI, permissions, or capabilities contracts.
5. Browser-side permission checks affect presentation only. The Rust backend remains authoritative.
6. TanStack Query owns backend/server state. Do not mirror query resources into Zustand.
7. Generated files are kit-owned and never manually edited.
8. Code generation consumes only repository-generated, trusted contracts and runs without production secrets.
9. Every browser-facing module declares its frontend capability surface. Every headless module explicitly declares `exposure: none`.
10. Do not introduce SSR, a component library, a design system, or a separate JavaScript server into the baseline profile without a new ADR.

## Execution order

Follow `machine/extensions/web-application-suite/tasks.yaml`. At a high level:

1. Integrate extension catalogs and validate the merged graph.
2. Export deterministic OpenAPI, AsyncAPI, permission, capability, and contract-manifest artifacts.
3. Establish the TypeScript workspace, generated client, and framework-neutral runtime.
4. Implement React providers, Router, Query, auth, authorization, errors, forms, and uploads.
5. Implement typed realtime clients and query synchronization.
6. Implement Vite development integration and Axum production static delivery.
7. Add component, contract, browser, security, accessibility, and performance tests.
8. Add idempotent generator modules, profiles, and upgrade rehearsals.
9. Run the suite-level acceptance and traceability checks.

## Dependency-selection rule

Use the researched baseline in `machine/extensions/web-application-suite/dependency-baseline.toml` as an initial lock target, not as permission to bypass package-manager resolution. Run the Phase W0 compatibility experiments before implementation.

The OpenAPI TypeScript ecosystem changed after the original architectural discussion: `openapi-fetch` and `openapi-react-query` are deprecated. This suite selects Orval, exact-pinned and constrained by ADR 0013. Do not silently restore the deprecated stack.

## Completion evidence

For each task, record:

- Exact commands executed.
- Tests and profile builds.
- Generated-contract diffs.
- Dependency and advisory results.
- Acceptance IDs satisfied.
- Any deviation and its ADR.

A task is not complete merely because the application starts. Its declared acceptance criteria and negative tests must pass.

---

# Web Feature Suite Recommendation Traceability

Every recommendation in this extension is mapped to a normative specification and an independently testable acceptance criterion.

- Recommendations: **80**
- Included: **80**
- Intentionally omitted: **0**

| Recommendation | Requirement | Specification | Acceptance |
|---|---|---|---|
| `REC-WEB-001` | Ensure web profile has a documented same-origin production topology | `OMNIUS-025` | `AC-WEB-001` |
| `REC-WEB-002` | Ensure framework-neutral SDK does not depend on React | `OMNIUS-025` | `AC-WEB-002` |
| `REC-WEB-003` | Ensure every browser-facing module declares a frontend exposure | `OMNIUS-025` | `AC-WEB-003` |
| `REC-WEB-004` | Ensure every headless module explicitly declares no frontend exposure and a reason | `OMNIUS-025` | `AC-WEB-004` |
| `REC-WEB-005` | Ensure product UI imports only public SDK entry points | `OMNIUS-025` | `AC-WEB-005` |
| `REC-WEB-006` | Ensure baseline web profile requires no JavaScript production server | `OMNIUS-025` | `AC-WEB-006` |
| `REC-WEB-007` | Ensure frontend build records the aggregate contract hash | `OMNIUS-025` | `AC-WEB-007` |
| `REC-WEB-008` | Ensure web configuration is typed and rejects unknown production keys | `OMNIUS-025` | `AC-WEB-008` |
| `REC-WEB-009` | Ensure missing required production assets fail startup or readiness | `OMNIUS-025` | `AC-WEB-009` |
| `REC-WEB-010` | Ensure web topology and browser capabilities are observable without exposing secrets | `OMNIUS-025` | `AC-WEB-010` |
| `REC-WEB-011` | Ensure openAPI export is byte-for-byte deterministic | `OMNIUS-026` | `AC-WEB-011` |
| `REC-WEB-012` | Ensure every selected public HTTP operation is covered by OpenAPI | `OMNIUS-026` | `AC-WEB-012` |
| `REC-WEB-013` | Ensure asyncAPI export covers every selected browser-facing asynchronous message | `OMNIUS-026` | `AC-WEB-013` |
| `REC-WEB-014` | Ensure permissions contract derives from the backend authorization registry | `OMNIUS-026` | `AC-WEB-014` |
| `REC-WEB-015` | Ensure capabilities contract distinguishes compiled, runtime, flag, entitlement, and permission concepts | `OMNIUS-026` | `AC-WEB-015` |
| `REC-WEB-016` | Ensure contract manifest verifies individual and aggregate SHA-256 hashes | `OMNIUS-026` | `AC-WEB-016` |
| `REC-WEB-017` | Ensure contract check fails on stale committed output | `OMNIUS-026` | `AC-WEB-017` |
| `REC-WEB-018` | Ensure semantic diff detects breaking operation, permission, schema, and event changes | `OMNIUS-026` | `AC-WEB-018` |
| `REC-WEB-019` | Ensure typeScript generation rejects duplicate or missing stable operation identifiers | `OMNIUS-026` | `AC-WEB-019` |
| `REC-WEB-020` | Ensure runtime metadata and embedded frontend contract hashes are compared observably | `OMNIUS-026` | `AC-WEB-020` |
| `REC-WEB-021` | Ensure generated HTTP client compiles under strict TypeScript settings | `OMNIUS-027` | `AC-WEB-021` |
| `REC-WEB-022` | Ensure sDK exposes documented subpath exports without private deep imports | `OMNIUS-027` | `AC-WEB-022` |
| `REC-WEB-023` | Ensure client factory supports relative and explicit base URLs plus injectable fetch | `OMNIUS-027` | `AC-WEB-023` |
| `REC-WEB-024` | Ensure expected RFC 9457 problems retain typed codes, fields, status, and request IDs | `OMNIUS-027` | `AC-WEB-024` |
| `REC-WEB-025` | Ensure retries are restricted by method, error class, and idempotency policy | `OMNIUS-027` | `AC-WEB-025` |
| `REC-WEB-026` | Ensure generated query keys are stable and exported through key factories | `OMNIUS-027` | `AC-WEB-026` |
| `REC-WEB-027` | Ensure cancellation propagates from Query to fetch through AbortSignal | `OMNIUS-027` | `AC-WEB-027` |
| `REC-WEB-028` | Ensure semantic wrappers exist only where they add lifecycle or product meaning | `OMNIUS-027` | `AC-WEB-028` |
| `REC-WEB-029` | Ensure generated code is derived, isolated, and never hand edited | `OMNIUS-027` | `AC-WEB-029` |
| `REC-WEB-030` | Ensure sDK exposes the contract hash against which it was generated | `OMNIUS-027` | `AC-WEB-030` |
| `REC-WEB-031` | Ensure session authentication works without exposing the session secret to JavaScript | `OMNIUS-028` | `AC-WEB-031` |
| `REC-WEB-032` | Ensure login, privilege elevation, logout, and logout-all execute the defined cache and realtime lifecycle | `OMNIUS-028` | `AC-WEB-032` |
| `REC-WEB-033` | Ensure cookie-authenticated unsafe requests pass and fail the approved CSRF negative matrix | `OMNIUS-028` | `AC-WEB-033` |
| `REC-WEB-034` | Ensure expired and revoked sessions produce stable typed handling without reconnect loops | `OMNIUS-028` | `AC-WEB-034` |
| `REC-WEB-035` | Ensure cross-tab login or logout convergence carries no credential material | `OMNIUS-028` | `AC-WEB-035` |
| `REC-WEB-036` | Ensure bearer refresh is single-flight and cannot enter an infinite refresh loop | `OMNIUS-028` | `AC-WEB-036` |
| `REC-WEB-037` | Ensure oIDC return destinations are restricted to approved locations | `OMNIUS-028` | `AC-WEB-037` |
| `REC-WEB-038` | Ensure frontend permission controls are presentation-only and direct backend denial is tested | `OMNIUS-028` | `AC-WEB-038` |
| `REC-WEB-039` | Ensure tenant changes isolate cached resources, route state, local state, and subscriptions | `OMNIUS-028` | `AC-WEB-039` |
| `REC-WEB-040` | Ensure protected route prerequisites avoid content flash and redirect loops | `OMNIUS-028` | `AC-WEB-040` |
| `REC-WEB-041` | Ensure realtime messages derive from AsyncAPI and reject unknown versions safely | `OMNIUS-029` | `AC-WEB-041` |
| `REC-WEB-042` | Ensure webSocket client reconnects with bounded jitter and resubscribes exactly once | `OMNIUS-029` | `AC-WEB-042` |
| `REC-WEB-043` | Ensure sSE client resumes with the documented cursor and tolerates duplicates | `OMNIUS-029` | `AC-WEB-043` |
| `REC-WEB-044` | Ensure authentication failure reaches a terminal or revalidation state without reconnect storm | `OMNIUS-029` | `AC-WEB-044` |
| `REC-WEB-045` | Ensure session and permission events trigger authoritative HTTP revalidation | `OMNIUS-029` | `AC-WEB-045` |
| `REC-WEB-046` | Ensure event-to-query effects use generated scoped query-key factories | `OMNIUS-029` | `AC-WEB-046` |
| `REC-WEB-047` | Ensure direct cache patching is limited to validated complete and version-compatible payloads | `OMNIUS-029` | `AC-WEB-047` |
| `REC-WEB-048` | Ensure tenant and principal changes re-establish only authorized subscriptions | `OMNIUS-029` | `AC-WEB-048` |
| `REC-WEB-049` | Ensure server drain and client disposal close transports without leaked handlers | `OMNIUS-029` | `AC-WEB-049` |
| `REC-WEB-050` | Ensure actual-browser tests exercise Axum WebSocket and SSE transports | `OMNIUS-029` | `AC-WEB-050` |
| `REC-WEB-051` | Ensure axum serves fingerprinted Vite assets through battle-tested middleware | `OMNIUS-030` | `AC-WEB-051` |
| `REC-WEB-052` | Ensure fingerprinted assets are immutable while the application shell is revalidated | `OMNIUS-030` | `AC-WEB-052` |
| `REC-WEB-053` | Ensure sPA fallback serves valid deep links and never swallows backend namespace 404 responses | `OMNIUS-030` | `AC-WEB-053` |
| `REC-WEB-054` | Ensure static delivery rejects traversal and does not expose source, environment, or build-secret files | `OMNIUS-030` | `AC-WEB-054` |
| `REC-WEB-055` | Ensure content types, validators, and precompressed negotiation are correct | `OMNIUS-030` | `AC-WEB-055` |
| `REC-WEB-056` | Ensure production CSP omits unsafe-eval and the full security-header policy is tested | `OMNIUS-030` | `AC-WEB-056` |
| `REC-WEB-057` | Ensure source-map publication follows an explicit non-public default policy | `OMNIUS-030` | `AC-WEB-057` |
| `REC-WEB-058` | Ensure vite development proxy supports HTTP, WebSocket, and unbuffered SSE | `OMNIUS-030` | `AC-WEB-058` |
| `REC-WEB-059` | Ensure configured public base path is consistent across Router, assets, API, WS, and SSE | `OMNIUS-030` | `AC-WEB-059` |
| `REC-WEB-060` | Ensure reference container uses frozen frontend dependencies and contains no build secrets | `OMNIUS-030` | `AC-WEB-060` |
| `REC-WEB-061` | Ensure tanStack Query owns remote resources and no routine Zustand mirror exists | `OMNIUS-031` | `AC-WEB-061` |
| `REC-WEB-062` | Ensure cursor pagination and filter state round-trip through typed URL parameters | `OMNIUS-031` | `AC-WEB-062` |
| `REC-WEB-063` | Ensure idempotency keys are reused only within one controlled action retry sequence | `OMNIUS-031` | `AC-WEB-063` |
| `REC-WEB-064` | Ensure optimistic concurrency conflicts produce a typed refresh, merge, or user-resolution path | `OMNIUS-031` | `AC-WEB-064` |
| `REC-WEB-065` | Ensure server field violations map to accessible form controls and preserve a global error | `OMNIUS-031` | `AC-WEB-065` |
| `REC-WEB-066` | Ensure upload initiation, progress, cancellation, retry, completion, quarantine, and cleanup are covered | `OMNIUS-031` | `AC-WEB-066` |
| `REC-WEB-067` | Ensure capability, feature flag, entitlement, and permission checks remain distinct | `OMNIUS-031` | `AC-WEB-067` |
| `REC-WEB-068` | Ensure tenant switching prevents stale tenant content from becoming visible | `OMNIUS-031` | `AC-WEB-068` |
| `REC-WEB-069` | Ensure vitest and Testing Library cover SDK and React integration behavior | `OMNIUS-032` | `AC-WEB-069` |
| `REC-WEB-070` | Ensure mSW fails unhandled test requests and uses contract-derived handlers only after compatibility validation | `OMNIUS-032` | `AC-WEB-070` |
| `REC-WEB-071` | Ensure playwright exercises login, authorization, tenancy, errors, uploads, realtime, and deep links against Axum | `OMNIUS-032` | `AC-WEB-071` |
| `REC-WEB-072` | Ensure chromium, Firefox, and WebKit support tiers are declared and exercised | `OMNIUS-032` | `AC-WEB-072` |
| `REC-WEB-073` | Ensure web security negative suite covers credential storage, CSRF, redirects, XSS boundary, CSP, and clickjacking | `OMNIUS-032` | `AC-WEB-073` |
| `REC-WEB-074` | Ensure orval generation is exact-pinned, trusted-input-only, isolated, advisory-scanned, and secret-free | `OMNIUS-032` | `AC-WEB-074` |
| `REC-WEB-075` | Ensure representative routes pass automated accessibility checks and recorded manual keyboard/screen-reader review | `OMNIUS-032` | `AC-WEB-075` |
| `REC-WEB-076` | Ensure bundle and runtime performance budgets detect significant regressions | `OMNIUS-032` | `AC-WEB-076` |
| `REC-WEB-077` | Ensure all extension modules and profiles validate with the base dependency graph | `OMNIUS-033` | `AC-WEB-077` |
| `REC-WEB-078` | Ensure adding or removing web support is idempotent and preserves application-owned files | `OMNIUS-033` | `AC-WEB-078` |
| `REC-WEB-079` | Ensure every web profile generates, installs frozen dependencies, contracts-checks, builds, tests, and smoke-tests | `OMNIUS-033` | `AC-WEB-079` |
| `REC-WEB-080` | Ensure upgrade rehearsal preserves application edits and supports at least one prior web-suite release | `OMNIUS-033` | `AC-WEB-080` |
