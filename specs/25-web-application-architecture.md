---
spec_id: OMNIUS-025
title: Web Application Architecture
version: 0.1.0
status: normative
last_verified: 2026-08-24
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
