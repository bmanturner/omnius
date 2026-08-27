---
spec_id: OMNIUS-027
title: Frontend Capability SDK
version: 0.1.0
status: normative
last_verified: 2026-08-24
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
