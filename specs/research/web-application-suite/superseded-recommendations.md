---
spec_id: RSK-WEB-RES-005
title: Superseded and Amended Recommendations
version: 0.1.0
status: evidence
last_verified: 2026-08-24
---

# Superseded and Amended Recommendations

## Purpose

This file records changes from the earlier conversational architecture advice so an implementation agent does not follow obsolete prose over the normative suite.

## Superseded: openapi-fetch and openapi-react-query

Earlier advice proposed:

```text
openapi-typescript
openapi-fetch
openapi-react-query
```

The openapi-typescript maintainers subsequently deprecated the non-core fetch family. This suite replaces that client layer with an exact-pinned, constrained Orval pipeline behind a stable service-kit adapter.

OpenAPI emitted by Rust remains authoritative. The change concerns the TypeScript client generator, not the contract architecture.

## Amended: latest TypeScript

TypeScript 7.0 is current, but the initial implementation baseline uses TypeScript 6.0.2 until the native compiler passes the W0 toolchain gate. This is an intentional compatibility hold, not a permanent rejection.

## Clarified: generated mocks

Contract-derived MSW generation is optional. The baseline always supports hand-authored scenario overrides and actual-backend Playwright tests. `@msw/source` is added only after compatibility and error-response fidelity are proven.

## Clarified: package layout

The conceptual SDK remains layered, but the initial implementation SHOULD use one physical package with subpath exports. Prematurely splitting many packages is not required.

## Unchanged recommendations

The following remain normative:

- React/TypeScript/Vite default SPA.
- same-origin Axum production delivery.
- TanStack Query server-state ownership.
- TanStack Router URL state.
- optional Zustand only for client-local state.
- deterministic OpenAPI/AsyncAPI/permissions/capabilities.
- typed auth, authorization, realtime, upload, error, pagination, and idempotency utilities.
- actual-backend Playwright coverage.
- append-only module/profile integration.
