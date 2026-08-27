---
spec_id: OMNIUS-WEB-README
title: Web Application Delivery & Frontend Capability SDK Feature Suite
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Web Application Delivery & Frontend Capability SDK Feature Suite

This directory is an **append-only extension** to the Omnius specification bundle version 0.1.0. It adds a browser-application delivery layer, deterministic consumer contracts, a reusable TypeScript client core, React integration, realtime synchronization, static delivery, testing, security, accessibility, generator profiles, and an implementation roadmap.

## Safe extraction

The ZIP is intentionally rooted at the specification-directory level. Extract it into an existing checkout with:

```bash
unzip -n omnius-web-feature-suite-v0.1.0.zip -d ./specs
```

`-n` refuses to overwrite existing paths. The bundle itself has been checked to contain no path that collides with the original v0.1.0 specification bundle.

After extraction:

```bash
python ./specs/tools/validate_web_feature_suite.py ./specs
```

The validator expects the original bundle and this extension to be present together.

## Entry points

1. `WEB_FEATURE_SUITE_AGENT_HANDOFF.md` — instructions for an autonomous implementation agent.
2. `WEB_FEATURE_SUITE_INTEGRATION.md` — how to merge the append-only machine catalogs into implementation state.
3. `25-web-application-architecture.md` through `34-web-suite-roadmap-acceptance-and-traceability.md` — normative specifications.
4. `machine/extensions/web-application-suite/` — machine-readable modules, profiles, tasks, acceptance criteria, schemas, risks, recommendations, and merge instructions.
5. `WEB_FEATURE_SUITE_VALIDATION_REPORT.md` — validation results and scope.

## Design summary

The default web profile is a same-origin React and TypeScript single-page application built by Vite and served by Axum in production. It uses:

- TanStack Router for route and URL state.
- TanStack Query for backend-owned server state.
- React Hook Form and Zod for form ergonomics and client-side boundary validation.
- Zustand only for genuinely client-local state.
- Deterministic OpenAPI, AsyncAPI, permissions, capabilities, and contract-manifest artifacts emitted by the Rust service.
- An exact-pinned, isolated Orval generation pipeline for TypeScript HTTP clients and query bindings.
- A framework-neutral client core with React adapters layered above it.
- Typed WebSocket and SSE clients whose events can update or invalidate TanStack Query data.
- Vitest, Testing Library, MSW, Playwright, and accessibility checks.

The suite does not make frontend checks authoritative for security, does not duplicate Rust DTOs by hand, does not make Zustand a second server-state cache, and does not make SSR part of the default deployment.
