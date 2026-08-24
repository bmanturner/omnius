---
spec_id: RSK-WEB-RES-003
title: Web Technology Selection Findings
version: 0.1.0
status: evidence
last_verified: 2026-08-24
---

# Web Technology Selection Findings

## Selected baseline

| Concern | Selection | Reason |
|---|---|---|
| UI runtime | React | Broad ecosystem and straightforward static deployment |
| Language | TypeScript 6.0.2 initially | Stable compiler API/tooling bridge while TypeScript 7 compatibility is proven |
| Build/dev | Vite | Mature static build, HMR, and backend proxy workflow |
| Routing | TanStack Router | Typed route and URL state |
| Remote data | TanStack Query | Established server-state cache, cancellation, invalidation, mutations |
| HTTP generation | Orval behind an adapter | Maintained OpenAPI client and Query generation; strict security constraints required |
| Forms | React Hook Form + Zod | Mature form ergonomics and optional runtime boundary validation |
| Client-local state | Zustand, optional | Small focused store when component state is insufficient |
| Realtime contract | AsyncAPI + JSON Schema | Channel/message semantics not adequately represented by OpenAPI |
| Static serving | tower-http ServeDir | Existing hardened Tower integration |
| Unit/components | Vitest + Testing Library | Vite-compatible, behavior-focused tests |
| Network mocks | MSW | Reuses browser-like network semantics |
| Browser E2E | Playwright | Cross-browser automation and diagnostics |

## Rejected as defaults

### openapi-fetch and openapi-react-query

The maintainers' 2026 roadmap deprecated openapi-fetch and narrowed the project back to its core. The suite therefore does not add these packages to a new long-lived platform baseline.

### Custom API generator

A custom generator would recreate OpenAPI traversal, schema naming, union handling, response typing, query key generation, and framework integration. The platform keeps an adapter boundary and may replace Orval if its gate fails, but does not begin by creating a generator.

### SSR framework

SSR adds a second application runtime or a different Rust rendering adapter. Many authenticated applications do not require it. It remains a future profile decision.

### Global store for API data

TanStack Query already solves remote data fetching, caching, cancellation, mutation, and invalidation. Duplicating resources in Zustand creates conflicting truth.

### Custom static server

Tower already has a maintained static filesystem service. The kit contributes correct route ordering, cache policy, and security configuration rather than file-serving internals.

## Conditional choices

- `@msw/source` is optional until compatibility and generated scenario quality are proven.
- TypeScript 7 adoption is gated because the native compiler changes tooling internals despite source compatibility goals.
- Zustand is included only in profiles that request client-local state.
- Direct event cache patches are allowed only with complete validated versioned payloads.
