---
spec_id: RSK-WEB-RES-004
title: Web Compatibility and Security Findings
version: 0.1.0
status: evidence
last_verified: 2026-08-24
---

# Web Compatibility and Security Findings

## openapi-typescript family

The project's 2026 roadmap deprecates `openapi-fetch` and narrows maintenance focus. The prior conversational recommendation to use `openapi-fetch` and `openapi-react-query` is therefore superseded for this suite.

Sources: `SRC-WEB-OPENAPITS-001`, `SRC-WEB-OPENAPITS-002`.

## Orval

Orval supplies Fetch and TanStack Query generation, including a custom client/mutator boundary. Multiple 2026 advisories involved code injection from hostile OpenAPI values, including enum descriptions, mock generation, and MCP generation.

The suite therefore permits Orval only with trusted repository-generated input, an exact pin, isolated secret-free generation, disabled unused generators, advisory review, compile tests, and an adapter boundary. It is not approved for arbitrary user-provided specifications.

Sources: `SRC-WEB-ORVAL-001` through `SRC-WEB-ORVAL-SEC-003`.

## TypeScript 6 and 7

TypeScript 6 is the stable bridge release from the JavaScript compiler to the native TypeScript 7 implementation. TypeScript 7 is current, but build tools that rely on compiler internals or programmatic APIs require an explicit compatibility pass. The initial baseline uses 6.0.2 and treats 7.x as a near-term upgrade gate rather than rejecting it.

Sources: `SRC-WEB-TS-001`, `SRC-WEB-TS-002`.

## React/Vite/TanStack

The selected versions MUST be resolved as one tested graph with React type packages, Vite React integration, Query devtools if enabled, Router tooling, Vitest, and the selected generator. Exact pins in the extension baseline are initial lock targets.

Sources: `SRC-WEB-REACT-001`, `SRC-WEB-VITE-001`, `SRC-WEB-TANSTACK-QUERY-001`, `SRC-WEB-TANSTACK-ROUTER-001`.

## Static serving and development

Vite's backend integration supports a normal static build and development-server workflow. `tower-http::ServeDir` provides the filesystem-serving primitive. Route fallback, cache policy, CSP, and namespace exclusion remain service-kit responsibilities.

Sources: `SRC-WEB-VITE-002`, `SRC-WEB-TOWERHTTP-001`.

## Realtime

WebSocket and SSE browser APIs have materially different header, reconnect, and directionality behavior. They share event schemas and lifecycle abstractions but are not represented as interchangeable transports.

Sources: `SRC-WEB-SSE-001`, `SRC-WEB-WEBSOCKET-001`, `SRC-WEB-OWASP-WS`.

## Phase W0 experiments

The agent MUST record:

1. Complete pnpm resolution under Node 24.19.0.
2. TypeScript 6.0.2 strict compilation of generated output.
3. A TypeScript 7.x comparison fixture without adopting it.
4. Orval trusted-input generation and advisory state.
5. Fetch mutator cancellation, credentials, problem-body, and request-ID behavior.
6. stable generated query keys for path/query/header inputs.
7. Vite React plugin and Vitest compatibility.
8. MSW 2 behavior and optional `@msw/source` compatibility.
9. Playwright browser image/version availability.
10. tower-http static fallback, precompressed asset, and cache behavior.
