---
spec_id: RSK-ADR-0013
title: Use an Exact-Pinned, Constrained Orval Pipeline for OpenAPI Clients
version: 0.1.0
status: accepted
last_verified: 2026-08-24
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
