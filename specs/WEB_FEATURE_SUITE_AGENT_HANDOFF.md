---
spec_id: RSK-WEB-HANDOFF
title: Autonomous Agent Handoff — Web Application Feature Suite
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Autonomous Agent Handoff — Web Application Feature Suite

You are extending an in-progress Rust Service Kit implementation. Read the original `AUTONOMOUS_AGENT_HANDOFF.md`, all accepted ADRs, this handoff, specifications `25` through `34`, and the extension machine catalogs before changing code.

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
