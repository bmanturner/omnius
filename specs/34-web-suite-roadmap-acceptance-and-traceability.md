---
spec_id: OMNIUS-034
title: Web Suite Roadmap, Acceptance, and Traceability
version: 0.1.0
status: normative
last_verified: 2026-08-24
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
