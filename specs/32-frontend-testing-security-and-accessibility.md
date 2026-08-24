---
spec_id: RSK-032
title: Frontend Testing, Security, and Accessibility
version: 0.1.0
status: normative
last_verified: 2026-08-24
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
