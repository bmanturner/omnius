---
title: Web application development
description: Contributor workflow for the Omnius browser application, framework-neutral SDK integration, routing, tests, and browser release evidence.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - frontend-contributor
  - maintainer
  - release-engineer
topics:
  - web
  - react
  - sdk
  - browser-testing
capabilities: []
source:
  - web/package.json
  - web/src/app.tsx
  - web/src/router.tsx
  - packages/web-sdk/package.json
evidence:
  - .github/workflows/ci.yml
  - release/web-suite-runbook.md
  - packages/web-sdk/src/internal/generated/contract-metadata.ts
last_verified: 2026-08-30
---

# Web application development

The browser application lives in `web/` and consumes the framework-neutral package in `packages/web-sdk/`. Read [Application architecture](../guides/web/application-architecture.md) before changing composition and [Generated contracts and SDK](../guides/web/generated-contracts-and-sdk.md) before changing generated client behavior.

A browser build proves that the checked-in application compiles. It does not prove that a backend profile is assembled, deployed, or reachable. Keep those evidence dimensions separate.

## Application boundaries

The current source divides responsibilities as follows:

- `web/src/main.tsx` creates the browser root.
- `web/src/app.tsx` composes the SDK provider, query client, authentication manager, and router.
- `web/src/router.tsx` defines the typed route tree, lazy route modules, authentication gates, validated search state, and base-path behavior.
- `packages/web-sdk/` owns transport, authentication, authorization, realtime, uploads, LLM, capabilities, React adapters, and testing support.
- `packages/web-sdk/src/internal/generated/` is generator-owned contract output.

Keep application UI and route policy in `web/`. Keep reusable wire behavior and public client APIs in the SDK. Keep contract-shaped generated types under `src/internal/generated/` and wrap them with stable manual APIs elsewhere.

## Start local development

Run from the repository root.

**Prerequisites:** Node.js `24.19.0`, pnpm `11.23.0`, a completed frozen dependency install, current generated SDK sources, and any separately configured development backend required by the route being exercised. Use development credentials only through local secret-safe configuration.

```bash
pnpm install --frozen-lockfile
pnpm sdk:check:generated
pnpm web:dev
```

**Expected result:** dependencies match the lockfile, generated SDK drift is absent, and Vite starts the browser development server using `web/` configuration.

**Failure path:** resolve lockfile or generator drift before debugging application code. If the UI starts but a request fails, distinguish SDK transport/configuration, backend availability, authentication, and route policy rather than adding a fake client response.

## Add or change a route

1. Add the lazy route implementation using the existing route organization.
2. Register it in the explicit typed route tree in `web/src/router.tsx`.
3. Declare authentication and authorization behavior at the route boundary.
4. Validate search parameters rather than reading untyped location state.
5. Preserve configured public-base and base-path behavior.
6. Use the SDK for contract-backed transport; do not create a second fetch convention in the application.
7. Add behavior tests for navigation, gating, state transitions, and real failure presentation.
8. Add browser coverage when the behavior depends on browser routing, storage, accessibility, or network integration.

Do not infer a backend route from a frontend screen. The generated OpenAPI and SDK define the available HTTP contract; optional realtime support exists only when the contract manifest selects it.

## Change SDK-consuming UI

Use public SDK exports rather than importing `src/internal/generated/` directly. The SDK package exports client, auth, authorization, realtime, uploads, LLM, capabilities, React, and testing surfaces. Its `sideEffects: false` declaration and boundary tests support framework-neutral consumption.

When generated types are awkward for application use, add or adjust a manual wrapper outside the generated directory. Do not hand-edit the generator-owned type to create a local exception.

## Run the fast web loop

Run from the repository root.

**Prerequisites:** pinned Node.js and package-manager versions, installed dependencies, and current contract/SDK output. These checks do not require production credentials.

```bash
pnpm web:typecheck
pnpm web:typecheck:ts7
pnpm web:test
pnpm web:build
```

**Expected result:** application code type-checks against both configured TypeScript lines, unit tests pass, and the production bundle builds.

**Failure path:** fix type compatibility, behavior, or bundling at the owning source. If the failure originates in generated SDK code, return to [Contract and SDK generation](./contract-and-sdk-generation.md) rather than weakening the web check.

## Run SDK checks after client-facing changes

Run from the repository root.

**Prerequisites:** pinned Node.js and package-manager versions, installed dependencies, and current artifacts in `contracts/`.

```bash
pnpm sdk:check:generated
pnpm sdk:typecheck
pnpm sdk:typecheck:ts7
pnpm sdk:test
pnpm sdk:test:boundaries
pnpm sdk:build
```

**Expected result:** generated drift, both TypeScript compatibility lines, SDK behavior, import boundaries, and package output all satisfy their checked-in gates.

**Failure path:** regenerate through `pnpm sdk:generate` only when the contract change is intentional. Keep manual fixes outside `src/internal/generated/` and preserve the public export boundary.

## Browser and release checks

End-to-end tests need a separately built and configured backend appropriate to the suite. Do not claim a passing browser test from a frontend-only build.

Run from the repository root.

**Prerequisites:** pinned toolchains, frozen dependencies, current contracts and SDK, the separately configured test backend, and the browser prerequisites described by the web scripts. Use isolated synthetic data and non-production credentials.

```bash
pnpm web:test:e2e
pnpm --dir web test:e2e:base-path
pnpm web:check:a11y:manual
pnpm web:release:gates
```

**Expected result:** the first three commands exercise the configured Playwright suite, nested-base scenario, and manual-accessibility evidence checker individually. `pnpm web:release:gates` runs those same three checks; it does not invoke `scripts/release/web_evidence.py` and does not read, create, or validate the bound evidence under `target/web-release-evidence`.

The complete bound-evidence decision is a separate release procedure. Follow the [web suite runbook](../../release/web-suite-runbook.md) to run the evidence tool, produce revision-bound documents, validate them, and enforce the release-ready decision.

**Failure path:** fix the failing application, SDK, backend, base-path, browser, accessibility, or bound-evidence contract at the owning step. Passing `pnpm web:release:gates` is not evidence that the separate bound-evidence procedure passed.

## Required review for web changes

Review the changed surface for:

- typed route and search-state compatibility;
- authentication and authorization gates;
- tenant and query-cache isolation;
- safe token and error handling in the browser;
- generated-contract drift and SDK public boundaries;
- base-path and public-base behavior;
- keyboard, focus, semantics, contrast, and assistive-technology behavior;
- supported TypeScript compatibility;
- browser error, loading, retry, and offline transitions;
- bundle and performance effects where the change can affect them.

The durable testing principles are in [Testing strategy](./testing-strategy.md). The release procedure is summarized in [Compatibility and release gates](./compatibility-and-release-gates.md).

## Evidence boundary

Web source, tests, and release reports establish only what they directly exercise. They do not demonstrate publication, production promotion, backend assembly, or a publicly reachable deployment.