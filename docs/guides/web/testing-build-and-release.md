---
title: Web testing, build, and release
description: Repository test lanes, deterministic generation gates, build evidence, accessibility approval, and coordinated release boundaries.
status: experimental
implementation: implemented
profile_availability:
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: not-applicable
audience:
  - web developers
  - release engineers
  - reviewers
topics:
  - testing
  - build
  - release
  - evidence
capabilities:
  - web-testing-build-and-release
source:
  - web/package.json
  - packages/web-sdk/package.json
  - .github/workflows/ci.yml
  - xtask/src/profiles.rs
  - release/web-suite-runbook.md
evidence:
  - web/browser-support.json
  - web/e2e/release-gates.config.test.mjs
  - web/e2e/browser.spec.ts
  - contracts/contract-manifest.json
last_verified: 2026-08-30
---

# Web testing, build, and release

The repository defines implemented web build and release gates, but gate definitions are not passing evidence. This page reports no run. A release claim requires retained results bound to the exact generated profile, API artifact, web artifact, contract identity, source revision, and manual approval evidence.

General repository test ownership is described in [testing strategy](../../development/testing-strategy.md). Compatibility lifecycle gates are described in [compatibility and release gates](../../development/compatibility-and-release-gates.md). Operational rollout and rollback belong to [web release and static delivery](../../operations/web-release-and-static-delivery.md).

## Toolchain prerequisites

The web SDK package declares Node.js `24.19.0` and pnpm `11.23.0`. A verifier should use the repository-pinned package manager and a frozen dependency graph. The browser lanes use Playwright-pinned browser engines as defined by `web/browser-support.json`.

Before any release lane:

1. identify the intended web profile;
2. record the source revision and toolchain versions;
3. use the selected contract manifest and generated artifacts;
4. keep all credentials in the approved secret provider, never in command text or evidence attachments;
5. choose a controlled backend/fixture target appropriate to the lane;
6. prepare artifact storage for reports without request or authentication secrets.

**Expected result:** every later result can be traced to one immutable input set.

**Failure path:** if inputs, profile, or contract identity are ambiguous, discard the run as release evidence and establish a clean evidence binding.

## Package script inventory

`web/package.json` defines these script identifiers:

- `dev`
- `build`
- `typecheck`
- `typecheck:e2e`
- `typecheck:ts7`
- `test`
- `test:release-config`
- `test:e2e`
- `test:e2e:full`
- `test:e2e:smoke`
- `test:e2e:base-path`
- `test:e2e:security`
- `test:e2e:a11y`
- `test:e2e:performance`
- `check:a11y:manual`
- `release:gates`

These names are repository entry points, not evidence that they were executed. Use package metadata for their exact definitions rather than reconstructing their underlying tools from documentation.

## Verification layers

### Deterministic contracts and SDK

The contract manifest, OpenAPI generation, contract metadata, package boundaries, and checked generated output should agree before application checks. HTTP generation validates canonical input and deterministic output. Contract metadata validates contract identity.

Realtime is an exception requiring explicit review: when AsyncAPI is not selected, the realtime generator exits successfully before comparing the checked-in generated realtime module. A green generation lane cannot currently prove realtime output is current. See [generated contracts and SDK](generated-contracts-and-sdk.md) and [realtime and uploads](realtime-and-uploads.md).

**Expected result:** selected canonical inputs and checked generated outputs are byte-coherent, with realtime either coherently selected and checked or explicitly absent without stale exported output.

**Failure path:** stop the release on drift or unresolved realtime lifecycle. Never hand-edit generator-owned output as the fix.

### Type and unit lanes

The script inventory separates application type checks, E2E type checks, an additional TypeScript lane, and unit tests. The SDK has its own checks and tests. Type success establishes static consistency only; unit success establishes the behavior exercised by those tests only.

**Expected result:** neutral SDK entry points remain React-free, application/source types agree, and behavior tests pass against their controlled boundaries.

**Failure path:** correct the owning source or canonical contract. Do not suppress a type failure with an unsafe assertion or weaken a behavioral assertion to match a regression.

### Browser lanes

Browser coverage is policy-based:

- Chromium Desktop receives the full lane;
- Firefox Desktop receives smoke coverage;
- WebKit Desktop receives smoke coverage.

The full Chromium lane includes actual-Axum functional checks, browser-security negative checks, representative accessibility/keyboard checks, and bundle/runtime budgets according to the support policy. Smoke lanes cover shell/deep links, reserved-route/capability behavior, headers, and representative accessibility checks.

Fixture-backed full-reference tests prove fixture behavior. They do not prove a generated web profile, the active `oauth-provider` application, or a production service. Evidence must label its target accurately.

**Expected result:** each policy lane records the engine, target, route set, artifact identities, and observed outcomes.

**Failure path:** a missing browser, skipped route, fixture-only target, or lost report makes the affected claim unavailable. Do not relabel smoke coverage as full support.

### Base-path and static-delivery lanes

Base-path evidence should include root and nested application bases, direct deep links, origin-root APIs, reserved-route behavior, immutable assets, and error responses. Release configuration checks should confirm source-map policy, build identity, route topology, and absence of private fixture material.

**Expected result:** generated assets resolve under the selected base while API paths retain origin-root semantics.

**Failure path:** if a fallback swallows API paths or a bundle contains private material, reject the artifact and fix the build/delivery source. See [static delivery and browser security](static-delivery-and-browser-security.md).

### Security lane

Browser security evidence should inspect CSP, framing denial, MIME protection, referrer policy, permissions policy, cross-origin mutation denial, and public source-map behavior. It should inspect the externally served response path because a proxy or CDN can change headers.

**Expected result:** the assembled artifact works under its restrictive policy without broad inline/eval exceptions.

**Failure path:** correct asset and route ownership. Do not loosen browser security merely to make a check pass.

### Accessibility lane

Automated accessibility is representative. Release approval also requires manual evidence bound to the exact artifacts and accepted through the runbook's approval step.

**Expected result:** automated reports and manual review together cover the release's primary and sensitive journeys.

**Failure path:** absent, stale, rejected, or differently bound manual evidence leaves the release not ready. See [accessibility, internationalization, and browser support](accessibility-i18n-and-browser-support.md).

### Performance lane

The support policy includes bundle/runtime budgets in the full Chromium lane. Performance evidence must identify measurement environment, route, cache state, artifact, and budget. A locally fast page or a unit benchmark is not a release result.

**Expected result:** all required measured routes meet their checked budgets under the specified harness.

**Failure path:** investigate bundle composition, request waterfalls, rendering, and target service behavior. Do not change the budget without an explicit compatibility/release decision.

## CI and generated profile matrix

The CI workflow defines frozen installation, generation drift, type lanes, SDK and application tests/build, Playwright lanes, release configuration, a generated profile matrix, contract compatibility/lifecycle checks, and supply-chain checks. `xtask/src/profiles.rs` participates in profile generation and matrix behavior.

A workflow file proves orchestration intent. It does not prove:

- the workflow was triggered for this revision;
- every job ran rather than skipped;
- generated profile outputs were retained;
- browser binaries were the expected versions;
- manual evidence was approved;
- an artifact was deployed;
- deployed headers or routes match fixture results.

The inspected workflow retains certain CI artifacts for seven days. Retention configuration does not prove an artifact exists. Release evidence must be captured before expiry under the project's evidence policy.

## Release decision

A web release should be one coordinated compatibility unit containing:

- selected profile and generated application/service output;
- API artifact identity;
- web HTML and hashed assets;
- canonical contract and generated SDK identity;
- capability document;
- browser/security/accessibility/performance evidence;
- manual accessibility approval;
- rollout and rollback identities.

The API and browser assets must be rolled forward or back coherently. The shell's contract-mismatch handling is a guardrail, not a deployment strategy.

## Release failure paths

| Failure | Required response |
|---|---|
| Contract or generation drift | Stop; reconcile canonical input and generated output. |
| Runtime capability disagrees with selected UI | Stop optional exposure; correct profile/runtime composition. |
| Browser fixture passes but assembled backend fails | Treat assembled scenario as authoritative for release. |
| Manual accessibility evidence absent | Do not mark release ready. |
| Security headers differ at public edge | Correct proxy/CDN/deployment policy and re-observe. |
| API and web rollback identities differ | Select a compatible pair before rollback. |
| Retained evidence expired or cannot be bound | Re-run the affected gate; do not infer a pass. |

## Evidence status

No install, generation, type check, test, build, browser lane, deployment, or release gate was run for this page. No retained release result was inspected. All script and CI references describe checked-in definitions only.
