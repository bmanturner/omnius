---
title: Web reference application workflows
description: Route-by-route browser workflow inventory constrained by the checked oauth-provider runtime and current capability evidence.
status: experimental
implementation: partial
profile_availability:
  - oauth-provider
public_exposure: unassembled
audience:
  - application developers
  - integrators
  - reviewers
topics:
  - reference-application
  - workflows
  - runtime-ceiling
  - routes
capabilities:
  - web-reference-application-runtime-ceiling
source:
  - web/src/router.tsx
  - web/src/routes/
  - web/src/auth-manager.ts
  - crates/reference-api/src/contracts.rs
evidence:
  - contracts/capabilities.json
  - contracts/openapi.json
  - web/e2e/browser.spec.ts
  - web/e2e/axum-fixture.mjs
last_verified: 2026-08-30
---

# Web reference application workflows

The checked browser source contains a broad reference application. The checked backend contract state is narrower: `contracts/capabilities.json` identifies the `oauth-provider` profile, reports `auth-oauth-server` available with bearer and session modes, and reports `web-auth` false at both compiled and runtime layers. No inspected evidence mounts or serves the browser application from that active runtime.

This mismatch is the reference application's current runtime ceiling. It must be stated, not reconciled by assuming the web source or fixture tests upgrade the active profile. The page is therefore partial and unassembled. Use the [availability matrix](../../reference/availability-and-exposure-matrix.md) for the authoritative classification.

## Evidence boundaries

| Evidence | What it proves | What it does not prove |
|---|---|---|
| `web/src/router.tsx` and route components | Browser route and workflow source exists. | A generated profile includes it or a service serves it. |
| `web/src/auth-manager.ts` | Browser session behavior is implemented in source. | `web-auth` is active in the checked runtime. |
| `contracts/capabilities.json` | Checked `oauth-provider` capability state and contract identity. | A separate environment has identical runtime state. |
| `contracts/openapi.json` | Generated HTTP contract input exists. | Every operation is mounted by the active service. |
| Full-reference E2E fixture | The fixture behaves as asserted. | The fixture is the generated profile, checked backend, or production app. |
| Actual-Axum E2E source | A harness is defined for concrete backend behavior. | The scenario was run or the web shell is mounted. |

Profile selection, specifications, generated artifacts, tests, and library source are not runtime assembly evidence.

## Current route inventory

### Public root route

The public root route mounts `StatusRoute` inside the shared shell and presents an operations service overview.

**Source journey:** mounting the route immediately requests readiness and runtime metadata, then presents deployment health, profile and API identity, revision and contract identity, and advertised capabilities.

**Runtime ceiling:** the source shell needs an independently assembled compatible backend to complete both queries. Vite or route source alone does not establish that backend or show that the active `oauth-provider` service serves the shell.

### `/records`

The public reference-record route owns `limit`, `cursor`, and `name` in the URL. It lists through `GET /reference-records`, creates with JSON and an idempotency key, and updates with `If-Match: "v<version>"`. Conflict/precondition responses expose reload or retry recovery. The route has no delete journey.

**Expected source behavior:** validated filters reproduce list state; confirmed mutations invalidate the scoped list; RFC 9457 problems remain structured.

**Failure path:** a missing operation or route is an assembly mismatch, not evidence that the browser should synthesize data. See [data fetching, forms, and errors](data-fetching-forms-and-errors.md).

### `/login`

The anonymous-only login route submits through the browser session manager and restores only a validated same-origin rooted return path.

**Expected source behavior:** successful login refreshes the public principal and enters the safe local destination.

**Failure path:** external return locations fall back to `/account`; structured authentication failures remain visible.

**Runtime ceiling:** checked capability metadata says `web-auth` is unavailable.

### `/register`

The anonymous-only route contains local account registration.

**Expected source behavior:** registration follows the backend-defined verification/account outcome without disclosing whether unrelated accounts exist.

**Failure path:** capability absence, disabled local registration, or validation failure must remain distinct.

**Runtime ceiling:** route source does not prove that local registration is selected by `oauth-provider` or exposed to a browser.

### `/verify-email`

The verification route consumes one named fragment value into memory and removes it from browser history immediately. It also provides resend behavior under the source workflow.

**Expected source behavior:** no one-time value remains in the address, persistent state, logs, or analytics.

**Failure path:** missing, expired, invalid, or consumed material produces a recoverable verification error rather than an invented token.

### `/forgot-password`

The anonymous-only route requests a reset.

**Expected source behavior:** the response does not reveal whether an account exists.

**Failure path:** preserve backend policy and rate-limit problems without changing the enumeration-safe presentation.

### `/reset-password`

The reset-completion route consumes one-time fragment state, removes it from the address, and submits the new credential through the defined backend operation.

**Expected source behavior:** successful completion clears transient material and returns to an appropriate authentication path.

**Failure path:** expired or invalid material is not recovered from browser storage; request a new workflow.

### `/authorize`

This authenticated route presents an OAuth authorization decision. It sends the approve/deny decision with backend-supplied opaque request state.

**Expected source behavior:** the backend remains owner of authorization state and redirect completion.

**Failure path:** missing, expired, invalid, or reused request state produces an authorization error, not a guessed redirect.

**Runtime ceiling:** the checked backend reports OAuth authorization-server capability, but that does not prove this browser route is mounted.

### `/account`

The authenticated account overview presents public principal/account information and navigation to subordinate account workflows.

**Expected source behavior:** the view contains no session credential, bearer value, or one-time key material.

**Failure path:** an anonymous or expired principal returns through the guarded login flow with only a validated local return path.

### `/account/security`

This authenticated route contains the password-change workflow present in source.

**Current source behavior:** the route submits password changes directly through the generated service client. Its router parent applies the authentication gate, but no checked source for this route applies a runtime-capability or presentation-authorization gate.

**Integration requirement:** add explicit capability and presentation-authorization gates before exposing any security action that depends on them. Those browser gates remain defense-in-depth; the backend must authorize the operation.

**Failure path:** the auth manager does not implement browser elevation; a flow requiring step-up cannot claim support until assembled with a concrete elevation mechanism.

### `/account/sessions`

This authenticated route lists and revokes sessions.

**Expected source behavior:** revocation refreshes the list; revoking the current session transitions the browser to anonymous state when confirmed.

**Failure path:** failed revocation leaves the session represented and does not optimistically claim it is gone.

### `/account/api-keys`

This authenticated route contains service-account and API-key issue, rotate, and revoke workflows.

**Expected source behavior:** newly issued or rotated key material is shown once, then cleared on acknowledgement or refresh; later views retain metadata only.

**Failure path:** a lost one-time value is never reconstructed or read from persistent storage.

### `/account/connected-apps`

This authenticated route lists OAuth grants and supports revocation.

**Expected source behavior:** confirmed revocation refreshes the grants list without logging out the browser session unless backend policy separately changes it.

**Failure path:** failed revocation keeps the grant visible and preserves the structured service problem.

## Source components outside the current route graph

The repository also contains tenancy and upload presentation source. The tenant switcher and upload panel are not imported into the application route graph. Their files do not add routes or runtime availability.

Realtime has an additional contract gap: no current AsyncAPI artifact is selected, while generated realtime output and a package export remain. The generator exits successfully on manifest non-selection before comparing that output. See [realtime and uploads](realtime-and-uploads.md).

## Fixture-only expectations

The full-reference fixture source expects `/events`, `/realtime/ws`, and `/uploads` to be absent. Those negative fixture expectations do not establish production absence, but they prevent using the fixture as evidence of realtime or upload assembly.

Fixture success also cannot upgrade the active `oauth-provider` capability artifact. A generated web profile must be produced and its real browser/API composition exercised before any profile-specific browser claim.

## Integration decision table

| Intended claim | Minimum missing evidence |
|---|---|
| “The browser app is served” | A concrete generated/assembled service returning the shell on recognized routes. |
| “Web auth is available” | Runtime capability reporting it compiled and available, plus exercised session routes. |
| “Account management is available” | Mounted generated operations and exercised protected browser routes. |
| “Reference records work” | Assembled route and backend operations exercised with conflict/problem behavior. |
| “Realtime works” | Selected AsyncAPI, coherent generated output, mounted endpoint, and lifecycle exercise. |
| “Uploads work” | Selected capability, generated initiation contract, mounted backend, and complete lifecycle exercise. |
| “A browser profile is release-ready” | Bound build, security, browser, accessibility, performance, and manual approval evidence. |

## Verification path

A future independent verification should start from the concrete generated profile and record its manifest, contract hash, capability response, API/web artifact identities, and public route topology. It should then exercise each claimed route against that exact backend, including negative authentication, authorization, conflict, secret-handling, and reserved-route behavior.

No profile generation, application launch, browser navigation, request, or test was run for this page. Current evidence supports the route inventory and runtime ceiling only.
