---
title: Web integration quickstart
description: Source-grounded steps for integrating the checked-in React application and generated web SDK without mistaking them for an assembled runtime.
status: experimental
implementation: source-only
profile_availability:
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: unassembled
audience:
  - application developers
  - integrators
topics:
  - web
  - integration
  - routing
  - contracts
capabilities: []
source:
  - web/src/app.tsx
  - web/src/router.tsx
  - packages/web-sdk/package.json
  - web/src/routes/status-route.tsx
  - web/vite.config.ts
  - web/package.json
  - package.json
  - packages/web-sdk/src/client/index.ts
  - contracts/capabilities.json
evidence:
  - web/e2e/browser.spec.ts
  - web/e2e/generated-profile.spec.ts
  - contracts/contract-manifest.json
last_verified: 2026-08-30
---

# Web integration quickstart

This page is an integration boundary, not a claim that a browser application is currently served. The repository contains a React application, generated HTTP contracts, framework-neutral and React SDK entry points, route-level workflows, and fixture tests. The checked capability artifact selects the `oauth-provider` profile and reports `web-auth` with both compiled and runtime availability set to `false`. No inspected evidence assembles the web application into that active runtime.

For exact status by profile, use the [availability matrix](../reference/availability-and-exposure-matrix.md). For the distinction between selected, compiled, mounted, and exposed behavior, use [capability and consumer contracts](../concepts/capability-and-consumer-contracts.md).

## Before integrating

Confirm all of the following from repository evidence:

1. The intended profile is one of `web`, `realtime-web`, `saas-web`, or `full-reference-web`. A profile catalog describes intended composition; it does not prove the application was built or mounted.
2. The browser and API share an origin in the intended deployment. The checked-in application configures same-origin credentials, and the static-delivery design keeps API routes at the origin root even when the application uses a nested base path.
3. The canonical contract manifest and OpenAPI artifact are the inputs to generation. Checked-in generated clients prove generation output only, not that an operation is mounted.
4. The integration has a real capability document from the runtime being exercised. Do not infer availability from package exports or rendered controls.
5. Authentication material remains in supported browser-managed flows. Never put a bearer token, cookie, invitation secret, reset secret, verification secret, API key, or presigned upload URL in documentation, logs, query strings, or committed configuration.

If any prerequisite is missing, stop at source integration. Do not label the result deployable or runtime-verified.

## Run the source shell locally

From the repository root:

```bash
pnpm install --frozen-lockfile
pnpm web:dev
```

`pnpm web:dev` starts the Vite development server only; it does not assemble or start an Omnius backend. Vite proxies declared backend paths to an independently started compatible backend at `http://127.0.0.1:8080` by default. Set `OMNIUS_DEV_PROXY_TARGET` to a different HTTP or HTTPS origin when the compatible backend listens elsewhere.

Opening `/` mounts `StatusRoute`, which immediately requests readiness and runtime metadata. A useful response therefore depends on that compatible backend. Loading or inspecting the Vite shell alone proves source behavior, not runtime assembly or verification.

## Integration sequence

### 1. Choose the SDK boundary

The package has no root `@omnius/web-sdk` export. Import each concern from its public subpath: `@omnius/web-sdk/client`, `@omnius/web-sdk/auth`, `@omnius/web-sdk/authorization`, `@omnius/web-sdk/realtime`, `@omnius/web-sdk/uploads`, `@omnius/web-sdk/llm`, `@omnius/web-sdk/capabilities`, or `@omnius/web-sdk/react`; reserve `@omnius/web-sdk/testing` for tests. This separation is enforced by the package boundary checks described in [generated contracts and SDK](../guides/web/generated-contracts-and-sdk.md).

The application composition in `web/src/app.tsx` creates one query client, one browser session authentication manager, a TanStack Router instance, and a `WebSdkProvider`. It defaults to a root-relative base URL and same-origin credentials, then disposes the authentication manager when the application unmounts. Preserve that single-owner lifecycle; do not create competing global clients or query caches.

**Expected result:** one application-owned SDK and query context supplies every route.

**Failure path:** if configuration produces conflicting SDK authentication or multiple unrelated query caches, correct composition before testing workflows. Do not work around it with route-local clients.

### 2. Mount routing under the deployment base path

`web/src/router.tsx` defines the current route source of truth. The application base path comes from Vite's public base URL and is normalized for TanStack Router. The API base remains origin-rooted; a nested browser path must not prefix API calls.

Current public routes are:

- `/`
- `/records`
- `/login`
- `/register`
- `/verify-email`
- `/forgot-password`
- `/reset-password`

Current authenticated routes are:

- `/authorize`
- `/account`
- `/account/security`
- `/account/sessions`
- `/account/api-keys`
- `/account/connected-apps`

The login, registration, and forgot-password routes use an anonymous guard. Verification and reset routes remain reachable while enforcing their own route logic. Route components are lazy-loaded, while the application shell owns navigation, route focus, and contract-mismatch presentation.

**Expected result:** a direct request to an application route returns the shell, while an API or reserved route keeps its backend semantics.

**Failure path:** if a reserved API path returns the browser shell, fix route topology and static fallback ownership. Do not add a catch-all that swallows backend routes. See [application architecture](../guides/web/application-architecture.md).

### 3. Treat capabilities as runtime gates

Parse the runtime capability document and make navigation and action availability depend on its compiled and runtime flags. A package export or source component is not a capability result. This is especially important for authentication, realtime, uploads, tenancy, and optional account functions.

The checked capability artifact is negative evidence for the active runtime: `web-auth` is not compiled or available there. It does not invalidate the checked-in web source; it establishes that the source and active profile are different evidence boundaries.

**Expected result:** unavailable functions are not offered as runnable runtime actions.

**Failure path:** if the capability response is absent, malformed, or contract-incompatible, fail closed and present the incompatibility. Do not assume optional features are enabled.

### 4. Connect authentication and account state

The browser session manager uses same-origin requests, exposes a public principal shape, and coordinates login/logout changes across tabs. One-time secrets are read into memory and removed from the browser address immediately. API keys are shown once and cleared after acknowledgement or refresh.

Use validated rooted same-origin return paths. The source accepts a value such as `/account` and rejects an external-origin return path, falling back to `/account`.

**Expected result:** login state, protected-route access, and cross-tab logout agree without exposing credentials.

**Failure path:** an elevation request currently throws because elevation is unsupported, and the application authentication manager's realtime reset hook is a no-op. Integrations requiring either behavior are incomplete until a concrete implementation is assembled. Continue with [authentication and account flows](../guides/web/authentication-and-account-flows.md).

### 5. Connect data through generated operations

The reference record workflow owns list filters in the URL. It supports `limit`, `cursor`, and `name`, with router validation constraining accepted values. Create requests use an idempotency key. Updates use a version-derived `If-Match` header. Conflict responses lead to an explicit reload or retry decision rather than a silent overwrite.

**Expected result:** navigation reproduces list state, mutations invalidate the appropriate scoped list, and RFC 9457 field errors appear at safe form locations.

**Failure path:** if an operation exists only in the generated client but the backend does not mount it, treat the response as an integration failure. Generation is not runtime assembly. See [data fetching, forms, and errors](../guides/web/data-fetching-forms-and-errors.md).

### 6. Add optional surfaces only after capability and contract evidence

Realtime and uploads are not baseline assumptions. The current contract manifest does not select AsyncAPI, while a checked-in generated realtime module and package export remain present. The realtime generator exits successfully when AsyncAPI is unselected, before comparing that checked-in module, so its drift status is not proven. The current browser fixture expects `/events`, `/realtime/ws`, and `/uploads` to be absent.

**Expected result:** an optional surface is mounted only when the selected profile, canonical contract, generated client, runtime capability result, and backend route agree.

**Failure path:** if any one of those layers disagrees, keep the feature unavailable and investigate the evidence gap. See [realtime and uploads](../guides/web/realtime-and-uploads.md).

## Source-level acceptance checklist

The integration is ready for independent runtime verification only when:

- application and API route ownership are disjoint;
- generated artifacts match the selected canonical contracts;
- runtime capability flags, not source presence, gate optional UI;
- protected routes restore only validated same-origin paths;
- tenant and principal identity scope every relevant query key;
- mutation conflicts and RFC 9457 errors remain visible and actionable;
- private material is absent from URLs, storage, logs, and built assets;
- accessibility and browser checks cover the assembled routes, not just fixtures;
- API and static assets have one coordinated release and rollback plan.

## Evidence status

No command or runtime verification was run for this page. An independent verifier must exercise the assembled application, observe its capability response and route behavior, and record the exact profile and artifact identities. Fixture tests and checked-in source remain design and test evidence only.
