---
title: Web authentication and account flows
description: Browser session ownership, protected routing, one-time secret handling, and checked-in account journeys.
status: experimental
implementation: source-only
profile_availability:
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: unassembled
audience:
  - web developers
  - identity integrators
  - security reviewers
topics:
  - authentication
  - sessions
  - accounts
  - browser-security
capabilities:
  - web-auth
  - web-identity-and-account-journeys
  - web-account-and-oauth-workflows
source:
  - web/src/auth-manager.ts
  - web/src/router.tsx
  - web/src/routes/login-route.tsx
  - web/src/routes/account-route.tsx
  - packages/web-sdk/src/auth/session.ts
evidence:
  - web/e2e/browser.spec.ts
  - web/e2e/session-boundaries.spec.ts
  - contracts/capabilities.json
last_verified: 2026-08-30
---

# Web authentication and account flows

The reusable `web-auth` SDK behavior is implemented, while the generic `web-account-and-oauth-workflows` profile classification remains source-only and unassembled; this page's frontmatter follows that generic capability. The checked capability artifact selects `oauth-provider` and reports `web-auth` as neither compiled nor runtime-available. Treat the generic routes below as source-backed workflows, not exposed endpoints. The concrete reading-list example is qualified separately and does not promote any `web` profile row.

Backend session semantics belong to [backend authentication and sessions](../backend/authentication-and-sessions.md). Trust boundaries and browser controls belong to [browser security](../../security/browser-security.md). Profile and exposure status belongs to the [availability matrix](../../reference/availability-and-exposure-matrix.md).

## Concrete reading-list example

`examples/reading-list` is a concrete assembled browser application, separate
from the generic `web` profile classification. Its six browser routes are:

- `/` for the authenticated reading list;
- `/login`;
- `/register`;
- `/verify-email`;
- `/forgot-password`;
- `/reset-password`.

Its application-owned composition provides registration, mandatory email
verification, login and logout, password recovery, PostgreSQL-backed
owner-scoped reading-item CRUD, and strong ETag preconditions for mutations.
The browser keeps session credentials in same-origin cookies and injects the
application's generated current-principal operation into the generic session
manager.

For this example, `http://localhost:3002` is the exact trusted origin. Login and
every unsafe cookie-authenticated request require an `Origin` header that
exactly matches that value; missing or different origins are denied rather than
falling back to permissive CORS or machine-callback handling. Verification and
recovery mail is delivered to local Mailpit through the development-only
plaintext SMTP provider. That provider is not a production option or a generic
profile default.

The journey is register, read the verification message in Mailpit, consume the
fragment token after removing it from browser history, log in, create/list/
finish/delete reading items with ETags, recover a password through the same
fragment rule, and log out. This is evidence about
`examples/reading-list` only, not every generated authenticated or web
application.

## Browser session owner

`BrowserSessionAuthManager` owns the application's public authentication snapshot. It creates the service client after removing any caller-supplied SDK authentication configuration, preventing two auth owners from competing. Requests use browser-managed same-origin credentials.

The public principal does not expose session identifiers or bearer credentials. Login, logout, and logout-all use generated operations. Each application adapts its own generated current-principal operation through `createGeneratedCurrentPrincipalPort`; the manager refreshes through that injected port and publishes transitions to subscribers.

Cross-tab state uses a `BroadcastChannel` named `omnius-auth-session`, with an in-memory fallback where that browser facility is unavailable. Disposing the manager closes its channel and listeners. The channel coordinates state changes; it does not transfer cookies or other credentials.

The manager currently has two important limitations:

- `elevate()` throws because browser elevation is unsupported;
- the realtime identity-transition reset hook is an explicit no-op.

An integration that requires privilege elevation or identity-bound realtime teardown is incomplete until it supplies and verifies those behaviors.

## Route guards and return paths

The current router applies an authenticated guard to:

- `/authorize`;
- `/account`;
- `/account/security`;
- `/account/sessions`;
- `/account/api-keys`;
- `/account/connected-apps`.

It applies an anonymous guard to `/login`, `/register`, and `/forgot-password`. Verification and reset completion are reachable without that anonymous guard and enforce workflow-specific state.

After login, a return path is accepted only when it resolves to the current origin and begins at the application root. A safe value such as `/account` can be restored. An external-origin value is rejected and the route falls back to `/account`.

This validation prevents open redirects but does not authorize the destination. In current source, the destination route applies its authentication gate; no checked destination route adds a runtime-capability or presentation-authorization gate. An integration must add those browser gates where required, and the backend remains authoritative for every operation.

## One-time secrets

Invitation, verification, and reset material is read from one named URL fragment field into memory, then removed from browser history with `history.replaceState`. Documentation and diagnostics must not show an example secret, even a plausible-looking test value.

The required invariant is:

1. read only the expected fragment field;
2. retain it only in transient memory for the workflow;
3. remove it from the visible address immediately;
4. never copy it into query strings, persistent browser state, logs, analytics, or error reports;
5. clear it when the workflow ends or the route is abandoned.

If the fragment is missing, malformed, or already consumed, present an invalid/expired workflow and provide a route back to a new request. Do not silently invent a value or retry with stale material.

API key issuance follows the same disclosure principle. Newly issued key material is shown once, held in route state, and cleared on acknowledgement or refresh. Later views may show metadata, not the original key.

## Checked-in journeys

### Login and logout

The login route submits credentials through the generated session operation, refreshes the public principal, and restores a validated local destination. Logout clears the current browser session; logout-all invalidates all sessions represented by the corresponding backend operation.

**Expected result:** the public principal, protected-route access, and other open tabs converge on the new state.

**Failure path:** preserve the structured service problem or network failure. Do not claim logout succeeded until the principal refresh and guarded routes agree.

### Local registration and email verification

The source contains local registration, verification, and resend-verification workflows. Availability depends on the assembled identity backend and capability response. Verification material follows the fragment-only rule above.

**Expected result:** successful registration advances to the backend-defined verification or account state without exposing one-time material.

**Failure path:** an expired or invalid verification request remains a recoverable verification error, with resend offered only when runtime capability and backend policy allow it.

### Password reset and change

The forgot-password route requests a reset without disclosing whether an account exists. Reset completion consumes one-time fragment material. The account security route contains an authenticated password-change workflow that calls the generated service client directly; its checked browser gate is authentication only.

**Expected result:** reset request responses remain enumeration-safe, completion removes transient material, and a confirmed password change updates the authenticated account state. An integration must add any required capability and presentation-authorization gates while retaining backend authorization.

**Failure path:** expired or rejected reset material is not retried from browser storage. Request a new reset through the public route.

### Session management

`/account/sessions` lists sessions and supports revocation. The UI must identify the current session without exposing its credential. Revoking a session should refresh the list; revoking the current session must be prepared to transition the browser to anonymous state.

**Expected result:** revoked sessions disappear or show their backend-defined terminal state, and a revoked current session loses protected access.

**Failure path:** a failed revocation remains visible and does not optimistically claim the session is gone.

### Connected applications

`/account/connected-apps` lists OAuth grants and supports revocation. Revoking a grant is distinct from logging out the browser session.

**Expected result:** the grant list refreshes and the revoked application's authorization is no longer represented.

**Failure path:** preserve the backend problem and keep the grant visible until revocation is confirmed.

### Service accounts and API keys

`/account/api-keys` contains service-account and API-key issue, rotate, and revoke flows. Newly issued or rotated key material is shown once. The checked route has an authenticated parent gate; capability and presentation-authorization checks are integration requirements rather than behavior proven in this route source, and backend authorization remains authoritative for every action.

**Expected result:** metadata remains listable after the one-time value is cleared.

**Failure path:** never reconstruct, cache, or log a lost one-time value. Issue or rotate through an authorized new action instead.

### OAuth authorization decision

`/authorize` renders a native authorization decision and posts an opaque request value together with the user's decision. The opaque value must stay exactly as supplied by the backend workflow; browser code must not decode it into authority or treat it as a credential for other requests.

**Expected result:** approve or deny returns control through the backend-owned authorization flow.

**Failure path:** missing, invalid, expired, or already-used request state produces an authorization error, not a guessed redirect.

## Capability and authorization ordering

A route should distinguish:

1. whether the runtime implements and exposes the feature;
2. whether a principal is authenticated;
3. whether that principal is authorized for the specific action;
4. whether one-time workflow state is valid.

Do not turn “feature unavailable” into “permission denied,” or “permission denied” into “not signed in.” Apply the canonical identity model from [identity, authorization, and tenancy](../../concepts/identity-authorization-and-tenancy.md), then use [authorization, tenancy, and capabilities](authorization-tenancy-and-capabilities.md) for browser presentation.

## Verification checklist

Runtime verification should observe the assembled surface and record:

- runtime capability and contract identity;
- anonymous and authenticated guard transitions;
- same-origin return-path acceptance and external-origin rejection;
- cross-tab logout convergence;
- absence of credentials and one-time material from URL, storage, logs, telemetry, and built assets;
- verification/reset expiry behavior;
- current-session revocation behavior;
- one-time API key clearing;
- unsupported elevation and realtime reset behavior where relevant.

No authentication request, browser scenario, or test was run for this documentation edit. The root E2E source proves fixture coverage only and does not establish that the generic account routes are mounted by a `web` profile; the reading-list qualification above applies only to its separately assembled example.
