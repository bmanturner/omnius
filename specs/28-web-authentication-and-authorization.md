---
spec_id: RSK-028
title: Web Authentication and Authorization Integration
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Web Authentication and Authorization Integration

## 1. Purpose

This specification integrates the base identity, session, JWT, OIDC, tenancy, and authorization capabilities into browser applications. It does not redesign backend identity.

## 2. Authentication modes

The SDK MUST support a declared authentication mode:

- `session` — same-origin opaque server-side session cookie; default for first-party web applications.
- `bearer` — externally supplied access token for mobile, public API, or separate-origin clients.
- `oidc-redirect` — browser authorization-code and PKCE flow terminating in a server-side session or approved token strategy.
- `none` — explicitly unauthenticated application.

Only compiled and configured modes may appear in capabilities metadata.

## 3. Session mode

In session mode:

- The session identifier MUST be stored in a `Secure`, `HttpOnly` cookie with an explicit `SameSite` policy.
- JavaScript MUST NOT receive, persist, or log the session secret.
- The API client MUST use the configured browser credentials policy.
- A session bootstrap endpoint MUST return the current public principal, session metadata, permission summary, and tenant context.
- Login and privilege elevation MUST rotate the server-side session identifier.
- Logout MUST clear client cache and realtime state in addition to revoking the server session.
- Expired or revoked sessions MUST produce a stable problem code.
- Tabs SHOULD converge after login/logout through a safe cross-tab signal that carries no credential.

The SDK MUST provide semantic primitives equivalent to:

```text
getSession
useSession
useCurrentPrincipal
login
logout
logoutAll
requireAuthenticated
requireAnonymous
```

## 4. CSRF and cross-origin controls

Cookie-authenticated unsafe methods MUST be protected by the backend's approved CSRF/cross-origin defense. The frontend adapter MUST:

- obtain and send any required anti-CSRF value without exposing the session identifier.
- avoid adding CSRF headers to untrusted origins.
- preserve same-origin defaults.
- treat CSRF rejection as a distinct typed problem.
- exercise negative tests for missing, stale, and cross-origin tokens.

CORS MUST NOT be enabled broadly merely to make development convenient. Vite development uses a proxy by default.

## 5. Bearer mode

The framework-neutral core MAY accept a token provider:

```ts
getAccessToken(): Promise<string | null>
```

The SDK MUST NOT prescribe local storage. Token persistence is a host-application security decision and MUST be documented by any profile that enables it.

Bearer integration MUST support:

- expiration-aware retrieval.
- one controlled refresh attempt.
- refresh single-flight.
- cancellation.
- logout/revocation.
- audience-specific clients.
- redacted diagnostics.

The SDK MUST prevent refresh loops.

## 6. OIDC browser flow

OIDC utilities MUST delegate authorization request construction, state, nonce, PKCE, token exchange, and account linking to the backend identity module unless an ADR explicitly chooses a public-client architecture.

The frontend MAY expose:

```text
beginOidcLogin(provider, returnTo)
completeOidcCallback
listLinkedIdentities
unlinkIdentity
```

`returnTo` values MUST be validated against approved same-origin locations.

## 7. Authorization presentation

The backend MUST include a public permission vocabulary and the principal's effective presentation permissions or claims suitable for UX decisions. The SDK MUST provide:

```text
can(permission, resourceContext?)
canAny(...)
canAll(...)
usePermission(...)
usePermissions(...)
RequirePermission
requirePermission
```

These controls hide, disable, redirect, or explain UI. They MUST NOT be described or tested as the security boundary.

Every protected backend operation MUST continue to authorize independently when invoked through HTTP, WebSockets, SSE-triggered commands, jobs, CLIs, or future adapters.

## 8. Tenant and organization context

When tenancy is enabled:

- Tenant context MUST be explicit in the session and/or selected route.
- The SDK MUST prevent accidental reuse of cached data across tenants by including tenant identity in appropriate query keys.
- Changing tenant MUST cancel or invalidate tenant-scoped queries, reset tenant-scoped local state, and re-establish realtime subscriptions.
- Tenant IDs MUST NOT be inferred solely from a mutable client store when the backend contract requires a route or header value.
- Cross-tenant authorization errors MUST retain the backend's generic disclosure policy.

## 9. Route prerequisites

Router helpers MAY enforce:

- authenticated-only routes.
- anonymous-only routes.
- tenant-required routes.
- permission-present routes.
- capability-present routes.

They MUST handle initial loading without flashing protected content and MUST avoid redirect loops. Deep links MUST preserve an approved return destination.

## 10. Cache and lifecycle behavior

On login, logout, principal change, privilege change, or tenant switch, the adapter MUST execute a defined cache policy. Sensitive per-principal queries MUST never remain visible to a subsequent principal in the same browser process.

Realtime session-revocation or permission-change events SHOULD trigger session revalidation rather than trusting event payloads as authority.

## 11. Testing

Required tests include:

- session bootstrap.
- login and logout.
- logout-all.
- CSRF rejection.
- session expiration.
- cross-tab logout.
- no credential in storage/logs.
- permission presentation.
- direct backend denial despite bypassing UI.
- tenant switch cache isolation.
- OIDC return-location validation.
- bearer refresh single-flight and loop prevention where bearer mode is enabled.

## 12. Acceptance linkage

This specification is satisfied by `AC-WEB-031` through `AC-WEB-040`.
