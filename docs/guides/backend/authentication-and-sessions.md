---
title: Authentication and sessions
description: Use assembled Omnius account, browser-session, API-key, and OAuth-provider flows while distinguishing library-only and unassembled identity providers.
status: experimental
implementation: implemented
profile_availability:
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - full-reference
public_exposure: assembled
audience:
  - developer
  - integrator
  - operator
topics:
  - backend
  - authentication
  - sessions
capabilities:
  - local-account-password
  - browser-sessions-postgres
  - browser-sessions-redis
  - jwt-resource-server
  - api-keys-service-accounts
  - oauth-oidc-provider
  - oidc-client-external-identities
  - mfa-totp
  - mfa-webauthn-passkeys
source:
  - crates/auth-core/src/lib.rs
  - crates/auth-password/src/lib.rs
  - crates/auth-session-postgres/src/lib.rs
  - crates/auth-session-redis/src/lib.rs
  - crates/auth-jwt/src/lib.rs
  - crates/auth-api-key/src/lib.rs
  - crates/auth-oauth-server/src/lib.rs
  - crates/auth-oidc/src/lib.rs
  - crates/auth-totp/src/lib.rs
  - crates/auth-webauthn/src/lib.rs
  - crates/reference-api/src/browser_auth.rs
  - crates/reference-api/src/account_auth.rs
  - crates/reference-api/src/oauth_provider.rs
  - crates/reference-api/src/lib.rs
  - crates/reference-api/src/api_key_auth.rs
evidence:
  - apps/api-server/tests/browser_auth.rs
  - apps/api-server/tests/oauth_provider.rs
  - apps/api-server/tests/authenticated_profile.rs
  - crates/auth-password/tests/registration.rs
  - crates/auth-session-postgres/tests/session_flow.rs
  - crates/auth-api-key/tests/api_keys.rs
  - crates/auth-jwt/tests/verifier.rs
last_verified: 2026-08-30
---

# Authentication and sessions

Authentication establishes a canonical internal `Principal`; it does not authorize a resource operation. The principal carries the authenticated subject, method, assurance level, scopes, and active tenant context needed by later layers. See [Identity, authorization, and tenancy](../../concepts/identity-authorization-and-tenancy.md) and [Authorization and tenancy](authorization-and-tenancy.md).

The reference API assembles local accounts, PostgreSQL browser sessions, API keys and service accounts, and an OAuth/OIDC provider. Other implemented identity libraries remain library-only or unassembled.

## Provider and exposure map

| Provider | Exposure | What that means |
| --- | --- | --- |
| Local account and password | Assembled | Registration, verification, reset, change, and invitation-aware flows are wired into the API server |
| PostgreSQL browser sessions | Assembled | Login, session lookup, logout, logout-all, and device-session revocation are wired |
| Redis browser sessions | Library only | Store and lifecycle exist; no selected profile or API-server mount |
| JWT resource server | Unassembled | Bearer parsing and verification library exists; the reference config keeps JWT resource-server authentication disabled |
| API keys and service accounts | Assembled | Managed key authentication is wired; secret material is shown only at creation |
| OAuth/OIDC provider | Assembled | Authorization-code/PKCE, consent, token, metadata, JWKS, UserInfo, and revocation are wired. Dynamic client registration is implemented, but the checked-in reference configuration disables it and therefore does not mount `/oauth/register` |
| External OIDC client | Library only | Upstream federation and external-identity linking code exists without a concrete reference mount |
| TOTP | Library only | Enrollment and verification components exist without a reference route composition |
| WebAuthn | Library only | Registration and authentication components exist without a reference route composition |

Do not infer runtime exposure from a profile, migration, OpenAPI artifact, library test, or configuration type.

## Local accounts

Passwords are processed with bounded Argon2id work and a pepper ring. Verification and reset values are stored as one-use digests rather than reusable plaintext credentials. The reference configuration uses invite-only registration; that is a reference setting, not a universal default.

The assembled account surface includes:

- `POST /auth/register`;
- `POST /auth/email/verification/request` and `/auth/email/verification/complete`;
- `POST /auth/password/reset/request` and `/auth/password/reset/complete`;
- `POST /auth/password/change`;
- invitation management exposed through the dedicated administration flow.

Request and reset endpoints must use uniform outward responses where account existence is sensitive. Never log passwords, reset values, verification values, or invitation values.

## PostgreSQL browser sessions

The assembled session surface includes:

- `POST /auth/login`;
- `GET /auth/session`;
- `POST /auth/logout` and `/auth/logout-all`;
- `GET /auth/sessions`;
- device-session revocation under `/auth/sessions/{device_id}`.

The reference cookie is `__Host-omnius_session`, with `Secure`, `HttpOnly`, and `SameSite=Lax`. The reference configuration uses a 12-hour idle lifetime and a 30-day absolute lifetime. Treat those values as the checked-in reference policy, not as hidden framework defaults.

The PostgreSQL guard checks validity, revocation, and expiry before a protected handler receives a principal. Invalid, expired, revoked, malformed, or backend-unavailable sessions fail closed. Logout clears the client cookie, but server-side revocation is the authority.

## Redis session distinction

The Redis session store is implemented but library-only. If a future application enables it, Redis becomes authoritative for those sessions: connectivity and readiness must be required, provider errors must fail closed, and shutdown must preserve the store's lifecycle contract. Use a dedicated Redis instance or database because the provider exposes no key-prefix hook.

There is no supported profile, runtime flag, or command for mounting Redis sessions in the reference application.

## API keys and service accounts

API-key material is displayed once at creation. Storage uses a keyed digest with pepper material and constant-time verification; later administration surfaces must show metadata, not the secret.

Documentation and diagnostics may use only a placeholder:

```http
Authorization: Bearer <redacted API key or access token>
```

Never use a realistic sample key. Missing, malformed, unknown, revoked, expired, or unverifiable credentials must produce a uniform authentication failure before the handler. Authorization still runs after key authentication.

## OAuth provider versus OIDC client

These roles are not interchangeable:

- The **OAuth/OIDC provider** is assembled in the `oauth-provider` profile and issues credentials for its configured issuer. Authorization code with PKCE, consent, token, discovery, JWKS, UserInfo, and revocation are first-party server responsibilities. Dynamic client registration is implemented behind `auth.authorization_server.dynamic_client_registration`; the checked-in reference value is `false`, so the reference server does not mount `/oauth/register`.
- The **external OIDC client** authenticates against an upstream issuer and links an external identity to a local account. Its library is implemented, but it is not mounted in the reference server.
- The **JWT resource server** validates upstream bearer tokens. Its library is implemented, but the reference runtime keeps it disabled and does not assemble a live upstream bearer path.

A mounted provider JWKS endpoint does not prove that incoming JWT resource-server authentication is enabled.

## MFA libraries

TOTP and WebAuthn both have implemented provider libraries and persistence evidence, but neither has a concrete application mount. Do not publish enrollment or assertion routes, claim step-up coverage, or raise a principal's assurance level until a real composition binds the ceremony, credential lifecycle, replay checks, recovery policy, and session update.

## Starting the assembled provider

This command starts the concrete reference API only after its dependencies and protected settings are ready.

**Prerequisites**

- run from the repository root with the repository Rust toolchain;
- use an isolated preproduction PostgreSQL database that contains no customer data while exercising production validation;
- inject every secret placeholder through protected configuration, including the PostgreSQL URL and identity cryptographic material;
- configure a non-production HTTPS issuer and its matching externally reachable origin;
- route account email through a controlled preproduction SMTP sink, and keep every sample user, client, and credential synthetic.

```bash
cargo run --locked --bin omnius-api-server -- server --config config/reference.toml --environment production
```

**Expected result:** the API server completes required PostgreSQL and identity initialization and exposes the assembled OAuth-provider and browser-auth surfaces for its configured issuer.

**Failure path:** startup must stop on missing or malformed secrets, database or migration incompatibility, invalid issuer/origin policy, or required identity-provider initialization failure. Correct the dependency or configuration; do not enable a fallback verifier or bypass migration checks.

The command does not assemble Redis sessions, an upstream JWT resource server, external OIDC login, TOTP, or WebAuthn. It is a documented verification recipe and was not run as part of this documentation work.

## Related pages

- [Authorization and tenancy](authorization-and-tenancy.md)
- [Identity, authorization, and tenancy](../../concepts/identity-authorization-and-tenancy.md)
- [Reliability and idempotency](../../concepts/reliability-and-idempotency.md)
- [Identity and permissions troubleshooting](../../troubleshooting/identity-and-permissions.md)
