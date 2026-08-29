---
spec_id: OMNIUS-019
title: Named Profiles and Profile Acceptance
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Named Profiles and Profile Acceptance


## Supported profiles

### `minimal`

Config, core runtime, HTTP shell, errors, tracing, health, graceful shutdown, test support, generator metadata. No external service.

### `api`

`minimal` plus PostgreSQL, migrations, validation, Problem Details, OpenAPI, idempotency, and outbound HTTP client.

### `authenticated-api`

`api` plus local accounts, passwords, PostgreSQL sessions, JWT verification, API keys, authorization, CSRF, local rate limits, security audit events, and required email delivery. The email module brings its `jobs-core` interface dependency but does not select a durable jobs provider. This profile is an OAuth resource server; upstream OIDC, WebAuthn, TOTP, Redis sessions, Cedar, and hosted OAuth/OIDC provider roles remain opt-in.

### `oauth-provider`

`authenticated-api` plus `auth-oauth-server`, the sole first-party OAuth Authorization Server and OpenID Provider module, together with its declared dependencies. It hosts the issuer without changing `authenticated-api` or any optional upstream OIDC, WebAuthn, TOTP, Redis-session, or Cedar module.

### `saas`

`authenticated-api` plus organizations/tenancy, invitations, audit, email/notifications, object storage, jobs, outbox/inbox, inbound/outbound webhooks, and feature flags. Default durable jobs use Redis/Apalis; a PGMQ variant is separately verified.

### `realtime`

`authenticated-api` plus SSE, WebSockets, presence, and Redis or NATS fan-out. The default uses Redis for ephemeral fan-out; durable replay requires NATS/outbox variant.

### `worker`

Config, telemetry, health/admin listener, PostgreSQL, selected queue/event provider, jobs, outbox relay, and integration adapters. No public API router.

### `full-reference`

A reference/CI composition exercising almost every non-conflicting module. It is not a recommended production starting point.

## Profile manifest

`machine/profiles.yaml` is derived from these definitions and specifies provider choices. A generated service records the exact profile version plus additions/removals.

## Common acceptance

Every profile:

- Generates from an empty directory.
- Uses only approved stable dependencies.
- Formats, lints without warnings, compiles, tests, and documents.
- Passes `cargo audit`, `cargo deny`, `cargo vet`, SBOM, semver, and spec verification.
- Starts with valid local config.
- Fails safely with invalid config.
- Exposes correct live/startup/ready/version behavior.
- Shuts down under deadline.
- Contains no unresolved placeholder.
- Produces a reproducible dependency graph and lockfile.

## Profile-specific acceptance

### Minimal

- Starts with no external services.
- `/live`, `/ready`, `/startup`, `/version`, and one example route work.
- Request ID, Problem Details, limits, trace, panic boundary, and drain are proven.
- Release binary and idle-memory targets are measured.

### API

- Clean database migrates.
- CRUD reference use case proves transactions, constraints, idempotency, cursor pagination, optimistic concurrency, OpenAPI, and errors.
- Pool exhaustion and DB outage affect readiness as designed.
- Migration command is separate in production mode.

### Authenticated API

- Complete delivered registration, verification, password, login/logout, recovery, and session-revocation lifecycle passes.
- Disabled, self-service, and invite-only registration policies are explicit; invitation tokens are identity-bound, expiring, and single-use.
- API-key/service-account management and API-key authentication protect every selected route, while session and bearer credentials map to the same canonical `Principal`.
- Session fixation, CSRF, enumeration, JWT validation, key rotation, rate limits, and authorization matrix pass.
- Mounted authentication routes agree with the resolved profile and advertised capabilities.

### OAuth provider

- OAuth and OpenID Connect discovery publish one exact issuer and only matching, mounted endpoints.
- Authorization Code with PKCE, explicit consent, secure client onboarding, resource/scope-bound access, rotating refresh credentials, and immediate grant revocation pass.
- Signed ID Tokens, JWKS, UserInfo, and RP-Initiated Logout interoperate exactly as advertised.
- Running routes, configuration, resolved `oauth-provider` closure, capabilities, and generated contracts remain in parity, and every resulting identity maps through `Principal`.

### SaaS

- Tenant isolation is proven across HTTP, jobs, cache, objects, search stub, and webhooks.
- Notification and webhook delivery are durable and idempotent.
- Outbox/inbox recover from restarts.
- Object upload passes quarantine/authorization/lifecycle.
- Audit records every administrative and security-sensitive action.

### Realtime

- Auth/origin/message authz, connection limits, slow consumer, revocation, multi-instance fan-out, and graceful drain pass.
- Replay/resume is offered only in durable variant.

### Worker

- Stops leasing on drain.
- Retries/dead-letter/idempotency pass.
- Admin health/metrics are protected.
- Fatal required task exit causes correct readiness/termination.

### Full reference

- All provider slots resolve without incompatible foundational duplicates.
- Cross-module flows pass end-to-end.
- Generated docs list every enabled capability and operational dependency.

## Invalid combinations

Generator negative tests include:

- Cache Redis without Redis core.
- Realtime Redis fan-out without Redis.
- Auth session provider missing a store.
- Two job providers selected as default.
- GraphQL subscriptions without realtime.
- Tenant module without authorization/audit.
- Removal of a dependency still required by another module.
- SQLx 0.9 forced into the 0.8 baseline without the upgrade ADR.
