---
spec_id: OMNIUS-016
title: Testing and Quality
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Testing and Quality


## Layers

1. Pure domain unit tests.
2. Module unit tests.
3. HTTP/service tests through Axum.
4. Real infrastructure integration tests.
5. Cross-module profile tests.
6. Property/fuzz/concurrency tests.
7. Load/soak/failure tests.
8. Upgrade/migration/generator tests.

## Tools

- `cargo-nextest` for isolated execution, retries only for diagnosed flaky external tests, partitions, and groups.
- Testcontainers and maintained modules for PostgreSQL, Redis, NATS, and compatible services.
- Wiremock for provider HTTP contracts.
- `proptest` for parsers, pagination, policy inputs, state machines.
- `cargo-fuzz` for untrusted parsers/protocols.
- Criterion for microbenchmarks where regressions matter.
- Tokio paused time/clock abstraction for deterministic expiry and scheduling.
- Optional Loom for project-authored concurrency primitives.

## Required test support

Deterministic clock, ID/random factories, config builders, principals/tenants, test server/client, email/object/webhook fakes, database reset/isolation, Redis namespace isolation, and safe event/job inspectors.

Fakes implement the same semantic contract; they do not silently behave more reliably than production.

## Required suites

### HTTP

Problem Details, content type, limits, timeout, request ID, CORS/CSRF, proxy spoofing, security headers, idempotency, pagination.

### Persistence

Fresh/upgrade migrations, constraints, transaction rollback, deadlock/serialization retry, pool exhaustion, rolling compatibility, backfill restart.

### Authentication

Session fixation/rotation/revoke/expiry, CSRF, password rehash, enumeration resistance, reset replay, JWT algorithm/issuer/audience/time/JWKS rotation, OIDC state/nonce/PKCE, API key lifecycle, WebAuthn ceremony, TOTP replay/recovery.

### Authorization/tenancy

Horizontal, vertical, cross-tenant, list/bulk, indirect reference, job/CLI transport, admin impersonation, missing policy.

### Async/realtime

Job retry/idempotency/dead letter/drain; outbox/inbox; broker disconnect; slow consumer; revoked session; resume semantics; multi-instance fan-out.

### Integrations

Webhook signature/replay; SSRF; provider rate limits; object size/type/quarantine; email template/sink; redaction.

## Profile matrix

Test named profiles and selected pairwise combinations, not only `--all-features`. Invalid combinations have negative generator tests.

## Load/failure

Provide scripts/scenarios for HTTP throughput/latency, auth bursts, pool saturation, cache outage, Redis reconnect, queue backlog, realtime fan-out/slow consumers, graceful rollout, and dependency latency.

## Flake policy

A retry is temporary quarantine with owner and expiry, never a permanent substitute. Tests use readiness conditions instead of sleeps and deterministic clocks instead of wall time.

## Coverage

Coverage is reported but no single percentage defines quality. Security-critical branches and every acceptance criterion require explicit tests.
