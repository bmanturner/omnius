---
spec_id: RSK-000
title: Scope, Principles, and Quality Attributes
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Scope, Principles, and Quality Attributes


## Problem

Rust services repeatedly re-solve configuration, pools, migrations, errors, observability, identity, permissions, caching, jobs, realtime delivery, tests, and deployment. Copying an old service preserves accidental choices; a large framework often imports unwanted architecture.

The service kit is the maintained middle ground: opinionated foundations, optional capabilities, explicit composition, and evidence-backed dependencies.

## Goals

The kit MUST:

1. Generate a useful service requiring no external infrastructure.
2. Add PostgreSQL, Redis, auth, jobs, realtime, storage, notifications, and related modules without restructuring the application.
3. Produce understandable code independent of generator internals.
4. Make secure, observable behavior the default.
5. Use established crates/services for commodity infrastructure.
6. Keep domain logic independent from transports, storage, and identity providers.
7. Define startup, failure, readiness, and shutdown behavior per module.
8. Prove named supported profiles rather than claim arbitrary combinations.
9. Upgrade generated services without destroying application code or data.
10. Maintain a complete recommendation-to-test trace.

## Non-goals

The first release is not:

- A web framework competing with Axum.
- An ORM or query language.
- An OAuth authorization server or identity provider.
- A policy language competing with Cedar.
- A durable message broker or webhook delivery platform.
- A universal payment/search/deployment abstraction.
- A dynamic binary plugin ABI.
- A generic DDD framework.
- A WAF, secret manager, backup system, or disaster-recovery platform.
- A guarantee that all module combinations work.

## No-reinvention rule

Capabilities fall into three classes.

### Adopt

Use a mature crate or external system directly behind configuration and a small integration layer. Examples: Axum, SQLx, Redis, OIDC, Argon2, WebAuthn, object storage, tracing, Svix.

### Thin adapter

Project-owned code may:

- Map a crate into the canonical domain interface.
- Add typed config, lifecycle, health, telemetry, and redaction.
- Coordinate an application transaction.
- Apply product authorization or tenancy.
- Normalize fakes.
- Preserve an escape hatch from a provider.

A thin adapter must remain small enough to delete; it must not become a parallel framework.

### Product-specific implementation

Application semantics must be implemented locally: membership roles, entitlements, moderation policy, consent, audit taxonomy, notification preference rules, and similar concerns.

## Quality attributes

### Correctness

- Concurrency-sensitive invariants are enforced in the database.
- Delivery semantics are stated explicitly.
- Retries are bounded and idempotent.
- All external waits have timeouts.
- Retryable state changes support idempotency.

### Security

- Default-deny authorization and tenant isolation.
- No secret values in logs, traces, metrics, errors, or diagnostics.
- Browser authentication includes secure cookie and CSRF controls.
- Token verification validates signature, algorithm, issuer, audience, and time claims.
- Dependencies pass advisory, license, source, and audit policy.

### Availability

- Required dependencies affect readiness.
- Optional caches and telemetry can degrade safely.
- Shutdown drains within a bounded deadline.
- Unbounded memory growth is a correctness defect.

### Operability

Every module defines logs, traces, metrics, probes, runbook signals, failure modes, and build/version metadata.

### Maintainability

Workspace direction is enforced, foundational versions are centralized, generated ownership is explicit, public APIs are semver-checked, and material decisions are recorded as ADRs.

### Performance

Clients/pools are reused, hot paths avoid needless allocation, and performance budgets are measured rather than guessed.

## Initial conformance targets

- Minimal profile startup under 500 ms on a typical development machine after compilation.
- Minimal release-mode idle RSS target under 35 MiB; exceeding it requires measurement and an ADR, not premature micro-optimization.
- No unbounded middleware or message queue.
- Configurable graceful-shutdown default of 30 seconds.
- Probe requests do not synchronously fan out to slow dependencies.
- Every profile generates and verifies from an empty directory in CI.
- Every direct dependency has rationale and an owner.
