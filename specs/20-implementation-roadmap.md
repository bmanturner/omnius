---
spec_id: RSK-020
title: Implementation Roadmap
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Implementation Roadmap


## Phase 0 — Compatibility and repository skeleton

Deliver:

- Rust 1.98.0/edition 2024 workspace.
- Dependency compatibility spike.
- `cargo tree -d` review.
- Baseline lockfile and dependency policy.
- ADRs 0001–0007.
- Spec/profile validators.
- CI skeleton.

Exit: every foundational candidate resolves; session store and job-provider variants are proven or explicitly deferred; no unexplained foundational duplicate.

## Phase 1 — Runtime kernel

Config, secrets, errors, IDs/time/clock, Axum/Tower shell, request ID, traces, Problem Details, health/startup/readiness, supervision, shutdown, build metadata, minimal profile.

Exit: minimal profile acceptance passes.

## Phase 2 — Test support

Nextest, test fixtures, deterministic clock/IDs, test server, Wiremock, Testcontainers plumbing, profile harness, generator snapshot tests.

Exit: clean CI provisions and tears down dependencies reliably without sleeps.

## Phase 3 — PostgreSQL and API contracts

SQLx pool, migrations, checked queries/offline metadata, transaction/retry helpers, CRUD reference domain, idempotency, pagination, ETag, OpenAPI, validation, outbound client.

Exit: API profile acceptance and migration upgrade rehearsal pass.

## Phase 4 — Identity

Principal, users/credentials, Argon2id, verification/reset, sessions, CSRF, JWT/JWKS, OIDC adapter, API keys, optional WebAuthn/TOTP, security events.

Exit: authenticated-api acceptance and threat tests pass.

## Phase 5 — Authorization, tenancy, audit

Built-in evaluator, permission matrix, organization/membership, tenant query discipline, audit, admin/impersonation, optional Cedar.

Exit: all horizontal/vertical/cross-tenant tests pass through every invocation path.

## Phase 6 — Redis/cache/rate limits

Redis core, Moka/Redis cache, failure policy, local rate limits, optional Redis session store, Pub/Sub adapter.

Exit: outage/reconnect/stampede/cardinality tests pass.

## Phase 7 — Durable work and events

Job provider interface, Apalis/Redis provider, optional PGMQ spike, outbox/inbox, scheduler, NATS JetStream provider, admin diagnostics.

Exit: at-least-once/idempotency/restart/drain/dead-letter tests pass.

## Phase 8 — Realtime

SSE, WebSocket protocol, auth/authz, bounded queues, slow-consumer behavior, fan-out, drain, optional replay.

Exit: realtime profile acceptance and load scenario pass.

## Phase 9 — Storage, email, notifications, webhooks

`object_store`, upload quarantine/scanner port, lettre/MiniJinja, notification orchestration, Svix adapter, inbound webhook framework, SSRF policy.

Exit: durable delivery, signature/replay, upload lifecycle, redaction tests pass.

## Phase 10 — Optional modules

Feature flags, search projection, billing/entitlement adapter skeleton, GraphQL, gRPC, localization, privacy lifecycle, consent, moderation.

Exit: each selected module satisfies standard lifecycle and profile tests; no optional module enters default profiles accidentally.

## Phase 11 — Generator and upgrade engine

`cargo-generate` template, module catalog, add/remove/doctor/diff/upgrade commands, managed regions, ownership enforcement, profile generation.

Exit: all profiles generate; add/remove is idempotent; upgrade rehearsals preserve application edits/data.

## Phase 12 — Hardening and release

Load/soak/failure tests, security review, cargo-vet imports, SBOM/provenance, runbooks, API compatibility, documentation, release process, supported-version policy.

Exit: complete traceability, zero open blocker, full-reference profile, signed release artifact.

## Phase discipline

A later phase may begin only when required interfaces are stable and the previous phase exit is recorded. Optional provider spikes may run early but cannot alter baseline silently.
