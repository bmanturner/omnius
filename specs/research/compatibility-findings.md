---
spec_id: OMNIUS-RES-003
title: Compatibility Findings
version: 0.1.0
status: evidence
last_verified: 2026-08-23
---

# Compatibility Findings


## Findings that changed or constrained the design

### SQLx line

- SQLx 0.9.0 is current at verification time.
- SQLx 0.8.6 remains a supported stable release.
- The published SQLx-backed tower-sessions store reviewed for this bundle targets SQLx 0.8.
- The initial baseline is therefore SQLx 0.8.6.
- SQLx 0.9 is not considered rejected; it is gated until the session/job/test ecosystem resolves coherently.

Sources: `SRC-SQLX-001`, `SRC-SQLX-002`, `SRC-SESSIONS-002`.

### Sessions

- `axum-login` is selected for first-party login/session integration.
- `tower-sessions` provides the session framework and replaceable stores.
- The implementation MUST resolve the exact compatible trio of `axum-login`, `tower-sessions`, and the selected store in Phase 0.
- The application uses the version of tower-sessions exposed/accepted by axum-login instead of forcing an independent incompatible line.

Sources: `SRC-AXUMLOGIN-001`, `SRC-SESSIONS-001`, `SRC-SESSIONS-002`.

### Redis connections

The official Redis crate documents async multiplexed connections as cheap to clone and states that an async connection pool is generally unnecessary. The default therefore uses a multiplexed connection or `ConnectionManager`; a pool requires a concrete connection-affinity/blocking reason.

Source: `SRC-REDIS-001`.

### CSRF

tower-http 0.7.0 includes CSRF/cross-origin protection middleware. The baseline uses it rather than adding a smaller Axum-specific CSRF crate.

Source: `SRC-TOWERHTTP-001`.

### Durable jobs

- Apalis 0.7.4 is the latest stable jobs framework line, and its Redis adapter is selected under ADR-0011.
- `apalis-redis 0.7.4` forces an isolated `redis 0.32.7` line and emits Rust 2024 never-type fallback future-incompatibility warnings on Cargo 1.98; stable replacement releases are not yet available.
- The reviewed PostgreSQL Apalis line remains prerelease and is not a default.
- `sqlxmq` stable targets an old SQLx generation and is not selected.
- PGMQ 0.33.7 passed a PostgreSQL 17 runtime spike on SQLx 0.8.6 and is an optional provider with versioned embedded SQL installation.

Sources: `SRC-APALIS-001`, `SRC-APALISPG-001`, `SRC-PGMQ-001`, `SRC-SQLXMQ-001`.

### Webhooks

Svix already supplies endpoint lifecycle, signing, retries, replay, delivery history, and self-hosted/managed operation. Production outbound delivery therefore uses Svix instead of a new service-kit subsystem.

Sources: `SRC-SVIX-001`, `SRC-SVIX-002`.

### Object storage

`object_store` supports the default backend set and is part of the Apache Arrow ecosystem. OpenDAL is viable but broader than the initial requirement, so it remains an ADR-gated alternative.

Sources: `SRC-OBJECTSTORE-001`, `SRC-OPENDAL-001`.

### OpenTelemetry version coupling

Rust OpenTelemetry crates evolve as a versioned family. `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`, and `tracing-opentelemetry` MUST be selected as a tested set and updated together.

Sources: `SRC-TRACINGOTEL-001`, `SRC-OTLP-001`.

## Phase 0 experiments

The implementation agent MUST record results for:

1. Complete default dependency resolution.
2. Session stack against SQLx 0.8.6.
3. Rustls provider/root choices for SQLx, Redis, reqwest, and identity clients.
4. Apalis Redis worker shutdown and retry behavior.
5. PGMQ extension/client compatibility if the provider is included.
6. OpenTelemetry trace export and shutdown flush.
7. object_store S3-compatible multipart/signed URL behavior.
8. tower-http CSRF behavior with session cookies and approved origins.
9. Profile generation in clean directories.
10. Upgrade from SQLx 0.8 baseline fixture.
