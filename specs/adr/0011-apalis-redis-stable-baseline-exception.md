---
spec_id: ADR-0011
title: Isolate the Apalis Redis Stable Baseline
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Isolate the Apalis Redis Stable Baseline

## Context

Phase 0 resolved `apalis-redis 0.7.4` against the current service-kit graph. It uses `redis 0.32.7`, while the general Redis capability uses `redis 1.6.0`; their connection types are incompatible. Cargo 1.98 also reports Rust 2024 never-type fallback warnings in four Apalis Redis methods that will become hard errors in a future Rust release. The available Apalis 1.0 releases are prereleases and cannot enter a default profile. PGMQ 0.33.7 is stable and SQLx 0.8.6-compatible, but requires an operational SQL installation and does not replace the Redis default for every profile.

## Decision

Keep `apalis 0.7.4` and `apalis-redis 0.7.4` as the default Redis jobs provider for the pinned Rust 1.98 baseline, subject to all of these controls:

- Isolate its `redis 0.32.7` client inside the jobs adapter; no Redis type crosses the provider port.
- Admit an explicitly aliased direct dependency only to enable Tokio, connection manager, ring rustls, and WebPKI roots on that line.
- Do not share pools or connection values with the general `redis 1.6.0` capability.
- Treat the future-incompatibility report as a toolchain-upgrade blocker.
- Upgrade only to a stable Apalis release that removes the warnings and passes the provider conformance suite; prereleases remain experimental-only.
- Re-evaluate this exception before every Rust baseline update and no later than 2026-11-23.

Keep PGMQ 0.33.7 as an explicitly selected optional PostgreSQL provider with embedded, versioned SQL installation and a project-owned supervised poll/drain adapter. Do not implement a custom durable queue.

## Consequences

- Default SaaS/worker profiles contain two Redis crate lines, but only behind separate provider boundaries.
- Binary size and advisory review include both lines.
- The Rust toolchain cannot advance if Apalis 0.7.4 stops compiling and no stable fixed release exists; that condition blocks the affected default profiles.
- PGMQ profiles carry extension/SQL lifecycle operations and do not silently replace Redis profiles.

## Validation

- The Phase 0 Apalis spike proves enqueue, processing, and bounded drain against Redis 8.
- The Phase 0 PGMQ spike proves embedded installation, enqueue, visibility read, archive, and cleanup against PostgreSQL 17.
- Dependency reports classify both Redis lines and retain one Tokio, Tower, SQLx, rustls, and Serde family.
- CI records Cargo future-incompatibility output and rejects an unreviewed Rust baseline change.
