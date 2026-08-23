# Durable jobs provider compatibility report

Date: 2026-08-23  
Task: T003  
Criterion: AC-JOB-001  
Decision: pass with the controlled Apalis exception in ADR-0011

## Apalis Redis

The stable baseline `apalis 0.7.4` plus `apalis-redis 0.7.4` compiled with Tokio 1.53.1 and Tower 0.5.3. The `jobs_apalis` spike used Redis 8 in a disposable container and directly proved enqueue, worker processing, completion signaling, and bounded monitor drain without polling sleeps.

Apalis Redis depends on `redis 0.32.7`; the general Redis capability uses `redis 1.6.0`. These client types cannot interoperate. The duplicate is isolated behind the jobs provider boundary, where no Redis type enters application services. The workspace admits an explicitly aliased `redis-apalis 0.32.7` dependency so the provider line enables Tokio, connection manager, rustls, ring-compatible TLS, and WebPKI roots. The two Redis lines never share pools or connection values.

Cargo 1.98 reports edition-2024 never-type fallback warnings in four `apalis-redis 0.7.4` methods. The crate compiles and the exercised methods work today, but a future Rust release will make the affected inference a hard error. Newer Apalis Redis releases are prerelease only. ADR-0011 accepts the stable 0.7.4 line for the pinned Rust 1.98 baseline, blocks toolchain upgrades that make it fail, and requires migration to a stable fixed release before that baseline moves.

## PGMQ

`pgmq 0.33.7` resolves on the existing SQLx 0.8.6 line. The provider enables embedded SQL installation, avoiding build-time or runtime downloads. The `jobs_pgmq` spike used PostgreSQL 17 in a disposable container and proved embedded installation, durable queue creation, enqueue, read with visibility timeout, payload/message-ID preservation, archive, and cleanup.

PGMQ is an optional provider because operators must install and upgrade its SQL layer and because the application still owns the supervised polling/drain loop. Transactional enqueue can share the application's SQLx transaction through PGMQ's connection-aware API. It does not justify a project-authored PostgreSQL queue.

## Provider decision

- Default Redis jobs provider: `apalis 0.7.4` + `apalis-redis 0.7.4`, with isolated `redis 0.32.7` and ADR-0011 controls.
- Optional PostgreSQL provider: `pgmq 0.33.7`, only in profiles that explicitly accept its operational SQL installation.
- Excluded: prerelease Apalis 1.0 providers, old-SQLx `sqlxmq`, prerelease `apalis-postgres`, and a custom durable queue.
- Delivery semantics remain at least once. Idempotency, deduplication, dead letters, and application effects are implementation requirements in Phase 7; provider selection alone does not satisfy them.

## Reproduction

```text
APALIS_REDIS_URL=redis://127.0.0.1:56379 \
  cargo run -p rsk-phase0-compatibility --bin jobs_apalis
PGMQ_DATABASE_URL=postgres://phase0:<test-password>@127.0.0.1:55433/phase0 \
  cargo run -p rsk-phase0-compatibility --bin jobs_pgmq
cargo report future-incompatibilities --id 1
```

All packages are stable crates.io releases and compile on Rust 1.98.0. T004 owns the complete advisory, license, source, maintenance, and unsafe-code policy results.

Primary references: [Apalis 0.7.4](https://docs.rs/apalis/0.7.4), [apalis-redis 0.7.4](https://docs.rs/apalis-redis/0.7.4), [PGMQ 0.33.7](https://docs.rs/pgmq/0.33.7), and [Rust 2024 never-type fallback](https://doc.rust-lang.org/edition-guide/rust-2024/never-type-fallback.html).
