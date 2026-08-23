---
spec_id: ADR-0005
title: Adopt Durable Work and Event Providers Instead of Building a Queue
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Adopt Durable Work and Event Providers Instead of Building a Queue


## Context

A durable queue requires leasing, retries, visibility timeouts, deduplication, dead letters, scheduling, storage cleanup, metrics, and recovery. Implementing this inside a boilerplate would recreate mature infrastructure. The current Rust ecosystem also has compatibility differences among PostgreSQL queue crates.

## Decision

Approved default/provider choices are:

- Apalis 0.7.4 with `apalis-redis` for Redis-backed jobs.
- PGMQ and its maintained Rust client as an optional PostgreSQL queue when the extension is acceptable.
- NATS JetStream through `async-nats` for durable distributed event streaming.
- Tokio/in-process channels only for non-durable best-effort work and tests.
- Application-owned transactional outbox/inbox tables coordinate domain transactions with external delivery.

Excluded from defaults:

- `sqlxmq` because its stable line targets an old SQLx generation.
- Prerelease `apalis-postgres` releases.
- A custom `FOR UPDATE SKIP LOCKED` general queue.

## Consequences

- Profiles select one jobs provider.
- The outbox is not treated as a full queue; it is a transactional relay boundary.
- Operators accept the infrastructure requirements of the selected provider.
- Job handlers assume at-least-once execution and must be idempotent.

## Validation

Provider compatibility spikes precede admission. Failure, lease expiry, duplicate execution, dead-letter, drain, and replay tests are mandatory.
