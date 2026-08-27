---
spec_id: OMNIUS-007
title: Redis, Caching, and Rate Limits
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Redis, Caching, and Rate Limits


## Separate capabilities

Redis connectivity, cache, sessions, rate limits, Pub/Sub, Streams, locks, and jobs are separate modules with separate criticality.

## Client

Use official `redis` async multiplexing or `ConnectionManager`. Do not add a generic pool merely for concurrency. Configure TLS/auth, connect and command timeouts, reconnect policy, client name, key prefix/schema, value limits, command-family metrics, and separate connections for blocking/PubSub behavior.

## Cache interface

Provide `NoopCache`, `MokaCache`, and `RedisCache`.

- Cache-aside default.
- Explicit typed TTL.
- Hot-key TTL jitter.
- Short documented negative caching.
- Request coalescing/stampede protection.
- Versioned keys.
- Bounded serialization.
- Hit/miss/stale/load/error metrics.
- Distinguish cache error from authoritative miss.

Redis cache normally fails open/degraded. Sessions, rate limits, and jobs may fail closed.

## Moka

Use Moka for bounded in-process caches with weighted capacity where possible, expiration/idle policy, invalidation, documented warmup, and no assumption of cross-instance coherence.

## Invalidation

Prefer short TTL, versioned namespace, after-commit invalidation, or replayable event-driven invalidation. Redis Pub/Sub is not the sole durable invalidation source.

## Rate limiting

### Local

Use `governor` and `tower-governor` for per-instance GCRA/token-bucket limits after trusted client identity extraction.

### Global

Prefer edge/WAF/API-gateway limits for broad IP abuse. App-level global limits apply to account, tenant, API key, or costly operation quotas.

If Redis is required, use one atomic operation/script, version/test it, define fail-open/closed, bound cardinality/TTL, and record an ADR when no stable adapter fits. Do not build a general distributed-rate-limit framework.

Separate policies cover login, reset, registration, invitation, API keys, upload, search/reporting, webhook replay, and administrative actions.

## Pub/Sub and Streams

Pub/Sub is only for loss-tolerant fan-out. Streams require explicit consumer groups, retention, retry, pending-entry recovery, and observability. NATS JetStream or a job provider is preferred for broad durable events.

## Locks

Not default. Prefer constraints/transactions, idempotency, queue ownership, then PostgreSQL advisory locks. A Redis lock guarding irreversible state requires fencing tokens and an ADR; plain `SET NX PX` is insufficient.
