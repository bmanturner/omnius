---
title: Caching, search, and rate limits
description: Apply Omnius Redis, cache, search, and rate-limit providers without confusing derived or library-only state with authoritative runtime assembly.
status: experimental
implementation: implemented
profile_availability:
  - minimal
  - api
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - worker
  - full-reference
  - ai-worker
public_exposure: assembled
audience:
  - developer
  - operator
topics:
  - backend
  - caching
  - search
  - rate-limiting
capabilities:
  - redis-core
  - cache
  - cache-local
  - cache-redis
  - rate-limit-local
  - rate-limit-redis
  - search-meilisearch
source:
  - crates/redis-core/src/lib.rs
  - crates/redis-core/src/config.rs
  - crates/cache-local/src/lib.rs
  - crates/cache-redis/src/lib.rs
  - crates/rate-limit-local/src/lib.rs
  - crates/rate-limit-redis/src/lib.rs
  - crates/search-meilisearch/src/lib.rs
  - apps/api-server/src/lib.rs
evidence:
  - crates/redis-core/tests/connection.rs
  - crates/cache-local/tests/cache.rs
  - crates/cache-redis/tests/cache.rs
  - crates/rate-limit-local/tests/layer.rs
  - crates/rate-limit-redis/tests/limiter.rs
  - crates/search-meilisearch/tests/contracts.rs
last_verified: 2026-08-30
---

# Caching, search, and rate limits

These providers have different authority and assembly boundaries. Only the local rate limiter is concretely assembled in the API server, where it protects OAuth endpoint groups. Redis core, both cache providers, the Redis rate limiter, and Meilisearch are implemented libraries without a concrete reference application mount.

Interpret profile availability through the canonical [modules, profiles, and composition model](../../concepts/modules-profiles-and-composition.md). The [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md) is the source of truth for each row.

## Exposure summary

| Capability | Runtime exposure | Boundary |
| --- | --- | --- |
| Redis core | Library only | Connection and health primitive; no reference config section or API-server dependency |
| Local cache | Library only | Per-process Moka cache |
| Redis cache | Library only | Shared cache implementation using Redis |
| Local rate limiter | Assembled | Applied to the mounted OAuth authorize, token, and revocation groups. A registration limiter is implemented but is applied only when dynamic client registration is enabled; the checked-in reference configuration disables it |
| Redis rate limiter | Library only | Atomic Redis algorithms; [no profile selects the module](../../concepts/modules-profiles-and-composition.md) and no app mounts it |
| Meilisearch | Library only | Derived search projection; [`full-reference` module selection](../../concepts/modules-profiles-and-composition.md) is not a mount |

The page is classified `assembled` because it includes the concretely mounted local limiter. Do not transfer that classification to the other providers.

## Redis connection boundary

When Redis is disabled, the connector returns no client instead of attempting a connection. When enabled, it performs an eager, bounded connection. Ordinary commands use multiplexed connections; blocking operations, Pub/Sub, and provider-specific work require dedicated connections.

Production Redis requires authenticated TLS. Health begins degraded until the provider proves availability. A concrete application must classify Redis as required when it backs authoritative sessions, global rate limits, or durable work; a cache-only use may be classified more softly. The library cannot make that policy decision for its caller.

Do not share a Redis database casually across unrelated authority domains. In particular, the Redis session provider requires a dedicated instance or database because it does not expose a key-prefix hook.

## Cache semantics

A cache is never the source of truth. Both implementations are used through cache-aside behavior:

```text
read authority
  -> on success, optionally populate cache
  -> on cache hit, return only data whose representation is safe for that key
  -> on cache error, bypass cache and read authority
```

Provider failures fail open by bypassing the cache. Authoritative errors are not cached. Request coalescing is process-local only; it is not a distributed single-flight guarantee.

Cache keys must include every security-relevant dimension, including tenant and principal when the representation differs by either. Invalidation after commit improves freshness but is not a correctness fence. Authoritative writes, revisions, and authorization checks must remain correct when invalidation is delayed or lost.

## Local and Redis rate limiting

The assembled API server derives rate-limit identity from transport `ConnectInfo` when present (falling back to loopback when absent) and bounded request context, then applies the local limiter to the OAuth authorize, token, and revocation groups. The implemented registration limiter is added only when dynamic client registration is enabled; the checked-in reference configuration leaves that route disabled. Because state is process-local, its limit is per process and cannot be described as a deployment-wide quota.

The Redis limiter implements fixed-window, sliding-window, and GCRA decisions atomically with Lua. Its default provider failure behavior is fail closed. It has [no profile selection](../../concepts/modules-profiles-and-composition.md) or reference application composition, so there is no supported runtime command for enabling it.

Select failure policy according to the protected action:

| Protected action | Safe provider-failure posture |
| --- | --- |
| Credential, token, registration, or revocation endpoint | Fail closed unless an explicitly reviewed alternative exists |
| Non-authoritative cache lookup | Bypass cache and continue to the authority |
| Search query over a derived index | Return unavailable or a bounded authoritative fallback; never skip authorization |

A `429 Too Many Requests` from one process does not prove that a distributed limit is active. Conversely, source code for the Redis limiter does not prove it is serving traffic.

## Search projection and authorization

Meilisearch is a derived projection, not an authority. The search service takes tenant identity from the canonical `Principal`, obtains candidate identifiers and revisions, loads authoritative records in a batch, and reauthorizes them before returning results.

The required flow is:

```text
Principal -> tenant-scoped search -> candidate IDs/revisions
          -> authoritative batch load -> authorization filter -> response
```

Never accept a tenant identifier from the query body as a substitute for the principal's active tenant. Never return the indexed document merely because Meilisearch matched it. A stale, missing, or unavailable index may reduce freshness or availability, but it must not widen access.

## Configuration and verification boundary

No runtime command is documented for Redis core, either cache provider, the Redis limiter, or Meilisearch because the repository contains no concrete reference composition for them. Adding an invented environment variable or startup flag would misrepresent library code as a product surface.

For the assembled local limiter, verify behavior only in a configured OAuth-provider environment with synthetic clients and no production credentials. The prerequisites are a migrated PostgreSQL database, externally injected reference secrets, a configured issuer, and a single API-server process if per-process behavior is under test. Expected behavior is a bounded OAuth endpoint returning RFC 9457 `429`; failure to observe it must be investigated at the application-composition and trusted-client-address layers. Do not increase request volume against a shared or production issuer.

This is a documented verification scenario and was not run as part of this documentation work.

## Related pages

- [Persistence and migrations](persistence-and-migrations.md)
- [Authentication and sessions](authentication-and-sessions.md)
- [Authorization and tenancy](authorization-and-tenancy.md)
- [Reliability and idempotency](../../concepts/reliability-and-idempotency.md)
- [Database, cache, and jobs troubleshooting](../../troubleshooting/database-cache-and-jobs.md)
