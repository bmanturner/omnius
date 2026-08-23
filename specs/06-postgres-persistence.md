---
spec_id: RSK-006
title: PostgreSQL Persistence
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# PostgreSQL Persistence


## Baseline

PostgreSQL is the primary relational database. SQLx **0.8.6** is the first supported line.

SQLx 0.9.0 was current at research time, but surrounding session-store integrations still target 0.8. The kit values one coherent graph over newest-version selection. Upgrade requires ADR-0003's gate.

## Pool

Configure URL/TLS, minimum/maximum connections, acquire timeout, idle timeout, maximum lifetime with jitter, initialization SQL, application name, statement/lock timeout policy, metrics/readiness, and graceful close.

Pool sizing accounts for replica count, workers, migrations, and database limits.

## Queries

- Prefer checked SQLx macros.
- Commit `.sqlx` offline metadata.
- Use `QueryBuilder` only with allowlisted identifiers.
- Never concatenate untrusted SQL.
- Select explicit columns.
- Do not log values.
- Enforce uniqueness, references, and concurrency-sensitive invariants in PostgreSQL.

## Transactions

Application services define boundaries. Helpers accept existing executors/transactions. Do not start hidden nested transactions. Business state, outbox, and idempotency share a transaction when required. Avoid network calls while holding a transaction.

## Retry

Retry only known transient SQLSTATE classes such as serialization failure/deadlock, only when the entire transaction closure is safe to repeat. Bound attempts, add jitter, count by SQLSTATE, and test forced conflicts. Do not retry constraint/syntax errors or ambiguous commits without idempotency.

## Migrations

Use SQLx migrations with one deterministic history.

- Production uses a dedicated migration command/job.
- A lock prevents concurrent migrators.
- Server startup verifies schema compatibility; auto-migrate only in explicit local/test mode.
- Forward-only by default.
- Destructive change uses expand/migrate/contract.
- Old/new versions coexist during rolling deployment.
- Module removal keeps history.
- Released checksums are immutable.

CI tests empty-to-head, previous-supported-to-head, rolling compatibility, and restartable backfills.

## Read replicas

Optional and explicit. Read-your-writes, authentication, authorization, billing entitlement, and idempotency default to primary. Measure lag.

## Advisory locks

Allowed for short database-scoped operational coordination with namespaced keys. They are not durable queue ownership.

## Tests and recovery

Use Testcontainers PostgreSQL with per-test isolation, migrations, deterministic fixtures, clock/ID controls, and failure injection.

Deployment docs define backup frequency, retention, PITR, restore rehearsal, encryption, RPO/RTO, and key-rotation compatibility.
