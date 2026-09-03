---
spec_id: OMNIUS-006
title: PostgreSQL Persistence
version: 0.1.0
status: normative
last_verified: 2026-09-03
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

## One migration history

Framework migration SQL is embedded only in
`omnius_migrations::MIGRATOR`. A generated service never copies framework SQL
or a root `.sqlx` directory. The consumer may own forward application SQL in
`migrations/` using the reserved inclusive version range
`9_000_000_000_000_000_000..=9_099_999_999_999_999_999`.

Migration preparation is separate from database I/O. The application passes
`ApplicationMigrations::none()` or
`ApplicationMigrations::embedded(&APPLICATION_MIGRATOR)` to the preparation
API exported by `service_kit::migrations`. Framework-only preparation borrows
the static framework migrator without allocating. Embedded application
migrations are validated and combined with the framework descriptors before a
PostgreSQL connection is attempted, producing an owned supported SQLx
`Migrator`.

Preparation rejects down migrations, duplicate versions across either source,
and application versions outside the reserved range. It preallocates the exact
combined capacity, preserves migration SQL, descriptions, and checksums, sorts
by version, and constructs the migrator through SQLx's public
`MigrationSource` API. Released checksums are immutable.

The prepared framework-plus-application set is the only migration set used by
startup compatibility checks, `migrate`, `migration-status`, and application
tests:

- Both sources share one `_sqlx_migrations` table and deterministic history.
- `migrate` is the only operation that acquires SQLx's advisory migration
  lock; repeated or concurrent runs converge.
- `migration-status` and compatibility checks are read-only queries and do not
  acquire that lock.
- `ignore_missing` is false for run, status, and compatibility inspection.
- Production uses a dedicated migration command or job. Server startup
  verifies compatibility and auto-migrates only in explicit local/test mode.
- Migrations are forward-only by default; destructive changes use
  expand/migrate/contract and support old/new binaries during rolling
  deployment.
- Module removal preserves application migration SQL and history.

Application files use the canonical forward grammar
`<positive-version>_<description>.sql`; `.up.sql`, `.down.sql`, malformed,
duplicate, and out-of-range files are rejected by the generated build script.
`migrations/application-compatibility.toml` is required exactly when
application SQL exists, and its ordered bounds must contain the application
head. Historical application SQL remains consumer-owned when migrations are
unselected and is embedded again if the module returns.

CI tests empty-to-head, previous-supported-to-head, rolling compatibility,
restartable backfills, validation before I/O, one history table, read-only
status, checksum/gap/dirty-history failures, and repeated/concurrent runs.

## Read replicas

Optional and explicit. Read-your-writes, authentication, authorization, billing entitlement, and idempotency default to primary. Measure lag.

## Advisory locks

Allowed for short database-scoped operational coordination with namespaced keys. They are not durable queue ownership.

## Tests and recovery

Use Testcontainers PostgreSQL with per-test isolation, migrations, deterministic fixtures, clock/ID controls, and failure injection.

Deployment docs define backup frequency, retention, PITR, restore rehearsal, encryption, RPO/RTO, and key-rotation compatibility.
