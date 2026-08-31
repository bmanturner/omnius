---
title: Persistence and migrations
description: Operate the assembled PostgreSQL boundary, apply forward migrations safely, and preserve transaction and tenant invariants.
status: experimental
implementation: implemented
profile_availability:
  - api
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - worker
  - full-reference
public_exposure: assembled
audience:
  - developer
  - operator
topics:
  - backend
  - postgresql
  - migrations
capabilities:
  - postgres
  - reference-postgres
source:
  - crates/postgres/src/lib.rs
  - crates/postgres/src/config.rs
  - crates/postgres/src/pool.rs
  - crates/postgres/src/transaction.rs
  - crates/migrations/src/lib.rs
  - crates/migrations/src/runner.rs
  - crates/reference-postgres/src/lib.rs
  - apps/api-server/src/main.rs
  - migrations/
evidence:
  - crates/postgres/tests/pool.rs
  - crates/postgres/tests/transactions.rs
  - crates/migrations/tests/migrations.rs
  - crates/migrations/tests/reference_rolling.rs
  - crates/reference-postgres/tests/records.rs
last_verified: 2026-08-30
---

# Persistence and migrations

PostgreSQL is the authoritative persistence boundary for the assembled API server and worker-capable profiles listed above. Redis-backed features, caches, search indexes, generated SQL metadata, and migration files do not replace that authority or prove that a route uses PostgreSQL.

The canonical production migration procedure is [Migrations](../../operations/migrations.md). This page explains the developer-facing persistence contract and the commands the assembled API server provides.

## Connection boundary

`PostgresPool` connects eagerly with bounded retries. Startup and readiness therefore fail when a required database cannot be reached; the service must not accept authority-dependent traffic with an unverified pool.

The connection configuration includes a secret URL, pool bounds, acquisition and connection timeouts, application naming, initialization SQL, and retry settings. In production, TLS mode must verify the server certificate and hostname (`verify-full`). Do not log the URL or copy it into a command line.

`config/reference.toml` contains `${POSTGRES_URL}` as a placeholder. The configuration loader does not expand it. Inject the real value through a supported protected layer, such as `OMNIUS__POSTGRES__URL`, before starting a database command.

A successful pool connection proves connectivity, not schema compatibility, migration cleanliness, tenant isolation, or route assembly.

## Transactions and retries

Use the serializable transaction runner for operations that require retryable serializable semantics. It:

1. begins a transaction;
2. runs the operation;
3. rolls back an operation failure;
4. retries only retryable operation failures with SQLSTATE `40001` or `40P01`, within its configured bound;
5. commits once the operation succeeds.

A commit failure is not retried. The caller cannot safely assume that re-running arbitrary side effects after a failed commit is harmless. Keep external effects out of the retryable closure, or use a durable post-commit pattern such as an outbox.

Transaction retries do not make an operation idempotent. See [Reliability and idempotency](../../concepts/reliability-and-idempotency.md) for replay semantics.

## Tenant safety

The pool does not inject tenant predicates and does not supply row-level tenant isolation by itself. Every tenant-owned repository operation must receive authoritative tenant context and include that tenant in its query and uniqueness scope.

The `reference_records` example has no tenant dimension. It demonstrates persistence mechanics only and must not be cited as a tenant-isolated repository design. See [Authorization and tenancy](authorization-and-tenancy.md) before adding tenant-owned data.

## Migration model

Omnius uses forward SQL migrations compiled into the migration runner. The runner checks migration history, checksum consistency, cleanliness, and the binary's supported schema range.

Production reference configuration disables migration-on-startup. Run the explicit migration command as a deployment step, then start the application only after status is acceptable. Do not repair the migration history table by hand and do not edit an already-applied migration.

The safe failure classes include database unavailability, lock timeout, dirty migration state, checksum mismatch, missing compiled migration, incompatible schema range, and migration execution failure. Diagnostics are redacted; investigate the migration identifier and database state without printing credentials or SQL parameters.

## Explicit production workflow

This guide intentionally provides no executable production migration command. Only the approved platform-owned migration action may invoke the repository administrative CLI, and only under the gated [migration runbook](../../operations/migrations.md). Running a command from a mutable source checkout does not bind the migration set, application candidate, credentials, or target identity.

Before that platform action is authorized, require:

- an immutable application revision and ordered migration digest;
- independently verified names for the environment and database target;
- explicit change authorization, a migration owner, an incident owner, and stop authority;
- a current protected backup and an independently rehearsed restore path;
- a production-representative non-production rehearsal;
- reviewed old/new binary and schema compatibility, including traffic sequencing;
- clean migration status before execution and retained status after execution.

**Expected result:** the revision-bound platform action reports a clean, compatible schema at the approved migration target, and the compatible application revision is admitted only after its bounded functional check passes.

**Failure path:** do not invoke or retry the action on an ambiguous target, missing recovery evidence, dirty state, checksum mismatch, unsupported version, timeout, or connectivity failure. Preserve redacted status, stop the deployment, and follow the [upgrade and rollback procedure](../../operations/upgrades-and-rollbacks.md). Never mark a migration applied manually to force startup.

## Provider distinction

- **PostgreSQL pool:** assembled authority and readiness boundary.
- **Reference PostgreSQL repository:** assembled only in the `oauth-provider` profile and intentionally not a tenant-isolation example.
- **SQLx metadata:** generated build input, not proof of runtime connectivity or migration status.
- **Redis, cache, and search:** separate provider boundaries; none is an authoritative substitute for PostgreSQL in the reference API.

## Related pages

- [Migrations](../../operations/migrations.md)
- [Backups, recovery, and retention](../../operations/backup-recovery-and-data-retention.md)
- [Upgrades and rollbacks](../../operations/upgrades-and-rollbacks.md)
- [Configuration and secrets](configuration-and-secrets.md)
- [Caching, search, and rate limits](caching-search-and-rate-limits.md)
- [Database, cache, and jobs troubleshooting](../../troubleshooting/database-cache-and-jobs.md)
