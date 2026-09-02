---
title: Migrations
description: Plan, authorize, apply, observe, and recover Omnius PostgreSQL schema changes without enabling unsafe startup migration behavior.
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
  - operator
  - database-administrator
topics:
  - operations
  - postgres
  - migrations
capabilities:
  - migrations
source:
  - crates/migrations/src/lib.rs
  - apps/api-server/src/main.rs
  - config/reference.toml
  - migrations
  - crates/generator/src/manager.rs
evidence:
  - docs/coverage-matrix.md
  - crates/migrations/tests
last_verified: 2026-09-02
---

# Migrations

The reference API assembles migration status and execution in its administrative CLI. Production reference configuration keeps `migrations.run_on_startup` disabled, making migration an explicit operator action. A selected profile or migration file is not evidence that a target database is current.

Use [persistence and migrations](../guides/backend/persistence-and-migrations.md) for the schema contract and [deployment topologies](deployment-topologies.md) for the surrounding release lifecycle.

## Generated local Compose ownership

For any generated profile selecting PostgreSQL and `migrations`, manager-derived `ops/compose.yaml` creates a one-shot `migrate` service that runs the generated binary's `migrate` command after PostgreSQL is healthy. The application waits for both database health and successful migration. Compose supplies `OMNIUS__MIGRATIONS__RUN_ON_STARTUP=false`, so the one-shot service is the only local migration owner.

The PostgreSQL data lives in the retained `postgres-data` named volume. Normal Compose stop/start therefore preserves both data and migration history; removing a module does not silently discard the retained volume declaration. Deleting the volume is a separate destructive data operation and is not part of the generated lifecycle.

This ownership is specific to generated development Compose. Direct launches and operator deployments retain the selected validated `migrations.run_on_startup` policy and the explicit `migrate` / `migration-status` commands. Do not copy the development credential bindings into another environment or run the startup and one-shot paths together.

## Safety boundary

A migration changes authoritative data. Apply it only with:

- explicit authorization for the named environment and database;
- a revision-bound migration set and application candidate;
- a current, protected backup and an independently rehearsed restore path;
- a disposable or non-production rehearsal using production-representative schema state;
- reviewed compatibility between the old binary, new binary, and every migration;
- a maintenance, capacity, lock, and monitoring plan;
- a rollback decision that does not assume destructive schema changes can be reversed.

Never enable production startup migrations merely to bypass an operational gate. Never paste database URLs, credentials, SQL contents, checksums, or customer data into incident records.

## Preflight procedure

**Prerequisites:** the safety boundary above, plus a migration owner, incident owner, and stop authority.

1. Confirm the target identity through the protected deployment configuration, not from a copied connection string.
2. Obtain migration status using the assembled API-server administrative surface in an authorized operator environment.
3. Resolve every reported dirty migration, checksum mismatch, sequence gap, database-too-old condition, or database-newer-than-binary condition before execution.
4. Review the candidate migration for transaction behavior, lock duration, table rewrites, new constraints, backfills, and interaction with running binaries.
5. Decide whether old and new application revisions may overlap. If not, define a traffic and process transition that prevents mixed-version access.
6. Verify available storage, connection headroom, replica lag policy, and the signals that will stop the change.
7. Record the last known good revision, restore evidence, and roll-forward plan.

**Expected result:** status is clean and compatible, the target is unambiguous, and the operator can name the stop conditions and recovery path before applying anything.

**Failure path:** do not apply migrations when status is dirty, checksums differ, a version gap exists, the candidate and database disagree, recovery evidence is missing, or the target identity cannot be independently established. Escalate with redacted status and revision metadata.

## Apply and observe

Use the assembled migration action only in the approved execution context. The repository documentation intentionally does not reproduce an executable production command because target selection and credential delivery are platform-owned controls.

During execution:

- admit one migration owner;
- prevent a second migration runner from being introduced by an application startup setting;
- watch database availability, lock waits, connection use, storage, replication, and application readiness through signals actually wired in that environment;
- retain typed, redacted failure codes rather than raw SQL or credentials;
- stop according to the approved criteria rather than retrying an ambiguous partial change.

After execution, obtain migration status again, then start or promote only the compatible application revision. Exercise application-specific readiness and a bounded functional smoke path. An HTTP `200` from a template readiness endpoint is not proof that migration-dependent behavior works.

## Failure handling

| Evidence | Likely boundary | Safe response |
|---|---|---|
| Database unavailable or operation timeout | Connectivity, credentials, saturation, or lock pressure | Stop new attempts; preserve status and database signals; restore capacity or connectivity before retrying |
| Dirty migration | Prior execution did not complete cleanly | Keep the application out of service; obtain database-owner review and a recovery plan |
| Checksum mismatch | Applied history differs from the candidate revision | Treat as integrity drift; do not edit recorded history or bypass the check |
| Sequence gap | Migration set is incomplete or deployed out of order | Restore the complete revision-bound set before continuing |
| Database too old/new | Binary and schema compatibility mismatch | Deploy a compatible bridge/roll-forward revision according to the approved plan |
| Execution failure | Schema, data, lock, or capacity issue | Preserve the failure state, stop automated retries, and choose restore or corrective roll-forward with database approval |

Migration errors are designed to redact SQL, paths, checksums, and credentials. Keep that boundary: do not add raw values to diagnostics merely because the typed error is concise.

## Recovery and rollback

Binary rollback is not automatically schema rollback. The AI/MCP release guidance explicitly forbids rolling back released migrations or durable history when a previous binary cannot interpret them. Prefer backward-compatible changes and roll-forward remediation. Use database restore only under the authorized recovery plan, with accepted data-loss and outage objectives.

The local recovery rehearsal runs the no-argument `scripts/recovery/rehearse-local` tool against disposable Docker PostgreSQL instances. It exercises a fixed synthetic schema, backup/restore integrity, and older-writer compatibility using checked-in SQL; it accepts no application candidate migration set and does not validate a candidate migration or rollback. It was not run for this documentation and does not prove production backup, off-site retention, encryption, scale, or compatibility. See [backup, recovery, and data retention](backup-recovery-and-data-retention.md).

## Evidence to retain

- target environment/database identity without credentials;
- application revision and ordered migration identities;
- preflight and post-change migration status;
- approvals, start/finish time, and operator identity;
- observed locks, availability, capacity, and readiness;
- stop/continue decisions;
- recovery or roll-forward action and resulting schema status.

No migration or database command was run while writing this page.