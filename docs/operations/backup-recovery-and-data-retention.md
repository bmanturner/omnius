---
title: Backup, recovery, and data retention
description: Establish production recovery and retention controls while separating normative policy from the repository's disposable local PostgreSQL rehearsal.
status: experimental
implementation: specified-only
profile_availability: []
public_exposure: unassembled
audience:
  - operator
  - database-administrator
  - privacy-owner
topics:
  - operations
  - recovery
  - retention
capabilities:
  - backup-recovery
  - recovery-rehearsal
source:
  - specs/06-postgres-persistence.md
  - specs/17-deployment-and-runtime-topology.md
  - scripts/recovery/rehearse-local
  - ops/recovery/compose.yaml
  - ops/recovery/thresholds.env
evidence:
  - docs/coverage-matrix.md
  - docs/verification-plan.md
last_verified: 2026-09-03
---

# Backup, recovery, and data retention

> **Implementation state: `specified-only`.** The production controls and retention requirements on this page are policy/specification, not implemented automation. The only currently implemented tooling described here is the operator-run, disposable local PostgreSQL recovery rehearsal; it is not a production backup system.

Production backup and recovery are specified but unassembled. The repository includes an implemented, operator-only **local** PostgreSQL recovery rehearsal. It creates an isolated Docker environment, uses a one-use password, backs up and restores a fixed synthetic schema, compares fingerprints, exercises a checked-in older-writer compatibility scenario, checks local timing thresholds, records `target/recovery/last-result.json`, and cleans up.

That tool is not a production backup system. It accepts no remote endpoint, is not invoked by CI, and uses an image tag rather than a digest-pinned database image. It does not prove off-site durability, encryption, key recovery, point-in-time recovery, production scale, orchestration, application readiness, retention enforcement, or a safe production rollback.

Classify data and ownership first using [data and privacy boundaries](../concepts/data-and-privacy-boundaries.md).

## Production recovery control set

For every stateful dependency, record:

| Control | Required decision |
|---|---|
| Ownership | Service owner, data owner, recovery operator, and approval authority |
| Scope | PostgreSQL, object storage, durable queues/streams, identity-provider state, configuration, signing/key references, and provider-specific state actually used |
| Objectives | Approved recovery point, recovery time, service restoration, and data-loss objectives |
| Protection | Encryption in transit and at rest, key custody, access separation, immutability, and off-site/failure-domain placement |
| Schedule | Backup/PITR cadence, verification, retention, expiry, legal hold, and rehearsal frequency |
| Consistency | Cross-store ordering, durable cursor/history handling, and the application revision/migration set needed to interpret restored data |
| Evidence | Revision-bound restore observation, integrity checks, timings, approvals, exceptions, and remediation |

Do not declare recovery complete when only PostgreSQL returns. A restored application may also require compatible object identities, queue history, OAuth configuration, signing material, provider configuration, and generated contracts.

## Authorized recovery rehearsal

**Prerequisites**

- written approval for a disposable, non-production environment;
- a reviewed repository revision;
- a local Docker engine reached through a Unix socket or Windows named pipe, with Docker Compose v2;
- isolated local Docker capacity and no production credentials;
- known-safe fixture data containing no customer information;
- retained thresholds and a destination for non-secret evidence.

1. Review `scripts/recovery/rehearse-local`, its fixed SQL under `scripts/recovery/sql`, and `ops/recovery` at the reviewed revision.
2. Confirm the active Docker endpoint uses `unix://` or `npipe://`, cannot address a production database, and has no production credential.
3. From the repository root, invoke the no-argument rehearsal:

   ```bash
   scripts/recovery/rehearse-local
   ```

4. Allow it to create isolated PostgreSQL instances, seed its synthetic schema, back up, restore, compare fingerprints, exercise the fixed deployment/older-writer compatibility SQL, and clean up. The checked-in `scripts/recovery/sql/deploy_candidate.sql` filename does not mean the tool accepts or validates an application's candidate migrations.
5. Inspect the recorded result and distinguish each timing, integrity, and compatibility assertion from production objectives or candidate-migration evidence.
6. Destroy residual disposable state according to the approved cleanup policy.

**Expected result:** the local rehearsal records a successful fixed synthetic backup/restore and older-writer compatibility cycle within its local thresholds and leaves no production dependency changed. It does not validate an application candidate migration or schema rollback.

**Failure path:** preserve the non-secret result artifact and failing phase, then stop. Do not point the local tool at production, weaken integrity checks, reuse its one-use credential, or claim success from partial phases.

The rehearsal was not run while writing this documentation. Its status in the [verification plan](../verification-plan.md) remains `not run`.

## Production restore procedure

The repository does not provide a production restore command. A platform-owned runbook must:

1. declare the incident, authorized restore point, accepted data loss, and traffic state;
2. preserve current evidence before mutation;
3. restore into an isolated target first, with keys and credentials delivered through protected systems;
4. verify provider-native integrity and application-level invariants;
5. align the database schema with a compatible application revision using the rules in [migrations](migrations.md);
6. reconcile dependent durable stores and external provider state;
7. exercise startup, readiness, identity, and one bounded business path;
8. obtain approval before switching traffic;
9. observe for delayed corruption, duplicate effects, stale cursors, and permission drift;
10. record realized recovery point/time and any objective breach.

**Expected result:** the restored system is internally consistent, revision-compatible, admitted only after approval, and monitored against explicit objectives.

**Failure path:** keep the restored target isolated. Choose another restore point or a reviewed roll-forward; never overwrite the only preserved evidence or improvise schema rollback.

## Retention and deletion

The privacy lifecycle has migration/schema support and partial library behavior, but no assembled API or worker proving end-to-end export/deletion processing. Therefore:

- retention policy remains an operator/data-owner responsibility;
- database rows do not prove deletion from backups, object storage, logs, audit stores, model-provider systems, or derived indexes;
- a retention deadline does not override legal hold or incident preservation without the appropriate authority;
- backup expiry and key destruction must be part of the same verified policy;
- restoration must not silently resurrect data whose deletion obligation still applies.

See [privacy, consent, and moderation](../security/privacy-consent-and-moderation.md) for control ownership.

## Unsafe interpretations

- “A backup file exists” does not mean it is restorable.
- “The local rehearsal passed” would not prove production recovery.
- “A migration exists” does not prove a retention worker is assembled.
- “Redis Pub/Sub or an in-process subscription delivered an event” is not durable recovery evidence.
- “A prior image is retained” does not mean it can read the current schema or durable history.