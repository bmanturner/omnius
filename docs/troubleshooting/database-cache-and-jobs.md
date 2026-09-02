---
title: Database, cache, and jobs troubleshooting
description: Diagnose PostgreSQL, migration, cache, rate-limit, outbox, scheduler, and worker symptoms while preserving authoritative-state and unassembled-runtime boundaries.
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
  - developer
topics:
  - troubleshooting
  - database
  - jobs
capabilities: []
source:
  - crates/postgres/src/lib.rs
  - crates/migrations/src/lib.rs
  - crates/cache-local/src/lib.rs
  - crates/jobs-pgmq/src/lib.rs
  - crates/outbox/src/lib.rs
evidence:
  - apps/api-server/tests/api_profile.rs
  - docs/coverage-matrix.md
last_verified: 2026-09-02
---

# Database, cache, and jobs troubleshooting

PostgreSQL and migrations are assembled by the OAuth-provider reference API and by generated persisted services. Generated local Compose supplies pinned PostgreSQL and one-shot migration ownership; direct/operator launches retain their explicit migration policy. Cache, Redis, durable job providers, outbox/inbox relays, schedulers, and worker runtimes are not runnable merely because a profile selects them: external bindings and typed application requirements must be supplied. Diagnose the concrete topology first; a `worker` profile is not proof of a worker executable.

Use [reliability and idempotency](../concepts/reliability-and-idempotency.md) before replay and [asynchronous processing](../concepts/asynchronous-processing.md) for provider semantics.

## The API is unready or database operations fail

**Discriminating evidence:** lifecycle component/status/staleness, typed PostgreSQL error, pool acquisition/connect timeout class, migration status, recent database availability/connection saturation, revision.

**Likely causes:** unreachable database, TLS/credential failure, exhausted pool, slow/locked database, migration incompatibility, or stale health refresh.

**Safe diagnostic:** inspect bounded pool and database control-plane signals using approved access. Confirm production TLS verification and secret reference provenance without exposing the URL or credentials. Separate connection acquisition from query execution.

**Resolution:** restore connectivity/capacity/credentials or resolve migration state. Keep the instance out of admission until application-specific readiness and a bounded database path recover.

**Escalation data:** environment/revision, safe error code, lifecycle component/age, pool state, database availability/lock summary, and migration status. Exclude URLs, SQL, bind values, and credentials.

No database scenario was run while writing this page.

## Migration status is dirty, mismatched, gapped, too old, or too new

**Discriminating evidence:** assembled migration-status classification and candidate migration identities.

**Likely cause:** partial prior execution, edited history, incomplete revision, or binary/schema incompatibility.

**Safe diagnostic:** preserve status and compare with the immutable candidate revision. Do not edit database migration history or print SQL/checksums into support output.

**Resolution:** stop application promotion and follow [migration operations](../operations/migrations.md) with database-owner approval, protected backup, rehearsal, and roll-forward/restore decision.

**Escalation data:** redacted status category, ordered migration identifiers, current/candidate revision, approvals, and last successful status.

## Data appears stale despite a cache invalidation

**Discriminating evidence:** whether cache is actually composed; authoritative PostgreSQL read; cache key scope/version; provider availability; process identity.

**Likely causes:** the application has no cache runtime, cache-aside provider failure, wrong tenant/version scope, or process-local coalescing mistaken for distributed coordination.

**Safe diagnostic:** re-read authoritative state through the authorized service path and inspect cache outcome metadata. Never use cached/search/realtime data to decide permission or ownership.

**Resolution:** correct composition/key/invalidation policy. The cache library fails open to the authoritative loader on provider errors; preserve that authority boundary. Do not add a distributed-lock guarantee to process coalescing.

**Escalation data:** composition, tenant-safe key class (not raw identifiers), authoritative version, cache outcome, provider class, and revision.

## Rate limits differ between replicas

**Discriminating evidence:** limiter implementation in the concrete composition and replica identity.

**Likely cause:** the assembled OAuth rate limiter is process-local. Adding replicas does not create a global limit. A Redis rate-limit library exists but is not selected by a profile or assembled.

**Safe diagnostic:** compare decisions per process and ingress/WAF controls without submitting abusive traffic.

**Resolution:** define an approved global authority at ingress or compose/test a distributed limiter. Keep authentication and abuse defenses layered; do not claim global enforcement from the local limiter.

## Jobs remain pending or no worker metrics/health endpoint exists

**Discriminating evidence:** concrete worker process inventory, configured provider, registered tasks, health/metrics, and durable queue rows.

**Likely cause:** no worker executable is assembled. Profile/module/schema presence alone cannot poll jobs.

**Safe diagnostic:** inspect the deployment's process composition before touching rows. If no `WorkerBuilder`/task registration/provider/lifecycle path exists, absence of processing is expected.

**Resolution:** compose a concrete worker with provider configuration, task registry, concurrency, health, drain, telemetry, and operator policy. Do not manually mark jobs complete or expose an ad hoc admin route.

**Escalation data:** revision/profile, concrete processes, provider configuration provenance, task type/version, and safe row-state counts.

## A running job is redelivered or an effect repeats

**Discriminating evidence:** job/effect identity, claim/lease owner, lease expiry, fencing token, retry/dead state, provider response, and outbox/inbox record.

**Likely causes:** lease expiry, worker loss, ambiguous external response, missing effect identity, or provider redelivery.

**Safe diagnostic:** preserve durable state and determine whether the effect committed at the authority/provider. At-least-once delivery means redelivery is possible.

**Resolution:** reconcile under the stable effect identity; retry only when the effect contract makes it safe. Repair fencing/idempotency rather than increasing retries.

**Escalation data:** identifiers, state transitions/timestamps, lease/fencing metadata, bounded provider correlation/outcome, and attempted decisions—never payload secrets.

## Realtime subscribers miss events

**Discriminating evidence:** actual transport/provider, connection interval, authoritative resource version, and replay support.

**Likely cause:** local/Redis Pub/Sub delivery is ephemeral or no realtime runtime is mounted. NATS source does not prove durable JetStream behavior.

**Safe diagnostic:** reconnect and re-read authoritative HTTP state. Do not infer a public path from the catalog/router mismatch.

**Resolution:** treat events as invalidation hints unless a composed durable contract proves replay. For scale design, see [scaling jobs, realtime, and MCP](../operations/scaling-jobs-realtime-and-mcp.md).