---
spec_id: OMNIUS-010
title: Jobs, Events, Outbox, and Scheduling
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Jobs, Events, Outbox, and Scheduling


## Provider policy

Do not implement a general durable queue.

Approved paths:

- Apalis 0.7.4 + `apalis-redis` when Redis is already required.
- PGMQ plus maintained Rust client when the PostgreSQL extension is operationally acceptable and passes compatibility.
- NATS JetStream through `async-nats` for durable distributed event streaming.
- In-process only for tests/development or explicitly non-durable best effort.

`sqlxmq` is rejected as default because its stable release targets an old SQLx line. `apalis-postgres` prereleases are not admitted to default profiles.

## Job contract

Each job has stable name, payload version/type, idempotency policy, attempts, jittered backoff, timeout, concurrency/rate policy, queue/priority, retention, dead-letter behavior, compatibility plan, metrics, and runbook.

Assume at-least-once execution. Handlers are idempotent or use transactional effect records.

## Enqueue

If a job follows committed domain state, enqueue transactionally through a supported backend or write an outbox record in the same transaction. Never commit state then perform unprotected best-effort enqueue.

## Outbox

Application-owned schema coordinates the application's transaction. Store event ID, aggregate, type/version, tenant, time, correlation/causation, trace context, payload, destination, lease/attempt state, publication time, and safe error class.

Relay is leased, bounded, restart-safe, idempotent, observable, and retains/archives records by policy.

## Inbox

Deduplicate by producer/event ID; write inbox and business effect transactionally where possible; retain at least through possible redelivery; acknowledge only after durable effect.

## Events

Use the versioned envelope in `examples/event-envelope.json`. Changes are additive; fields are never repurposed; consumers ignore unknown fields; breaking changes get a new version/type; PII classification is documented.

## NATS JetStream

Declaratively define streams, subjects, retention, replication, limits, durable consumers, ack wait, dead-letter behavior, lag/redelivery metrics, and least-privilege credentials. Core NATS is only ephemeral.

## Scheduler

Every schedule defines time zone, expression, misfire/catch-up, max concurrent runs, lease/leader policy, idempotency window, replay, audit, and metrics.

Preferred: external orchestrator enqueues durable job; dedicated scheduler with lease; queue-native scheduling. Never run the same timer independently on every server replica.

## Drain and admin

Workers stop leasing, complete bounded work, extend valid long leases, safely release abandoned leases, and distinguish cancellation/failure.

Provide authorized/audited status, oldest age, dead jobs, replay, pause/resume, redacted payload view, worker heartbeat, and outbox backlog.
