---
title: Jobs, events, and scheduling
description: Provider-specific job delivery, event durability, transactional handoff, scheduling, and the current worker assembly boundary.
status: experimental
implementation: implemented
profile_availability:
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - worker
  - full-reference
public_exposure: unassembled
audience:
  - rust-application-developer
  - operator
  - module-provider-author
  - security-reviewer
topics:
  - jobs
  - events
  - outbox
  - inbox
  - scheduling
  - reliability
capabilities:
  - jobs-apalis-redis
  - jobs-pgmq
  - transactional-outbox
  - transactional-inbox
  - durable-scheduler
  - durable-nats-events
  - ephemeral-redis-events
source:
  - crates/jobs-apalis-redis/src/lib.rs
  - crates/jobs-pgmq/src/lib.rs
  - crates/outbox/src/lib.rs
  - crates/inbox/src/lib.rs
  - crates/scheduler/src/lib.rs
  - crates/events-nats/src/lib.rs
  - crates/events-redis-ephemeral/src/lib.rs
  - specs/10-jobs-events-outbox-and-scheduling.md
evidence:
  - specs/machine/profiles.yaml
  - migrations/2026082313_create_outbox_and_inbox.sql
  - migrations/2026082314_create_durable_schedules.sql
  - templates/base-service/apps/service/src/main.rs
last_verified: 2026-08-30
---

# Jobs, events, and scheduling

Omnius provides implemented libraries for typed jobs, two durable job providers, transactional event handoff, a PostgreSQL scheduler, and Redis or NATS event delivery. None of these capabilities is assembled into a checked-in worker process or public job API.

Interpret selections through the canonical [modules, profiles, and composition model](../../concepts/modules-profiles-and-composition.md). No inspected binary invokes `WorkerBuilder`, and there is no supported worker command to run. Start with the canonical [asynchronous-processing model](../../concepts/asynchronous-processing.md), then apply the [reliability and idempotency rules](../../concepts/reliability-and-idempotency.md) to every effect.

## Availability and exposure

| Capability | Selected profiles | Implementation | Exposure | Missing runtime evidence |
|---|---|---|---|---|
| Redis/Apalis jobs | [`saas`, `worker`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | Implemented | Unassembled | Provider construction, handlers, and a worker executable |
| PostgreSQL PGMQ jobs | [`saas-pgmq`](../../concepts/modules-profiles-and-composition.md) | Implemented | Unassembled | Provisioned queues, provider construction, handlers, and a worker executable |
| Transactional outbox and inbox | [`saas`, `saas-pgmq`, `realtime-durable`, `worker`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | Implemented | Unassembled | Application transaction integration, publisher/consumer, and relay registration |
| Durable scheduler | [`saas`, `saas-pgmq`, `worker`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | Implemented | Unassembled | Schedule factory, dispatcher, registered task, and operator surface |
| NATS JetStream events | [`realtime-durable`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | Implemented | Unassembled | Provisioning, publisher, consumer handlers, and registered tasks |
| Redis Pub/Sub events | [`realtime`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | Implemented | Unassembled | Provider construction, listener registration, and application subscribers |

The [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md) is authoritative when these classifications change.

## Typed contracts are not a queue

`jobs-core` defines versioned job and domain-event envelopes, policy, delivery context, handler outcomes, and stable effect identity. It intentionally provides no queue, persistence, retry executor, scheduler, outbox, inbox, or transport. An application must choose and compose each of those separately.

Delivery is at least once. A handler can run again after a lease expires, a process stops before acknowledgement, or an acknowledgement fails. Business effects therefore need an idempotency boundary derived from the delivery context; a successful provider acknowledgement must not be treated as exactly-once execution.

Keep payloads bounded and avoid secrets or unnecessary personal data. Envelope diagnostics are designed to redact payloads, but the selected provider still persists or transports the envelope.

## Choose a job provider explicitly

Redis/Apalis and PGMQ implement the same typed job declarations without erasing provider behavior.

| Concern | Redis/Apalis | PostgreSQL PGMQ |
|---|---|---|
| Backing service | Redis through the provider's isolated client line | The workspace PostgreSQL pool and PGMQ extension |
| [Profile selection](../../concepts/modules-profiles-and-composition.md) | [`saas`, `worker`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | [`saas-pgmq`](../../concepts/modules-profiles-and-composition.md) |
| Routing isolation | Namespace includes job name, queue, priority, exact version, and dispatch-policy fingerprint | Deterministic source and dead-letter queues bind the exact version and dispatch policy |
| Runtime setup | Connects using secret-bearing Redis configuration | Deployment tooling provisions queues; runtime connection verifies queues, control state, and permissions |
| Lease model | Apalis delivery with provider-owned recovery and bounded worker timing | One-message reads; transitions are fenced to the exact durable `read_ct` lease |
| Concurrency and rate | Enforced by its worker/provider composition | Limits are local to each worker, so horizontal replicas multiply aggregate concurrency and start rate |
| Dead replay identity | Preserves both canonical job identity and source message identity | Preserves canonical job identity but creates a new source message identity |
| Connection secret | Redis URL is secret-wrapped and redacted | Provider receives an already configured PostgreSQL pool; it does not own a separate connection-secret field |

Do not write provider-neutral recovery procedures that conceal these differences. In particular, automation correlating dead-letter replays must account for PGMQ's new source message identity.

Both providers support bounded timing, status, durable pause state, retained dead metadata, replay, cleanup, retries, and graceful cancellation in library code. Those APIs are not mounted operator endpoints. Authorization and audit must surround any application-owned pause or replay surface.

### Job failure semantics

- **Transient handler or provider failure:** the provider may retry according to the typed job policy and bounded backoff.
- **Attempt exhaustion or terminal outcome:** the item moves to provider-specific dead storage and remains subject to retention.
- **Expired visibility or interrupted acknowledgement:** another delivery can occur; effects must remain idempotent.
- **Changed job declaration:** exact version and dispatch-policy routing prevents an incompatible worker from silently consuming the record.
- **Pause:** stops new leasing for the exact provider namespace; it does not undo an already committed effect.
- **Shutdown:** a composed worker must stop leasing and drain within its configured bound. No checked-in process currently proves that lifecycle.

## Transactional event handoff

### Outbox: commit intent with business state

`PostgresOutbox::append` uses a caller-owned database connection. The application can therefore commit the business change and publication intent in one transaction. A separate relay leases records and calls an application-supplied publisher at least once, using the event ID as the outbound idempotency key.

This closes the gap between a database commit and publication only when all pieces are composed. It does not select a broker, take ownership of the application transaction, or make a non-idempotent downstream effect exactly once. Publisher unavailability, lease conflict, retry exhaustion, or relay absence leaves records pending or exhausted according to the relay policy.

### Inbox: deduplicate before applying an effect

`PostgresInbox` claims an incoming producer/event identity inside a caller-owned transaction. Claim results distinguish a new event, an already completed event, an in-progress claim, and an immutable mismatch. The stored payload digest rejects a redelivery that reuses identity with different content.

Completion, release, and resume are fenced. The application still owns the business effect and broker acknowledgement. Commit the inbox transition and business effect together; acknowledge the broker only after that transaction commits.

The outbox/inbox migration proves schema availability, not a running relay or consumer. See [persistence and migrations](persistence-and-migrations.md) and [operational scaling](../../operations/scaling-jobs-realtime-and-mcp.md).

## Event durability is provider-specific

### NATS JetStream

The NATS event library implements durable JetStream publication and consumers, including redelivery, acknowledgement, lag/status seams, resource provisioning/verification, and a dead-letter policy. `NatsOutboxPublisher` connects the outbox boundary to JetStream. Durability requires an assembled and correctly provisioned stream, durable consumer configuration, registered handlers, and retained broker state; the interface or [`realtime-durable` profile selection](../../concepts/modules-profiles-and-composition.md) alone proves none of those.

The same crate also exposes bounded Core NATS fan-out. Core NATS owns no stream, cursor, acknowledgement, or replay state and must be treated as ephemeral.

### Redis Pub/Sub

The Redis event provider is deliberately loss-tolerant. Messages can be lost before subscription readiness, during disconnect or supervised restart, when the bounded receiver is full, when a message is oversized, and during shutdown. There is no replay, acknowledgement, or delivery guarantee.

The configured message limit bounds publishing and retained delivery, but Redis parsing can transiently allocate a complete protocol value first. Deployments must restrict publish authority to exact channels and independently bound Redis protocol bulk values. Do not use this provider for events whose loss would violate a business invariant.

## Durable scheduling

The PostgreSQL scheduler stores schedule definitions and runs, uses database-clock leases and fencing, and dispatches idempotent typed jobs. It supports timezone-aware cron schedules and three misfire policies:

- `skip`: omit missed occurrences;
- `fire_once`: materialize one run after the gap;
- bounded `catch_up`: materialize a configured finite number of missed runs.

Create, update, pause, and replay carry actor and reason data, but no assembled authorization, audit, or HTTP administration surface is proven. The scheduler also does not choose a job provider. A host must supply the schedule envelope factory, dispatcher, supervised task registration, dependency health policy, and shutdown behavior.

Failure handling is lease-based: a failed or interrupted claim can become eligible for recovery after its lease, while fencing prevents a stale owner from completing a newer claim. Dispatch must use stable idempotency identity so recovery does not duplicate the business effect.

## Composition checklist

Before representing any of these capabilities as operational, retain evidence for all applicable items:

1. [Exact profile and module selection](../../concepts/modules-profiles-and-composition.md), without treating it as assembly.
2. Provider provisioning and secret injection in a disposable environment.
3. Concrete handler, relay, consumer, or scheduler registration in a real process.
4. Migrations and dependency readiness tied to that process.
5. Idempotent effects under duplicate delivery and expired leases.
6. Bounded retry, dead-letter, replay, retention, and drain behavior.
7. Authorized, audited administrative actions.
8. Redacted logs, metrics, and health checks actually wired by the deployment.

Verification for this page remains **not run**. The focused source tests and verification plan are evidence locations, not retained runtime results.