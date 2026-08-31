---
title: Asynchronous processing
description: The canonical job, event, delivery, duplicate-safety, leasing, scheduling, and durability model.
status: experimental
implementation: implemented
profile_availability:
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - worker
  - full-reference
public_exposure: library-only
audience:
  - rust-application-developer
  - operator
  - ai-application-developer
  - mcp-developer
topics:
  - jobs
  - domain-events
  - scheduling
  - delivery
capabilities:
  - typed-jobs-and-domain-events
source:
  - specs/10-jobs-events-outbox-and-scheduling.md
  - crates/jobs-core/src/lib.rs
evidence:
  - crates/jobs-core/tests/contracts.rs
  - crates/jobs-apalis-redis/src/lib.rs
  - crates/jobs-pgmq/src/lib.rs
  - crates/worker/src/lib.rs
last_verified: 2026-08-30
---

# Asynchronous processing

Asynchronous processing moves an effect outside the initiating request's execution window. It does not remove the need for authority, deadlines, bounded resources, compatibility, or duplicate safety.

## Audience path

Application authors should start here before selecting a queue, writing a worker, publishing a domain event, or scheduling work. Operators should continue to the jobs/realtime guide for concrete provider setup and to the operations page for scaling and recovery procedures.

## Jobs and events

- A **job** is a command for a named handler to attempt an effect. It has a stable name and version, bounded payload and metadata, a queue, retry/dead-letter/concurrency policy, and an idempotency requirement.
- A **domain event** is a fact that an application state transition committed. It has a stable type and version, source and subject, occurrence time, tenant/correlation/causation metadata where applicable, and a bounded payload.
- A **delivery** is one attempt to hand a job or event to a consumer. Multiple deliveries may represent one logical message.

Never use an event as an unaudited command, or treat queue acknowledgement as proof that the business effect committed.

## Envelope and effect identity

The envelope is the compatibility and trust boundary between producer, provider, and handler. Validate its version, limits, identifiers, timestamps, tenant context, and trace/correlation metadata before decoding application payloads.

Every duplicate-sensitive handler derives one stable effect identity from the logical job/event and its target effect. A transport delivery ID is not sufficient when redelivery creates a new delivery. The same identity must reach downstream database writes and external providers that support idempotency. See [reliability and idempotency](reliability-and-idempotency.md).

## At-least-once model

Assume at-least-once delivery unless a concrete provider and application prove a stronger bounded contract. A worker can crash after the effect commits but before acknowledgement; the broker then redelivers. Therefore:

1. validate and authorize the envelope;
2. claim or deduplicate the effect in durable state;
3. execute the effect under the remaining deadline;
4. commit application state and the durable outcome;
5. acknowledge only after the outcome is safe;
6. classify failures as retryable, permanent, cancelled, or dead-lettered;
7. expose bounded diagnostics without logging payloads or secrets.

Exactly-once delivery is not promised. Duplicate-safe effects are the application invariant.

## Leases, fencing, and concurrency

Durable workers use bounded leases/visibility timeouts so abandoned work can be recovered. A lease holder that loses ownership must be fenced from completing or acknowledging the effect. Lease renewal, worker heartbeat, and graceful drain need finite timeouts and cancellation-aware behavior.

Concurrency belongs to the job type and provider capacity, not an unbounded task spawn. Apply per-handler concurrency, global resource limits, quotas, and downstream admission. A scheduler and queue must tolerate two processes observing the same due work without duplicating the logical effect.

## Transactional handoff

When a state transition and event publication must agree, write application state and an outbox record in one database transaction. A relay later publishes the outbox record and marks progress with retry-safe leasing. Consumers use an inbox/effect ledger where duplicate delivery could repeat a side effect.

An outbox table or library alone is not a durable event pipeline. The composition also needs a running relay, provider, consumer/worker, restart behavior, retention, and operations coverage.

## Scheduling

Persist schedules and next-run state when durability is required. Define timezone and daylight-saving semantics explicitly, claim due runs with leases/fencing, enqueue a stable job identity, and advance state without silently skipping or duplicating a logical run. A schedule definition is not a running scheduler.

## Realtime delivery

Redis Pub/Sub fanout is ephemeral and appropriate only when loss is acceptable and recovery does not depend on replay. Durable NATS-style delivery requires stream provisioning, retention and consumer policy, acknowledgement/redelivery behavior, and a composed publisher/consumer runtime. Protocol libraries and profile selection alone do not prove either transport is serving clients.

## Current assembly boundary

`jobs-core` implements typed jobs and domain events, policies, bounded envelopes, delivery context, handler/enqueuer ports, and stable effect identity. It intentionally does not provide a queue, persistence, retry executor, scheduler, outbox/inbox relay, or transport.

Redis and PGMQ provider crates implement concrete queue behavior. The outbox, inbox, scheduler, durable-event, and reusable worker crates provide substantial implementation and migrations. They remain unassembled in checked-in applications: the API application does not register a provider or worker, and no checked-in executable constructs `WorkerBuilder`. The `worker` profile and other profile selections are generation choices, not evidence of a running worker process.

Accordingly, `typed-jobs-and-domain-events` is classified `library-only`. A deployment may claim an operational async capability only after provider configuration, persistence, producer, relay/worker, handler registration, health, restart, and recovery paths are composed and verified together.

## Evidence

- [Jobs, events, outbox, and scheduling specification](../../specs/10-jobs-events-outbox-and-scheduling.md)
- [Typed job and event contracts](../../crates/jobs-core/src/lib.rs)
- [Core async contract tests](../../crates/jobs-core/tests/contracts.rs)
- [Redis job provider](../../crates/jobs-apalis-redis/src/lib.rs)
- [PGMQ job provider](../../crates/jobs-pgmq/src/lib.rs)
- [Reusable worker runtime](../../crates/worker/src/lib.rs)
- [Outbox implementation](../../crates/outbox/src/lib.rs)
- [Inbox implementation](../../crates/inbox/src/lib.rs)
- [Scheduler implementation](../../crates/scheduler/src/lib.rs)
- [Checked-in API process composition](../../apps/api-server/src/main.rs)

## Next

- [Jobs, events, and scheduling](../guides/backend/jobs-events-and-scheduling.md)
- [Realtime](../guides/backend/realtime.md)
- [Scaling jobs, realtime, and MCP](../operations/scaling-jobs-realtime-and-mcp.md)
