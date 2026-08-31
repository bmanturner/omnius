---
title: Scaling jobs, realtime, and MCP
description: Plan capacity and failure handling for Omnius asynchronous libraries while preserving the current unassembled runtime boundary.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: unassembled
audience:
  - operator
  - platform-engineer
topics:
  - operations
  - scaling
  - asynchronous-processing
capabilities:
  - worker-composition-and-operations
source:
  - crates/jobs-core/src/lib.rs
  - crates/jobs-pgmq/src/lib.rs
  - crates/outbox/src/lib.rs
  - crates/realtime-core/src/lib.rs
  - crates/mcp-server-core/src/lib.rs
  - migrations/2026082807_create_mcp_mrtr_state.sql
  - migrations/2026082808_create_mcp_tasks.sql
evidence:
  - docs/coverage-matrix.md
  - specs/10-jobs-events-outbox-and-scheduling.md
  - specs/35-llm-mcp-feature-suite-architecture.md
last_verified: 2026-08-30
---

# Scaling jobs, realtime, and MCP

Omnius contains implemented libraries for jobs, events, outbox/inbox processing, schedulers, realtime transports, MCP protocol surfaces, and worker lifecycle. No checked-in application proves a runnable worker binary, realtime listener, or MCP listener/stdio process. A `worker`, realtime, or MCP profile selects modules; it does not assemble those runtimes.

Use [asynchronous processing](../concepts/asynchronous-processing.md) for envelopes, leases, retries, and delivery semantics. Use the [availability and exposure matrix](../reference/availability-and-exposure-matrix.md) before planning capacity.

## Current operational boundary

| Surface | Implemented evidence | Missing composition proof |
|---|---|---|
| Job providers and worker runtime | Local/PostgreSQL/PGMQ provider code, bounded worker constructs, retry/dead state | Concrete worker executable, provider configuration, health, admin surface, and exercised drain |
| Outbox/inbox and scheduler | PostgreSQL schema and source behavior for claims, leases, fencing, redelivery, misfire, and dead state | Running relay/scheduler tasks in an application |
| Realtime | In-process, Redis Pub/Sub, and NATS-related transport source | Mounted WebSocket/SSE routes and application registration |
| MCP | Registries, handlers, authorization, transports, tasks, elicitation, subscriptions | First-party server binary, HTTP mount, stdio binary, auth-server routes, durable task workers |

The realtime catalog path `/realtime/events` and the source router path `/events` conflict. Neither proves an externally mounted route. Do not configure ingress from either artifact without a concrete composition contract.

## Scale-unit design

Before introducing replicas, name the unit being scaled:

- HTTP request handling;
- job polling and effect execution;
- outbox relay;
- scheduler ownership;
- realtime connection handling;
- MCP request processing;
- long-running MCP task/elicitation workers.

For each unit, specify the durable authority, claim/lease/fencing behavior, effect identity, retry policy, dead/ambiguous state, partitioning, per-tenant fairness, concurrency limit, health, drain, and operator surface. A shared interface is not enough; provider semantics determine recovery and scale safety.

Redis Pub/Sub and local subscriptions are ephemeral. They provide no replay, acknowledgement, or durable cursor guarantee. The NATS adapter source does not prove JetStream durability. Use authoritative HTTP reads to reconstruct state unless a composed, documented event contract proves more.

## Capacity review procedure

**Prerequisites**

- a concrete application composition and provider configuration;
- production-representative, non-sensitive workload models;
- authorized disposable load environment;
- observability and stop criteria for every dependency;
- replay-safe test effects.

1. Enumerate each running task/listener from the composition root.
2. Identify its authority and delivery semantics, including leases and fencing.
3. Model arrival rate, service time, concurrency, connection count, payload size, provider quotas, and per-tenant limits.
4. Confirm the configured shutdown window accommodates claim release, in-flight effects, and connection drain.
5. Exercise one instance, then multiple instances, observing duplicate delivery, lease expiry, ordering, backlog age, and dependency saturation.
6. Interrupt workers and transports at bounded points, then verify redelivery and effect identity rather than assuming exactly-once execution.
7. Admit production capacity only after the provider-specific health and recovery behavior is documented.

**Expected result:** capacity is tied to a concrete runtime, bottleneck, and recoverable provider state; replica changes do not weaken authorization, tenant isolation, or effect identity.

**Failure path:** stop when duplicate effects, unbounded backlog, stale leases, lost ephemeral events, tenant starvation, or unsafe drain appears. Correct the composition/provider contract before raising concurrency.

No load or failure experiment was run while writing this page.

## Failure handling by state

- **Pending backlog grows:** separate insufficient capacity from provider unavailability, poison work, tenant concentration, or downstream quota exhaustion.
- **Running lease expires:** assume redelivery is possible; inspect fencing and effect identity before retrying.
- **Ambiguous provider response:** preserve the operation identity and reconcile; do not blindly resubmit.
- **Dead work accumulates:** stop automatic churn, retain safe metadata, classify the root cause, then authorize replay or discard.
- **Realtime clients diverge:** reconnect and re-read authoritative state; ephemeral transport is not a durable log.
- **MCP long-running request stalls:** do not invent completion/progress behavior. Dedicated completion/progress support is unavailable. Checked-in MRTR/task migrations establish schema definitions, but repository/worker assembly and applied runtime state for tasks and elicitation remain unproven.

## Operational controls required before assembly

- bounded concurrency and per-tenant fairness;
- least-privilege database/broker/provider credentials;
- health and readiness registered for authoritative dependencies;
- drain hooks for pollers, relays, schedulers, connections, and provider clients;
- redacted metrics for queue depth/age, claims, retries, dead state, connection churn, and authorization failures;
- authenticated operator actions with audit evidence;
- compatibility rules for envelopes, durable history, and cursors;
- incident and roll-forward procedures.

See [database, cache, and jobs troubleshooting](../troubleshooting/database-cache-and-jobs.md) and [MCP troubleshooting](../troubleshooting/mcp-discovery-transports-and-auth.md) for symptom-led diagnosis.