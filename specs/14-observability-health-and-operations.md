---
spec_id: RSK-014
title: Observability, Health, and Operations
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Observability, Health, and Operations


## Logs and traces

Use `tracing`, `tracing-subscriber`, `tracing-opentelemetry`, and `opentelemetry-otlp`. Local output is human-readable; production is structured JSON.

Bounded fields include service/version/environment, request ID, route template/method, status/code, principal kind/auth method, bounded tenant class, dependency operation, job/event type/attempt, and correlation/causation.

Never attach bodies, tokens, cookies, passwords, arbitrary SQL, email content, or unbounded user input.

## Propagation

Use W3C Trace Context and allowlisted Baggage. Propagate to HTTP, jobs, events, and webhooks. Baggage is never authorization input or an unbounded metric label.

## Metrics

Use `metrics` and `metrics-exporter-prometheus`; OTLP metrics are optional after compatibility validation.

Required families:

- HTTP count/latency/status/in-flight/rejection.
- DB pool utilization/acquire/query/error class.
- Redis latency/error/reconnect/cache.
- Outbound dependency latency/status/retry.
- Queue depth/age/attempt/duration/dead letter.
- Outbox backlog/age.
- Realtime connections/messages/drops/slow consumers.
- Auth success/failure class.
- Authorization denial by action class.
- Rate-limit decision.
- Email/webhook delivery.
- Process CPU/memory/descriptors/tasks where available.

Raw user, tenant, object, URL, SQL, error message, and request ID are prohibited labels.

## Probes

- `/live`: process/runtime only.
- `/ready`: cached aggregate.
- `/startup`: startup phase.
- `/version`: safe build metadata.
- Detailed diagnostics on protected admin listener.

Probe requests do not synchronously stampede dependencies.

## Readiness

False before drain. Required DB/session store failure makes affected service unready. Cache is normally degraded. Telemetry exporter remains best effort. Other providers follow module criticality.

## Admin listener

Separate network surface for metrics, dependency/task/queue/outbox diagnostics, and optional profiling.

## Operational hooks

Example alert semantics cover availability/latency, DB saturation, queue/outbox age, auth anomalies, authorization spikes, delivery failure, restart loops, readiness flapping, and error-budget burn. Runbooks state first diagnostics and safe remediation.
