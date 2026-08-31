---
title: Observability model
description: The canonical relationship among logs, metrics, traces, health, audit, correlation, redaction, and operational evidence.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - rust-application-developer
  - operator
  - security-and-privacy-reviewer
  - ai-application-developer
topics:
  - observability
  - telemetry
  - health
  - audit
capabilities: []
source:
  - specs/14-observability-health-and-operations.md
  - crates/telemetry/src/lib.rs
  - crates/audit/src/lib.rs
evidence:
  - apps/server/src/main.rs
  - apps/api-server/src/main.rs
  - config/minimal.toml
  - config/reference.toml
last_verified: 2026-08-30
---

# Observability model

Observability explains what a system did without exposing the data it was trusted to process. Logs, metrics, traces, health, and audit are complementary signals with different audiences, retention, and access controls.

## Audience path

Application authors should apply these field and correlation rules at every new boundary. Operators should continue to the operations pages for concrete collection, probe, dashboard, alert, and incident procedures. Security reviewers should keep telemetry and accountability evidence inside the [data and privacy boundaries](data-and-privacy-boundaries.md).

## Signal responsibilities

| Signal | Primary question | Required properties |
|---|---|---|
| Structured logs | What bounded event occurred in this process? | Stable event/error names, severity, service/version/environment, outcome, safe identifiers, and redacted fields |
| Metrics | Is behavior changing at fleet scale? | Bounded label sets, explicit units, counters/histograms/gauges chosen by semantics, and actionable aggregation |
| Traces | Where did a request/effect spend time across boundaries? | W3C trace context, stable span names, bounded attributes/events, status from outcome, and linked async causation |
| Health | Should this process receive traffic or remain running? | Separate liveness, readiness, startup, drain, staleness, and dependency criticality semantics |
| Audit | Who attempted or completed a security/business state change under which authority? | Durable actor/tenant/action/resource/outcome evidence, protected access, retention, and no secrets or raw content |

Logs are not an audit ledger. Audit records are not debug logs, health probes, or metric dimensions.

## Correlation model

Create a bounded request identity at ingress and preserve standards-compliant trace context. Retain correlation and causation across HTTP calls, job/event envelopes, schedulers, outbound providers, LLM operations, and MCP tool execution.

- **Trace identity** joins spans in one distributed trace.
- **Request identity** gives operators a safe handle to return in errors and search logs.
- **Correlation identity** joins related work that may outlive one trace.
- **Causation identity** points to the message or operation that produced the current work.
- **Effect identity** prevents duplicate business side effects; it is defined in [reliability and idempotency](reliability-and-idempotency.md).

These identifiers support diagnostics and duplicate safety. None authenticates a caller, chooses a tenant, or authorizes an action.

Accept only syntactically valid W3C trace context and explicitly allowlisted bounded baggage. Baggage is untrusted metadata: do not use it for authorization, tenant resolution, or metric labels.

## Logs

Use named structured events and a stable safe error code/class. Include only the context needed to operate the system: service, version, environment, operation, outcome, duration, attempt, provider class, queue/route template where safe, and bounded opaque correlation identifiers.

Never log request/response or job/event bodies, passwords, tokens, cookies, authorization headers, SQL text, arbitrary model prompts/completions, raw email addresses, object contents, or rejected untrusted values. Redaction is defense in depth; fields that must not leave a trust boundary should not be emitted in the first place.

Startup failures need a bounded pre-telemetry fallback so a process that cannot initialize its subscriber/exporter remains diagnosable without dumping configuration or secrets.

## Metrics

Metric labels must remain low-cardinality and non-sensitive. Do not label with raw user or tenant IDs, object IDs, request/correlation IDs, full URLs, SQL, arbitrary error strings, model text, or provider payloads. Prefer route/operation templates, outcome classes, stable error codes, provider class, queue, model/provider identifiers from bounded registries, and dependency names.

Measure work at the boundary that owns it: request latency/outcomes, queue depth and age, handler attempts, retry/dead-letter state, dependency latency, circuit/admission state, token/cost/finish classes for LLM operations, and probe state. A metric should map to a capacity, reliability, security, or product decision.

## Traces

Start spans at ingress, application/use-case transitions, database/provider calls, enqueue/publish operations, worker deliveries, and model/tool calls. Name spans by stable operation rather than untrusted URLs or content. Record bounded outcomes and latency phases; avoid high-volume per-item spans when an aggregate event is sufficient.

Async work does not always remain one parent/child trace. Preserve correlation/causation or span links so redelivery and fanout remain understandable without falsifying a continuous call stack.

## Health and lifecycle

Liveness reports whether the process event loop and health refresh are functioning; it should not fail for every optional dependency. Readiness reports whether the process can accept its declared traffic and goes false before draining. Startup remains false until required initialization completes. Health staleness must fail conservatively.

Probe semantics and task criticality come from [runtime lifecycle](runtime-lifecycle.md). Health bodies expose bounded component state and build/schema compatibility, never credentials, private endpoints, stack traces, or dependency payloads.

## Audit

Record audit evidence for authentication changes, authorization-sensitive operations, tenant administration, credential/OAuth activity, privacy lifecycle actions, moderation, operator actions, and other accountable state transitions. Use canonical principal and authoritative tenant context, stable action/resource classes, safe outcomes, request/correlation identity, and bounded reason codes.

Audit storage and query access require explicit authorization and retention. The checked-in audit crate is an internal PostgreSQL library; no general public audit-query surface is proven.

## Current assembly boundary

The telemetry crate implements process-global structured logging, redacting formatters, W3C trace/baggage propagation, optional OTLP trace export, optional Prometheus recording, bounded service spans, LLM telemetry helpers, and bounded exporter shutdown.

Both checked-in applications initialize the telemetry layer and instrument their application runtime. Their checked-in development configurations use pretty logs and set Prometheus to `false`; those configurations do not prove a metrics endpoint or external telemetry backend. The minimal application also assembles public lifecycle probes. Sink availability, dashboards, alerts, retention, and production access controls belong to the concrete deployment and operations evidence.

## Evidence

- [Observability, health, and operations specification](../../specs/14-observability-health-and-operations.md)
- [Telemetry implementation](../../crates/telemetry/src/lib.rs)
- [Audit implementation](../../crates/audit/src/lib.rs)
- [Minimal application telemetry composition](../../apps/server/src/main.rs)
- [OAuth-provider application telemetry composition](../../apps/api-server/src/main.rs)
- [Minimal checked-in telemetry configuration](../../config/minimal.toml)
- [OAuth-provider checked-in telemetry configuration](../../config/reference.toml)

## Next

- [Observability operations](../operations/observability.md)
- [Health, readiness, and shutdown](../operations/health-readiness-and-shutdown.md)
- [Incident response](../operations/incident-response.md)
