---
title: Observability
description: Operate the telemetry, health, correlation, and audit signals actually composed by Omnius without assuming a universal collector or dashboard.
status: experimental
implementation: implemented
profile_availability:
  - minimal
  - api
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - worker
  - full-reference
  - mcp-http
public_exposure: assembled
audience:
  - operator
  - security-analyst
topics:
  - operations
  - telemetry
  - diagnostics
capabilities: []
source:
  - crates/telemetry/src/lib.rs
  - crates/telemetry/src/config.rs
  - crates/telemetry/src/redact.rs
  - crates/http/src/lib.rs
  - apps/api-server/src/main.rs
  - apps/mcp-server/src/main.rs
evidence:
  - docs/coverage-matrix.md
  - apps/server/tests/minimal_service.rs
  - apps/mcp-server/tests/process_lifecycle.rs
last_verified: 2026-09-03
---

# Observability

Omnius assembles telemetry bootstrap, service spans, HTTP tracing, health state, and bounded telemetry shutdown in the checked-in servers. Individual libraries also emit metrics or audit events. The repository does **not** prove a universal collector, metrics scrape endpoint, dashboard, alert policy, retention system, or mounted audit query API.

Use the signal semantics in the canonical [observability model](../concepts/observability-model.md). The [availability and exposure matrix](../reference/availability-and-exposure-matrix.md) remains the authority for whether each producer is assembled, library-only, or unassembled.

## Signal inventory

| Signal | Evidence-qualified state | Operational use |
|---|---|---|
| Bootstrap phase output | Assembled by checked-in server processes | Separate configuration, metadata, telemetry, health, HTTP, OAuth, MCP, and provider startup failures |
| Service span and structured tracing | Assembled | Correlate revision/service/environment with runtime activity |
| HTTP request spans | Assembled in shared HTTP shell | Method, matched route, request ID, response status, and latency; unmatched routes use a bounded label |
| Health state | Assembled; dependencies are application-specific | Admission, startup, liveness, and dependency diagnosis |
| Static delivery counters | Implemented in the static delivery library and conditional composition | Bounded asset class/status/fallback/missing-asset observations when static delivery is actually enabled |
| PostgreSQL pool telemetry | Assembled in the reference API and MCP processes | Diagnose acquisition, connectivity, timeout, and pool pressure without logging SQL or URLs |
| Security audit library | Implemented but library-only; no public query surface proven | Accountable state-change evidence only after a concrete sink/composition is verified |
| MCP request/HTTP lifecycle | Assembled for the dedicated one-tool MCP process | Diagnose admission, bearer denial class, request latency, readiness, and drain without logging tokens or tool payloads |
| LLM, jobs, realtime, and optional MCP primitive signals | Producer contracts exist in libraries | Unassembled in checked-in applications; do not alert on nonexistent runtimes |

## Telemetry boundary

The checked-in reference configuration disables Prometheus export. That value is not proof of a scrape surface or an operator stack. Before relying on any metric or trace, establish the configured exporter, destination, transport security, authentication, sampling, buffering, retention, and failure behavior in the concrete deployment.

Sensitive-header handling, redaction utilities, and low-cardinality labels reduce exposure, but they do not make arbitrary application fields safe. Never attach credentials, cookies, authorization headers, connection URLs, request bodies, tenant payloads, prompts, tool arguments, model outputs, or uploaded content to telemetry.

## Deployment procedure

**Prerequisites**

- an approved signal destination and retention policy;
- data classification for each emitted field;
- ownership for alerts and incident escalation;
- the exact application/revision and enabled exporters.

1. Enumerate producers from the concrete composition, not the catalog.
2. Map each producer to its configured destination and failure mode.
3. Verify service, version, and environment identity agree with the compiled application; startup rejects a mismatch in the checked-in servers.
4. Define bounded-cardinality dimensions and redact sensitive fields before emission.
5. Set alerts on customer-impacting states: sustained unreadiness, startup failure, required-task exit, migration/database failure, drain overrun, and repeated security-sensitive rejection.
6. Verify telemetry shutdown fits inside the platform termination budget.
7. Record gaps explicitly. A library metric without a mounted runtime or exporter is not an available signal.

**Expected result:** every relied-on signal has a concrete producer, destination, access policy, retention period, owner, and tested interpretation.

**Failure path:** if exporter initialization fails, identity validation rejects configuration, or signal delivery is unavailable, follow the application's configured startup/failure semantics. Do not expose an unauthenticated diagnostic endpoint or turn on payload logging as a shortcut.

No exporter or observability backend was exercised while writing this page.

## Investigation workflow

1. Establish the time window, environment, service identity, revision, and affected tenant only where authorization permits.
2. Begin with lifecycle and typed error state, then correlate HTTP request IDs and supervised-task events.
3. Compare dependency signals with the application's readiness definition.
4. Determine whether absence of data means no event, an unassembled producer, an exporter problem, sampling, or retention expiry.
5. Preserve redacted evidence and the query criteria used; avoid screenshots containing secrets or customer content.
6. Escalate with the smallest useful data set: codes, bounded metadata, timestamps, correlations, and topology.

## Alert design

- Prefer rates, duration, and sustained state over single events.
- Keep unmatched URLs, identifiers, prompts, and raw error strings out of metric labels.
- Separate optional/degraded task exits from required task exits.
- Couple a health alert to its application-specific component and staleness.
- Treat usage reservations, commits, releases, and reconciliation as different LLM accounting events when that runtime is composed.
- Treat audit storage and queryability as separate from audit event creation.

## Related operations

- [Health, readiness, and shutdown](health-readiness-and-shutdown.md)
- [Incident response](incident-response.md)
- [LLM provider operations](llm-provider-operations.md)
- [Security model](../security/security-model.md)

The evidence status for documentation verification remains `not run`; see the [verification plan](../verification-plan.md).