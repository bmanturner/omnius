---
spec_id: OMNIUS-003
title: Core Runtime and Lifecycle
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Core Runtime and Lifecycle


## Foundation

Tokio provides the runtime; Axum routing; Tower services/layers; tower-http middleware; `tokio-util` cancellation/task tracking; `clap` process modes.

## Bootstrap phases

1. Process preflight and panic hook.
2. CLI parse.
3. Bootstrap stderr logging.
4. Config load/validation.
5. Telemetry.
6. Timed dependency initialization.
7. Migration policy check.
8. Application construction.
9. Listener bind.
10. Supervised task start.
11. Startup success/readiness.
12. Run loop.

Startup errors have stable codes and causal operator detail without secrets.

## Supervisor

Every long-lived task records name, module, criticality, start time, heartbeat where relevant, restart policy, cancellation token, shutdown timeout, and exit result.

- Required task exit marks unready and normally initiates shutdown.
- Degraded task exit marks the capability degraded.
- Best-effort exporter failure reports and continues.
- Restarts are bounded with capped jittered backoff.

## Termination

Handle `SIGTERM`, `SIGINT`, fatal dependency failure, and optional administrative drain. A second termination signal forces exit.

Drain order:

1. Mark unready.
2. Stop accepting new traffic/work.
3. Stop schedulers/consumers leasing new jobs.
4. Notify realtime clients when possible.
5. Wait within per-class deadlines.
6. Cancel remaining work.
7. Flush telemetry under a short deadline.
8. Close pools/clients.
9. Exit with meaningful status.

## Timeouts

Explicit typed timeouts exist for dependency connect, pool acquire, headers, request/handler, body streaming, outbound requests, jobs, shutdown stages, and exporter flush.

## Panic policy

Request panics become generic 500 responses and traces. A panic in a required supervised task is fatal. Clients never receive panic payloads/backtraces.

## Build metadata

Expose safe service/version, Git revision, build time, compiler version, kit version, profile/modules, and schema compatibility range.
