---
title: Runtime lifecycle
description: The canonical bootstrap, supervision, readiness, drain, shutdown, and safe-failure model for assembled Omnius applications.
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
public_exposure: library-only
audience:
  - rust-application-developer
  - operator
topics:
  - runtime
  - lifecycle
  - readiness
  - shutdown
capabilities:
  - runtime-lifecycle
  - health-readiness-shutdown
source:
  - specs/03-core-runtime-and-lifecycle.md
  - crates/runtime/src/lib.rs
  - crates/health/src/lib.rs
evidence:
  - apps/server/src/main.rs
  - apps/server/tests/minimal_service.rs
  - apps/api-server/src/main.rs
  - apps/mcp-server/src/main.rs
  - apps/mcp-server/tests/process_lifecycle.rs
last_verified: 2026-09-02
---

# Runtime lifecycle

Runtime behavior belongs to each concrete composition root. Shared runtime and health libraries provide bounded primitives, but the application decides which dependencies are required, which tasks are supervised, and when readiness is true.

## Audience path

Application developers should use this page when wiring a process. Operators should continue to the health and observability pages for exact probes, configuration, diagnostics, and incident actions for a concrete application.

## Lifecycle states

```text
preflight
  -> configuration validation
  -> telemetry bootstrap
  -> dependency initialization
  -> application construction
  -> listener/task start
  -> startup complete
  -> ready and serving
  -> draining
  -> bounded shutdown
  -> telemetry flush and exit
```

Validation and required initialization finish before a process reports readiness. A listener accepting connections is not sufficient. During drain, readiness becomes false before the process stops taking new work.

## Bootstrap contract

A composition root should perform these operations in dependency order:

1. install process-level panic handling and parse only supported CLI modes;
2. load layered configuration and validate both fields and cross-module composition;
3. initialize telemetry without exposing secret source detail;
4. construct external dependencies under explicit connection deadlines;
5. verify migration compatibility when persistence is part of the application;
6. build typed route/task state and register supervised work;
7. bind listeners;
8. mark startup complete and evaluate readiness;
9. enter the run loop.

The specification describes the complete target contract. A checked-in app proves only the phases visible in its source. For example, the minimal reference service has no migration or external-dependency phase because it assembles neither persistence nor an external provider.

## Supervision and criticality

Every long-lived task needs an identity, owning module, cancellation path, shutdown deadline, exit observation, and declared criticality:

- **required:** unexpected exit makes the application unready and normally initiates shutdown;
- **degraded:** failure impairs its capability while other required work may continue;
- **best effort:** failure remains observable without deciding service readiness.

A restart policy is explicit and bounded; it must not create an infinite silent crash loop. Library `TaskSpec` or worker-builder support does not establish that an application registered a task.

## Probe semantics

| Probe | Meaning | Must not mean |
|---|---|---|
| `/live` | The process/runtime can answer | Dependencies are usable or traffic is safe |
| `/startup` | The application completed its startup boundary | It remains ready after a later dependency failure |
| `/ready` | The application's cached required-readiness aggregate currently permits new work | Every optional/degraded provider is healthy |
| `/version` | Safe build/profile/module/schema metadata chosen by the app | Internal dependency versions, secrets, or deployment health |

Probe implementations should use cached state rather than synchronously stampeding dependencies. Detailed dependency/task diagnostics belong on a protected operator surface when one is assembled.

## Drain and termination

The dependency-aware order is:

1. mark unready;
2. stop accepting new traffic and stop leasing new background work;
3. notify long-lived clients where the assembled transport supports it;
4. wait within per-class deadlines;
5. cancel remaining work;
6. shut down supervised tasks and close clients/pools;
7. flush telemetry under its own short deadline;
8. exit with a meaningful status.

`SIGINT`, `SIGTERM`, required-task failure, or an explicit administrative drain may initiate this flow when supported by the application. A second termination signal is the force-cancel path, not a normal successful shutdown.

The checked-in minimal service concretely drains its listener and supervisor, applies separate listener and telemetry deadlines, and returns exit status 130 after a second termination signal. Do not copy those exact timeout values or dependency semantics to another application without its configuration and composition evidence.

The dedicated MCP process begins listener and MCP drain together, rejects new MCP work, bounds already admitted work by the listener deadline, and treats forced MCP drain as a forced process outcome before PostgreSQL and telemetry teardown. Its exact dependencies and deadlines remain distinct from both the minimal and API processes.

## Failure boundaries

Startup and runtime errors expose stable safe codes while retaining causal detail for operators. Client responses never include panic payloads, backtraces, credentials, or arbitrary provider errors. Timeouts are typed by operation; one undifferentiated global timeout cannot express connect, header, handler, lease, drain, and exporter semantics safely.

## Availability boundary

The coverage matrix marks lifecycle/health as assembled across the base profile family because concrete checked-in applications assemble the shared probes and lifecycle primitives. That classification does not prove identical dependencies, readiness inputs, listeners, tasks, or shutdown order for generated and uninspected applications. Read the concrete app's composition and operations page.

## Evidence

- [Runtime lifecycle specification](../../specs/03-core-runtime-and-lifecycle.md)
- [Runtime supervisor implementation](../../crates/runtime/src/lib.rs)
- [Health implementation](../../crates/health/src/lib.rs)
- [Minimal lifecycle composition](../../apps/server/src/main.rs)
- [Minimal black-box lifecycle contract](../../apps/server/tests/minimal_service.rs)
- [OAuth-provider composition](../../apps/api-server/src/main.rs)
- [Authenticated MCP lifecycle composition](../../apps/mcp-server/src/main.rs)
- [Authenticated MCP process contract](../../apps/mcp-server/tests/process_lifecycle.rs)

## Next

- [Health, readiness, and shutdown](../operations/health-readiness-and-shutdown.md)
- [Configuration and secrets](../guides/backend/configuration-and-secrets.md)
- [Observability model](observability-model.md)
