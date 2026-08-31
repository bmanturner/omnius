---
title: Health, readiness, and shutdown
description: Operate Omnius lifecycle probes, drain behavior, supervised tasks, and bounded shutdown using application-specific evidence.
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
public_exposure: assembled
audience:
  - operator
  - platform-engineer
topics:
  - operations
  - health
  - lifecycle
capabilities: []
source:
  - crates/health/src/lib.rs
  - crates/runtime/src/lib.rs
  - apps/server/src/main.rs
  - apps/api-server/src/main.rs
evidence:
  - apps/server/tests/minimal_service.rs
  - apps/api-server/tests/api_profile.rs
  - docs/coverage-matrix.md
last_verified: 2026-08-30
---

# Health, readiness, and shutdown

The minimal server and OAuth-provider reference API assemble lifecycle endpoints at `/live`, `/ready`, `/startup`, and `/version`. Their names are shared, but their readiness dependencies are application-specific. Use the canonical state model in [runtime lifecycle](../concepts/runtime-lifecycle.md); this page covers operator decisions.

## Probe meanings

| Surface | Operator question | Safe use |
|---|---|---|
| `/live` | Is the process lifecycle responsive? | Restart a wedged process only after platform and incident policy agree |
| `/startup` | Has application initialization completed? | Protect slow initialization from premature liveness intervention |
| `/ready` | May this concrete application receive new work now? | Gate admission and remove a draining or dependency-unready instance |
| `/version` | Which compiled application metadata is serving? | Correlate a response with a revision; do not treat it as health |

Do not make liveness depend on every remote provider: an outage could turn a shared dependency failure into a restart storm. Do not make readiness unconditional when the application requires an authoritative dependency to serve correctly.

The generated base-service template currently marks readiness without dependency checks. That behavior is generated-only and is not proof that a generated service is safe to admit traffic.

## Reference API readiness

The API composition registers PostgreSQL health and starts a refresher. Health data can become stale; operator policy must distinguish a recent dependency result from absence of refresh. Static delivery, when enabled in the concrete application, also has a readiness contract for its built assets.

Not every selected module contributes a health signal. Job providers, realtime transports, LLM providers, MCP transports, and Redis-backed capabilities are unassembled in checked-in applications unless a concrete composition proves otherwise. Do not create platform probes for catalog entries alone.

## Admission procedure

**Prerequisites**

- the exact application and revision;
- its documented authoritative dependencies;
- probe routing that cannot be confused with a different service;
- an alert and escalation owner.

1. Confirm `/startup` completes within the platform's approved startup budget.
2. Confirm `/live` remains responsive without requiring optional remote services.
3. Inspect `/ready` together with the dependency signals that this application actually registers.
4. Correlate `/version` or `/api/_meta` metadata with the candidate revision.
5. Admit traffic only after a bounded functional check of a migration- and identity-dependent path appropriate to the application.

**Expected result:** the instance reports started, live, and ready for its concrete dependency set, and its metadata matches the intended revision.

**Failure path:** keep the instance out of admission. Capture the lifecycle state, revision, health component/status, staleness, recent startup phase, and dependency evidence. Do not mask an unready dependency by changing the probe or increasing retries without diagnosing the source.

This is a source-derived procedure; it was not exercised while writing this page.

## Drain and shutdown

Both assembled servers use supervised lifecycle handling. The first supported termination signal begins drain and bounded shutdown. The applications stop accepting new work, cancel supervised tasks, wait for listener completion within configured bounds, and flush telemetry. The reference API also closes email delivery and the PostgreSQL pool. A second signal forces exit rather than extending the graceful path indefinitely.

**Authorized shutdown procedure**

1. Remove the instance from admission and verify new traffic is no longer assigned.
2. Trigger the platform's normal termination mechanism once.
3. Observe readiness transition, listener drain, supervised task exits, provider closure, and telemetry flush using available signals.
4. Let the configured bounds expire only according to the incident plan.
5. Use force termination only when graceful progress is no longer acceptable and record the possible interrupted work.

**Expected result:** no new requests are admitted, in-flight work receives the allowed drain window, tasks stop, providers close, and the process exits inside the platform budget.

**Failure path:** if the listener, task, provider, or telemetry flush exceeds its bound, capture the stuck component and cancellation state. Forced exit can interrupt effects; apply the replay rules in [reliability and idempotency](../concepts/reliability-and-idempotency.md) before retrying work.

## Alerting principles

- Alert on sustained lifecycle state and customer impact, not single probe samples.
- Separate process deadlock, startup failure, dependency unreadiness, and drain timeout.
- Attach revision and request/operation correlation where available.
- Avoid tenant, credential, prompt, body, cookie, or database URL labels.
- Validate platform thresholds against the configured application deadlines so the platform does not kill a process before its own drain contract can complete.

## Common mistakes

- Using `/version` as readiness.
- Treating unconditional template readiness as dependency readiness.
- Restarting every replica for a shared database outage.
- Assuming the `worker` profile has a worker health endpoint.
- Assuming a library provider appears in the application's health registry.
- Sending repeated termination signals during a normal drain.

See [observability](observability.md) for signal ownership, [deployment topologies](deployment-topologies.md) for admission planning, and [startup troubleshooting](../troubleshooting/startup-and-configuration.md) for phase-specific diagnosis.