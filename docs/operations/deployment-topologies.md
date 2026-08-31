---
title: Deployment topologies
description: Choose an evidence-qualified Omnius deployment shape without confusing profiles, generated templates, or libraries with an assembled service.
status: experimental
implementation: implemented
profile_availability:
  - oauth-provider
public_exposure: assembled
audience:
  - operator
  - platform-engineer
topics:
  - operations
  - deployment
  - composition
capabilities:
  - api-reference
  - oauth-provider
  - base-service-template
  - health
  - web-static
source:
  - apps/api-server/src/main.rs
  - apps/api-server/src/contracts.rs
  - config/reference.toml
  - templates/base-service/apps/service/src/lib.rs
  - templates/base-service/ops/Dockerfile
evidence:
  - docs/coverage-matrix.md
  - apps/api-server/tests/api_profile.rs
last_verified: 2026-08-30
---

# Deployment topologies

Omnius has one broad, concrete application assembly in this repository: `apps/api-server`, compiled as the `oauth-provider` profile. The base-service template is implemented generator input, but a template or selected profile is not a deployment. Start with the distinctions in [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md) and check each capability in the [availability and exposure matrix](../reference/availability-and-exposure-matrix.md).

## Evidence-qualified choices

| Choice | Evidence | Operational ceiling |
|---|---|---|
| OAuth-provider reference API | `apps/api-server` composition, contracts, and reference configuration | Assembled HTTP service with PostgreSQL, account/session/API-key/OAuth behavior, email integration, health, migrations, telemetry, drain, and bounded shutdown |
| Minimal checked-in service | Separate `apps/server` composition | Small assembled lifecycle and HTTP surface; not the broad reference API |
| Generated base service | Template source and generator behavior | Generated-only until an operator inspects the rendered project, builds it, and exercises its concrete dependencies |
| Catalog profile | Profile selection data | Selection only; it does not prove a binary, listener, worker, provider credentials, routes, or public exposure |
| LLM or MCP profile | Extension catalog data and libraries | Unassembled in the checked-in applications; no LLM router mount or MCP listener/stdio binary is proven |

The generated template exposes useful local-container controls, including a non-root user, read-only filesystem configuration, a constrained temporary directory, and `no-new-privileges`. Its readiness is unconditional and its container files are local examples, not a production topology, ingress policy, secret system, or orchestrator definition.

## Plan a deployment

**Prerequisites**

- an approved revision and an explicitly named concrete application;
- the resolved capability and contract artifacts for that revision;
- a protected configuration and secret-delivery plan;
- an authorized PostgreSQL owner for the reference API;
- documented ingress, certificate, DNS, capacity, observability, backup, and rollback ownership.

**Procedure**

1. Name the executable and composition root. Do not use a profile name as shorthand for a running system.
2. Compare the application's actual dependencies, mounted routes, background tasks, and capability metadata with the intended topology.
3. Replace reference secret placeholders through the supported configuration layers. They are not defaults and are not interpolated automatically.
4. Keep production migrations explicit. The reference configuration sets startup migration execution off; follow [migrations](migrations.md).
5. Establish application-specific health semantics and shutdown budgets using [health, readiness, and shutdown](health-readiness-and-shutdown.md).
6. Define the only telemetry sinks and alerts actually wired by the application; see [observability](observability.md).
7. Prove backup and restore outside production before admitting traffic. The repository's local rehearsal is not a production backup system.
8. Bind release evidence, contract compatibility, and rollback artifacts to the same revision. Follow [upgrades and rollbacks](upgrades-and-rollbacks.md).
9. Apply the controls in [deployment hardening](../security/deployment-hardening.md) at the real platform boundary.

**Expected result:** the deployment record names a concrete binary, exact configuration authority, dependencies, mounted surfaces, lifecycle probes, migration owner, recovery owner, and rollback decision.

**Failure path:** stop promotion when evidence is only a profile, template, generated artifact, workflow definition, or runbook. Obtain assembly and exercised-runtime evidence rather than weakening the deployment claim.

## Topology-specific cautions

### OAuth-provider reference API

PostgreSQL and the API listener are concrete dependencies. SMTP-backed account mail is assembled but conditional on protected credentials and reachable infrastructure. Local rate limiting is process-local, so additional replicas do not create a global limit. JWT code may be selected while the reference configuration keeps it disabled. Realtime, durable job workers, the web application, LLM HTTP routes, and MCP transports are not materialized by this application.

### Generated base service

Inspect the generated result rather than relying on template source. Confirm whether static delivery is enabled, what readiness actually checks, and whether any selected provider has a bootstrap, health registration, shutdown hook, and secret path. Do not copy local compose settings into production without a platform-specific threat and capacity review.

### Separate process roles

A `worker` profile selects job-related modules but does not prove a worker executable or verified `WorkerBuilder` composition. Realtime and MCP likewise require concrete listeners, providers, authorization, health, and drain behavior. See [scaling jobs, realtime, and MCP](scaling-jobs-realtime-and-mcp.md).

## Promotion record

Retain, without secrets:

- revision and immutable artifact identities;
- concrete application and compiled profile identity;
- contract/capability hashes and compatibility decision;
- configuration provenance and secret references, never secret values;
- migration status and authorized migration record;
- health and shutdown observations for this application;
- recovery and rollback evidence tied to the candidate;
- approvals required by the web or AI/MCP runbooks.

No deployment, smoke test, or release gate was run while writing this page.