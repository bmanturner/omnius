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
  - crates/reference-api/src/contracts.rs
  - config/reference.toml
  - templates/base-service/apps/service/src/lib.rs
  - templates/base-service/ops/Dockerfile
  - crates/generator/src/manager.rs
evidence:
  - docs/coverage-matrix.md
  - apps/api-server/tests/api_profile.rs
last_verified: 2026-09-02
---

# Deployment topologies

Omnius has separate concrete checked-in application assemblies: `apps/api-server` for the OAuth-provider API, `apps/mcp-server` for the authenticated reference MCP resource, and `apps/server` for the minimal HTTP process. Generated services are a different boundary. The base-service template and its derived configuration/Compose renderers are implemented generator inputs, but a template or selected profile is not a deployment. Start with the distinctions in [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md) and check each capability in the [availability and exposure matrix](../reference/availability-and-exposure-matrix.md).

## Evidence-qualified choices

| Choice | Evidence | Operational ceiling |
|---|---|---|
| OAuth-provider reference API | `apps/api-server` composition, contracts, and reference configuration | Assembled HTTP service with PostgreSQL, account/session/API-key/OAuth behavior, email integration, health, migrations, telemetry, drain, and bounded shutdown |
| Authenticated reference MCP | Separate `apps/mcp-server` composition and configuration | Dedicated bearer-protected HTTP resource with one reference-record tool; not assembly for broader MCP profile primitives |
| Minimal checked-in service | Separate `apps/server` composition | Small assembled lifecycle and HTTP surface; not the broad reference API |
| Generated minimal service | Derived project with `config/reference.toml` and application-only `ops/compose.yaml` | Runnable local application topology after render/build; not a production deployment or proof of optional capability assembly |
| Generated persisted service | Derived project with pinned PostgreSQL, named volume, and one-shot migration service | Runnable repository-owned local infrastructure; advanced application and external requirements remain fail closed |
| Catalog profile | Profile selection data | Selection only; it does not prove a binary, listener, worker, provider credentials, routes, or public exposure |
| LLM profile | Extension catalog data and libraries | Provider endpoint/credentials and typed application requirements remain external/application-owned prerequisites |
| MCP profile | Extension catalog data plus the separate checked-in reference MCP application | The dedicated app proves only its authenticated reference tool; a generated advanced profile still requires all selected application contracts |

The generated container runs as an unprivileged numeric user with a read-only root, bounded `/tmp`, and `no-new-privileges`. The image runs from `/app`, includes `/app/config`, and uses `service healthcheck --address 127.0.0.1:3000`. These are local-container controls, not a production ingress policy, secret system, capacity model, or orchestrator definition.

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
3. Supply secrets through exact hierarchical environment keys or a fully resolved higher-precedence layer. `${...}` in TOML is literal text and is never interpolated.
4. Name exactly one migration owner. Generated persisted Compose owns local migration through its one-shot service; direct/operator launches retain their explicit startup or administrative-command policy.
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

### Generated services

Inspect the generated result rather than relying on template source. `config/base.toml` contains safe base process policy; manager-derived `config/reference.toml` contains strict typed defaults for the resolved framework runtime and never contains secret values. Persisted direct launches require `OMNIUS__POSTGRES__URL` and exact 32-byte `OMNIUS__PAGINATION__CURSOR_SIGNING_KEY`; process environment overrides both files and explicit CLI overrides remain highest precedence.

Minimal Compose contains only `app`, binds it to `0.0.0.0:3000` inside the container, and publishes `127.0.0.1:3000:3000`. Persisted Compose adds digest-pinned `postgres`, health-gated startup, retained `postgres-data`, and one-shot `migrate`; `app` waits for database health and successful migration. Compose sets `OMNIUS__MIGRATIONS__RUN_ON_STARTUP=false`, so startup and one-shot migration do not race. Normal stop/start retains the named database volume.

Dependencies without a repository-owned pinned and health-checked descriptor remain external. Compose emits required `${NAME:?message}` YAML bindings for their exact endpoints/credentials and no substitute containers. Application-owned advanced requirements are closed typed traits, not router/task bags or runnable defaults. Missing external bindings or application contracts intentionally prevent startup.

### Separate process roles

A `worker` profile selects job-related modules but does not prove a worker executable or verified `WorkerBuilder` composition. Generated realtime and broader MCP selections likewise need their concrete listeners, providers, authorization, health, and drain behavior; the dedicated reference MCP application proves only its own narrow composition. See [scaling jobs, realtime, and MCP](scaling-jobs-realtime-and-mcp.md).

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