---
title: Choose a profile
description: Select a generator profile by required capability and provider shape while keeping selection separate from generated output and runtime assembly.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - evaluator
  - rust-application-developer
  - module-provider-author-and-contributor
topics:
  - profiles
  - selection
  - generation
  - composition
capabilities: []
source:
  - specs/machine/profiles.yaml
  - specs/machine/module-catalog.yaml
  - specs/19-profiles-and-acceptance.md
evidence:
  - crates/generator/src/catalog.rs
  - crates/generator/src/render.rs
  - crates/generator/tests/base_service.rs
last_verified: 2026-09-02
---

# Choose a profile

The canonical profile definition and its selection-versus-assembly boundaries are in [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md#profile). This page applies that model to the checked-in profile catalogs and the choice of an initial service shape.

## Audience path

Use this page after the [overview](overview.md) when choosing an initial service shape. Module authors should continue to the composition concept and module reference; evaluators should verify the chosen capability's implementation and exposure classification before adopting it.

## Selection layers

Keep these questions separate:

1. **Selected:** does profile resolution include the required module and a compatible provider?
2. **Generated:** has the generator materialized the resolved profile into an inspectable artifact?
3. **Compiled:** does a specific application depend on the implementation?
4. **Assembled:** does that application's composition root construct it, register work, and mount a public or operator entry point?
5. **Deployed:** does environment-specific release evidence show that exact application and configuration running?

Only the first question is answered by `specs/machine/profiles.yaml`. See [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md) for the canonical model.

## Base profile map

The authoritative base-profile data describes these selection intents:

| Profile | Selection intent | Important boundary |
|---|---|---|
| `minimal` | Core configuration, telemetry, runtime, HTTP, health, local rate limiting, test support, and generator metadata without runtime dependencies | Generated Compose contains only the application; the checked-in minimal service remains a separate concrete composition |
| `api` | Extend `minimal` with PostgreSQL, migrations, validation, OpenAPI, idempotency, and outbound HTTP | Generated local Compose provides pinned PostgreSQL and one-shot migrations, but does not prove every selected library is mounted |
| `authenticated-api` | Extend `api` with local identity, sessions, API keys, basic authorization, audit, email, and typed job contracts | Typed job contracts are not a queue or worker |
| `oauth-provider` | Extend `authenticated-api` with the OAuth/OIDC server and tenancy | The checked-in `apps/api-server` is the concrete reference app for this profile; inspect its composition for live routes |
| `saas` | Select Redis-backed cache/jobs plus tenancy, admin, outbox/inbox, scheduler, storage, notifications, webhooks, and feature flags | No checked-in application assembles the entire selection |
| `saas-pgmq` | Select the SaaS shape with local cache and PGMQ jobs instead of Redis jobs | Provider-specific delivery and operations remain distinct |
| `realtime` | Select authenticated ephemeral Redis fan-out with SSE and WebSocket modules | Selection does not prove mounted realtime routes or durability |
| `realtime-durable` | Select authenticated NATS-backed realtime plus outbox/inbox | “Durable” is profile intent; provider, publisher, consumer, and worker assembly still need evidence |
| `worker` | Select PostgreSQL, Redis/Apalis jobs, outbox/inbox, scheduler, HTTP health, and runtime libraries | No checked-in worker binary constructs this full worker composition |
| `full-reference` | CI/reference selection of nearly all mutually compatible base modules | It is not a recommended production topology or a checked-in all-capabilities process |

Extension profiles for web, LLM, MCP, and combined AI surfaces have separate availability and exposure states. Use the [profile reference](../reference/profiles.md) rather than inferring their inheritance from a base-profile name.

## Generated local topology boundary

Generated `minimal` Compose builds only `app`, binds the container to `0.0.0.0:3000`, and publishes only `127.0.0.1:3000:3000` on the host. A persisted profile adds digest-pinned `postgres`, the retained `postgres-data` named volume, a health gate, and one-shot `migrate`. The application waits for PostgreSQL health and migration success. Compose disables startup migration application, making `migrate` the sole local owner; stopping and restarting the stack retains the named database volume.

This runnable local topology is deliberately narrow. Redis/Valkey, NATS, object storage, SMTP/email, OIDC, webhook, feature-flag, search, and LLM provider dependencies remain external unless a future closed descriptor supplies a repository-owned pinned and health-checked topology. Generated Compose requires their exact endpoint/credential variables with `${NAME:?message}` and creates no substitute containers. `${...}` here is Compose validation syntax; it does not interpolate TOML.

Advanced profiles can therefore be valid generated scaffolds while remaining intentionally fail closed. Their closed typed application requirements still need concrete policy, handler, registry, authorization, and provider traits. Declared routers, tasks, health checks, or catalog metadata are not substitutes for those application-owned ports.

## Decision procedure

1. Write down the externally observable capability, trust boundary, and persistence or delivery guarantee you need.
2. Find its exact row in the [availability and exposure matrix](../reference/availability-and-exposure-matrix.md). Stop if the implementation or exposure classification is insufficient.
3. Find the owning module and any provider slot in the [module and capability reference](../reference/modules-and-capabilities.md).
4. Choose the smallest profile whose resolved selection contains that module and one compatible provider. Do not choose `full-reference` merely to avoid a decision.
5. Identify the intended composition root. A server route, background worker, generated web application, LLM provider, and MCP transport may require different executables or entry points.
6. Require concrete generated or checked-in application evidence before calling the capability available. Require runtime/deployment evidence before calling it running.
7. Review operations and security prerequisites for every external service, secret, migration, public listener, and durable worker introduced by the selection.

## Common mistakes

- Treating profile inheritance as a running dependency graph.
- Calling a module “enabled” because it appears in profile data or `Cargo.toml`.
- Treating a focused test as application composition.
- Inferring a route from OpenAPI or a browser capability from generated SDK output.
- Treating the `worker` profile description as evidence of a worker executable.
- Treating runtime feature flags as structural module selection.

## Evidence

- [Authoritative base profiles](../../specs/machine/profiles.yaml)
- [Authoritative module catalog](../../specs/machine/module-catalog.yaml)
- [Generator catalog resolution](../../crates/generator/src/catalog.rs)
- [Generator rendering](../../crates/generator/src/render.rs)
- [Checked-in minimal composition](../../apps/server/src/main.rs)
- [Checked-in OAuth-provider composition](../../apps/api-server/src/main.rs)

## Next

- [Modules, profiles, and composition](../concepts/modules-profiles-and-composition.md)
- [Profile reference](../reference/profiles.md)
- [Availability and exposure matrix](../reference/availability-and-exposure-matrix.md)
