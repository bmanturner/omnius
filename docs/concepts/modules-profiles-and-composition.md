---
title: Modules, profiles, and composition
description: Canonical definitions and evidence rules for module catalogs, profile resolution, generated projects, application assembly, and public exposure.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - rust-application-developer
  - module-provider-author-and-contributor
topics:
  - modules
  - profiles
  - generator
  - composition
capabilities:
  - profile-selection
source:
  - specs/02-module-system-and-generator.md
  - specs/machine/module-catalog.yaml
  - specs/machine/profiles.yaml
  - crates/service-kit/src/catalog.rs
  - crates/generator/src/cargo_service.rs
evidence:
  - crates/generator/src/catalog.rs
  - crates/generator/src/render.rs
  - templates/base-service/apps/service/src/composition.rs
last_verified: 2026-09-03
---

# Modules, profiles, and composition

This page owns module and profile terminology and the distinction between catalog selection and running behavior. Capability and composition-root terminology remains with the linked canonical concept owners below.

## Audience path

Application developers should use this model when choosing or reviewing a profile. Module authors should continue to the module reference and creation guide for descriptor fields, ownership, and compatibility rules.

## Canonical terms

### Module

A **module** is a stable catalog unit with an ID, dependencies, conflicts, ownership, criticality, typed configuration, closed runtime dependency IDs, and optional migrations, routes, tasks, health checks, metrics, secrets, typed application requirements, and generator-owned regions. A module may map to one crate, several crates, generated wiring, or metadata. It is not synonymous with a crate, route, profile, capability, or local container.

### Profile

A **profile** is a named runtime-module selection. Resolution expands
inheritance, then validates that the declared selection already satisfies
dependencies, conflicts, provider choices, and the runtime/tooling boundary.
Testing, generation, evaluation, preview, and conformance tooling never enters
runtime profile state. A profile is not a runtime mode, product edition,
deployment topology, or promise that selected modules are assembled.

A generated selection is a thin independent application workspace with one
managed immutable `omnius-service-kit` Git dependency. The consumer owns
application code, assets, configuration, contracts, operations files, and
application migrations; Omnius framework/tooling source and framework SQL are
not copied. External endpoints, credentials, and application-owned
policy/handler/provider traits remain required inputs and fail closed when
absent.

### Capability

For the canonical definition of **capability** and its consumer-facing contract semantics, see [capability and consumer contracts](capability-and-consumer-contracts.md#canonical-terms). This page only classifies module selection, generation, and assembly evidence in relation to that definition.

### Composition root

For the canonical definition of **composition root** and its system-boundary responsibilities, see [architecture](architecture.md#composition-roots). This page applies that architectural term when classifying whether selected or generated modules are assembled.

## Evidence states

| State | Exact meaning |
|---|---|
| **Selected** | Resolved authoritative profile data contains the module. Avoid “enabled” or “available” at this layer. |
| **Generated** | A generator materialized an inspectable project or artifact for a resolved profile. |
| **Compiled** | A particular application includes the relevant implementation in its build graph. |
| **Assembled** | A non-test application constructs the capability and mounts or registers its entry point. |
| **Deployed** | Environment-specific runtime/release evidence identifies that concrete application and configuration. |

Public exposure adds a separate classification:

- **assembled:** mounted in a concrete checked-in application with a public or operator entry point;
- **generated-only:** materialized contract or project output without independent runtime assembly evidence;
- **library-only:** reusable implementation without promised public application composition;
- **unassembled:** declarations or source exist, but the inspected application does not mount them;
- **not-applicable:** the page describes a concept or build-time concern rather than a public runtime surface.

These values do not form an automatic promotion pipeline. A library may be intentionally library-only; a generated artifact may describe a target without proving a process.

## Resolution and provider slots

Profile resolution should:

1. expand profile inheritance;
2. require the final declared selection to contain every runtime prerequisite;
3. reject conflicts, duplicate modules, and every tooling module;
4. reject duplicate providers in one provider slot;
5. resolve IDs to root service-kit canonical contracts in composition order;
6. classify hashed generated ownership, application ownership, managed
   regions, and the semantic dependency lock;
7. emit and seal one deterministic plan before mutation.

Jobs, events, sessions, object storage, policy, search, and feature flags have provider-specific semantics. Selecting one provider is an architectural choice, not an interchangeable runtime toggle. Dual-provider operation requires explicit migration design and evidence.

## Repository examples

| Observation | Defensible claim | Forbidden inference |
|---|---|---|
| `minimal` resolves to its ordered machine-catalog runtime modules | Those modules are selected for generation and agree with the service-kit feature subset | The separate checked-in `apps/server` composition is exact catalog `minimal` proof |
| `apps/server` reports its compiled module IDs and mounted routes | The checked-in `minimal-reference` process assembles its documented minimal HTTP surface | Every `minimal` selection or fresh generated application behaves identically |
| `apps/api-server` identifies `oauth-provider` and constructs concrete dependencies/routes | The checked-in reference app assembles its documented OAuth-provider surface | Every descendant profile or workspace library is live |
| `worker` selects queue, outbox, inbox, and scheduler libraries | The worker generation intent includes those modules | A checked-in worker executable leases or processes durable work |
| `full-reference` selects nearly all compatible base modules | It is broad CI/reference selection evidence | One all-capabilities process or recommended production topology exists |
| `contracts/contract-manifest.json` names `oauth-provider` | The committed artifacts belong to that contract profile | Another app serves those artifacts or all declared transports |

## Structural choice versus runtime choice

Use source/profile composition for major capability and provider choices. Use Cargo features only for additive implementation details inside a crate. Use runtime configuration to configure code already compiled and assembled. Use product feature flags to vary product behavior by environment or subject. A feature flag must not create an authorization bypass or pretend that an absent structural capability exists.

## Removal and release-identity updates

Module removal changes future wiring while preserving application-owned files,
historical application migrations, and data. Create-once application templates
remain application-owned through remove and re-add. Same-release selection
changes use `add`, `remove`, or `profile set`; only `cargo service update`
transitions release identity. Exact behavior belongs to the
[generator CLI reference](../reference/generator-cli.md).

## Evidence

- [Module-system specification](../../specs/02-module-system-and-generator.md)
- [Authoritative module catalog](../../specs/machine/module-catalog.yaml)
- [Authoritative base profiles](../../specs/machine/profiles.yaml)
- [Catalog resolution implementation](../../crates/generator/src/catalog.rs)
- [Rendering implementation](../../crates/generator/src/render.rs)
- [Generated composition metadata template](../../templates/base-service/apps/service/src/composition.rs)
- [Committed contract manifest](../../contracts/contract-manifest.json)

## Next

- [Choose a profile](../getting-started/choose-a-profile.md)
- [Modules and capabilities reference](../reference/modules-and-capabilities.md)
- [Creating a module](../development/creating-a-module.md)
