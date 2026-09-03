---
title: Project layout
description: A map of the repository's application, library, generation, contract, data, consumer, and operations boundaries.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - rust-application-developer
  - contributor
topics:
  - repository
  - workspace
  - ownership
  - evidence
capabilities: []
source:
  - Cargo.toml
  - specs/01-system-architecture.md
  - specs/02-module-system-and-generator.md
evidence:
  - apps/server/src/main.rs
  - apps/api-server/src/main.rs
  - apps/mcp-server/src/main.rs
  - templates/base-service/apps/service/src/main.rs
last_verified: 2026-09-03
---

# Project layout

The repository is organized by ownership and evidence role, not by a claim that every directory participates in one executable.

## Audience path

Use this map before changing source or interpreting a capability. Application developers should continue to the architecture and composition concepts; contributors should use the development pages for workspace commands, generated ownership, and release gates.

## Top-level map

| Path | Primary role | Interpretation boundary |
|---|---|---|
| `apps/server/` | Checked-in minimal reference-service composition | Concrete for its five mounted HTTP routes only |
| `apps/api-server/` | Checked-in OAuth-provider reference-app composition | Concrete for the dependencies, tasks, and routes its source constructs; not every profile |
| `apps/mcp-server/` | Checked-in authenticated MCP reference-app composition | Concrete for resource metadata, `POST /mcp`, and `reference_records.list.v1`; not optional MCP primitives |
| `crates/service-kit/` | Reusable generated-service runtime/composition façade and canonical module contracts | Source-workspace framework package; consumers resolve it through one immutable Git dependency rather than copying it |
| `crates/` | Reusable domain, application, transport, infrastructure, protocol, and test libraries | Implementation source is not runtime assembly |
| `templates/base-service/` | Generator input for a thin independent application | Contains application/config/ops shape, never a copied framework or tooling workspace |
| `specs/machine/` | Authoritative profile, module, typed configuration/application requirement, and runtime dependency data | Runtime selections reject tooling; selection and specification are not runtime proof |
| `specs/` | Normative intent, ADRs, traceability, and validation material | Desired behavior remains separate from implementation evidence |
| `contracts/` | Deterministic consumer artifacts for the manifest's named profile | Generated-only evidence; inspect composition independently |
| `config/` | Checked-in source-application configuration inputs | Generated consumers own their configuration and derived runtime overlay; neither location is secret delivery |
| `migrations/` | Framework migration source embedded by `omnius-migrations` | Generated consumers do not copy it; their reserved-range application SQL remains in their own `migrations/` |
| `.sqlx/` | Source-workspace offline SQLx query metadata | Derived build evidence that is never copied into generated consumers |
| `web/` | Browser application source and web validation assets | Browser source is not proof that the Rust app serves it |
| `packages/web-sdk/` | Generated/consumer-facing TypeScript SDK boundary | SDK availability follows its exact contract and generation classification |
| `ops/`, `scripts/`, `release/` | Recovery inputs, controlled automation, runbooks, and evidence schemas | A script or evidence schema is not a report that an operation ran |
| `compat/` | Compatibility fixtures and snapshots | Historical compatibility evidence, not a live service |
| `docs/` | User documentation and canonical evidence classifications | Classification follows source; documentation does not upgrade availability |
| `xtask/` | Repository automation and contract/generation checks | Consult the command reference before invoking a task |

## Rust workspace boundaries

The root `Cargo.toml` explicitly lists applications and crates as workspace members. A workspace dependency makes code available to build; it does not mount a route or start a task. The intended dependency direction is:

```text
application composition
  -> transport and infrastructure adapters
  -> application services and narrow capability handles
  -> domain and core types
```

Application composition roots own concrete construction. Handler state should contain the exact capability handles required by that route group rather than one global bag of optional infrastructure. Read [architecture](../concepts/architecture.md) for these invariants.

## Generated and application-owned material

A fresh generated project is an independent Cargo workspace with one
`apps/service` Rust member, a committed lock, and one managed canonical Git
dependency alias for `omnius-service-kit`. It contains application source,
assets, configuration, contracts, operations files, and reserved-range
application SQL when present. It contains no copied Omnius crates, local
framework façade, tooling source, framework migrations, root `.sqlx`, specs, or
templates.

Strict schema-2 state classifies hashed kit-owned/derived files,
application-owned files, managed regions, and the semantically validated
dependency lock. Create-once web/SDK/contract templates become
application-owned immediately and survive remove/re-add. Lifecycle changes use
the installed `cargo-service`; only `update` transitions immutable release
identity. The [generator CLI reference](../reference/generator-cli.md) and
[generator development guide](../development/generator-and-profile-development.md)
own exact procedures.

## Finding evidence safely

When evaluating a feature, inspect in this order:

1. its row in the [availability and exposure matrix](../reference/availability-and-exposure-matrix.md);
2. its authoritative module/profile declaration, if profile selection matters;
3. the implementation crate and focused behavioral evidence;
4. a concrete application composition root;
5. the public or operator entry point mounted by that composition;
6. deployment-specific evidence, if the claim is that it is running.

A later layer cannot be inferred from an earlier one.

## Evidence

- [Workspace membership and shared package policy](../../Cargo.toml)
- [System architecture specification](../../specs/01-system-architecture.md)
- [Module ownership specification](../../specs/02-module-system-and-generator.md)
- [Minimal composition root](../../apps/server/src/main.rs)
- [OAuth-provider composition root](../../apps/api-server/src/main.rs)
- [Authenticated MCP composition root](../../apps/mcp-server/src/main.rs)
- [Base-service template entry point](../../templates/base-service/apps/service/src/main.rs)
- [Contract manifest](../../contracts/contract-manifest.json)

## Next

- [Architecture](../concepts/architecture.md)
- [Modules, profiles, and composition](../concepts/modules-profiles-and-composition.md)
- [Workspace and tooling](../development/workspace-and-tooling.md)
