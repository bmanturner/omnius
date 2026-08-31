---
title: Omnius overview
description: An evidence-bounded introduction to the source-composed Rust service kit, its checked-in applications, and its optional capability families.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - evaluator
  - rust-application-developer
  - operator
topics:
  - getting-started
  - architecture
  - evidence
  - composition
capabilities: []
source:
  - specs/00-scope-and-principles.md
  - specs/01-system-architecture.md
  - Cargo.toml
evidence:
  - apps/server/src/main.rs
  - apps/api-server/src/main.rs
  - specs/machine/profiles.yaml
last_verified: 2026-08-30
---

# Omnius overview

Omnius is a source-composed Rust service kit. It combines reusable crates, machine-readable profile and module data, generation inputs, checked-in reference applications, and consumer contract artifacts. Those layers answer different questions; none is evidence for all the others.

## Audience path

- **Evaluating the repository:** follow the [minimal-service quickstart](quickstart.md), then check the [availability and exposure matrix](../reference/availability-and-exposure-matrix.md) before relying on another capability.
- **Building a Rust service:** understand [profiles and composition](choose-a-profile.md), then use the backend guides for the capability you intend to assemble.
- **Operating a service:** start with the checked-in application's health and lifecycle surface, then follow the operations pages for its concrete dependencies.
- **Building a consumer:** follow the [web quickstart](web-quickstart.md), [LLM quickstart](llm-quickstart.md), or [MCP server quickstart](mcp-server-quickstart.md) for the surface you are integrating. A generated contract or implemented library is not proof of a live endpoint.

## What is concrete

| Evidence layer | What it establishes | What it does not establish |
|---|---|---|
| `apps/server` | A checked-in, no-external-service HTTP process with probes, build metadata, one example route, and graceful drain | Database, identity, jobs, realtime, LLM, MCP, or admin capability |
| `apps/api-server` | A checked-in OAuth-provider reference application and the routes and dependencies its composition root actually mounts | Assembly for every profile or every workspace crate |
| `crates/*` | Reusable implementation contracts and adapters | A listener, route, worker, provider, or operator surface |
| `specs/machine/*` and generator source | Profile selection, module relationships, and generation intent | A generated artifact or running deployment |
| `contracts/*` | Generated consumer artifacts for their named contract profile | Independent proof that a route or channel is mounted |
| normative specifications | Intended architecture and acceptance boundaries | Implementation or runtime availability by themselves |

The [evidence inventory](../evidence-inventory.md) explains this hierarchy. The [coverage matrix](../coverage-matrix.md) records the classification used by every documentation page.

## The system shape

Application binaries own composition. They load and validate configuration, construct only the dependencies they need, mount routes or supervised work with typed state, announce readiness, and drain in dependency-aware order. Reusable crates stay below those composition roots. Read [architecture](../concepts/architecture.md) for the dependency and trust-boundary model.

Use the canonical [module and profile definitions](../concepts/modules-profiles-and-composition.md#canonical-terms) and the canonical [capability and consumer-contract definitions](../concepts/capability-and-consumer-contracts.md#canonical-terms). The evidence layers and application choices on this page apply those definitions rather than introducing overview-local variants.

## Choose the first proof you need

1. **Need a local process with no external services?** Run the [minimal-service quickstart](quickstart.md).
2. **Need to select a service shape?** Use [choose a profile](choose-a-profile.md), then inspect the exact availability classification.
3. **Need to understand the repository?** Read [project layout](project-layout.md).
4. **Need an optional surface?** Start from its guide or quickstart, but retain every `library-only`, `generated-only`, or `unassembled` caveat.
5. **Need production assurance?** Use the operations, security, and development gates tied to the concrete application and deployment; a profile name is not release evidence.

## Evidence

- [System architecture specification](../../specs/01-system-architecture.md)
- [Workspace membership](../../Cargo.toml)
- [Minimal reference-service composition](../../apps/server/src/main.rs)
- [OAuth-provider reference-app composition](../../apps/api-server/src/main.rs)
- [Authoritative profile data](../../specs/machine/profiles.yaml)

## Next

- [Minimal-service quickstart](quickstart.md)
- [Choose a profile](choose-a-profile.md)
- [Project layout](project-layout.md)
