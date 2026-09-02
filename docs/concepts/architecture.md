---
title: Architecture
description: The canonical system model for dependency direction, composition roots, trust boundaries, and evidence-backed capability exposure.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - evaluator
  - rust-application-developer
  - contributor
topics:
  - architecture
  - composition
  - dependency-direction
  - trust-boundaries
capabilities:
  - foundation-architecture
  - core-primitives
  - core-types
  - core-errors
  - core-identifiers
  - core-clock
  - build-metadata
source:
  - specs/01-system-architecture.md
  - specs/03-core-runtime-and-lifecycle.md
  - Cargo.toml
evidence:
  - apps/server/src/main.rs
  - apps/api-server/src/main.rs
  - apps/mcp-server/src/main.rs
  - crates/core/src/lib.rs
last_verified: 2026-09-02
---

# Architecture

Omnius uses explicit source composition. Applications choose and construct capabilities at compile time; runtime configuration may configure compiled behavior but does not remove code, dependencies, or attack surface.

## Audience path

Read this page before a surface-specific guide. Application developers should continue through composition and lifecycle. Consumer authors should continue through capability and contract boundaries before relying on generated artifacts.

## System model

```text
public or operator entry point
  -> boundary parsing and validation
  -> identity and request/tenant context, when required
  -> authorization at the application boundary, when required
  -> application use case and transaction
  -> narrow capability handles
  -> infrastructure adapters
  -> external systems
```

The architectural dependency direction points inward:

```text
apps -> transports/infrastructure -> application/domain -> core
```

Domain and core code do not depend on HTTP frameworks, SQL row types, Redis clients, authentication mechanisms, or telemetry exporters. Transport code parses an external contract and calls an application boundary. Infrastructure adapters own vendor-specific clients and persistence representation.

## Composition roots

Every executable is its own composition root. It is responsible for:

1. parsing its supported process mode and loading validated configuration;
2. initializing safe telemetry;
3. constructing dependencies in dependency order;
4. registering supervised tasks and typed route state;
5. binding public or operator listeners;
6. marking startup and readiness only after required initialization;
7. draining work and closing dependencies in bounded reverse order.

This is an architectural contract, not a claim that every specified process mode exists. The checked-in minimal reference service supports `server` and `profile-info`. The checked-in API reference application is compiled for `oauth-provider`. Other workspace libraries, profile descriptions, and template inputs need their own concrete composition evidence.

## State and capability handles

Route and task groups receive only the state they require. A database pool, queue client, object store, or provider SDK should remain behind a narrow application-facing handle. Avoid a global service locator full of optional clients: it makes impossible combinations compile and obscures which dependency controls readiness.

Core libraries provide bounded error codes, safe error separation, typed identifiers, an injectable clock boundary, and validated build metadata. Their classification is `library-only` across the base profiles in the coverage matrix. The minimal app exposes a safe subset of build metadata at `/version`; that route does not turn every core primitive into a public API.

## Trust boundaries

Treat each crossing independently:

- **Network input:** untrusted until size, syntax, origin/proxy, timeout, and semantic validation finish.
- **Identity:** authentication establishes a canonical principal; it does not authorize an action.
- **Tenant context:** accepted only after authoritative membership resolution, never directly from a client hint.
- **Application effects:** authorization, transaction ownership, idempotency, and audit belong at the use-case boundary.
- **Async transport:** envelopes carry bounded identity and correlation context, but a consumer must re-establish authorization and effect safety.
- **Provider adapters:** external diagnostics and payloads remain untrusted and must not cross safe error or telemetry boundaries verbatim.
- **Consumer artifacts:** OpenAPI, capability, permission, SDK, or protocol output is generated contract evidence, not independent exposure evidence.

Surface-specific identity, data, LLM, MCP, and browser controls belong to their canonical concept and security pages.

## Evidence layers

| Claim | Minimum useful evidence |
|---|---|
| Architecture is specified | Normative specification |
| A reusable behavior exists | Implementation source plus focused behavioral evidence |
| A profile selects a module | Resolved authoritative profile data |
| A project was generated | Inspectable generated artifact |
| An application assembles a capability | Non-test composition root plus its mounted entry point or registered task |
| A consumer contract is emitted | Exact generated artifact and manifest for the named contract profile |
| A capability is deployed | Environment-specific runtime or release evidence |

Do not promote a claim by skipping a layer. The [coverage matrix](../coverage-matrix.md) applies these distinctions consistently.

## Reference boundaries

- **Minimal reference service:** checked-in `apps/server`, no external services, five HTTP routes.
- **OAuth-provider reference app:** checked-in `apps/api-server`, concrete only for the dependencies and surfaces it constructs.
- **Authenticated MCP reference app:** checked-in `apps/mcp-server`, concrete for exact resource OAuth, `POST /mcp`, and one read-only reference-record tool; optional primitives remain unassembled.
- **Base-service template:** generation input under `templates/`, not an application instance.
- **Full-reference profile:** a broad CI/reference selection, not a universal process or production topology.

## Evidence

- [System architecture specification](../../specs/01-system-architecture.md)
- [Runtime and lifecycle specification](../../specs/03-core-runtime-and-lifecycle.md)
- [Workspace graph](../../Cargo.toml)
- [Minimal application composition](../../apps/server/src/main.rs)
- [OAuth-provider application composition](../../apps/api-server/src/main.rs)
- [Authenticated MCP application composition](../../apps/mcp-server/src/main.rs)
- [Core primitive exports](../../crates/core/src/lib.rs)

## Next

- [Modules, profiles, and composition](modules-profiles-and-composition.md)
- [Runtime lifecycle](runtime-lifecycle.md)
- [Capability and consumer contracts](capability-and-consumer-contracts.md)
