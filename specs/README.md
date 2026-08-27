---
spec_id: OMNIUS-README
title: Omnius Specification Bundle
version: 0.1.0
status: informative
last_verified: 2026-08-23
---

# Omnius Specification Bundle


## Purpose

This bundle is the normative build specification for an opinionated, modular Rust backend service kit. It is designed to be passed directly to an autonomous programming agent.

The product is not a monolithic starter with every integration compiled in. It consists of:

1. A small runtime kernel.
2. Workspace crates implementing opt-in capabilities.
3. Named profiles composing coherent services.
4. A generator and `xtask` surface for safe module management.
5. Reference applications and a conformance suite.
6. An upgrade and supply-chain policy.

The dependency research was verified on **August 23, 2026**. Versions form a reviewed compatibility baseline, not permission to skip compilation, advisory, or license checks.

## Binding architectural decisions

- Rust 2024 edition and Cargo resolver 3.
- Tokio, Axum, Tower, and tower-http form the runtime and HTTP foundation.
- PostgreSQL is the primary relational database.
- SQLx **0.8.6** is the first supported line. SQLx 0.9.0 is deliberately gated because important surrounding integrations still target 0.8.
- Redis capabilities are split by purpose rather than represented by one generic switch.
- Browser authentication uses `axum-login` and `tower-sessions`; JWT verification uses `jsonwebtoken`; OIDC uses `openidconnect` and `oauth2`.
- Authorization is enforced in application services. Basic RBAC/ownership is built in; Cedar is optional.
- Outbound webhook delivery uses Svix instead of implementing a delivery platform.
- Apache Arrow `object_store` is the default object-storage abstraction.
- Durable jobs use an established backend. The kit does not create a new queue.
- Observability uses `tracing`, OpenTelemetry, and the `metrics` facade.
- Modules are composed at source/build time. There is no dynamic Rust plugin ABI.

## Normative language and precedence

**MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

When documents conflict:

1. Accepted ADRs.
2. Security and data-integrity requirements.
3. Module-specific specifications.
4. General architecture specifications.
5. Machine-readable catalogs.
6. Examples and research notes.

A machine-readable file that disagrees with a normative Markdown specification is a defect.

## Agent reading order

1. `AGENTS.md`
2. `SPEC_INDEX.md`
3. `00-scope-and-principles.md`
4. `01-system-architecture.md`
5. `02-module-system-and-generator.md`
6. `21-crate-selection-matrix.md`
7. `20-implementation-roadmap.md`
8. The current phase's specifications and ADRs
9. `22-recommendation-traceability.md`
10. `23-agent-task-graph.md`

## Definition of complete

The kit is complete only when:

- Every named profile generates in a clean directory.
- Every generated profile passes format, lint, compile, test, documentation, advisory, license, and source-policy checks.
- Reference applications demonstrate HTTP, PostgreSQL, sessions, JWT, authorization, jobs, realtime, graceful shutdown, and operational tooling.
- Every optional module has configuration, lifecycle, health, metrics, failure semantics, local infrastructure, integration tests, and documentation.
- The traceability matrix has no missing recommendation.
- No prerelease, yanked crate, git dependency, or incompatible duplicate foundational crate enters a default profile without an ADR.
- Generated repositories contain no placeholder macro, unimplemented production path, example secret, unbounded queue, or route bypassing authorization.
- Upgrade rehearsals prove that existing generated services can receive kit updates without overwriting application-owned code or deleting data.

## Bundle structure

- Numbered specifications are normative.
- `adr/` records architecture decisions.
- `machine/` contains catalogs and schemas consumed by tools.
- `examples/` contains contract examples, not copy-paste production implementations.
- `research/` records evidence and selection methodology.
- `SHA256SUMS` verifies artifact integrity.
