---
spec_id: ADR-0002
title: Use Source-Level Module Composition
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Use Source-Level Module Composition


## Context

The service kit must let teams opt into PostgreSQL, Redis, authentication, jobs, realtime, storage, and product modules. Cargo features are additive and unified across the graph. A dynamically loaded Rust plugin system would require an ABI, type erasure, version negotiation, and a larger security surface.

## Decision

Major capabilities are composed as workspace crates and generated source wiring.

- Named profiles select initial composition.
- Workspace dependencies include capabilities.
- Cargo features are limited to additive implementation details inside a crate.
- Runtime toggles enable behavior already compiled into the binary.
- Product feature flags govern user/tenant behavior and are not architecture toggles.
- No dynamically loaded Rust plugin ABI is provided.

## Consequences

- Supported combinations are explicit and testable.
- A disabled runtime module still exists in the binary; security-sensitive removal requires source composition.
- The generator owns manifests and declared managed regions.
- Mutually exclusive providers use provider slots and profile validation rather than Cargo feature tricks.

## Validation

- `cargo xtask profiles verify` resolves every named profile.
- The generator rejects provider-slot conflicts and missing dependencies.
- Removing a module never deletes historical migrations or application data automatically.
