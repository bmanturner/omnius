---
spec_id: ADR-0001
title: Use Rust, Tokio, Axum, and Tower
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Use Rust, Tokio, Axum, and Tower


## Context

The service kit needs one network/runtime model shared by HTTP, gRPC, middleware, background work, shutdown, and observability. Selecting multiple async runtimes or unrelated middleware models would increase dependency duplication and make module composition harder.

## Decision

Use:

- Rust 2024 edition.
- A pinned current stable Rust toolchain.
- Tokio as the sole async runtime.
- Axum as the default HTTP framework.
- Tower as the service and middleware abstraction.
- tower-http for standardized HTTP middleware.
- Hyper only when a lower-level need is not exposed by Axum.

The first baseline is Rust 1.98.0, Tokio 1.53.1, Axum 0.8.9, Tower 0.5.3, and tower-http 0.7.0.

## Consequences

- HTTP, gRPC through Tonic, retries, limits, tracing, and middleware share Tower semantics.
- Modules must not introduce Actix, async-std, smol, Rocket, or another runtime/framework into supported profiles.
- A specialized service may choose another framework only by forking the service-kit architecture or accepting a replacement ADR.
- Direct Hyper use is localized and does not leak into domain/application code.

## Validation

- Dependency policy rejects a second async runtime.
- Profile builds inspect duplicate Tokio/Hyper/Tower versions.
- The minimal reference service demonstrates startup, request handling, cancellation, and graceful drain.
