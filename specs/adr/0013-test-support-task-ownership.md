---
spec_id: ADR-0013
title: Test-support task ownership
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# ADR 0013: Test-support task ownership

## Context

T020 depended only on T010 while its catalog module requires both `core` and `config`, and its output named config builders. It also assigned principal fixtures before T040 defines the canonical `Principal`, despite the `auth-core` catalog entry owning the test-principal factory. The normative testing specification additionally requires a test server/client and deterministic randomness, but the T020 output omitted both.

Implementing a temporary principal DTO would create a second identity convention and force a later migration. Omitting the production config loader or HTTP shell from T020 dependencies would likewise hide real compile-time dependencies.

## Decision

T020 depends on T010, T011, and T014. Its output is the deterministic clock, deterministic ID/random source, hermetic config builder, and loopback test server/client. T040 owns the canonical `Principal` and its test-principal factory.

T021 continues to own runner policy. T022 depends on that policy and owns real infrastructure, T023 owns provider HTTP fakes, and T024 owns profile-generation tests. T020 does not add Testcontainers, Wiremock, or a parallel identity model.

## Consequences

The deterministic base crate can be completed without preempting authentication design. Later identity tests extend test support through the canonical auth-core type rather than adapting a temporary fixture. Task dependencies now match the module catalog and the types used by the implementation.
