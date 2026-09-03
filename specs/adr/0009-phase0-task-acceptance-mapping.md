---
spec_id: ADR-0009
title: Separate Repository Skeleton and Minimal Profile Acceptance
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Separate Repository Skeleton and Minimal Profile Acceptance

## Context

The original task graph assigned `AC-CORE-001`, “Minimal profile starts without external services,” to both `T000` and `T017`. `T000` is limited to the repository/workspace skeleton, while the runtime, configuration, telemetry, HTTP, Problem Details, probes, and shutdown implementation required by `AC-CORE-001` is dependency-ordered through `T010`–`T017`. Requiring the Phase 1 behavior at `T000` makes the graph cyclic in practice and contradicts the declared output of `T000` and the Phase 1 exit.

## Decision

`T000` uses `AC-REPO-001`: the repository skeleton compiles with the pinned toolchain. `T017` remains the sole task that satisfies `AC-CORE-001`.

No implementation requirement is removed or deferred. This change only associates each criterion with the first task whose declared dependencies can satisfy it.

## Consequences

- Phase 0 can resolve dependencies before production runtime modules exist.
- The minimal service remains mandatory at the Phase 1 exit.
- Task validators must reject criteria assigned before their required implementation dependencies.

## Validation

- `cargo check --workspace --all-targets --locked` proves `AC-REPO-001` for `T000`.
- The bundle validator confirms both criterion IDs exist and task references resolve.
- `T017` and the minimal profile conformance suite prove `AC-CORE-001`.
