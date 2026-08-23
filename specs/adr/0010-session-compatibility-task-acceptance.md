---
spec_id: ADR-0010
title: Separate Session Dependency Compatibility from Principal Conformance
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Separate Session Dependency Compatibility from Principal Conformance

## Context

The original task graph assigned `AC-AUTH-009`, “Session and JWT map to the same canonical Principal,” to `T002`. The declared output of `T002` is a Phase 0 dependency compatibility report for `axum-login`, `tower-sessions`, its stores, and SQLx. Canonical `Principal`, session authentication, and JWT adapters are dependency-ordered through `T040`, `T042`, and `T043`; they cannot exist during `T002` without bypassing the implementation graph.

## Decision

`T002` uses `AC-COMPAT-001`: session and store dependencies resolve on coherent stable lines. `T040` retains `AC-AUTH-009`, and the authenticated profile later proves cross-mechanism principal conformance.

No identity requirement is removed or weakened. The new criterion verifies only the compatibility output that Phase 0 can produce.

## Consequences

- Phase 0 blocks on incompatible session, SQLx, Axum, Tower, or rustls lines.
- Identity conformance remains an implementation and contract-test requirement in Phase 4.
- Task validation must distinguish dependency evidence from behavioral conformance.

## Validation

- The Phase 0 compatibility member compiles both PostgreSQL and Redis session-store types with exact pins.
- `cargo tree` shows one `tower-sessions-core` line and one SQLx line.
- Phase 4 contract tests prove `AC-AUTH-009` using session and JWT credentials.
