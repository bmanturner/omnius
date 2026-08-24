---
spec_id: ADR-0010
title: Separate Session Dependency Compatibility from Principal Conformance
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Separate Session Dependency Compatibility from Principal Conformance

## Context

The original task graph assigned `AC-AUTH-009`, “Session and JWT map to the same canonical Principal,” to `T002`. The declared output of `T002` is a Phase 0 dependency compatibility report for `axum-login`, `tower-sessions`, its stores, and SQLx. Canonical `Principal`, session authentication, and JWT adapters are dependency-ordered through `T040`, `T042`, and `T043`; they cannot exist during `T002` without bypassing the implementation graph.

## Decision

`T002` uses `AC-COMPAT-001`: session and store dependencies resolve on coherent stable lines. `T040` creates and tests the sole canonical `Principal` plus a reusable conformance fixture under `AC-AUTH-014`. After `T042` and `T043` provide the real session and JWT adapters, `T047` runs both adapters against that fixture to prove `AC-AUTH-009`.

No identity requirement is removed, weakened, or satisfied by a fixture-only substitute. Dependency compatibility, canonical identity invariants, and adapter conformance remain distinct proofs owned by the first tasks whose declared dependencies can produce them.

## Consequences

- Phase 0 blocks on incompatible session, SQLx, Axum, Tower, or rustls lines.
- `T040` can prove the canonical `Principal` identity, time, assurance, and scope invariants without pretending credential adapters already exist.
- `T047` owns the real cross-mechanism proof, so a fixture-only test cannot satisfy `AC-AUTH-009`.
- Task validation must distinguish dependency evidence, canonical identity invariants, and behavioral adapter conformance.

## Validation

- The Phase 0 compatibility member compiles both PostgreSQL and Redis session-store types with exact pins.
- `cargo tree` shows one `tower-sessions-core` line and one SQLx line.
- `T040` contract tests prove `AC-AUTH-014` with the sole canonical `Principal` and reusable conformance fixture.
- `T047` contract tests run the actual `T042` session and `T043` JWT adapters against that fixture to prove `AC-AUTH-009`.
