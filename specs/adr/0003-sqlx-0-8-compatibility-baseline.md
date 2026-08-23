---
spec_id: ADR-0003
title: Pin SQLx 0.8.6 as the Initial Compatibility Baseline
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Pin SQLx 0.8.6 as the Initial Compatibility Baseline


## Context

SQLx 0.9.0 is current at the bundle verification date. Important integration crates, notably the selected SQLx-backed session store, still target SQLx 0.8. Selecting 0.9 solely because it is newest would create duplicate SQLx lines, incompatible pool/transaction types, or pressure to write a custom session store.

## Decision

The first supported persistence line is SQLx 0.8.6.

- PostgreSQL is the primary database.
- The lockfile pins the reviewed patch.
- SQLx checked queries and offline metadata are required.
- Adapter crates must resolve onto the same SQLx 0.8 line where their types cross boundaries.
- SQLx 0.9 remains an upgrade candidate, not a default.

## Upgrade gate

The upgrade ADR may be accepted only when:

1. Session-store, job/provider, and test integrations have stable compatible releases.
2. The resolved graph does not introduce duplicate foundational SQLx versions that cross APIs.
3. Empty-to-head and supported-version-to-head migration tests pass.
4. Compile-time query metadata is regenerated.
5. Pool, transaction, TLS, and feature behavior is reviewed.
6. All named profiles and upgrade fixtures pass.

## Consequences

- The baseline values ecosystem coherence over version novelty.
- Security patches on the supported line remain mandatory.
- Modules must not independently raise SQLx.
- SQLx 0.9 experiments are isolated to a non-default compatibility branch/profile.

## Validation

Phase 0 records `cargo tree -d`, feature resolution, and adapter compatibility. CI fails if a direct dependency changes the SQLx baseline without an accepted ADR.
