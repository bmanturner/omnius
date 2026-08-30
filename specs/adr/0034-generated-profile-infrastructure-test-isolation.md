---
spec_id: ADR-0034
title: Isolate Infrastructure Tests in Generated-Profile Verification
version: 0.1.0
status: accepted
last_verified: 2026-08-29
---

# Isolate Infrastructure Tests in Generated-Profile Verification

## Context

The inherited generated-profile gate renders the `minimal` and `authenticated-api` profiles into clean directories, runs their workspace tests and documentation tests, and executes each generated service's `profile-info` command. That gate verifies generator output and cross-module composition under `AC-GEN-001`.

The rendered workspaces also contain real PostgreSQL, Redis, NATS, and MinIO integration tests. Those tests require Testcontainers and belong to the real-infrastructure layer defined by OMNIUS-016. Running them inside the generated-profile gate conflates generator correctness with container-daemon availability and duplicates the dedicated workspace integration gate.

The existing nextest classification was incomplete. It named individual PostgreSQL test binaries, leaving other container-backed integration binaries such as PostgreSQL pool lifecycle and fresh migration tests outside the `postgres-integration` group. A container timeout could therefore fail the generated-profile gate after its deterministic unit and non-infrastructure integration contracts had passed.

## Decision

Keep the generated-profile gate's workspace-wide unit, non-infrastructure integration, documentation, and executable smoke coverage. Exclude only tests assigned to the explicit `postgres-integration`, `redis-integration`, `nats-integration`, and `minio-integration` nextest groups in that gate.

Classify every PostgreSQL integration-test binary in `omnius-postgres`, `omnius-migrations`, and `omnius-idempotency` with `kind(test)`, while retaining their library unit tests in the generated-profile gate. The generated nextest configuration assigns Testcontainers fixtures and selected PostgreSQL-backed capability crates to the same explicit infrastructure groups. Specific infrastructure tests continue to run unchanged in the repository's normal `cargo nextest run --workspace` and release/profile infrastructure gates.

This is test-layer isolation, not a retry, ignore annotation, mock substitution, or reduction to `--lib`. The generated-profile gate must continue to run every non-infrastructure integration test from both rendered workspaces.

Task `T126` owns this accepted-subsystem correction. `T151` depends on `T126`, so no LLM or MCP runtime work proceeds on an ungoverned generated-profile gate.

## Consequences

- `AC-GEN-001` remains deterministic and continues to cover clean-directory rendering, generated unit and non-infrastructure integration tests, documentation tests, and the generated executable contract.
- OMNIUS-016 real-infrastructure coverage remains mandatory in its dedicated gate and retains the original container-backed tests.
- New external-service integration tests must be assigned to an explicit nextest infrastructure group before they enter generated profiles.
- A missing or incorrect group assignment is a configuration defect; it must not be hidden by broad package, integration-target, or library-only filtering.
- `T126` is a completed prerequisite of `T151`; future extension tasks inherit the governed test-layer boundary.

## Validation

- The generated `minimal` and `authenticated-api` workspaces run all tests except the four named infrastructure groups.
- Static-delivery and other non-infrastructure integration tests remain present in the generated-profile nextest result.
- PostgreSQL pool, migrations, idempotency, authentication, and Testcontainers tests remain discoverable under `postgres-integration` in the repository configuration.
- The full generator and specification validator suites pass.
- The merged task graph records `T126` before `T151`.
