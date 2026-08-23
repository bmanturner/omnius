---
spec_id: RSK-HANDOFF
title: Autonomous Agent Handoff
version: 0.1.0
status: informative
last_verified: 2026-08-23
---

# Autonomous Agent Handoff


## Objective

Implement the modular Rust service kit exactly as specified in this bundle. The first deliverable is the service-kit repository and conformance/reference applications, not a product-specific backend.

## Start here

1. Read `AGENTS.md`.
2. Read ADR-0001 through ADR-0009.
3. Run the Phase 0 tasks in `machine/tasks.yaml`.
4. Resolve and record the exact dependency graph from `machine/dependency-baseline.toml`.
5. Do not begin the generator until two independently shaped reference services have proven the module boundaries.

## Inputs an agent should load

Minimum context:

- `README.md`
- `AGENTS.md`
- `00-scope-and-principles.md`
- `01-system-architecture.md`
- `02-module-system-and-generator.md`
- `20-implementation-roadmap.md`
- `21-crate-selection-matrix.md`
- `23-agent-task-graph.md`
- `machine/module-catalog.yaml`
- `machine/profiles.yaml`
- `machine/acceptance-criteria.yaml`
- `machine/tasks.yaml`

Load the relevant numbered spec and ADR for each task. `COMPLETE_SPEC.md` provides a single-file alternative when the agent cannot index directories.

## Phase 0 required output

Before writing production modules, commit:

- A scratch compatibility workspace or reproducible report.
- Exact Rust/Cargo and direct dependency versions.
- `cargo tree -d` output with foundational duplicates classified.
- Selected rustls crypto provider and root strategy.
- Compatible `axum-login`/`tower-sessions`/session-store versions.
- SQLx 0.8.6 feature set and offline metadata procedure.
- Apalis Redis spike results.
- PGMQ spike results if that provider remains supported.
- OpenTelemetry family versions and export/flush spike.
- A dependency-admission report for any proposed addition/substitution.
- An updated ADR if the baseline cannot be implemented coherently.

## Task execution

`machine/tasks.yaml` is the canonical task graph. Each task has dependencies and acceptance criteria. The agent should:

1. Select an unblocked task.
2. Create tests for its acceptance criteria.
3. Implement the smallest complete vertical slice.
4. Run task-level commands.
5. Update docs and generated artifacts.
6. Record evidence.
7. Commit with the task ID.
8. Run phase/profile verification before advancing.

## Prohibited shortcuts

- Do not replace real infrastructure integration tests with mocks.
- Do not write a session store, JWT verifier, OAuth/OIDC flow, password hash, WebAuthn parser, durable queue, object-store client, webhook delivery service, or observability protocol.
- Do not silently raise SQLx to 0.9.
- Do not use a prerelease provider in default profiles.
- Do not put every optional dependency in one global application state.
- Do not encode major architecture choices as mutually exclusive Cargo features.
- Do not grant authorization in HTTP middleware alone.
- Do not publish events before the state transaction commits.
- Do not accept unbounded queues, retries, bodies, frames, pagination, or concurrency.
- Do not freeze the generator interface before two reference applications exist.

## Required final evidence

The implementation handoff is complete when the agent supplies:

- Repository URL/commit.
- Generated output for all nine profiles.
- Dependency and license reports.
- Test, fuzz-smoke, and profile-conformance reports.
- OpenAPI and schema artifacts.
- Migration-upgrade report.
- Security and threat-model review.
- Performance baseline.
- Container/SBOM/provenance artifacts.
- Recommendation traceability with every `REC-*` marked verified.
- Risk register with remaining accepted risks and owners.
