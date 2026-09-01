---
title: Generator and profile development
description: Development workflow for Omnius service lifecycle generation, ownership-safe rendering, profile catalogs, and matrix evidence.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - contributor
  - maintainer
  - release-engineer
topics:
  - generator
  - profiles
  - service-lifecycle
capabilities:
  - generator-module-lifecycle
  - generator
  - service-management
source:
  - crates/generator/src/render.rs
  - crates/generator/src/catalog.rs
  - xtask/src/service.rs
  - xtask/src/profiles.rs
  - specs/machine/profiles.yaml
evidence:
  - crates/generator/tests/module_management.rs
  - crates/generator/tests/base_service.rs
  - .github/workflows/ci.yml
last_verified: 2026-08-30
---

# Generator and profile development

The generator turns declarative module and profile catalogs into managed service trees. Its job is deterministic composition and ownership-safe lifecycle management, not runtime assembly. A generated profile can still lack an application that mounts its routes or starts its workers.

Read [Modules, profiles, and composition](../concepts/modules-profiles-and-composition.md) for the model, [Profiles](../reference/profiles.md) for the inventory, and the [Availability and exposure matrix](../reference/availability-and-exposure-matrix.md) before changing availability claims.

## Sources of truth

| Concern | Source |
| --- | --- |
| Base modules | `specs/machine/module-catalog.yaml` |
| Base profiles | `specs/machine/profiles.yaml` |
| Web modules and profiles | `specs/machine/extensions/web-application-suite/` |
| AI/MCP modules and profiles | `specs/machine/extensions/llm-mcp-suite/` |
| Template | `templates/base-service/` |
| Catalog parsing and validation | `crates/generator/src/catalog.rs`, `crates/generator/src/modules.rs` |
| Rendering and ownership | `crates/generator/src/render.rs` |
| Lifecycle CLI | `xtask/src/service.rs` |
| Profile verification and matrix | `xtask/src/profiles.rs` |

Catalogs have explicit schema and bundle versions. Definitions are strict: inheritance, dependencies, conflicts, and provider slots are validated rather than repaired implicitly.

## Current profile families

The checked-in catalogs define these evidence families:

- Base: `minimal`, `api`, `authenticated-api`, `oauth-provider`, `saas`, `saas-pgmq`, `realtime`, `realtime-durable`, `worker`, `full-reference`.
- Web: `web-sdk-only`, `web`, `realtime-web`, `saas-web`, `full-reference-web`.
- AI: `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`.
- MCP: `mcp-local`, `mcp-http`, `mcp-enterprise`.
- AI+MCP (`ai_mcp` in JSON): `ai-platform`, `full-reference-ai`.

This inventory is catalog availability only. Family is derived from resolved `llm-*` and `mcp-*` modules; consult the canonical reference matrix before describing implementation or exposure.

## Lifecycle command contract

The service-management command family in `cargo xtask` implements only `add`, `remove`, `upgrade`, `doctor`, and `diff`. The lifecycle commands accept `--project`; mutation commands support `--dry-run`; machine-readable output uses `--json` or `--machine` where implemented. The machine envelope is schema version 1.

Do not document `service new` or `profile set`: those subcommands are not implemented by `xtask/src/main.rs`. The existence of `templates/base-service/` does not create a public CLI command.

## Ownership-safe rendering

Every generated path must have one ownership mode:

- kit-owned files are protected from overwriting user modifications;
- application-owned files remain available for application changes;
- derived files are reproducible outputs;
- managed regions delimit generated content inside preserved files.

The renderer rejects a non-empty unmanaged destination. On managed services it refuses changed or missing kit-owned files, preserves application-owned files and unknown extra files, and uses backups for applicable managed mutations. Removal behavior follows catalog policy; released migrations and data are not casually deleted.

Render logic itself does not run formatting or validation. Profile verification supplies those checks where the profile declares them.

## Change a module catalog

1. Edit only the catalog that owns the module.
2. Keep the declared catalog schema and bundle version consistent with the parser.
3. Make dependencies, conflicts, and provider slots explicit.
4. Define file ownership and managed regions before adding templates.
5. Add lifecycle tests for dependency closure, conflict behavior, provider exclusivity, removal, backups, regions, and repeated renders.
6. Update profiles only when their documented purpose requires the module.
7. Verify that profile inheritance does not create hidden conflicts.

See [Creating a module](./creating-a-module.md) for the full module workflow.

## Change a profile

A profile definition has an ID, description, module list, and optional parent. When changing it:

1. Keep the profile's purpose narrower than its implementation inventory.
2. Prefer inheritance only when the derived profile genuinely preserves the parent's contract.
3. Ensure every module dependency is present after inheritance.
4. Ensure conflicts and provider slots resolve to one valid selection.
5. Regenerate matrix evidence rather than assuming a catalog-valid profile renders.
6. Update documentation classification only from the canonical coverage evidence, not from the profile file alone.

## Validate catalogs

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain is installed. Catalog verification requires no production credentials.

```bash
cargo xtask profiles verify
```

**Expected result:** base and extension catalogs satisfy their strict schema, version, inheritance, dependency, conflict, and provider-slot rules.

**Failure path:** fix the owning YAML or parser contract. Do not duplicate a module, drop a conflict, or choose an arbitrary provider merely to satisfy validation.

## Test lifecycle behavior

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain is installed; repository fixtures must be writable in Cargo's test output directories.

```bash
cargo test -p omnius-generator --test module_management
cargo test -p omnius-generator --test base_service
```

**Expected result:** lifecycle composition and base-service rendering satisfy their checked-in contracts, including repeated-render and ownership behavior covered by the suites.

**Failure path:** isolate whether the defect is catalog validation, render ownership, managed state, upgrade/removal policy, or fixture expectation. Regenerate only output owned by the generator; preserve application-owned fixture changes.

## Preview a managed change

Run from the repository root.

**Prerequisites:** set `PROJECT_PATH` to an existing managed service with `.omnius/service.toml`, `MODULE_ID` to an exact catalog ID, and `TARGET_VERSION` to an exact version accepted by the current catalog. Use a disposable or backed-up development project and no production secrets.

```bash
cargo xtask service add "$MODULE_ID" --dry-run --project "$PROJECT_PATH"
cargo xtask service upgrade --to "$TARGET_VERSION" --dry-run --project "$PROJECT_PATH"
cargo xtask service doctor --project "$PROJECT_PATH" --json
cargo xtask service diff --project "$PROJECT_PATH"
```

**Expected result:** add and upgrade print plans without mutation, doctor emits structured state diagnostics, and diff shows managed changes.

**Failure path:** stop on unmanaged destinations, modified kit-owned files, invalid metadata, dependency/conflict failures, or an unavailable target version. Do not apply a mutation until the dry-run is understood and the ownership conflict is resolved.

## Generate profile matrix evidence

Run from the repository root.

**Prerequisites:** pinned Rust and Node.js toolchains plus the pinned package-manager version; frozen JavaScript dependencies; and disposable services required by each row's `resolved_services`. Use synthetic configuration only for test inputs. If application contribution files are installed, the report must label them synthetic and classification-ineligible. `--automated-evidence-only` deliberately does not satisfy manual release policy.

```bash
cargo xtask profiles generate-verify --jobs 1 --automated-evidence-only
```

For configuration-only matrix inspection:

```bash
cargo xtask profiles generate-verify --matrix-only
```

**Expected result:** the full command performs fresh and repeated renders, checks byte identity and metadata, runs doctor/diff and profile-specific checks, and writes exactly 24 rows to `target/profile-matrix/report.json` with schema version 5. Rows record the five profile kinds; resolved modules/providers/services; untouched composition root and executable command; concrete registrar-backed and application-required modules; fixture origin; route/task/health and operation/capability/transport registrations; migration range; positive/negative workflows; readiness/outage/shutdown observations; retained artifacts; and `selected`, `generated`, `compiled`, or `assembled`. The nine required composition/process/protocol IDs are `composition-manifest`, `migration-policy`, `startup-readiness`, `registered-routes-tasks-health`, `representative-workflow`, `negative-workflow`, `dependency-outage`, `bounded-shutdown`, and `runtime-contract-parity`.

**Failure path:** a required skip is a failure. Missing application contributions, unavailable disposable dependencies, `llm-embeddings`, synthetic fixtures, enterprise MCP/Apps/durable-backplane gaps, full-reference product ports, or operation/capability/transport drift keep the row unassembled. Use the row to identify the owning catalog, template, generated artifact, or service prerequisite; never replace a missing dependency with an in-memory fallback.

## Compatibility expectations

Generator changes must preserve or intentionally version:

- `.omnius/service.toml` state interpretation;
- machine-output schema 1;
- catalog and bundle schema compatibility;
- ownership and managed-region semantics;
- add/remove/upgrade idempotence and backup behavior;
- released migration and data retention policy;
- deterministic output across repeated renders;
- contract and SDK generation invoked by affected profiles.

A breaking lifecycle or state change requires an explicit migration path and release-gate review. See [Compatibility and release gates](./compatibility-and-release-gates.md).

## Evidence boundary

Generator tests and matrix reports prove only the phases and exact roots they execute. The untouched generated root is default classification authority. A library/router test, generated contract, deterministic provider double, or synthetic application fixture never proves default assembly, deployment, promotion, or public exposure.