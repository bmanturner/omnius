---
title: Generator CLI
description: Exact executable commands for profile verification, contract generation, and module lifecycle management.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - platform-developer
  - service-developer
topics:
  - generator
  - command-line-interface
  - profiles
capabilities: []
source:
  - xtask/src/main.rs
  - xtask/src/profiles.rs
  - xtask/src/service.rs
  - crates/generator/src/lib.rs
evidence:
  - crates/generator/tests/module_management.rs
last_verified: 2026-08-30
---

# Generator CLI

Omnius exposes repository tooling through `cargo xtask`. There is no executable `generator` command tree under `cargo xtask`. The specification also names `cargo service new` and `profile set`, but the executable dispatcher does not implement them. Use only the commands below.

Profile selection and generated output are build-time evidence. They do not prove that a concrete application assembles or exposes the selected modules; see [Profiles](profiles.md) and [Availability and exposure](availability-and-exposure-matrix.md).

## Common command contract

Run every command from the repository root with the Rust toolchain and workspace dependencies available. A successful exit means the requested repository operation completed; it is not a release result or runtime availability claim. Invalid commands, unknown options, malformed values, and failed checks return a nonzero exit with an error on stderr.

The commands on this page are reported from source and were not run as part of this documentation pass.

## Specification and profile commands

| Command | Purpose | Expected result | Failure path |
|---|---|---|---|
| `cargo xtask specs generate` | Regenerate machine specification artifacts. | The specification generation operation completes. | Generation errors or an unsupported argument return nonzero. |
| `cargo xtask specs verify` | Check generated specification artifacts for drift. | Checked-in and generated specification state agree. | Drift or validation failure returns nonzero. |
| `cargo xtask specs extensions record` | Record extension composition artifacts. | Extension records are regenerated. | Invalid extension inputs or write failures return nonzero. |
| `cargo xtask profiles verify` | Compose the base, web, AI, MCP, and combined overlays and validate the module and profile catalogs with the generator parsers. | All composed catalogs parse and satisfy catalog validation. | Extra arguments, parse errors, invalid inheritance, missing requirements, conflicts, or provider-slot collisions return nonzero. |
| `cargo xtask profiles generate-verify [--jobs 1] [--report PATH] [--automated-evidence-only] [--matrix-only]` | Generate all 24 profiles sequentially and evaluate the selected matrix policy. | One schema-version-5 row is written per profile; each completed profile retains only its binary and report artifacts; success requires every required check and selected policy. | Invalid options, any `--jobs` value other than `1`, a required skipped/failed check, unresolved process evidence, or a failed policy returns nonzero. `--matrix-only` is also rejected in CI. |

### `profiles generate-verify` options

| Option | Exact behavior |
|---|---|
| `--jobs 1` | Explicitly selects the only supported worker count. Profiles always build sequentially; after each row records evidence, its Cargo cache is removed while the generated binary is retained. |
| `--report PATH` | Writes the report to `PATH`. A relative path is resolved from the repository root. The default is `target/profile-matrix/report.json`. |
| `--automated-evidence-only` | Selects the automated-evidence policy. A profile must reach `automated_ready`. |
| `--matrix-only` | Produces a report-only local diagnostic. It is rejected when `CI` or `GITHUB_ACTIONS` is `1` or `true`, case-insensitively. |

`--automated-evidence-only` and `--matrix-only` are mutually exclusive. With neither option, the enforced policy applies. These definitions do not assert that any matrix run passed or that a report was retained.

Schema 5 distinguishes selected modules from concrete registrar-backed `assembled_modules`, records application requirements and synthetic-fixture origin, and retains route/task/health plus operation/capability/transport evidence. The required behavioral IDs are documented in the [verification plan](../verification-plan.md#profile-evidence-contract-and-follow-up-examples-handoff). Synthetic fixtures are classification-ineligible.

## Contract commands

| Command | Purpose | Expected result | Failure path |
|---|---|---|---|
| `cargo xtask contracts generate` | Generate OpenAPI, conditionally generate or remove AsyncAPI, and rewrite the checked-in contract set. | The canonical contract leaves and manifest are written. | Generation, schema, canonicalization, or write failures return nonzero. |
| `cargo xtask contracts check` | Verify source-generated OpenAPI and conditional AsyncAPI, validate the committed contract set, regenerate it, and compare canonical bytes. | No checked-in contract drift is found. | Invalid artifacts or byte drift return nonzero. |
| `cargo xtask contracts diff --against PATH` | Compare the current contract set with a directory, artifact directory, manifest, or constrained Git revision. | Findings are printed; the command exits successfully when no breaking finding exists. | Invalid or escaping input and breaking findings return nonzero. |

See [Contracts and code generation](contracts-and-code-generation.md) for artifact scope and compatibility classes.

## Module lifecycle commands

All module lifecycle commands accept an optional `--project PATH`; otherwise the current directory is the project. `--json` and `--machine` are aliases for the same schema-version-1 machine output. Do not combine incompatible or repeated options.

| Command | Additional operands | Result semantics |
|---|---|---|
| `cargo xtask service add MODULE [--project PATH] [--dry-run] [--json\|--machine]` | One module ID is required. | Resolves the addition and applies it unless `--dry-run` is present. |
| `cargo xtask service remove MODULE [--project PATH] [--dry-run] [--json\|--machine]` | One module ID is required. | Resolves the removal and applies it unless `--dry-run` is present. |
| `cargo xtask service upgrade --to VERSION [--project PATH] [--dry-run] [--json\|--machine]` | Exactly one target version is required. | Plans and applies the managed upgrade unless `--dry-run` is present. |
| `cargo xtask service doctor [--project PATH] [--json\|--machine]` | No module or version operand. | Reports `clean` or `unhealthy`; `unhealthy` returns nonzero. |
| `cargo xtask service diff [--project PATH] [--json\|--machine]` | No module or version operand. | Reports `clean` or `changes`; both are successful command results. |

Machine failures use the code `service-command-failed`. Unknown options, missing operands, extra operands, and invalid combinations fail before a lifecycle operation is applied.

Resolution, planning, managed-state validation, apply, and I/O failures return nonzero. `service doctor` also returns nonzero for an `unhealthy` result; `service diff` deliberately returns success for both `clean` and `changes`.

## Catalog and runtime boundary

The `omnius-generator` library embeds the base, web, and AI/MCP catalog YAML at compile time. Profile resolution validates declared dependency closure, conflicts, and provider-slot uniqueness; it does not insert missing dependencies or assemble a listener, worker, route, database, provider, or browser application. The checked-in minimal service also does not exactly match the catalog's `minimal` module selection. Treat generated projects as artifacts to inspect and exercise, not as availability proof.
