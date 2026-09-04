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
  - crates/generator/src/cargo_service.rs
  - crates/generator/src/render.rs
  - crates/generator/src/catalog.rs
  - crates/generator/src/manager.rs
  - crates/generator/src/application_templates.rs
  - crates/service-kit/src/catalog.rs
  - xtask/src/profiles.rs
  - specs/machine/profiles.yaml
evidence:
  - crates/generator/tests/module_management.rs
  - crates/generator/tests/base_service.rs
  - .github/workflows/ci.yml
last_verified: 2026-09-03
---

# Generator and profile development

The generator turns declarative module/profile catalogs and thin templates into independent application workspaces. Its job is deterministic composition, immutable dependency binding, and ownership-safe lifecycle management, not runtime assembly. Framework Rust, migrations, lifecycle source, specifications, and templates stay in Omnius; a generated profile can still lack application contributions that mount routes or start workers.

Read [Modules, profiles, and composition](../concepts/modules-profiles-and-composition.md) for the model, [Profiles](../reference/profiles.md) for the inventory, and the [Availability and exposure matrix](../reference/availability-and-exposure-matrix.md) before changing availability claims.

## Sources of truth

| Concern | Source |
| --- | --- |
| Base modules | `specs/machine/module-catalog.yaml` |
| Base profiles | `specs/machine/profiles.yaml` |
| Web modules and profiles | `specs/machine/extensions/web-application-suite/` |
| AI/MCP modules and profiles | `specs/machine/extensions/llm-mcp-suite/` |
| Thin application template | `templates/base-service/` |
| Catalog parsing and validation | `crates/generator/src/catalog.rs`, `crates/generator/src/modules.rs` |
| Service-kit feature/dependency regions and canonical contracts | `specs/machine/module-catalog.yaml`, `crates/service-kit/src/catalog.rs` |
| Rendering, ownership, sealed plans, and recovery | `crates/generator/src/render.rs`, `crates/generator/src/manager.rs`, `crates/generator/src/journal.rs` |
| Installed lifecycle CLI | `crates/generator/src/cargo_service.rs`, `crates/generator/src/bin/cargo-service.rs` |
| Repository profile verification and matrix | `xtask/src/profiles.rs` |

Catalogs have explicit schema and bundle versions. Definitions are strict: inheritance, dependencies, conflicts, and provider slots are validated rather than repaired implicitly.

## Current profile families

The checked-in catalogs define these evidence families:

- Base: `minimal`, `api`, `authenticated-api`, `oauth-provider`, `saas`, `saas-pgmq`, `realtime`, `realtime-durable`, `worker`, `full-reference`.
- Web: `web-sdk-only`, `web`, `realtime-web`, `saas-web`, `full-reference-web`.
- AI: `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`.
- MCP: `mcp-http`, `mcp-enterprise`.
- AI+MCP (`ai_mcp` in JSON): `ai-platform`, `full-reference-ai`.

This is 23 bundled profiles in total. The AI/MCP extension contributes eight profiles: four AI, exactly two MCP (`mcp-http`, `mcp-enterprise`), and two combined AI+MCP profiles. This inventory is catalog availability only. Family is derived from resolved `llm-*` and `mcp-*` modules; consult the canonical reference matrix before describing implementation or exposure.

## Lifecycle command contract

`cargo-service` is a separately Git-installable Cargo subcommand and the only
public generated-project lifecycle. It implements:

```text
cargo service new <NAME> --profile <PROFILE> [--path <PATH>] [--offline] [--json]
cargo service add <MODULE> [--project <PATH>] [--dry-run] [--offline] [--json]
cargo service remove <MODULE> [--project <PATH>] [--dry-run] [--offline] [--json]
cargo service profile set <PROFILE> [--project <PATH>] [--dry-run] [--offline] [--json]
cargo service update [--project <PATH>] [--dry-run] [--offline] [--json]
cargo service doctor [--project <PATH>] [--json]
cargo service diff [--project <PATH>] [--json]
```

`new` defaults to `./<NAME>` and requires a nonexistent destination; other
commands default to `.`. The target release is always the clean immutable
identity of the executing CLI. `update` is the only identity transition and
`profile set` replaces the exact runtime closure. `doctor` and `diff` are
read-only. `--offline` means canonical Cargo-cache-only resolution. There is no
project-owned service xtask, version-only upgrade target, runtime
repository/revision flag, or `--machine` alias.

## Ownership-safe thin rendering

A fresh service has one Rust member, `apps/service`, and one managed
`service-kit` alias selecting `omnius-service-kit` at the exact package version,
canonical HTTPS Git URL, and full immutable revision. Application-added
workspace members and ordinary dependencies are preserved.

Every generated path has one explicit ownership mode:

- kit-owned and derived files carry approved SHA-256 values;
- application-owned files are never overwritten or deleted;
- managed regions delimit generated content inside preserved files;
- `Cargo.lock` is a shared `dependency-lock` validated semantically against the
  manifest and package graph.

Extension application templates are created once only when a regular file is
missing, immediately become application-owned, and survive remove/re-add and
profile changes. Unsafe paths, symlinks, framework source/migrations, and
tooling are forbidden in that inventory.

`new` resolves in a sibling stage and publishes by one rename. Existing-project
mutations refuse changed generated hashes/regions, seal all operations and lock
bytes before apply, and use a durable journal with stale-input checks and
crash recovery. Released application migrations and data are not deleted.

## Derived runtime artifacts

`config/reference.toml`, `ops/compose.yaml`, `ops/Dockerfile`,
`docs/module-catalog.md`, and the React and testing SDK barrels selected by web
modules are classified deterministic outputs of the resolved selection.
Initial render and `add`, `remove`, `profile set`, `update`, `doctor`, and
`diff` use the same renderers. The barrels therefore export exactly the
installed adapters; do not hand-edit these outputs or introduce a second
overlay, topology, or export convention.

Catalog configuration fields are closed and typed. Each framework field
declares its dotted path, TOML type, required flag, and either a safe
`reference_default` or an exact hierarchical environment binding. Validation
rejects undeclared/secret defaults, missing required bindings/defaults, and
selected-module conflicts. `${...}` in TOML is never an environment reference.

The generated process loads `config/base.toml`, selected
`config/reference.toml`, any development-only local file, process environment,
and explicit overrides in order. Persisted profiles leave only
`postgres.url` out of the framework overlay; its exact key is
`OMNIUS__POSTGRES__URL`. Idempotency has no pagination or cursor-signing-secret
configuration.

## Runtime dependencies and application contracts

Runtime dependencies use a closed ID and descriptor registry, not free-form service names. A `compose` descriptor must provide a digest-pinned image, stable service and volume, health check, exact development bindings, and optional migration ownership. An `external` descriptor provides exact required endpoint/credential environment bindings and no container. Generated Compose renders those external bindings as `${NAME:?message}` YAML expressions so configuration fails closed before startup.

Application requirements are closed canonical enum values owned by root
`omnius-service-kit`. Generated composition supplies only the profile ID,
ordered runtime module IDs, providers, and runtime-disabled modules; it does
not copy contracts or registrar source. Each requirement maps to one named
runtime family with narrow `Arc<dyn Trait + Send + Sync>` ports. Routers, task
specs, health checks, and contract fragments are outputs after the application
supplies those ports. Missing contributions and incomplete grouped runtimes
fail closed. `ApplicationExtension` is the sole application router/OpenAPI
source, while OpenAPI and idempotency remain independent.

## Change a module catalog

1. Edit only the catalog that owns the module.
2. Keep the declared catalog schema and release/bundle version consistent.
3. Make dependencies, conflicts, provider slots, and runtime/tooling kind explicit.
4. Maintain `composition.crates`; specification generation owns the
   service-kit dependency/feature region and canonical catalog source.
5. Define generated ownership and create-once application templates before
   adding files.
6. Add lifecycle tests for dependency closure, conflicts, provider
   exclusivity, removal, semantic lock scope, hashes/regions, repeated plans,
   and journal recovery.
7. Update profiles only when their runtime purpose requires the module;
   `kind: tooling` is forbidden in lifecycle selections.
8. Verify that profile inheritance does not create hidden conflicts.

See [Creating a module](./creating-a-module.md) for the full module workflow.

## Change a profile

A profile definition has an ID, description, module list, and optional parent. When changing it:

1. Keep the profile's purpose narrower than its implementation inventory.
2. Prefer inheritance only when the derived profile genuinely preserves the parent's contract.
3. Select runtime modules only; testing, generation, evaluation, preview, and
   conformance tooling belongs outside profile state.
4. Ensure every module dependency is present after inheritance.
5. Ensure conflicts and provider slots resolve to one valid selection.
6. Preserve create-once application templates independently from runtime
   selection/removal.
7. Regenerate matrix evidence rather than assuming a catalog-valid profile renders.
8. Update documentation classification only from canonical coverage evidence, not from the profile file alone.

## Validate catalogs

Run from the repository root.

The checked-in `cargo xtask` alias expands to
`cargo run --locked --package xtask --`.

**Prerequisites:** the pinned Rust toolchain is installed. Catalog verification requires no production credentials.

```bash
cargo xtask profiles verify
```

**Expected result:** base and extension catalogs satisfy strict schema,
release/bundle version, runtime-only selection, inheritance, dependency,
conflict, and provider-slot rules. Specification check mode also covers the
generated `crates/service-kit/Cargo.toml` region and `src/catalog.rs`.

**Failure path:** fix the owning YAML, generated service-kit region, or parser
contract. Do not duplicate a module, select tooling at runtime, drop a
conflict, or choose an arbitrary provider merely to satisfy validation.

## Test lifecycle behavior

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain is installed; repository fixtures must be writable in Cargo's test output directories.

```bash
cargo test --locked -p omnius-generator --test module_management
cargo test --locked -p omnius-generator --test base_service
```

**Expected result:** lifecycle composition and thin base-service rendering
satisfy state, release identity, ownership, semantic lock/graph, one-shot
resolution, and recovery contracts.

**Failure path:** isolate catalog validation, rendering, provenance, state,
lock scope, journal recovery, update/removal policy, or fixture expectation.
Regenerate only generator-owned output; preserve application-owned changes.

## Preview a managed change

Use an installed clean immutable `cargo-service` release matching the project.
Set `PROJECT_PATH` to a schema-2 managed service and `MODULE_ID` to an exact
runtime catalog ID.

```bash
cargo service add "$MODULE_ID" --dry-run --project "$PROJECT_PATH"
cargo service profile set minimal --dry-run --project "$PROJECT_PATH"
cargo service update --dry-run --project "$PROJECT_PATH"
cargo service doctor --project "$PROJECT_PATH" --json
cargo service diff --project "$PROJECT_PATH"
```

**Expected result:** mutations resolve and seal exact file/lock/graph plans
without applying, doctor emits one structured document, and diff reports
managed changes. Add `--offline` only for canonical cache-only resolution.

**Failure path:** stop on dirty/unbound tooling, identity or provenance
mismatch, source override/vendor configuration, ownership/hash drift,
dependency conflicts, tooling selection, stale inputs, or out-of-scope lock
changes. Do not apply until the sealed dry-run is understood.

## Generate profile matrix evidence

Run from the repository root.

**Prerequisites:** pinned Rust and Node.js toolchains plus the pinned package-manager version; frozen JavaScript dependencies; a remotely reachable full commit SHA containing the exact generator/framework source under test; and disposable services required by each row's `resolved_services`. Use synthetic configuration only for test inputs. If synthetic typed application runtime files are installed, the report must label them synthetic and classification-ineligible. `--automated-evidence-only` deliberately does not satisfy manual release policy.

```bash
REV=<full-lowercase-40-hex-revision>
OMNIUS_RELEASE_REVISION="$REV" cargo xtask profiles generate-verify --jobs 1 --automated-evidence-only
```

For configuration-only matrix inspection, bind the same reachable revision:

```bash
OMNIUS_RELEASE_REVISION="$REV" cargo xtask profiles generate-verify --matrix-only
```

**Expected result:** the full command performs fresh and repeated renders, checks byte identity and metadata, runs doctor/diff and profile-specific checks, and writes exactly 23 rows to `target/profile-matrix/report.json` with schema version 5. Rows record the five profile kinds; resolved modules/providers/services; untouched composition root and executable command; concrete registrar-backed and application-required modules; fixture origin; route/task/health and operation/capability/transport registrations; migration range; positive/negative workflows; readiness/outage/shutdown observations; retained artifacts; and `selected`, `generated`, `compiled`, or `assembled`. The nine required composition/process/protocol IDs are `composition-manifest`, `migration-policy`, `startup-readiness`, `registered-routes-tasks-health`, `representative-workflow`, `negative-workflow`, `dependency-outage`, `bounded-shutdown`, and `runtime-contract-parity`.

The create-once contract seed in a fresh consumer remains application-owned and
identifies `generated-application` until that application emits its own named
contract set. The matrix validates the seed's schemas and hashes without
rewriting its profile or module inventory; runtime registration parity is
verified separately from the generated service process.

**Failure path:** a required skip is a failure. Missing typed application requirements, unavailable disposable dependencies, `llm-embeddings`, synthetic fixtures, enterprise MCP/Apps/durable-backplane gaps, full-reference product ports, or operation/capability/transport drift keep the row unassembled. Use the row to identify the owning catalog, template, generated artifact, or service prerequisite; never replace a missing dependency with an in-memory fallback.

## Compatibility expectations

Generator changes must preserve or intentionally migrate:

- strict schema-2 `.omnius/service.toml` and release identity;
- schema-version-1 JSON command envelopes;
- catalog and bundle compatibility;
- ownership hashes, managed regions, create-once application files, and
  dependency-lock semantics;
- add/remove/profile-set/update idempotence and bounded graph diffs;
- one resolution per sealed plan and durable crash recovery;
- application migration/data retention and one combined SQLx history;
- deterministic output across repeated renders;
- contract and SDK application templates without runtime tooling selection.

A breaking lifecycle or state change requires an explicit migration path and release-gate review. See [Compatibility and release gates](./compatibility-and-release-gates.md).

## Evidence boundary

Generator tests and matrix reports prove only the phases and exact roots they execute. The untouched generated root is default classification authority. A library/router test, generated contract, deterministic provider double, or synthetic application fixture never proves default assembly, deployment, promotion, or public exposure.