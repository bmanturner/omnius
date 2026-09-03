---
title: Creating a module
description: Contributor workflow for defining, implementing, composing, testing, and reviewing a new Omnius module.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - contributor
  - maintainer
  - module-owner
topics:
  - modules
  - composition
  - generator
capabilities: []
source:
  - specs/machine/module-catalog.yaml
  - crates/generator/src/modules.rs
  - Cargo.toml
evidence:
  - crates/generator/tests/module_management.rs
  - crates/generator/src/manager.rs
  - crates/service-kit/src/catalog.rs
last_verified: 2026-09-03
---

# Creating a module

The canonical definition of a module is in [Modules, profiles, and composition](../concepts/modules-profiles-and-composition.md#module). When creating one, explicitly specify its ownership, dependencies, conflicts, configuration, operational surfaces, and removal behavior. The current inventory lives in [Modules and capabilities](../reference/modules-and-capabilities.md).

Adding a crate is not the same as adding a module. Adding a module is not the same as selecting it in a profile, and selection is not proof that a runtime assembles or publicly exposes it.

## Before implementation

Establish the module boundary before writing code:

1. Identify one coherent responsibility and an owner.
2. Reuse an existing module when the change only extends its implementation.
3. Determine required modules, incompatibilities, and any mutually exclusive provider slot.
4. State persistence and removal behavior before introducing stored state.
5. Identify configuration and secret fields without committing secret values.
6. Record routes, background tasks, health checks, metrics, fixtures, and acceptance evidence only when the implementation actually owns them.
7. Classify managed/derived artifacts and any create-once application templates.
8. Check [Compatibility and release gates](./compatibility-and-release-gates.md) for contract and migration consequences.

## Define the catalog entry

The base catalog is `specs/machine/module-catalog.yaml`. Suite extensions use their own module catalogs under `specs/machine/extensions/`. Match the catalog that owns the capability; do not duplicate the same module into a second catalog.

`crates/generator/src/modules.rs` defines the strict module schema. A definition includes:

- identity: `id`, `title`, `version`, `owner`, `spec`, and `kind`;
- selection: `requires`, `conflicts_with`, and optional `provider_slot`;
- lifecycle: `criticality`, `runtime_toggle`, persistence, and removal behavior;
- implementation: closed runtime dependency IDs, primary crates, acceptance evidence, fixtures, and typed configuration;
- composition: root service-kit feature/dependency mapping and canonical contracts, plus closed `application_requirements` enum values for application-owned ports;
- operational surfaces: routes, background tasks, health checks, and metrics prefix as declared outputs, never proof that an application port exists;
- generated ownership: managed regions, derived files, and explicit create-once application templates.

Unknown or missing fields are schema failures. Keep dependency and conflict data declarative; do not hide composition requirements in template code. A provider slot represents a deliberate exclusive choice and must be tested as such.

Only modules with a runtime catalog kind may appear in a bundled profile or
`cargo service add`. Tooling modules remain repository/dev tools and must not
enter generated runtime state or service-kit feature contracts.

### Configuration and dependency metadata

For framework-owned configuration, declare each field's full dotted path, scalar/array type, required flag, and either a safe `reference_default` or exact hierarchical `environment` key. A secret field must never have a reference default. A required field must have a safe default or environment binding, and selected modules may not conflict on either. Generated TOML contains values, not interpolation expressions; `${...}` is literal TOML text and must not be used.

Choose a `runtime_dependencies` ID from the closed registry. Add a new descriptor only when the dependency contract itself is new. Repository-owned local infrastructure requires a digest-pinned image, stable Compose service/volume names, health check, exact configuration bindings, and explicit development-only labeling for any credential. Otherwise use an `external` descriptor with exact endpoint/credential variables; the generator will require them without inventing a local service.

### Typed application requirements

Every application-owned policy, handler, credential-bearing provider,
registry, or lifecycle port must use an existing canonical
`ApplicationRequirement`, or add one to the closed root service-kit enum and
its total provider-family mapping. Catalog strings outside that set are
rejected. Generated composition contains only profile ID, ordered runtime
module IDs, providers, and runtime-disabled modules; consumers never copy
canonical route/task/health/requirement literals.

Do not satisfy a requirement with a generic router, task collection, health
check, or declarative registration. Those are outputs only after the
application supplies the narrow named trait object. Missing runtime families
fail with `MissingContribution`, incomplete grouped runtimes fail with
`ContractMismatch`, and a runtime-disabled module skips only its own dormant
requirements.

## Add implementation code

When the module needs a new Rust crate:

1. Create the crate under the repository's existing naming and layout convention.
2. Add it to the explicit source-workspace member list in `Cargo.toml`.
3. Add its composition package mapping to the machine catalog so specification
   generation updates the root `omnius-service-kit` optional dependency,
   feature, and canonical registrar table.
4. Inherit workspace package metadata and lints rather than defining a second policy.
5. Keep public types at the module boundary and provider/client SDK types inside adapters.
6. Use typed configuration; identify secrets in catalog metadata and preserve redacted errors.
7. Add focused tests in the owning crate.

When no new crate is needed, point `primary_crates` at the existing implementation. Never create an empty crate merely to make a catalog entry look complete.

## Declare generated ownership

Choose ownership based on who may safely modify a consumer path:

- **Kit-owned:** deterministic generated application glue protected by an
  approved SHA-256.
- **Application-owned:** consumer code/assets/configuration/operations/data
  that the lifecycle never overwrites or deletes.
- **Derived:** reproducible output protected by an approved SHA-256.
- **Managed region:** a bounded generated region within an otherwise preserved
  application file.
- **Dependency lock:** the shared committed `Cargo.lock`, validated
  semantically rather than against golden whole-file bytes.

An extension may declare an explicit application template. It is created only
when the regular path is missing, immediately becomes application-owned, and
is preserved on remove/re-add/profile changes. Unsafe paths, symlinks, copied
framework source, framework SQL, and tooling are forbidden in that inventory.

`new` requires a nonexistent destination and publishes a fully resolved sibling
stage by rename. Existing-project commands preserve application-owned paths
and unknown application additions, refuse modified generated hashes/regions,
and preserve historical application migrations. Design the module so add,
remove, profile-set, and update remain safe under those rules.

## Add profile selection only where justified

A module does not need to appear in every profile. Add it to a profile only
when that profile's documented runtime purpose requires the module, its
dependencies can be satisfied, and its catalog kind is not `tooling`.
Inherited profiles must remain free of conflicts and provider-slot ambiguity.

Profile selection is catalog configuration. It does not prove route mounting,
worker startup, credentials, or deployment. Record runtime assembly only where
application source and evidence demonstrate it.

## Exercise a dry-run add

Use a clean, immutable `cargo-service` release whose identity matches the
schema-2 project.

**Prerequisites:** set `MODULE_ID` to the exact runtime catalog ID and
`PROJECT_PATH` to an existing managed service directory containing
`.omnius/service.toml`. Keep application work under source control and never
use production secrets.

```bash
cargo service add "$MODULE_ID" --dry-run --project "$PROJECT_PATH"
```

**Expected result:** the command validates state, manifests, Cargo provenance,
the runtime dependency closure, and the bounded package graph; it resolves and
seals exact lock bytes once and reports the plan without applying it. Add
`--offline` only for canonical cache-only resolution.

**Failure path:** resolve unknown/tooling IDs, dependency/provider conflicts,
release mismatch, dirty/unbound CLI, source override/vendor configuration,
ownership drift, or an out-of-scope lock diff at its source. Do not remove
`--dry-run` until the sealed plan is understood.

## Verify service state

```bash
cargo service doctor --project "$PROJECT_PATH" --json
cargo service diff --project "$PROJECT_PATH"
```

**Expected result:** `doctor` emits one schema-version-1 JSON command envelope
whose project data validates strict schema-2 state, immutable release
provenance, generated hashes/regions, and semantic lock identity. `diff`
reports deterministic managed changes without mutation.

**Failure path:** treat missing metadata, release/source mismatch, ownership
drift, invalid managed regions, or lock disagreement as a lifecycle defect.
Repair through the matching installed CLI or `cargo service update`; never
edit state to silence diagnostics.

## Required module tests

At minimum, cover every catalog behavior the module introduces:

- dependency closure and ordering;
- direct and inherited conflicts;
- provider-slot exclusivity;
- add and repeated-add idempotence;
- dependent removal and declared persistence/removal policy;
- managed-region and application-owned-file preservation;
- dependency-lock and bounded package-graph validation;
- journal fault recovery around ordinary, lock, and state writes;
- doctor and diff reporting;
- fresh profile generation and exact `profile set` transitions;
- public contracts, migrations, routes, tasks, health checks, and metrics named by the module.

### Run generator lifecycle tests

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain is installed; tests use repository fixtures and must not receive production credentials.

```bash
cargo test --locked -p omnius-generator --test module_management
cargo xtask profiles verify
```

**Expected result:** module lifecycle invariants pass and the declared profile
catalogs validate schema, inheritance, runtime-only selection, dependencies,
conflicts, and provider slots. The repository's `cargo xtask` alias executes
the xtask package with `cargo run --locked`.

**Failure path:** fix the catalog, generator, ownership metadata, or implementation that violates the invariant. Do not loosen a shared invariant only for the new module.

## Contracts, security, and operations review

A module review must include the concerns it changes:

- **Contracts:** regenerate and semantically compare OpenAPI, optional AsyncAPI, permissions, capabilities, and manifest artifacts.
- **Persistence:** review forward migration, compatibility window, rollback limits, and removal retention.
- **Security:** review authentication, authorization, tenant boundaries, secret handling, outbound destinations, and diagnostic redaction.
- **Operations:** define bounded timeouts, health behavior, metrics, background-task ownership, and external-service prerequisites.
- **Profiles:** confirm the module is selected only by intended profiles and does not imply unproved exposure.

Use [Contract and SDK generation](./contract-and-sdk-generation.md) for generated surfaces and [Compatibility and release gates](./compatibility-and-release-gates.md) for evidence requirements.

## Completion criteria

A module change is complete only when its strict catalog entry, implementation, workspace membership when applicable, generator ownership, lifecycle behavior, focused tests, affected profiles, contracts, and security/operations review agree. Publication, deployment, and profile availability remain separate decisions.