---
title: Workspace and tooling
description: Repository layout, pinned toolchains, workspace conventions, and the commands contributors use to inspect the Omnius workspace.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - contributor
  - maintainer
topics:
  - workspace
  - toolchains
  - repository-layout
capabilities: []
source:
  - Cargo.toml
  - rust-toolchain.toml
  - package.json
  - .cargo/config.toml
evidence:
  - .github/workflows/ci.yml
  - .config/nextest.toml
last_verified: 2026-08-30
---

# Workspace and tooling

Omnius is a mixed Rust and TypeScript workspace. This page describes the checked-in contributor contract; it does not imply that every library is assembled into a runnable application. For composition and profile semantics, see [Modules, profiles, and composition](../concepts/modules-profiles-and-composition.md). For the repository-wide quality gates, see [Testing strategy](./testing-strategy.md).

## Pinned environment

The repository declares the versions contributors and CI are expected to use:

| Tool | Repository declaration | Value |
| --- | --- | --- |
| Rust | `rust-toolchain.toml` | `1.98.0`, minimal profile, with `clippy` and `rustfmt` |
| Cargo feature resolver | `Cargo.toml` | resolver `3` |
| Rust edition | `Cargo.toml` | `2024` |
| Node.js | root `package.json` | `24.19.0` |
| pnpm | root `package.json` | `11.23.0` |

Use the pinned tools rather than silently substituting a local version. The root Node package is private, and the Rust workspace applies shared package metadata and lints. In particular, workspace policy forbids unsafe code and denies broad Clippy failures and `unwrap` use.

## Repository map

The main contributor surfaces are:

- `apps/`: assembled application crates that exist in this checkout.
- `crates/`: reusable Rust libraries, adapters, generator code, and test support.
- `packages/`: TypeScript packages, including the framework-neutral web SDK.
- `web/`: the browser application.
- `xtask/`: repository maintenance, generation, compatibility, and evidence commands.
- `specs/machine/`: machine-readable module, profile, capability, and extension catalogs.
- `contracts/`: generated public contract artifacts and their manifest.
- `templates/base-service/`: generator-owned base service template.
- `release/`: release-gate runbooks; these are procedures, not proof of a publication.

The Rust workspace uses an explicit member list in `Cargo.toml`. Creating a crate directory is therefore insufficient: a new crate must also be added to the workspace when it is intended to participate in workspace commands. See [Creating a module](./creating-a-module.md) before changing composition metadata.

## Cargo xtask

`.cargo/config.toml` defines `cargo xtask` as `cargo run --package xtask --`. Prefer the alias because it uses the repository's checked-in task implementation.

The service lifecycle command surface is deliberately narrow:

```text
cargo xtask service add
cargo xtask service remove
cargo xtask service upgrade
cargo xtask service doctor
cargo xtask service diff
```

There is no documented `service new` or `profile set` command. Do not infer command availability from a generator library, template, catalog, or test.

### Confirm xtask integration

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain is installed; no application credentials are required.

```bash
cargo xtask profiles verify
```

**Expected result:** Cargo builds the local `xtask` package if necessary and validates the checked-in profile catalogs.

**Failure path:** if Cargo rejects the toolchain or package, restore the versions declared by `rust-toolchain.toml` and `Cargo.toml`. A catalog error belongs to its machine-readable source; do not infer or add an undocumented task flag.

## Install JavaScript dependencies

Run from the repository root.

**Prerequisites:** Node.js `24.19.0`, pnpm `11.23.0`, and access to the package registry used by the lockfile. Production credentials are not required.

```bash
pnpm install --frozen-lockfile
```

**Expected result:** dependencies are installed without changing `pnpm-lock.yaml`.

**Failure path:** a lockfile mismatch is a repository change to resolve, not a reason to drop `--frozen-lockfile`. A version failure should be corrected by using the versions in the root `package.json`.

## Work at the narrowest scope

Use the smallest command that covers the changed contract:

- Rust package behavior: use the exact package and test target named by the owning development page.
- Repository integration and generation: use the implemented xtask subcommand for that artifact or catalog.
- SDK behavior: begin with `pnpm sdk:test`, adding the generation, compatibility, boundary, and build commands required by the change.
- Browser application behavior: begin with `pnpm web:test`, adding type, build, and browser commands required by the change.
- Full profile and release evidence: use only the documented matrix or release-gate procedure.

Do not treat a successful library test as proof that an application mounts a route, starts a worker, or exposes a protocol. Runtime assembly and public exposure are separate evidence dimensions in the [Availability and exposure matrix](../reference/availability-and-exposure-matrix.md).

## Generated and owned files

Before editing generated output, identify its owner:

- Contract generators own the generated files under `contracts/`.
- SDK generators own `packages/web-sdk/src/internal/generated/`.
- The service generator distinguishes kit-owned, application-owned, derived, and managed-region content.
- Machine catalogs under `specs/machine/` are source inputs and must remain internally consistent.

Regenerate through the owning command instead of hand-editing generated files. Manual SDK behavior belongs outside `src/internal/generated/`; application-specific service changes belong in application-owned files or declared managed regions. See [Contract and SDK generation](./contract-and-sdk-generation.md) and [Generator and profile development](./generator-and-profile-development.md).

## Secrets and local configuration

Never place credentials in command lines, fixtures, generated reports, or committed local configuration. Provider adapters accept secret-bearing configuration through typed boundaries, and CI examples are not a source of production values. Use synthetic fixtures and redacted diagnostics for contributor tests.

## What this page proves

The manifests and task source prove the repository layout, pinned versions, aliases, and available scripts. They do not prove that a profile is assembled, that a generated contract is deployed, or that release evidence has been accepted.