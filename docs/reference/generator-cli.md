---
title: Generator CLI
description: Installed cargo-service commands, immutable release identity, and thin generated-service lifecycle contracts.
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
  - .cargo/config.toml
  - crates/generator/src/bin/cargo-service.rs
  - crates/generator/src/cargo_service.rs
  - crates/generator/src/release.rs
  - crates/generator/src/provenance.rs
evidence:
  - crates/generator/tests/module_management.rs
  - crates/generator/src/cargo_service.rs
last_verified: 2026-09-03
---

# Generator CLI

`cargo-service` is the only public lifecycle interface for a generated Omnius
service. It is an installable Cargo subcommand, not a project-owned `xtask`.
Repository-only specification, profile, and contract maintenance remains under
the repository's `cargo xtask` alias, which expands to `cargo run --locked`.

Profile selection and generated output are build-time evidence. They do not
prove that a concrete application assembles or exposes the selected modules;
see [Profiles](profiles.md) and
[Availability and exposure](availability-and-exposure-matrix.md).

## Install an immutable release

Before a registry release exists, install the CLI from the canonical
repository and a full lowercase 40-hex commit:

```console
REV=<full-lowercase-40-hex-revision>
cargo install --locked \
  --git https://github.com/bmanturner/omnius.git \
  --rev "$REV" \
  --bin cargo-service \
  omnius-generator
```

A normal Git installation derives the checked-out commit. Reproducible
packagers and CI additionally set `OMNIUS_RELEASE_REVISION="$REV"` for that
installation; the build fails if the requested value is invalid or disagrees
with Git `HEAD`.

Cargo invokes the binary as `cargo-service service ...`; the binary removes
exactly one leading `service` token. These forms are therefore equivalent:

```console
cargo service doctor
cargo-service doctor
```

`cargo help service`, `cargo service --help`, and direct `cargo-service --help`
describe the same interface.

## Command surface

```text
cargo service new <NAME> --profile <PROFILE> [--path <PATH>] [--offline] [--json]
cargo service add <MODULE> [--project <PATH>] [--dry-run] [--offline] [--json]
cargo service remove <MODULE> [--project <PATH>] [--dry-run] [--offline] [--json]
cargo service profile set <PROFILE> [--project <PATH>] [--dry-run] [--offline] [--json]
cargo service update [--project <PATH>] [--dry-run] [--offline] [--json]
cargo service doctor [--project <PATH>] [--json]
cargo service diff [--project <PATH>] [--json]
cargo service --version
```

`new` defaults to `./<NAME>` and requires the destination not to exist. It
resolves the complete candidate in a sibling stage and publishes it with one
rename; an existing empty or nonempty destination fails with
`destination-exists`. Other commands default `--project` to `.`.

`--dry-run` performs validation, exact Cargo resolution, semantic package-graph
checks, and plan sealing, then reports the exact file and lock diff without
applying it. `--offline` limits lifecycle resolution to artifacts already in
Cargo's cache for the canonical source; it does not vendor dependencies.

### Selection changes

`add` and `remove` change one runtime module while preserving a valid ordered
dependency closure. Removal preserves application-owned files, retained data,
and all historical application migrations. Runtime selections reject
`generator`, `test-support`, and every other module whose catalog kind is
`tooling`; generated tests obtain `test-support` only through the
`service-kit` dev-dependency.

`profile set` is an exact transition to the target profile closure. It clears
explicit additions and removals, reports module/provider changes, and preserves
application-owned files, create-once application templates, retained data, and
historical application migrations.

`update` moves the project to the immutable release of the executing CLI. It
has no `--to`, source, branch, tag, or revision operand. It is also the only
command that accepts a validated legacy schema-1 project; every other
schema-1 operation fails with guidance to run `cargo service update`.

### Inspection

`doctor` and `diff` are read-only and never resolve or write a lockfile.
`doctor` reports `clean` or `unhealthy`; unhealthy returns exit 1. `diff`
reports `clean` or `changes`, both with exit 0. At the current release identity
they compare recorded hashes/managed regions with the desired output. At an
older identity they validate the recorded integrity and source structure
without claiming to reconstruct old bytes; repair guidance is to install the
recorded CLI or run `update`.

`--version` prints:

```text
cargo-service 0.3.0 (kit 0.3.0, <revision>)
```

It reports `unbound` or `dirty` explicitly when applicable.

## Release binding and mutation refusal

Mutating commands require a clean CLI build bound to a full immutable
revision. Staged, unstaged, or non-ignored untracked paths make a source build
dirty. A build without Git metadata or an explicit valid
`OMNIUS_RELEASE_REVISION` is unbound. Dirty and unbound binaries may show help,
version, `doctor`, and `diff`, but `new`, `add`, `remove`, `profile set`, and
`update` fail before staging or mutation. `add`, `remove`, and `profile set`
also require the executing CLI identity to equal the project identity;
`update` alone may transition it.

Before mutation, the tool recursively validates workspace manifests and
effective Cargo configuration. It rejects noncanonical Omnius dependencies,
mixed revisions, patches, replacements, Cargo paths, and source replacement
from project ancestors or `CARGO_HOME`. Vendoring is consequently a build-only
preparation:

```console
cargo vendor --locked
cargo build --locked --offline
```

The source-replacement configuration emitted for vendoring makes `doctor`
non-clean and blocks lifecycle mutation until it is removed. No vendor tree is
part of the generated boundary.

## Thin workspace and strict state

A fresh service is an independent Cargo workspace with one Rust member,
`apps/service`, and one direct Omnius dependency declaration. The managed root
`service-kit` alias names `omnius-service-kit` at the exact `0.3.0` version,
canonical HTTPS Git URL, full immutable revision, disabled defaults, and
selected runtime features. The member inherits that alias. Framework source,
framework migrations, lifecycle source, templates, specifications, root
`.sqlx`, and local façade crates are not generated. Application-added members
and ordinary dependencies remain application-owned.

`.omnius/service.toml` is strict schema 2 and binds framework version,
repository, revision, profile/modules/providers, retention, ownership and
managed-region hashes, and lock identity. Kit-owned and derived files carry
approved SHA-256 hashes. Application-owned files have no golden hash and are
not overwritten. `Cargo.lock` has the separate `dependency-lock` ownership
kind and is validated semantically against manifests and the resolved graph.

Extension catalogs may provide explicit application templates for web, SDK,
and contract assets. On first selection the lifecycle creates only missing
regular files, immediately records them application-owned, and never
overwrites or deletes them on removal or re-add. Unsafe paths, symlinks, and
framework/tooling content in this inventory are refused.

## Sealed apply and output

A mutation acquires the project lifecycle lock, recovers any incomplete prior
transaction, computes pure non-lock operations, resolves once in the exact
sibling stage, validates the bounded framework dependency-closure graph diff,
and seals exact lock bytes and expected input hashes. Apply performs stale
input checks but never invokes Cargo. It journals originals durably and writes
ordinary paths before `Cargo.lock` and state, using fsync plus rename; recovery
converges to the complete old or new identity.

Human results are written to stdout and diagnostics to stderr. `--json` writes
exactly one stdout document and no human prose:

```json
{"schema_version":1,"command":"add","status":"planned","project":".","release":{},"plan":{},"diagnostics":[],"error":null}
```

Clap syntax failures exit 2. Operational or validation failures exit 1.
Healthy/no-op success exits 0. Stable error codes include
`invalid-arguments`, `release-unbound`, `release-dirty`, `release-mismatch`,
`stale-plan`, `destination-exists`, `legacy-baseline-mismatch`,
`source-override`, `offline-resolution-failed`, `lock-source-mismatch`, and
`lock-diff-out-of-scope`.

## Repository-only maintenance

The source repository retains separate xtask subcommands for specification,
profile, and contract maintenance. Its `.cargo/config.toml` alias invokes
xtask with `cargo run --locked`; generated consumers do not receive those
sources or use them for lifecycle management.
