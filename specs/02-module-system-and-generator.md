---
spec_id: OMNIUS-002
title: Module System and Generator
version: 0.1.0
status: normative
last_verified: 2026-09-03
---

# Module System and Generator


## Toggle types

| Mechanism | Purpose |
|---|---|
| Generated profile | Initial service composition |
| Managed service-kit features | Major runtime capabilities |
| Cargo features | Additive codec, TLS, exporter, or adapter detail inside one crate |
| Runtime config | Enable a compiled route, worker, schedule, exporter |
| Product feature flag | Change behavior by environment, tenant, user, or cohort |

Mutually exclusive system architectures must not be modeled solely as Cargo features.

## Module descriptor

Every module satisfies `machine/module-manifest.schema.json` and declares:

- Stable ID, title, owner, version, kind.
- Dependencies, conflicts, and provider slot.
- Criticality.
- Configuration prefix/schema.
- Migrations, routes, tasks, health checks, metrics.
- Secrets and external services.
- Test fixtures and acceptance IDs.
- Managed regions, derived artifacts, and create-once application templates.
- Removal behavior.

## Lifecycle

```text
discover -> validate -> plan -> initialize -> register
 -> start -> ready -> run -> drain -> stop -> close
```

- Validation finishes before listeners open.
- Initialization is timed.
- Required failures abort startup.
- Tasks register with the supervisor.
- Readiness waits for required initialization.
- Drain stops new work before canceling in-flight work.

## Capability handles

Expose narrow application interfaces such as `BlobStore`, `JobEnqueuer`, `MailSender`, `EventPublisher`, and `FeatureEvaluator`; do not expose vendor clients to handlers.

Raw SQLx pools remain inside persistence adapters. Avoid generic repositories unless there are two real implementations or a proven test seam.

## Provider slots

At most one default provider per slot:

- Jobs: Apalis/Redis, PGMQ, external.
- Events: in-process, NATS JetStream, external.
- Object storage: local, S3, GCS, Azure.
- Feature flags: flagd/OFREP, Unleash, no-op.
- Policy: built-in, Cedar.
- Search: Meilisearch, supplied adapter.
- Sessions: PostgreSQL, Redis.

Dual providers are allowed only for migrations with tests.

## Installed lifecycle tool

`cargo-service` is the only public generated-service lifecycle tool. It is
installed from the canonical repository at one immutable, full lowercase
40-hex revision:

```console
REV=<full-lowercase-40-hex-revision>
cargo install --locked \
  --git https://github.com/bmanturner/omnius.git \
  --rev "$REV" \
  --bin cargo-service \
  omnius-generator
```

Reproducible packagers and CI also set `OMNIUS_RELEASE_REVISION="$REV"` while
installing. The build fails when that value is invalid or disagrees with the
checked-out commit. Repository-only specification, profile, and contract tasks
remain under `cargo xtask`; generated projects never contain or invoke a
project-owned lifecycle `xtask`.

The public command surface is:

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

`new` defaults to `./<NAME>` and requires a nonexistent destination. Other
commands default to the current directory. `--offline` restricts lifecycle
resolution to Cargo's existing cache; it does not create or use a vendor tree.
There is no user-selectable framework source or revision option. `update`
always targets the executing CLI's release identity, and `profile set` replaces
the runtime selection with the exact target profile closure while clearing
explicit additions and removals.

## Thin generated workspace

A generated service is an independent application workspace, not an Omnius
source fork. Its Rust workspace initially contains only `apps/service`.
Application code, assets, contracts, configuration, operations files, and
reserved-range migrations live in the consumer repository. The framework,
registrars, framework migrations, lifecycle implementation, specifications,
and templates remain in Omnius and are never copied into the service.

The root manifest contains one managed dependency, aliased as `service-kit`,
with package `omnius-service-kit`, exact framework version, canonical HTTPS Git
URL, full immutable revision, disabled default features, and the selected
runtime-module features. `apps/service` inherits only that alias; its
dev-dependency separately enables `test-support`. Other application-owned
workspace members and ordinary dependencies are preserved. Any additional
`omnius-*` dependency or alternate/path/registry/branch/tag source is invalid.

## State and ownership

`.omnius/service.toml` uses strict schema 2. It binds the service to the
framework version, byte-exact canonical repository URL, full revision, profile,
ordered runtime modules, providers, retention policy, ownership records,
managed-region hashes, and dependency-lock identity. State is an assertion of
the generated boundary, never a source-selection mechanism. `Cargo.lock` is
committed and classified `dependency-lock`; it is validated semantically
against the manifest and resolved package graph instead of by a golden
whole-file hash.

Files and regions are classified as kit-owned, managed-region,
application-owned, derived, or dependency-lock. Every kit-owned or derived
file records its approved SHA-256; the state file cannot hash itself.
Application-owned files are never overwritten or deleted. Extension catalogs
may declare explicit application templates: the lifecycle creates a missing
regular file once, records it application-owned, preserves it across
remove/re-add/profile changes, and refuses symlinks, unsafe paths, and
framework/tooling artifacts in that inventory.

Every mutation validates and seals a complete plan before writing, refuses
conflicts or changed managed inputs, and applies through a durable transaction
journal. A stale plan fails before writes; interruption recovery converges to
the complete old or new state. `--dry-run` still performs exact Cargo
resolution and reports the sealed lock/package diff but does not mutate the
project. `doctor` and `diff` are read-only.

## Release and selection rules

`new`, `add`, `remove`, `profile set`, and `update` require the executing
`cargo-service` build to be bound to a clean immutable release. Staged,
unstaged, and non-ignored untracked build inputs make it dirty; absent Git
metadata without an explicit valid release revision makes it unbound. `add`,
`remove`, and `profile set` also require the CLI and project identities to
match. Only `update` may move an older project to the executing identity.

Runtime selections contain only runtime modules. `generator`, `test-support`,
and every other `kind: tooling` module are rejected by `new`, `add`, and
`profile set` and are absent from runtime state and feature contracts.
`test-support` is available only through the generated dev-dependency.

Adding or removing a module updates the managed framework dependency and
generated composition selection, resolves the dependency closure, and
reconciles classified configuration/operations artifacts. Removal preserves
application-owned files, create-once templates, retained data declarations,
and all historical application migrations. It refuses removal when selected
dependents would become invalid.

Templates, profiles, and module APIs are release-bound. Schema-2 revision or
version changes use `cargo service update`; a private one-way schema-1 reader
exists only for validated legacy updates. All other commands reject schema 1
with guidance to run `cargo service update`.
