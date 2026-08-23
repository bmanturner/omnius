---
spec_id: RSK-002
title: Module System and Generator
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Module System and Generator


## Toggle types

| Mechanism | Purpose |
|---|---|
| Generated profile | Initial service composition |
| Workspace crates/dependencies | Major capabilities |
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
- Generator-owned files/regions.
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

## Generator

Use `cargo-generate` for initial expansion and project-owned `xtask` for ongoing management.

Required command surface:

```text
cargo service new <name> --profile <profile>
cargo service add <module>
cargo service remove <module>
cargo service profile set <profile>
cargo service doctor
cargo service diff
cargo service upgrade --to <version>
```

The first release may expose these as `cargo xtask service ...`.

## Ownership

Files are classified:

- Kit-owned.
- Managed-region.
- Application-owned.
- Derived.

The generator:

- Plans before mutation.
- Refuses unresolved conflicts.
- Creates a backup patch/branch.
- Is idempotent.
- Formats and validates output.
- Never edits application-owned code.
- Never deletes data migrations.
- Records module versions.
- Supports dry-run and machine-readable output.
- Fails if managed regions were corrupted.

## Add/remove behavior

Adding resolves dependencies, checks crate compatibility, wires config/routes/tasks, adds migrations and local infrastructure, adds health/metrics/tests/docs, updates manifests, and verifies profiles.

Removing stops future use and removes code wiring, but preserves historical migrations/data. It produces an optional cleanup plan and refuses removal when dependents exist.

## Upgrades

Templates and module APIs are versioned. Upgrade tooling uses semantic transformations and managed manifests, not blind replacement. Every release tests fresh generation plus upgrades from previous supported releases with application-owned edits.
