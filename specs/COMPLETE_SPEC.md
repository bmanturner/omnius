---
spec_id: RSK-COMPLETE
title: Complete Rust Service Kit Specification
version: 0.1.0
status: generated
last_verified: 2026-08-23
---

# Complete Rust Service Kit Specification


This is a generated single-file rendering of the human-readable specifications.
Machine-readable catalogs, schemas, examples, and validation tools remain separate
files in the bundle and are authoritative where referenced.


---

<!-- BEGIN README.md -->

# Rust Service Kit Specification Bundle


## Purpose

This bundle is the normative build specification for an opinionated, modular Rust backend service kit. It is designed to be passed directly to an autonomous programming agent.

The product is not a monolithic starter with every integration compiled in. It consists of:

1. A small runtime kernel.
2. Workspace crates implementing opt-in capabilities.
3. Named profiles composing coherent services.
4. A generator and `xtask` surface for safe module management.
5. Reference applications and a conformance suite.
6. An upgrade and supply-chain policy.

The dependency research was verified on **August 23, 2026**. Versions form a reviewed compatibility baseline, not permission to skip compilation, advisory, or license checks.

## Binding architectural decisions

- Rust 2024 edition and Cargo resolver 3.
- Tokio, Axum, Tower, and tower-http form the runtime and HTTP foundation.
- PostgreSQL is the primary relational database.
- SQLx **0.8.6** is the first supported line. SQLx 0.9.0 is deliberately gated because important surrounding integrations still target 0.8.
- Redis capabilities are split by purpose rather than represented by one generic switch.
- Browser authentication uses `axum-login` and `tower-sessions`; JWT verification uses `jsonwebtoken`; OIDC uses `openidconnect` and `oauth2`.
- Authorization is enforced in application services. Basic RBAC/ownership is built in; Cedar is optional.
- Outbound webhook delivery uses Svix instead of implementing a delivery platform.
- Apache Arrow `object_store` is the default object-storage abstraction.
- Durable jobs use an established backend. The kit does not create a new queue.
- Observability uses `tracing`, OpenTelemetry, and the `metrics` facade.
- Modules are composed at source/build time. There is no dynamic Rust plugin ABI.

## Normative language and precedence

**MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

When documents conflict:

1. Accepted ADRs.
2. Security and data-integrity requirements.
3. Module-specific specifications.
4. General architecture specifications.
5. Machine-readable catalogs.
6. Examples and research notes.

A machine-readable file that disagrees with a normative Markdown specification is a defect.

## Agent reading order

1. `AGENTS.md`
2. `SPEC_INDEX.md`
3. `00-scope-and-principles.md`
4. `01-system-architecture.md`
5. `02-module-system-and-generator.md`
6. `21-crate-selection-matrix.md`
7. `20-implementation-roadmap.md`
8. The current phase's specifications and ADRs
9. `22-recommendation-traceability.md`
10. `23-agent-task-graph.md`

## Definition of complete

The kit is complete only when:

- Every named profile generates in a clean directory.
- Every generated profile passes format, lint, compile, test, documentation, advisory, license, and source-policy checks.
- Reference applications demonstrate HTTP, PostgreSQL, sessions, JWT, authorization, jobs, realtime, graceful shutdown, and operational tooling.
- Every optional module has configuration, lifecycle, health, metrics, failure semantics, local infrastructure, integration tests, and documentation.
- The traceability matrix has no missing recommendation.
- No prerelease, yanked crate, git dependency, or incompatible duplicate foundational crate enters a default profile without an ADR.
- Generated repositories contain no placeholder macro, unimplemented production path, example secret, unbounded queue, or route bypassing authorization.
- Upgrade rehearsals prove that existing generated services can receive kit updates without overwriting application-owned code or deleting data.

## Bundle structure

- Numbered specifications are normative.
- `adr/` records architecture decisions.
- `machine/` contains catalogs and schemas consumed by tools.
- `examples/` contains contract examples, not copy-paste production implementations.
- `research/` records evidence and selection methodology.
- `SHA256SUMS` verifies artifact integrity.


<!-- END README.md -->


---

<!-- BEGIN AGENTS.md -->

# Autonomous Implementation Agent Contract


## Mission

Build the service kit described by this bundle. Optimize for a small, secure, coherent system whose supported combinations are continuously proven, not for producing the most code.

## Non-negotiable rules

1. **Run Phase 0 first.** Create a disposable compatibility workspace, resolve the proposed graph, and record actual versions plus duplicate Tokio, Hyper, Axum, Tower, SQLx, rustls, Serde, and OpenTelemetry lines.
2. **Never substitute silently.** A crate, version line, backend, authentication approach, or architecture change requires an ADR and traceability update.
3. **Do not hand-roll established infrastructure.** Do not create a custom framework, session engine, JWT/JWK parser, OAuth/OIDC implementation, password hash, WebAuthn implementation, object-store client, webhook delivery system, migration engine, observability protocol, or durable queue.
4. **Thin adapters are expected.** Project code may normalize a crate behind a narrow port, add configuration/lifecycle/telemetry, coordinate a transaction, or enforce application semantics.
5. **Compile at every task boundary.**
6. **Test real infrastructure.** Mocks alone are insufficient for PostgreSQL, Redis, NATS, object storage, migrations, cookies, auth flows, and shutdown.
7. **Use secure defaults.** Development relaxations must be explicit and impossible to activate accidentally in production.
8. **Leave no placeholders.** Production paths contain no placeholder macro, unimplemented production path, panic-based normal error handling, disabled security control, or plausible credential.
9. **No project-authored unsafe code** without a security ADR and focused review.
10. **Preserve data.** Removing a module never automatically reverses migrations, drops tables, deletes objects, or erases audit history.
11. **Protect application-owned code.** Generator changes are limited to kit-owned files and declared managed regions.
12. **Use UTC internally.**
13. **Default deny** on missing identity, missing tenant, unknown permission, malformed forwarded data, invalid signature, and ambiguous security configuration.

## Dependency admission gate

Before adding a direct dependency, record:

- The problem it solves.
- Why the standard library or an existing selected crate is insufficient.
- Latest stable release and proposed baseline.
- License and source.
- MSRV and toolchain fit.
- Release/maintenance activity.
- Documentation quality.
- Security advisories and unsafe-code footprint.
- Foundational dependencies it duplicates.
- Alternatives considered.
- Profiles/modules that require it.

A dependency MUST NOT enter a default profile without an ADR if it:

- Is only usable as a release candidate or prerelease.
- Forces a second incompatible foundational runtime/data/telemetry line.
- Is archived, effectively abandoned, or materially undocumented.
- Uses a denied license or unreviewed git source.
- Duplicates a selected foundational capability.
- Has a known unmitigated advisory affecting enabled code.

## Required repository commands

The implementation MUST expose equivalent commands through `cargo xtask`:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo test --doc --workspace
cargo check --workspace --all-targets
cargo deny check
cargo audit
cargo vet
cargo cyclonedx --all
cargo semver-checks
cargo xtask profiles verify
cargo xtask specs verify
cargo xtask migrations verify
```

`--all-features` is not a substitute for profile testing. Cargo features are additive and can conceal invalid combinations.

## Code rules

- `thiserror` for reusable/domain errors; `anyhow` only in binaries and operational tooling.
- HTTP types, SQLx row types, provider SDK types, and crate-specific auth types do not leak into domain services.
- No global `AppState` full of `Option<T>`.
- No generic repository trait without two real implementations or a demonstrated test seam.
- Reuse configured clients and pools.
- Bound request bodies, frames, queues, concurrency, pagination, retries, and retention.
- Every retry documents safety/idempotency.
- Every long-lived task is supervised, observable, cancellable, and drained.
- Every externally supplied URL passes centralized SSRF policy.
- Every log/trace field and metric label is assessed for secrets, PII, and cardinality.
- Public module APIs are documented and semver-checked.
- Production code avoids `unwrap()`; `expect()` is limited to statically proven invariants and includes a precise message.

## Task protocol

For every task:

1. Read its dependencies and acceptance IDs.
2. State affected contracts/files in the task record.
3. Implement tests with the behavior.
4. Run the smallest relevant command set.
5. Run profile verification at phase end.
6. Update generated docs/examples.
7. Update traceability when scope changes.
8. Commit atomically using the task ID.

Recommended subject:

```text
<type>(<module>): <imperative summary> [T###]
```

## Stop conditions

Stop and create a blocking ADR/risk when:

- The dependency graph cannot resolve coherently.
- A required integration has no stable compatible release.
- Implementation would weaken a security invariant.
- A migration cannot support rolling deployment.
- Correctness would depend on an unbounded queue or best-effort delivery.
- A generator action could overwrite application code.
- A recommendation cannot be implemented or verified as specified.

Do not resolve a stop condition by silently implementing a replacement framework.


<!-- END AGENTS.md -->


---

<!-- BEGIN AUTONOMOUS_AGENT_HANDOFF.md -->

# Autonomous Agent Handoff


## Objective

Implement the modular Rust service kit exactly as specified in this bundle. The first deliverable is the service-kit repository and conformance/reference applications, not a product-specific backend.

## Start here

1. Read `AGENTS.md`.
2. Read ADR-0001 through ADR-0012.
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


<!-- END AUTONOMOUS_AGENT_HANDOFF.md -->


---

<!-- BEGIN SPEC_INDEX.md -->

# Specification Index


| Document | Subject |
|---|---|
| `00-scope-and-principles.md` | Goals, non-goals, quality attributes, no-reinvention policy |
| `01-system-architecture.md` | Workspace, layers, dependency rules, process topology |
| `02-module-system-and-generator.md` | Module contract, provider slots, profiles, generator ownership |
| `03-core-runtime-and-lifecycle.md` | Bootstrap, supervision, health, graceful shutdown |
| `04-configuration-and-secrets.md` | Typed configuration, validation, secret handling |
| `05-http-api-contract.md` | HTTP conventions, middleware, validation, OpenAPI |
| `06-postgres-persistence.md` | SQLx, pools, migrations, transactions, test databases |
| `07-redis-cache-and-rate-limits.md` | Redis roles, Moka, cache semantics, limiting |
| `08-authentication-and-identity.md` | Sessions, password, JWT, OIDC, API keys, WebAuthn, TOTP |
| `09-authorization-tenancy-and-audit.md` | RBAC/ownership, Cedar, tenant isolation, audit |
| `10-jobs-events-outbox-and-scheduling.md` | Durable work, events, outbox/inbox, schedulers |
| `11-realtime-websockets-and-sse.md` | Long-lived transports, fan-out, backpressure |
| `12-object-storage-email-and-notifications.md` | Blob storage, templates, providers, preferences |
| `13-webhooks-and-outbound-integrations.md` | Svix, inbound verification, outbound clients, SSRF |
| `14-observability-health-and-operations.md` | Logs, traces, metrics, probes, diagnostics |
| `15-security-and-supply-chain.md` | Threat model, dependency controls, SBOM, hardening |
| `16-testing-and-quality.md` | Test layers, containers, fuzzing, load, conformance |
| `17-deployment-and-runtime-topology.md` | Binaries, containers, rollout, backup/recovery |
| `18-optional-product-modules.md` | SaaS, GraphQL/gRPC, search, localization, lifecycle |
| `19-profiles-and-acceptance.md` | Named compositions and profile definition of done |
| `20-implementation-roadmap.md` | Ordered phases and exits |
| `21-crate-selection-matrix.md` | Approved dependencies and rejected defaults |
| `22-recommendation-traceability.md` | Complete coverage of the original design |
| `23-agent-task-graph.md` | Executable task decomposition |
| `24-risk-register.md` | Known risks, triggers, mitigations |
| `adr/*.md` | Binding architecture decisions |
| `machine/*` | Derived catalogs, schemas, profiles, acceptance data |
| `examples/*` | Contract examples |
| `research/*` | Evidence and selection method |

## Validation

`cargo xtask specs verify` MUST:

- Confirm unique `spec_id`, version, status, and verification date.
- Confirm every catalog module appears in a specification.
- Confirm every profile references known modules and satisfies dependencies/conflicts.
- Confirm every referenced acceptance ID exists.
- Confirm every recommendation has a destination and verification method.
- Confirm every source ID exists in `research/sources.md`.
- Reject unresolved placeholder markers in normative files.


<!-- END SPEC_INDEX.md -->


---

<!-- BEGIN 00-scope-and-principles.md -->

# Scope, Principles, and Quality Attributes


## Problem

Rust services repeatedly re-solve configuration, pools, migrations, errors, observability, identity, permissions, caching, jobs, realtime delivery, tests, and deployment. Copying an old service preserves accidental choices; a large framework often imports unwanted architecture.

The service kit is the maintained middle ground: opinionated foundations, optional capabilities, explicit composition, and evidence-backed dependencies.

## Goals

The kit MUST:

1. Generate a useful service requiring no external infrastructure.
2. Add PostgreSQL, Redis, auth, jobs, realtime, storage, notifications, and related modules without restructuring the application.
3. Produce understandable code independent of generator internals.
4. Make secure, observable behavior the default.
5. Use established crates/services for commodity infrastructure.
6. Keep domain logic independent from transports, storage, and identity providers.
7. Define startup, failure, readiness, and shutdown behavior per module.
8. Prove named supported profiles rather than claim arbitrary combinations.
9. Upgrade generated services without destroying application code or data.
10. Maintain a complete recommendation-to-test trace.

## Non-goals

The first release is not:

- A web framework competing with Axum.
- An ORM or query language.
- An OAuth authorization server or identity provider.
- A policy language competing with Cedar.
- A durable message broker or webhook delivery platform.
- A universal payment/search/deployment abstraction.
- A dynamic binary plugin ABI.
- A generic DDD framework.
- A WAF, secret manager, backup system, or disaster-recovery platform.
- A guarantee that all module combinations work.

## No-reinvention rule

Capabilities fall into three classes.

### Adopt

Use a mature crate or external system directly behind configuration and a small integration layer. Examples: Axum, SQLx, Redis, OIDC, Argon2, WebAuthn, object storage, tracing, Svix.

### Thin adapter

Project-owned code may:

- Map a crate into the canonical domain interface.
- Add typed config, lifecycle, health, telemetry, and redaction.
- Coordinate an application transaction.
- Apply product authorization or tenancy.
- Normalize fakes.
- Preserve an escape hatch from a provider.

A thin adapter must remain small enough to delete; it must not become a parallel framework.

### Product-specific implementation

Application semantics must be implemented locally: membership roles, entitlements, moderation policy, consent, audit taxonomy, notification preference rules, and similar concerns.

## Quality attributes

### Correctness

- Concurrency-sensitive invariants are enforced in the database.
- Delivery semantics are stated explicitly.
- Retries are bounded and idempotent.
- All external waits have timeouts.
- Retryable state changes support idempotency.

### Security

- Default-deny authorization and tenant isolation.
- No secret values in logs, traces, metrics, errors, or diagnostics.
- Browser authentication includes secure cookie and CSRF controls.
- Token verification validates signature, algorithm, issuer, audience, and time claims.
- Dependencies pass advisory, license, source, and audit policy.

### Availability

- Required dependencies affect readiness.
- Optional caches and telemetry can degrade safely.
- Shutdown drains within a bounded deadline.
- Unbounded memory growth is a correctness defect.

### Operability

Every module defines logs, traces, metrics, probes, runbook signals, failure modes, and build/version metadata.

### Maintainability

Workspace direction is enforced, foundational versions are centralized, generated ownership is explicit, public APIs are semver-checked, and material decisions are recorded as ADRs.

### Performance

Clients/pools are reused, hot paths avoid needless allocation, and performance budgets are measured rather than guessed.

## Initial conformance targets

- Minimal profile startup under 500 ms on a typical development machine after compilation.
- Minimal release-mode idle RSS target under 35 MiB; exceeding it requires measurement and an ADR, not premature micro-optimization.
- No unbounded middleware or message queue.
- Configurable graceful-shutdown default of 30 seconds.
- Probe requests do not synchronously fan out to slow dependencies.
- Every profile generates and verifies from an empty directory in CI.
- Every direct dependency has rationale and an owner.


<!-- END 00-scope-and-principles.md -->


---

<!-- BEGIN 01-system-architecture.md -->

# System Architecture


## Style

Use a Cargo workspace with explicit source composition. Major capabilities are crates; Cargo features are reserved for additive implementation details within a crate.

```text
service/
├── apps/
│   ├── server/
│   ├── worker/
│   ├── scheduler/
│   └── admin-cli/
├── crates/
│   ├── core/
│   ├── runtime/
│   ├── http-api/
│   ├── domain/
│   ├── persistence-postgres/
│   ├── cache-redis/
│   ├── auth-*/
│   ├── authorization/
│   ├── jobs-*/
│   ├── realtime/
│   ├── integrations-*/
│   └── test-support/
├── migrations/
├── config/
├── deploy/
├── specs/
└── xtask/
```

Small capabilities may share a crate when separation would be ceremonial.

## Dependency direction

```text
apps -> transport/infrastructure adapters -> application services -> domain/core
```

- Domain code does not depend on Axum, SQLx, Redis, reqwest, sessions, JWT, or telemetry.
- Transport adapters call application services.
- Persistence adapters do not leak row types.
- Application services depend on narrow ports only where a real volatile boundary exists.
- No global service locator or circular workspace dependency.

## Composition root

Each executable owns composition:

1. Parse CLI.
2. Load and validate config.
3. Initialize bootstrap logging and telemetry.
4. Build dependencies in order.
5. Verify migration compatibility.
6. Construct typed state.
7. Mount routes/start supervised tasks.
8. Mark startup complete and evaluate readiness.
9. Run until termination.
10. Drain and close in reverse order.

## State

Do not create a global structure full of optional infrastructure. Mount routes only when their dependencies exist and give route groups typed state containing exactly their capabilities.

## Request context

Canonical context includes:

- Request ID.
- Trace context.
- `Principal` or anonymous state.
- Tenant/organization context.
- Locale/time-zone hints.
- Client metadata after trusted-proxy processing.
- Deadline/cancellation signal.

Domain services receive only needed fields.

## Executable modes

The reference implementation supports:

```text
server
worker
scheduler
migrate
migration-status
seed
create-admin
backfill
reindex
replay-outbox
inspect-config
doctor
profile-info
```

## Command flow

```text
transport input
 -> boundary validation
 -> authentication
 -> request/tenant context
 -> application authorization
 -> use case/transaction
 -> outbox or durable job in same transaction when needed
 -> response
```

## Event flow

```text
domain event
 -> transactional outbox
 -> relay/worker
 -> broker, realtime projection, webhook, search, notification
 -> inbox/deduplication
```

Never publish externally before the state transaction commits.

## Criticality

Each module is:

- **Required:** failure prevents readiness.
- **Degraded:** affected capability is impaired but core service may remain ready.
- **Best effort:** failure is visible but does not affect serving.

Examples: primary PostgreSQL required; authoritative session store required; cache degraded; telemetry exporter best effort.

## Source composition

Modules are compiled into the service. Runtime settings can enable compiled routes/workers but do not remove dependencies or attack surface. Product feature flags are separate. Dynamic Rust library loading is out of scope.


<!-- END 01-system-architecture.md -->


---

<!-- BEGIN 02-module-system-and-generator.md -->

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


<!-- END 02-module-system-and-generator.md -->


---

<!-- BEGIN 03-core-runtime-and-lifecycle.md -->

# Core Runtime and Lifecycle


## Foundation

Tokio provides the runtime; Axum routing; Tower services/layers; tower-http middleware; `tokio-util` cancellation/task tracking; `clap` process modes.

## Bootstrap phases

1. Process preflight and panic hook.
2. CLI parse.
3. Bootstrap stderr logging.
4. Config load/validation.
5. Telemetry.
6. Timed dependency initialization.
7. Migration policy check.
8. Application construction.
9. Listener bind.
10. Supervised task start.
11. Startup success/readiness.
12. Run loop.

Startup errors have stable codes and causal operator detail without secrets.

## Supervisor

Every long-lived task records name, module, criticality, start time, heartbeat where relevant, restart policy, cancellation token, shutdown timeout, and exit result.

- Required task exit marks unready and normally initiates shutdown.
- Degraded task exit marks the capability degraded.
- Best-effort exporter failure reports and continues.
- Restarts are bounded with capped jittered backoff.

## Termination

Handle `SIGTERM`, `SIGINT`, fatal dependency failure, and optional administrative drain. A second termination signal forces exit.

Drain order:

1. Mark unready.
2. Stop accepting new traffic/work.
3. Stop schedulers/consumers leasing new jobs.
4. Notify realtime clients when possible.
5. Wait within per-class deadlines.
6. Cancel remaining work.
7. Flush telemetry under a short deadline.
8. Close pools/clients.
9. Exit with meaningful status.

## Timeouts

Explicit typed timeouts exist for dependency connect, pool acquire, headers, request/handler, body streaming, outbound requests, jobs, shutdown stages, and exporter flush.

## Panic policy

Request panics become generic 500 responses and traces. A panic in a required supervised task is fatal. Clients never receive panic payloads/backtraces.

## Build metadata

Expose safe service/version, Git revision, build time, compiler version, kit version, profile/modules, and schema compatibility range.


<!-- END 03-core-runtime-and-lifecycle.md -->


---

<!-- BEGIN 04-configuration-and-secrets.md -->

# Configuration and Secrets


## Crates

Use `config`, Serde, `secrecy`, `clap`, and `garde` for semantic validation.

## Precedence

1. Compiled defaults.
2. Base file.
3. Environment-specific file.
4. Local uncommitted development file.
5. Environment variables.
6. Explicit CLI overrides.

Production never implicitly reads `.env`.

## Conventions

- Environment keys: `<SERVICE>__SECTION__FIELD`.
- Durations and byte sizes include units.
- URLs use typed parsing.
- Unknown top-level and security-sensitive keys are rejected.
- Deprecated keys become errors after their announced removal release.

Each module owns typed config and validates required values, mutual exclusions, schemes, production controls, timeout/pool relationships, cookie/origin policy, TLS, secret presence, and unsupported runtime states.

## Secrets

Secrets:

- Use `SecretString` or equivalent.
- Avoid `Debug`, `Display`, serialization, traces, metrics, and error context.
- Are exposed only immediately before use.
- Come from production secret injection.
- Support rotation.
- Never appear in examples, snapshots, tests, or diagnostics.

Repositories may contain `${DATABASE_URL}`-style placeholders, never plausible keys.

## Diagnostics

`inspect-config` emits effective non-secret config, value sources, redacted secret presence/source, validation result, profile/modules, and development warnings. Output must be safe for incident attachment after review.

## Reload

Initial dynamic reload is limited to log filters, selected sampling, feature-provider refresh, and explicitly safe thresholds. Database URLs, signing keys, proxy ranges, origins, and policy changes require atomic module-specific support.

## Acceptance

- Invalid production cookie/origin policy fails startup.
- Unknown sensitive keys fail.
- Secret formatting never reveals values.
- Precedence tests are deterministic.
- Every profile has redacted example config.


<!-- END 04-configuration-and-secrets.md -->


---

<!-- BEGIN 05-http-api-contract.md -->

# HTTP API Contract


## Handler responsibility

Axum handlers parse/validate transport input, obtain request/principal/tenant context, call an application service, and map the result to the stable HTTP contract. They do not contain SQL, password hashing, provider retry loops, or substantive authorization rules.

## Middleware order

The effective order is documented and integration-tested. Outer to inner:

1. Panic boundary.
2. Request ID.
3. Sensitive-header marking.
4. Trusted-proxy/client metadata.
5. Trace span.
6. Concurrency controls.
7. Header/request deadlines.
8. Body limit.
9. CORS.
10. CSRF/cross-origin protection for cookie-authenticated mutation.
11. Authentication.
12. Request/tenant context.
13. Route-specific rate limit.
14. Handler.
15. Security headers, compression, and metrics.

Rejections still carry request ID and observability.

## Request IDs

Generate UUIDv7. Accept an inbound value only from a trusted proxy after syntax/length validation. Return it to the client and propagate it to logs, traces, errors, jobs, and event causation metadata.

## Problem Details

Errors use RFC 9457-compatible `application/problem+json` with stable `type`, `title`, HTTP `status`, application `code`, `request_id`, optional safe `detail`, and optional field errors using JSON Pointer paths.

Internal causes, SQL, traces, secrets, and raw provider responses are never returned. Authentication and recovery responses resist enumeration.

## Validation

Use `garde` at transport boundaries; keep business invariants in domain/application code and database constraints.

Reject unknown fields for security-sensitive commands, unsupported content types, invalid text encodings, oversized/nested collections, and malformed pagination/filter expressions.

## Pagination

Default to opaque cursor pagination with bounded `limit`, stable sort plus unique tiebreaker, allowlisted filters/sorts, and `next_cursor`. Offset pagination is limited to bounded administrative data.

## Idempotency

Retryable state-changing operations support `Idempotency-Key`.

Persist principal/tenant scope, operation, request hash, in-progress/completed status, safe response, and expiry. Reusing a key with a different request conflicts. Coordinate business effect and idempotency record transactionally where possible.

## Conditional requests

Mutable resources should expose version/ETag and use `If-Match`. Cacheable reads may use `If-None-Match`. Auth and recovery responses are `no-store`; user-specific responses use correct private policy.

## CORS and CSRF

CORS is deny-by-default. Credentials never use wildcard origin. Cookie-authenticated mutation uses tower-http 0.7 CSRF/cross-origin protection plus origin policy; SameSite is defense in depth.

## Trusted proxies

Honor forwarded headers only when the immediate peer is trusted. Bound hop count; reject malformed chains. Direct clients cannot choose effective IP, scheme, or host.

## Initial defaults

- JSON body: 2 MiB.
- Auth body: 64 KiB.
- Header read: 5 seconds.
- General handler/total body deadline: 30 seconds.
- Max page size: 100.
- Accepted request ID: at most 128 bytes.

Upload/stream routes override explicitly.

## OpenAPI

Use `utoipa` and OpenAPI 3.1. CI deterministically generates and validates the document, diffs breaking changes, and requires operation ID, auth scheme, responses, and Problem Details for every public route. Admin APIs use a separate document/listener.

## Outbound HTTP

Reuse configured `reqwest::Client` instances per policy class. Use rustls, connect/total timeouts, controlled redirects, response size limits, explicit proxy behavior, user agent, retry only for safe/idempotent operations, tracing, and metrics.


<!-- END 05-http-api-contract.md -->


---

<!-- BEGIN 06-postgres-persistence.md -->

# PostgreSQL Persistence


## Baseline

PostgreSQL is the primary relational database. SQLx **0.8.6** is the first supported line.

SQLx 0.9.0 was current at research time, but surrounding session-store integrations still target 0.8. The kit values one coherent graph over newest-version selection. Upgrade requires ADR-0003's gate.

## Pool

Configure URL/TLS, minimum/maximum connections, acquire timeout, idle timeout, maximum lifetime with jitter, initialization SQL, application name, statement/lock timeout policy, metrics/readiness, and graceful close.

Pool sizing accounts for replica count, workers, migrations, and database limits.

## Queries

- Prefer checked SQLx macros.
- Commit `.sqlx` offline metadata.
- Use `QueryBuilder` only with allowlisted identifiers.
- Never concatenate untrusted SQL.
- Select explicit columns.
- Do not log values.
- Enforce uniqueness, references, and concurrency-sensitive invariants in PostgreSQL.

## Transactions

Application services define boundaries. Helpers accept existing executors/transactions. Do not start hidden nested transactions. Business state, outbox, and idempotency share a transaction when required. Avoid network calls while holding a transaction.

## Retry

Retry only known transient SQLSTATE classes such as serialization failure/deadlock, only when the entire transaction closure is safe to repeat. Bound attempts, add jitter, count by SQLSTATE, and test forced conflicts. Do not retry constraint/syntax errors or ambiguous commits without idempotency.

## Migrations

Use SQLx migrations with one deterministic history.

- Production uses a dedicated migration command/job.
- A lock prevents concurrent migrators.
- Server startup verifies schema compatibility; auto-migrate only in explicit local/test mode.
- Forward-only by default.
- Destructive change uses expand/migrate/contract.
- Old/new versions coexist during rolling deployment.
- Module removal keeps history.
- Released checksums are immutable.

CI tests empty-to-head, previous-supported-to-head, rolling compatibility, and restartable backfills.

## Read replicas

Optional and explicit. Read-your-writes, authentication, authorization, billing entitlement, and idempotency default to primary. Measure lag.

## Advisory locks

Allowed for short database-scoped operational coordination with namespaced keys. They are not durable queue ownership.

## Tests and recovery

Use Testcontainers PostgreSQL with per-test isolation, migrations, deterministic fixtures, clock/ID controls, and failure injection.

Deployment docs define backup frequency, retention, PITR, restore rehearsal, encryption, RPO/RTO, and key-rotation compatibility.


<!-- END 06-postgres-persistence.md -->


---

<!-- BEGIN 07-redis-cache-and-rate-limits.md -->

# Redis, Caching, and Rate Limits


## Separate capabilities

Redis connectivity, cache, sessions, rate limits, Pub/Sub, Streams, locks, and jobs are separate modules with separate criticality.

## Client

Use official `redis` async multiplexing or `ConnectionManager`. Do not add a generic pool merely for concurrency. Configure TLS/auth, connect and command timeouts, reconnect policy, client name, key prefix/schema, value limits, command-family metrics, and separate connections for blocking/PubSub behavior.

## Cache interface

Provide `NoopCache`, `MokaCache`, and `RedisCache`.

- Cache-aside default.
- Explicit typed TTL.
- Hot-key TTL jitter.
- Short documented negative caching.
- Request coalescing/stampede protection.
- Versioned keys.
- Bounded serialization.
- Hit/miss/stale/load/error metrics.
- Distinguish cache error from authoritative miss.

Redis cache normally fails open/degraded. Sessions, rate limits, and jobs may fail closed.

## Moka

Use Moka for bounded in-process caches with weighted capacity where possible, expiration/idle policy, invalidation, documented warmup, and no assumption of cross-instance coherence.

## Invalidation

Prefer short TTL, versioned namespace, after-commit invalidation, or replayable event-driven invalidation. Redis Pub/Sub is not the sole durable invalidation source.

## Rate limiting

### Local

Use `governor` and `tower-governor` for per-instance GCRA/token-bucket limits after trusted client identity extraction.

### Global

Prefer edge/WAF/API-gateway limits for broad IP abuse. App-level global limits apply to account, tenant, API key, or costly operation quotas.

If Redis is required, use one atomic operation/script, version/test it, define fail-open/closed, bound cardinality/TTL, and record an ADR when no stable adapter fits. Do not build a general distributed-rate-limit framework.

Separate policies cover login, reset, registration, invitation, API keys, upload, search/reporting, webhook replay, and administrative actions.

## Pub/Sub and Streams

Pub/Sub is only for loss-tolerant fan-out. Streams require explicit consumer groups, retention, retry, pending-entry recovery, and observability. NATS JetStream or a job provider is preferred for broad durable events.

## Locks

Not default. Prefer constraints/transactions, idempotency, queue ownership, then PostgreSQL advisory locks. A Redis lock guarding irreversible state requires fencing tokens and an ADR; plain `SET NX PX` is insufficient.


<!-- END 07-redis-cache-and-rate-limits.md -->


---

<!-- BEGIN 08-authentication-and-identity.md -->

# Authentication and Identity


## Canonical principal

All mechanisms map to:

```rust
pub struct Principal {
    pub subject_id: SubjectId,
    pub kind: PrincipalKind,
    pub tenant_id: Option<TenantId>,
    pub auth_method: AuthMethod,
    pub authenticated_at: OffsetDateTime,
    pub assurance: AssuranceLevel,
    pub scopes: Vec<Scope>,
}
```

Domain/application code never consumes raw cookies, JWT claims, OIDC types, or API-key rows.

## Browser sessions

Use `axum-login` with the compatible `tower-sessions` stack. Phase 0 selects a mutually compatible SQLx or Redis store; do not hand-write a store while a maintained one exists.

Defaults:

- Opaque high-entropy session identifier.
- `__Host-` cookie, `Secure`, `HttpOnly`, `Path=/`, no `Domain`.
- `SameSite=Lax` unless a documented flow requires otherwise.
- Idle and absolute expiry.
- Rotation after login, privilege change, recovery, password reset, or MFA enrollment.
- Revoke current/device/all sessions.
- Device/session metadata.
- Cleanup task.
- CSRF/origin protection.
- Authentication hash invalidating sessions after sensitive changes.

PostgreSQL is default for the authenticated API profile; Redis is optional when already required.

## Passwords

Use RustCrypto Argon2id and PHC strings. Calibrate on deployment hardware with a security minimum, unique random salt, optional managed pepper, rehash-on-login, constant-time library verification, generic errors, bounded input, optional breached-password adapter, and session invalidation after change.

Never implement a hash/KDF or comparison.

## Verification and recovery

Tokens are random, single-use, short-lived, purpose/subject scoped, stored hashed, rate-limited, invalidated after use/security change, and audited without the value. Recovery cannot be weaker than enrollment without explicit risk acceptance.

## JWT

Use `jsonwebtoken`. Allowlist algorithms; control `kid`; validate signature, issuer, audience, expiry, not-before, and required claims; apply bounded skew; distinguish token classes; cache/refresh JWKS safely; bound size; prevent algorithm confusion; map to `Principal`.

The kit is a resource server, not an authorization server.

Self-issued access tokens use asymmetric signing, short lifetime, key rotation/JWKS, and opaque hashed rotating refresh tokens with reuse detection and revocation linkage.

## OIDC/OAuth client

Use `openidconnect` and `oauth2`: Authorization Code + PKCE, state, nonce, issuer validation, JWKS rotation, exact redirect URIs, tightly controlled protocol redirects, proof for account linking, multiple identities, explicit unlink/recovery, and correct distinction between ID and access tokens.

## API keys/service accounts

Use visible identifier plus secret; store only a hash; show once; record name, owner, scopes, tenant, expiry, last use; support overlap rotation and immediate revoke; distinguish service identities; audit lifecycle.

## Passkeys

Use `webauthn-rs` at or above security-fixed baseline. Validate RP ID/origins, persist ceremony state, define discoverable credential behavior, track counter/transports, require recent auth for lifecycle, and test multiple authenticators. Do not parse WebAuthn yourself.

## TOTP

Use `totp-rs`; encrypt seeds, confirm enrollment, bound skew, prevent replay, issue hashed one-time recovery codes, rate-limit verification, and represent resulting assurance in `Principal`.

## Security events

Emit safe typed events for login, logout, session lifecycle, password/recovery, identity link/unlink, API-key lifecycle, MFA/passkey lifecycle, refresh reuse, and administrative identity action. Never include credential material.


<!-- END 08-authentication-and-identity.md -->


---

<!-- BEGIN 09-authorization-tenancy-and-audit.md -->

# Authorization, Tenancy, and Audit


## Boundary

Authorization is enforced in application services so it applies to HTTP, WebSockets, jobs, CLI, GraphQL, and gRPC.

```text
authorize(principal, action, resource, context) -> allow | deny(reason)
```

Unknown action, missing tenant/resource context, and evaluator error deny by default.

## Built-in policy

Support roles-to-permissions, ownership, tenant membership, administrative capability, API scope restrictions, step-up assurance, and bounded contextual conditions. Route middleware may enforce coarse authentication but not replace service-level checks.

## Cedar

Optional for centrally authored RBAC/ABAC/ReBAC.

- Version schema/policies.
- Validate at build/deploy.
- Centralize entity construction.
- Deny on evaluation failure.
- Avoid high-cardinality decision metrics.
- Support staged/shadow policy rollout.
- Keep database/product invariants outside Cedar.

## Required authorization tests

Anonymous/authenticated; horizontal access; vertical escalation; cross-tenant; list filtering; bulk operations; indirect references; jobs acting for users; stale token roles/scopes; support/impersonation; newly added route without declared action.

Maintain a machine-readable permission matrix.

## Tenancy

When enabled, tenant appears in principal/context, database constraints and every tenant query, cache keys, job/event/webhook envelopes, object paths, quotas, audit, and bounded metrics. A path tenant is never trusted without membership validation.

Default isolation is explicit predicates plus constraints/tests. PostgreSQL RLS is optional defense in depth and requires transaction-local context, pool leakage tests, explicit migration/admin roles, and fail-closed missing context.

## Organization model

Organization, membership, role assignment, invitations, status, ownership transfer, last-owner protection, suspension, deletion. Grants are versioned/audited.

## Audit

Append-only application audit records event/time, actor, effective tenant, action, resource, outcome, request/correlation/causation IDs, safe metadata, reason, and separate impersonator/subject identities. Never store secrets or arbitrary large before/after data.

## Impersonation

Requires dedicated permission, recent high-assurance auth, reason, short lifetime, prominent context, complete audit, and restrictions on credentials/payment/security enrollment.


<!-- END 09-authorization-tenancy-and-audit.md -->


---

<!-- BEGIN 10-jobs-events-outbox-and-scheduling.md -->

# Jobs, Events, Outbox, and Scheduling


## Provider policy

Do not implement a general durable queue.

Approved paths:

- Apalis 0.7.4 + `apalis-redis` when Redis is already required.
- PGMQ plus maintained Rust client when the PostgreSQL extension is operationally acceptable and passes compatibility.
- NATS JetStream through `async-nats` for durable distributed event streaming.
- In-process only for tests/development or explicitly non-durable best effort.

`sqlxmq` is rejected as default because its stable release targets an old SQLx line. `apalis-postgres` prereleases are not admitted to default profiles.

## Job contract

Each job has stable name, payload version/type, idempotency policy, attempts, jittered backoff, timeout, concurrency/rate policy, queue/priority, retention, dead-letter behavior, compatibility plan, metrics, and runbook.

Assume at-least-once execution. Handlers are idempotent or use transactional effect records.

## Enqueue

If a job follows committed domain state, enqueue transactionally through a supported backend or write an outbox record in the same transaction. Never commit state then perform unprotected best-effort enqueue.

## Outbox

Application-owned schema coordinates the application's transaction. Store event ID, aggregate, type/version, tenant, time, correlation/causation, trace context, payload, destination, lease/attempt state, publication time, and safe error class.

Relay is leased, bounded, restart-safe, idempotent, observable, and retains/archives records by policy.

## Inbox

Deduplicate by producer/event ID; write inbox and business effect transactionally where possible; retain at least through possible redelivery; acknowledge only after durable effect.

## Events

Use the versioned envelope in `examples/event-envelope.json`. Changes are additive; fields are never repurposed; consumers ignore unknown fields; breaking changes get a new version/type; PII classification is documented.

## NATS JetStream

Declaratively define streams, subjects, retention, replication, limits, durable consumers, ack wait, dead-letter behavior, lag/redelivery metrics, and least-privilege credentials. Core NATS is only ephemeral.

## Scheduler

Every schedule defines time zone, expression, misfire/catch-up, max concurrent runs, lease/leader policy, idempotency window, replay, audit, and metrics.

Preferred: external orchestrator enqueues durable job; dedicated scheduler with lease; queue-native scheduling. Never run the same timer independently on every server replica.

## Drain and admin

Workers stop leasing, complete bounded work, extend valid long leases, safely release abandoned leases, and distinguish cancellation/failure.

Provide authorized/audited status, oldest age, dead jobs, replay, pause/resume, redacted payload view, worker heartbeat, and outbox backlog.


<!-- END 10-jobs-events-outbox-and-scheduling.md -->


---

<!-- BEGIN 11-realtime-websockets-and-sse.md -->

# Realtime: WebSockets and Server-Sent Events


## Selection

Use SSE for server-to-client streaming. Use WebSockets for bidirectional low-latency commands. Domain events remain transport-independent.

## Upgrade

Before WebSocket upgrade:

- Authenticate through an allowed session or bearer mechanism.
- Validate browser `Origin`.
- Resolve tenant/principal.
- Enforce per-IP/principal/tenant connection limits.
- Negotiate an allowlisted subprotocol.
- Propagate request/trace context.
- Reject oversized/malformed headers.

Upgrade authentication does not authorize later messages.

## Protocol

Versioned envelope:

```json
{
  "v": 1,
  "id": "019...",
  "type": "subscription.create",
  "correlation_id": "019...",
  "payload": {}
}
```

Every command is bounded, parsed, validated, mapped to a named application action, authorized against its resource, rate-limited where needed, and receives a structured reply.

## Lifecycle

Require heartbeats, idle timeout, maximum lifetime or reauthentication, session/token revocation handling, bounded inbound/outbound queues, slow-consumer policy, meaningful close codes, graceful drain, and bounded metrics.

A full outbound queue never grows. Coalesce/drop only explicitly coalescible updates, require resync, or disconnect.

## Subscriptions

Server-side subscriptions are scoped to principal/tenant. Topic names are not authorization. Membership changes revoke affected subscriptions. Resume cursors are opaque and available only with replay storage. Presence is ephemeral.

## Fan-out

Use Redis Pub/Sub only when loss is acceptable, NATS for wider fan-out, and durable streams for replay. Realtime adapters consume application events; domain services never call connection registries.

## SSE

Include auth/authz, heartbeat comments, bounded buffers, proxy buffering guidance, drain/reconnect, and `Last-Event-ID` only with real replay semantics.

## Tests

Invalid origin, expired/revoked session after connection, cross-tenant subscription, oversized frame, malformed command, slow consumer, reconnect/resume, multi-instance fan-out, drain, and load/backpressure.


<!-- END 11-realtime-websockets-and-sse.md -->


---

<!-- BEGIN 12-object-storage-email-and-notifications.md -->

# Object Storage, Email, and Notifications


## Object storage

Use Apache Arrow `object_store` by default. OpenDAL is optional only when its broader backend matrix is needed.

Default adapters: in-memory tests, local development, S3-compatible, GCS, Azure.

## Blob port

Support streaming put/get/range, metadata/head, delete, copy/move semantics, multipart upload, checksum/conditional operations, signed upload/download, and stable object keys. Handlers do not receive provider credentials/clients.

## Upload security

- Random server object keys.
- Normalized original filename only as metadata.
- Re-detect content where required.
- Size/multipart limits and checksums.
- Authorize signed URL issuance.
- Short expiry.
- Quarantine before processing/publication.
- External malware-scanner hook.
- Constrained parsing workers for risky media.
- Safe content disposition; never execute uploaded content.

## Lifecycle

Define owner/tenant prefix, retention, orphan cleanup, soft-delete window, legal hold, encryption, replication/backup ownership, and audit. Database/object changes use intent/job reconciliation; they are not one transaction.

## Email

Use `lettre` for message/SMTP and MiniJinja for runtime templates. Provider HTTP APIs use mature official SDKs or narrow reqwest adapters.

Support text+HTML, bounded attachments, internationalized headers, provider ID, idempotency, retry classification, bounce/complaint/delivery events, test sinks, preview command, template linting, snapshots, and redaction.

## Notifications

Product orchestration defines event, recipient, channels, preference category, mandatory exception, locale/time zone, template version, dedupe/digest, and delivery status. Normal delivery is a durable job, not synchronous HTTP work.

## Preferences/unsubscribe

Scoped optional-category unsubscribe; separate security/transactional classification; authenticated or signed single-purpose changes; opaque/signed tokens; audit.


<!-- END 12-object-storage-email-and-notifications.md -->


---

<!-- BEGIN 13-webhooks-and-outbound-integrations.md -->

# Webhooks and Outbound Integrations


## Outbound webhooks

Use Svix managed or self-hosted for production. The kit provides a thin adapter, not a delivery platform.

Support application/endpoint lifecycle, secret rotation, event IDs/types, idempotent enqueue, status, replay, test event, suspension, and safe correlation. Local fake is test/development only.

## Public event contract

Stable event ID, type/version, time, tenant/application, data, safe previous attributes, and safe correlation metadata. Public schemas are semver-governed.

## Inbound webhooks

Provider adapters:

1. Apply strict size/header limits.
2. Preserve raw bytes.
3. Verify signature and timestamp before processing.
4. Enforce replay window/deduplication.
5. Parse a versioned provider event.
6. Persist receipt/inbox.
7. Acknowledge to provider contract.
8. Process asynchronously.
9. Reconcile through provider API when ordering/authenticity requires it.

Raw signed bodies are not logged by default.

## SSRF

Central validation for user-configurable URLs:

- HTTPS in production unless explicitly exempted.
- Scheme allowlist and no URL credentials.
- DNS resolution plus resolved-address checks.
- Block loopback, link-local, private, multicast, metadata, and configured internal ranges unless explicitly permitted.
- Re-check redirects/resolutions.
- Bounded or disabled redirects.
- Port policy.
- Connect/response timeouts and response cap.
- Never forward internal auth headers.
- Egress network policy as defense in depth.

## General integration adapter

Define reusable reqwest policy, authentication/rotation, idempotency, retry classification, provider rate limits, bulkhead/circuit behavior when justified, redaction, Wiremock contract tests, sandbox mode, health semantics, and reconciliation. Do not erase provider semantics behind a universal interface.


<!-- END 13-webhooks-and-outbound-integrations.md -->


---

<!-- BEGIN 14-observability-health-and-operations.md -->

# Observability, Health, and Operations


## Logs and traces

Use `tracing`, `tracing-subscriber`, `tracing-opentelemetry`, and `opentelemetry-otlp`. Local output is human-readable; production is structured JSON.

Bounded fields include service/version/environment, request ID, route template/method, status/code, principal kind/auth method, bounded tenant class, dependency operation, job/event type/attempt, and correlation/causation.

Never attach bodies, tokens, cookies, passwords, arbitrary SQL, email content, or unbounded user input.

## Propagation

Use W3C Trace Context and allowlisted Baggage. Propagate to HTTP, jobs, events, and webhooks. Baggage is never authorization input or an unbounded metric label.

## Metrics

Use `metrics` and `metrics-exporter-prometheus`; OTLP metrics are optional after compatibility validation.

Required families:

- HTTP count/latency/status/in-flight/rejection.
- DB pool utilization/acquire/query/error class.
- Redis latency/error/reconnect/cache.
- Outbound dependency latency/status/retry.
- Queue depth/age/attempt/duration/dead letter.
- Outbox backlog/age.
- Realtime connections/messages/drops/slow consumers.
- Auth success/failure class.
- Authorization denial by action class.
- Rate-limit decision.
- Email/webhook delivery.
- Process CPU/memory/descriptors/tasks where available.

Raw user, tenant, object, URL, SQL, error message, and request ID are prohibited labels.

## Probes

- `/live`: process/runtime only.
- `/ready`: cached aggregate.
- `/startup`: startup phase.
- `/version`: safe build metadata.
- Detailed diagnostics on protected admin listener.

Probe requests do not synchronously stampede dependencies.

## Readiness

False before drain. Required DB/session store failure makes affected service unready. Cache is normally degraded. Telemetry exporter remains best effort. Other providers follow module criticality.

## Admin listener

Separate network surface for metrics, dependency/task/queue/outbox diagnostics, and optional profiling.

## Operational hooks

Example alert semantics cover availability/latency, DB saturation, queue/outbox age, auth anomalies, authorization spikes, delivery failure, restart loops, readiness flapping, and error-budget burn. Runbooks state first diagnostics and safe remediation.


<!-- END 14-observability-health-and-operations.md -->


---

<!-- BEGIN 15-security-and-supply-chain.md -->

# Security and Software Supply Chain


## Threat model

Assume untrusted internet input, malicious authenticated users, compromised API keys, buggy providers, dependency vulnerabilities, and operator mistakes. Each module documents assets, trust boundaries, abuse cases, and controls.

## Build policy

Required:

- Committed `Cargo.lock`.
- crates.io releases only by default.
- Reviewed exact foundational baseline.
- Automated update PRs in bounded groups.
- `cargo-audit` on every PR and scheduled.
- `cargo-deny` for advisories, licenses, sources, bans/duplicates.
- `cargo-vet` policies/imports.
- CycloneDX SBOM.
- `cargo-semver-checks` for public crates.
- Provenance/attestation in release pipeline.
- Review of build scripts, proc macros, native libraries, and unsafe code.
- No ignored advisory without owner, applicability, mitigation, expiry, and ADR/risk entry.

## Dependency policy

Allowlist licenses compatible with intended distribution. Deny unknown/git sources by default. Treat duplicate foundational versions as errors unless explicitly permitted. Minimize enabled features and direct dependencies.

A new major line receives a compatibility spike before merge. Release candidates never become defaults solely to obtain compatibility.

## Application hardening

- Request/response limits and timeouts.
- Least-privilege DB/Redis/NATS/object/provider credentials.
- Separate migration and runtime DB roles where practical.
- Secure cookies, CSRF, origin policy.
- Token/JWK validation and key rotation.
- Central authorization.
- Tenant isolation.
- SSRF and upload controls.
- Safe error format and redaction.
- Audit trails.
- Idempotency/replay protection.
- Admin surface isolation.
- No public debug/profiling endpoints.

## Cryptography

Use established RustCrypto, rustls, WebAuthn, and JWT/OIDC libraries. No custom cryptographic primitive or protocol. Randomness comes from OS-backed CSPRNG. Algorithms/parameters are allowlisted and versioned.

## Secrets

Production secrets use a managed store/injection mechanism. Define rotation and overlap for DB/provider credentials, JWT signing keys, webhook secrets, encryption keys, and API keys. Avoid long-lived static cloud keys where workload identity exists.

## Data protection

Classify data and define encryption, access, log policy, retention, export, deletion, legal hold, and breach-response ownership. Encryption at rest does not replace authorization.

## Vulnerability response

The release process records dependency inventory and build provenance. A critical applicable advisory triggers triage, patched build, targeted tests, compatibility check, SBOM update, and release notes. Unsupported generated-service versions have a published policy.


<!-- END 15-security-and-supply-chain.md -->


---

<!-- BEGIN 16-testing-and-quality.md -->

# Testing and Quality


## Layers

1. Pure domain unit tests.
2. Module unit tests.
3. HTTP/service tests through Axum.
4. Real infrastructure integration tests.
5. Cross-module profile tests.
6. Property/fuzz/concurrency tests.
7. Load/soak/failure tests.
8. Upgrade/migration/generator tests.

## Tools

- `cargo-nextest` for isolated execution, retries only for diagnosed flaky external tests, partitions, and groups.
- Testcontainers and maintained modules for PostgreSQL, Redis, NATS, and compatible services.
- Wiremock for provider HTTP contracts.
- `proptest` for parsers, pagination, policy inputs, state machines.
- `cargo-fuzz` for untrusted parsers/protocols.
- Criterion for microbenchmarks where regressions matter.
- Tokio paused time/clock abstraction for deterministic expiry and scheduling.
- Optional Loom for project-authored concurrency primitives.

## Required test support

Deterministic clock, ID/random factories, config builders, principals/tenants, test server/client, email/object/webhook fakes, database reset/isolation, Redis namespace isolation, and safe event/job inspectors.

Fakes implement the same semantic contract; they do not silently behave more reliably than production.

## Required suites

### HTTP

Problem Details, content type, limits, timeout, request ID, CORS/CSRF, proxy spoofing, security headers, idempotency, pagination.

### Persistence

Fresh/upgrade migrations, constraints, transaction rollback, deadlock/serialization retry, pool exhaustion, rolling compatibility, backfill restart.

### Authentication

Session fixation/rotation/revoke/expiry, CSRF, password rehash, enumeration resistance, reset replay, JWT algorithm/issuer/audience/time/JWKS rotation, OIDC state/nonce/PKCE, API key lifecycle, WebAuthn ceremony, TOTP replay/recovery.

### Authorization/tenancy

Horizontal, vertical, cross-tenant, list/bulk, indirect reference, job/CLI transport, admin impersonation, missing policy.

### Async/realtime

Job retry/idempotency/dead letter/drain; outbox/inbox; broker disconnect; slow consumer; revoked session; resume semantics; multi-instance fan-out.

### Integrations

Webhook signature/replay; SSRF; provider rate limits; object size/type/quarantine; email template/sink; redaction.

## Profile matrix

Test named profiles and selected pairwise combinations, not only `--all-features`. Invalid combinations have negative generator tests.

## Load/failure

Provide scripts/scenarios for HTTP throughput/latency, auth bursts, pool saturation, cache outage, Redis reconnect, queue backlog, realtime fan-out/slow consumers, graceful rollout, and dependency latency.

## Flake policy

A retry is temporary quarantine with owner and expiry, never a permanent substitute. Tests use readiness conditions instead of sleeps and deterministic clocks instead of wall time.

## Coverage

Coverage is reported but no single percentage defines quality. Security-critical branches and every acceptance criterion require explicit tests.


<!-- END 16-testing-and-quality.md -->


---

<!-- BEGIN 17-deployment-and-runtime-topology.md -->

# Deployment and Runtime Topology


## Process topology

Supported deployable roles:

- Public API/server.
- Worker.
- Scheduler.
- Migration/admin job.
- Optional internal/admin API.

A small service may package subcommands in one image. Production permissions/config are role-specific.

## Container

Multi-stage build, reproducible dependency caching, pinned toolchain, non-root runtime, minimal filesystem, explicit CA certs/time-zone data needs, correct signal handling, read-only root where practical, writable temp policy, no compiler/package manager in runtime, healthcheck guidance, and OCI labels/SBOM/provenance.

Do not choose musl solely for image size without testing TLS/DNS/native dependencies and performance. Glibc slim is an acceptable default.

## Networking/TLS

Document whether TLS terminates at load balancer/proxy or process. Honor forwarded headers only from configured proxies. Admin listener is separately bound/restricted. Egress policy protects metadata/internal services.

## Migrations and rollout

Production deployment sequence:

1. Backup/restore readiness confirmed for risky changes.
2. Run expand-compatible migration under lock.
3. Deploy compatible new code gradually.
4. Monitor readiness/errors/queue/outbox.
5. Run restartable backfill.
6. Verify old-version absence.
7. Contract in a later release.

Server startup verifies schema range and refuses incompatible schema.

## Graceful rollout

Readiness turns false before listener drain. Termination grace exceeds service shutdown deadline plus margin. Workers stop leasing. Realtime clients receive reconnect guidance where possible.

## Configuration/secrets

Environment or mounted secret integration, no baked secrets, least privilege per role, rotation procedures, and startup validation.

## Local development

Compose file or equivalent starts only profile dependencies, has health checks, persists optional dev data, exposes no default credentials outside localhost, and provides reset/seed commands.

## Backup/recovery

Per stateful dependency define owner, backup/replication, retention, encryption, RPO/RTO, restore procedure, and rehearsal schedule. Object storage, PostgreSQL, NATS/queue state, feature provider, and identity-provider configuration are considered.

## Operational commands

`migrate`, `migration-status`, `backfill`, `reindex`, `replay-outbox`, `doctor`, and `inspect-config` are safe, idempotent where possible, observable, authorized by deployment permissions, and have dry-run for destructive/high-volume work.


<!-- END 17-deployment-and-runtime-topology.md -->


---

<!-- BEGIN 18-optional-product-modules.md -->

# Optional Product and Transport Modules


## Principle

These modules are intentionally separate from the kernel. Each must satisfy the standard module contract, but product semantics remain application-owned.

## Organizations

Includes organization, membership, roles, invitations, ownership transfer, suspension, quotas, tenant context, and lifecycle. Depends on PostgreSQL, authentication, authorization, and audit.

## Admin/support

Includes user/tenant lookup, suspension, safe data repair commands, audited impersonation, and controlled feature overrides. Runs on a separate protected surface. No generic “run arbitrary SQL” endpoint.

## Billing and entitlements

Separates:

- Provider adapter.
- Customer/subscription/invoice mirror.
- Product plan and entitlement evaluation.
- Usage metering.
- Webhook reconciliation.
- Grace/dunning policy.
- Audit and repair tooling.

Provider semantics are not erased behind a pretend universal billing model. Stripe or another provider receives its own adapter/ADR. Entitlements are read from authoritative local state after verified webhook/API reconciliation.

## Feature flags

Use the OpenFeature Rust SDK and a provider such as flagd/OFREP where appropriate. The module defines:

- Typed flag keys/defaults.
- Evaluation context allowlist.
- Timeout/caching/failure default.
- Exposure/audit events.
- Removal date/owner for temporary flags.
- No secrets or unbounded context.
- No use of flags to bypass authorization or schema compatibility.

A no-op/static provider supports tests and small deployments.

## Search

Default optional adapter is Meilisearch through its maintained SDK; applications may supply OpenSearch or another provider by ADR.

- Search index is a derived projection, not source of truth.
- Versioned index/schema and aliases.
- Outbox-driven indexing.
- Replay/backfill/reindex.
- Staleness status.
- Tenant filter enforced in index/query.
- Search result IDs reauthorized before sensitive response.

## GraphQL

Use `async-graphql` only when selected.

- Same application services and authorization.
- Depth/complexity/list limits.
- Persisted/allowlisted operations where threat model requires.
- DataLoader batching.
- Introspection policy.
- Separate GraphQL error mapping plus request ID.
- Subscription transport follows realtime spec.
- No business logic in resolvers.

## gRPC

Use `tonic`.

- Interceptors for request ID, tracing, auth, deadlines.
- Canonical status/error detail mapping.
- Message/decompression limits.
- Reflection only on protected/internal surfaces.
- Health service.
- Streaming backpressure and cancellation.
- Same application authorization.

## Localization

Use Project Fluent (`fluent-bundle`) where runtime localization is needed.

- BCP 47 locale negotiation.
- Explicit fallback chain.
- UTC storage and localized rendering.
- Time-zone/currency/plural handling.
- Template/catalog validation.
- Missing-message metrics without user text.
- Email/notification integration.

## Data lifecycle and privacy

Defines export, deletion, anonymization, retention, legal hold, and data inventory. Work is durable, restartable, audited, and reconciles PostgreSQL, object storage, search, queues, and providers.

## Consent/legal

Versioned terms/privacy/consent records with subject, version, time, jurisdiction/source, withdrawal where applicable, and immutable evidence. Legal text itself is externally governed.

## Moderation

Product-specific reports, evidence, actions, appeal, policy version, actor, subject, audit, notification, and retention. Authorization distinguishes reporter, moderator, administrator, and automated system.

## API transport providers

REST is default. GraphQL and gRPC are opt-in adapters, not replacement architectures. All share canonical application services, principal, authorization, tenancy, errors, events, and observability.


<!-- END 18-optional-product-modules.md -->


---

<!-- BEGIN 19-profiles-and-acceptance.md -->

# Named Profiles and Profile Acceptance


## Supported profiles

### `minimal`

Config, core runtime, HTTP shell, errors, tracing, health, graceful shutdown, test support, generator metadata. No external service.

### `api`

`minimal` plus PostgreSQL, migrations, validation, Problem Details, OpenAPI, idempotency, and outbound HTTP client.

### `authenticated-api`

`api` plus password/session authentication, JWT verification, authorization, CSRF, local rate limits, security audit events, and PostgreSQL session store.

### `saas`

`authenticated-api` plus organizations/tenancy, invitations, audit, email/notifications, object storage, jobs, outbox/inbox, inbound/outbound webhooks, and feature flags. Default durable jobs use Redis/Apalis; a PGMQ variant is separately verified.

### `realtime`

`authenticated-api` plus SSE, WebSockets, presence, and Redis or NATS fan-out. The default uses Redis for ephemeral fan-out; durable replay requires NATS/outbox variant.

### `worker`

Config, telemetry, health/admin listener, PostgreSQL, selected queue/event provider, jobs, outbox relay, and integration adapters. No public API router.

### `full-reference`

A reference/CI composition exercising almost every non-conflicting module. It is not a recommended production starting point.

## Profile manifest

`machine/profiles.yaml` is derived from these definitions and specifies provider choices. A generated service records the exact profile version plus additions/removals.

## Common acceptance

Every profile:

- Generates from an empty directory.
- Uses only approved stable dependencies.
- Formats, lints without warnings, compiles, tests, and documents.
- Passes `cargo audit`, `cargo deny`, `cargo vet`, SBOM, semver, and spec verification.
- Starts with valid local config.
- Fails safely with invalid config.
- Exposes correct live/startup/ready/version behavior.
- Shuts down under deadline.
- Contains no unresolved placeholder.
- Produces a reproducible dependency graph and lockfile.

## Profile-specific acceptance

### Minimal

- Starts with no external services.
- `/live`, `/ready`, `/startup`, `/version`, and one example route work.
- Request ID, Problem Details, limits, trace, panic boundary, and drain are proven.
- Release binary and idle-memory targets are measured.

### API

- Clean database migrates.
- CRUD reference use case proves transactions, constraints, idempotency, cursor pagination, optimistic concurrency, OpenAPI, and errors.
- Pool exhaustion and DB outage affect readiness as designed.
- Migration command is separate in production mode.

### Authenticated API

- Complete registration/verification/login/logout/reset/session-revoke flow.
- Session fixation, CSRF, enumeration, JWT validation, key rotation, rate limits, and authorization matrix pass.
- One endpoint demonstrates session and bearer identity mapping to the same `Principal`.

### SaaS

- Tenant isolation is proven across HTTP, jobs, cache, objects, search stub, and webhooks.
- Notification and webhook delivery are durable and idempotent.
- Outbox/inbox recover from restarts.
- Object upload passes quarantine/authorization/lifecycle.
- Audit records every administrative and security-sensitive action.

### Realtime

- Auth/origin/message authz, connection limits, slow consumer, revocation, multi-instance fan-out, and graceful drain pass.
- Replay/resume is offered only in durable variant.

### Worker

- Stops leasing on drain.
- Retries/dead-letter/idempotency pass.
- Admin health/metrics are protected.
- Fatal required task exit causes correct readiness/termination.

### Full reference

- All provider slots resolve without incompatible foundational duplicates.
- Cross-module flows pass end-to-end.
- Generated docs list every enabled capability and operational dependency.

## Invalid combinations

Generator negative tests include:

- Cache Redis without Redis core.
- Realtime Redis fan-out without Redis.
- Auth session provider missing a store.
- Two job providers selected as default.
- GraphQL subscriptions without realtime.
- Tenant module without authorization/audit.
- Removal of a dependency still required by another module.
- SQLx 0.9 forced into the 0.8 baseline without the upgrade ADR.


<!-- END 19-profiles-and-acceptance.md -->


---

<!-- BEGIN 20-implementation-roadmap.md -->

# Implementation Roadmap


## Phase 0 — Compatibility and repository skeleton

Deliver:

- Rust 1.98.0/edition 2024 workspace.
- Dependency compatibility spike.
- `cargo tree -d` review.
- Baseline lockfile and dependency policy.
- ADRs 0001–0007.
- Spec/profile validators.
- CI skeleton.

Exit: every foundational candidate resolves; session store and job-provider variants are proven or explicitly deferred; no unexplained foundational duplicate.

## Phase 1 — Runtime kernel

Config, secrets, errors, IDs/time/clock, Axum/Tower shell, request ID, traces, Problem Details, health/startup/readiness, supervision, shutdown, build metadata, minimal profile.

Exit: minimal profile acceptance passes.

## Phase 2 — Test support

Nextest, test fixtures, deterministic clock/IDs, test server, Wiremock, Testcontainers plumbing, profile harness, generator snapshot tests.

Exit: clean CI provisions and tears down dependencies reliably without sleeps.

## Phase 3 — PostgreSQL and API contracts

SQLx pool, migrations, checked queries/offline metadata, transaction/retry helpers, CRUD reference domain, idempotency, pagination, ETag, OpenAPI, validation, outbound client.

Exit: API profile acceptance and migration upgrade rehearsal pass.

## Phase 4 — Identity

Principal, users/credentials, Argon2id, verification/reset, sessions, CSRF, JWT/JWKS, OIDC adapter, API keys, optional WebAuthn/TOTP, security events.

Exit: authenticated-api acceptance and threat tests pass.

## Phase 5 — Authorization, tenancy, audit

Built-in evaluator, permission matrix, organization/membership, tenant query discipline, audit, admin/impersonation, optional Cedar.

Exit: all horizontal/vertical/cross-tenant tests pass through every invocation path.

## Phase 6 — Redis/cache/rate limits

Redis core, Moka/Redis cache, failure policy, local rate limits, optional Redis session store, Pub/Sub adapter.

Exit: outage/reconnect/stampede/cardinality tests pass.

## Phase 7 — Durable work and events

Job provider interface, Apalis/Redis provider, optional PGMQ spike, outbox/inbox, scheduler, NATS JetStream provider, admin diagnostics.

Exit: at-least-once/idempotency/restart/drain/dead-letter tests pass.

## Phase 8 — Realtime

SSE, WebSocket protocol, auth/authz, bounded queues, slow-consumer behavior, fan-out, drain, optional replay.

Exit: realtime profile acceptance and load scenario pass.

## Phase 9 — Storage, email, notifications, webhooks

`object_store`, upload quarantine/scanner port, lettre/MiniJinja, notification orchestration, Svix adapter, inbound webhook framework, SSRF policy.

Exit: durable delivery, signature/replay, upload lifecycle, redaction tests pass.

## Phase 10 — Optional modules

Feature flags, search projection, billing/entitlement adapter skeleton, GraphQL, gRPC, localization, privacy lifecycle, consent, moderation.

Exit: each selected module satisfies standard lifecycle and profile tests; no optional module enters default profiles accidentally.

## Phase 11 — Generator and upgrade engine

`cargo-generate` template, module catalog, add/remove/doctor/diff/upgrade commands, managed regions, ownership enforcement, profile generation.

Exit: all profiles generate; add/remove is idempotent; upgrade rehearsals preserve application edits/data.

## Phase 12 — Hardening and release

Load/soak/failure tests, security review, cargo-vet imports, SBOM/provenance, runbooks, API compatibility, documentation, release process, supported-version policy.

Exit: complete traceability, zero open blocker, full-reference profile, signed release artifact.

## Phase discipline

A later phase may begin only when required interfaces are stable and the previous phase exit is recorded. Optional provider spikes may run early but cannot alter baseline silently.


<!-- END 20-implementation-roadmap.md -->


---

<!-- BEGIN 21-crate-selection-matrix.md -->

# Crate Selection and Compatibility Matrix


## Selection rule

“Battle-hardened” is not reduced to popularity. Admission weighs stable releases, maintenance, documentation, ecosystem role, security record, license, MSRV, dependency convergence, and whether an established external service is more appropriate.

The observed version is the reviewed baseline as of August 23, 2026. Phase 0 must resolve exact patches and record the lockfile. Default profiles may not drift to a different major/minor line automatically.

## Matrix

| Area | Selected component | Baseline | Status | Rationale | Constraint/alternative | Source |
|---|---|---:|---|---|---|---|
| Toolchain | `Rust` | 1.98.0 | **Default** | Current stable; edition 2024; pin for reproducibility. | Do not use `stable` floating in release builds. | `SRC-RUST-001` |
| Runtime | `tokio` | 1.53.1 | **Default** | De facto async runtime; broad ecosystem fit. | Do not add a second runtime. | `SRC-TOKIO-001` |
| HTTP | `axum` | 0.8.9 | **Default** | Tokio/Tower-native, maintained under Tokio ecosystem. | Actix/Rocket are valid elsewhere but would split architecture. | `SRC-AXUM-001` |
| Services | `tower` | 0.5.3 | **Default** | Standard service/layer model used by Axum and Tonic. | Avoid custom middleware framework. | `SRC-TOWER-001` |
| HTTP middleware | `tower-http` | 0.7.0 | **Default** | Maintained common middleware; now includes CSRF/cross-origin protection. | Avoid miscellaneous one-off middleware crates when tower-http covers it. | `SRC-TOWERHTTP-001` |
| Runtime utilities | `tokio-util` | 0.7.x | **Default** | CancellationToken, codec/task utilities; aligned with Tokio. | Phase 0 pins exact patch. | `SRC-TOKIO-002` |
| Serialization | `serde / serde_json` | 1.x | **Default** | Rust ecosystem standard. | No replacement abstraction. | `SRC-AXUM-001` |
| Errors | `thiserror` | 2.x | **Default** | Typed reusable errors. | `anyhow` limited to binaries/tools. | `SRC-RUST-001` |
| CLI errors | `anyhow` | 1.x | **Limited** | Excellent contextual errors in composition/ops commands. | Not exposed from library/domain APIs. | `SRC-RUST-001` |
| Config | `config` | 0.15.25 | **Default** | Layered, typed configuration. | Figment considered; config has broader neutral adoption. | `SRC-CONFIG-001` |
| Secrets | `secrecy` | 0.10.3 | **Default** | Explicit secret exposure and redacted formatting. | Not a secret manager. | `SRC-SECRECY-001` |
| CLI | `clap` | 4.6.6 | **Default** | Mature derive/builder CLI. | No custom parser. | `SRC-CLAP-001` |
| Validation | `garde` | 0.23.0 | **Default** | Typed derive validation, context, nested reports. | `validator` is acceptable by ADR; one library only. | `SRC-GARDE-001` |
| OpenAPI | `utoipa` | 5.5.0 | **Default in API profiles** | Established code-first OpenAPI integration. | `aide` rejected as simultaneous second schema stack. | `SRC-UTOIPA-001` |
| Problem Details | `local thin type` | RFC 9457 | **Default** | Small stable wire contract; no need for an obscure framework. | Must conform exactly; not a new error framework. | `SRC-RFC9457` |
| HTTP client | `reqwest` | 0.13.4 | **Default** | Mature async client; reusable pools; rustls support. | No per-request client construction. | `SRC-REQWEST-001` |
| Database | `sqlx` | 0.8.6 | **Default** | Async SQL, checked queries, migrations; compatible surrounding ecosystem. | 0.9.0 upgrade is gated; Diesel not mixed into baseline. | `SRC-SQLX-001` |
| Database latest | `sqlx` | 0.9.0 | **Candidate** | Current observed release. | Not default until session/jobs/telemetry graph converges. | `SRC-SQLX-002` |
| Redis | `redis` | 1.6.0 | **Optional foundation** | Official client; async multiplexed connections and reconnection manager. | No default deadpool/bb8 for async use. | `SRC-REDIS-001` |
| Local cache | `moka` | 0.12.16 | **Optional default** | Mature bounded concurrent cache. | Do not use unbounded DashMap as cache. | `SRC-MOKA-001` |
| Sessions | `axum-login` | 0.18.0 | **Default authenticated profile** | Integrates auth backend and sessions with Axum. | Pin to compatible tower-sessions graph in Phase 0. | `SRC-AXUMLOGIN-001` |
| Session middleware | `tower-sessions` | 0.15.x compatible line | **Default authenticated profile** | Established Tower session layer with provider stores. | Exact core/store versions are compatibility-gated. | `SRC-SESSIONS-001` |
| Session SQL store | `tower-sessions-sqlx-store` | 0.15.0 candidate | **Default after Phase 0** | Maintained store currently targets SQLx 0.8. | Do not write a custom store if graph resolves. | `SRC-SESSIONS-002` |
| Password hash | `argon2` | 0.5.3 | **Default password auth** | RustCrypto Argon2id/PHC implementation. | Never custom KDF. | `SRC-ARGON2-001` |
| JWT | `jsonwebtoken` | 11.0.0 | **Default bearer module** | Widely adopted JWT/JWK support. | Do not parse/verify JWT manually. | `SRC-JWT-001` |
| OIDC | `openidconnect` | 4.0.1 | **Optional auth** | Protocol-aware OIDC client/verifier. | OAuth alone is not identity. | `SRC-OIDC-001` |
| OAuth client | `oauth2` | 5.0.0 | **Optional auth** | PKCE and OAuth client flows. | No custom protocol implementation. | `SRC-OAUTH-001` |
| Passkeys | `webauthn-rs` | 0.5.5+ | **Optional auth** | Security-focused WebAuthn implementation. | Minimum line must include current security fixes. | `SRC-WEBAUTHN-001` |
| TOTP | `totp-rs` | 6.0.0 | **Optional auth** | Maintained TOTP implementation. | Seed storage/replay remain app responsibilities. | `SRC-TOTP-001` |
| Policy engine | `cedar-policy` | 4.12.x | **Optional** | Official Cedar engine for RBAC/ABAC/ReBAC. | Basic provider remains simpler default. | `SRC-CEDAR-001` |
| Rate limit | `governor` | 0.10.4 | **Default local** | Established GCRA implementation. | Not a distributed-global limiter. | `SRC-GOVERNOR-001` |
| Rate limit layer | `tower-governor` | 0.8.0 | **Default local** | Tower/Axum adapter for governor. | Global quotas require edge/Redis design. | `SRC-TOWERGOV-001` |
| Object storage | `object_store` | 0.14.1 | **Default optional** | Apache-maintained multi-cloud/local abstraction. | Official SDK may be used for provider-only features. | `SRC-OBJECTSTORE-001` |
| Object alternative | `opendal` | current stable | **Candidate** | Broader backend matrix. | Only by ADR; do not compile both by default. | `SRC-OPENDAL-001` |
| Email | `lettre` | 0.11.23 | **Default optional** | Mature message/SMTP implementation. | Provider HTTP APIs remain separate adapters. | `SRC-LETTRE-001` |
| Templates | `minijinja` | 2.24.0 | **Default notifications** | Mature runtime templates. | Askama is alternative for compile-time templates, not simultaneous. | `SRC-MINIJINJA-001` |
| Jobs | `apalis + apalis-redis` | 0.7.4 | **Default Redis jobs by ADR-0011** | Stable Tower-inspired job processing and Redis backend. | Isolated Redis 0.32.7 line and future-incompatibility controls are mandatory; prerelease upgrades excluded. | `SRC-APALIS-001` |
| Postgres jobs | `pgmq` | 0.33.7 | **Optional provider** | Avoids custom queue when PGMQ SQL installation is acceptable. | Phase 0 passed on SQLx 0.8.6; operators own versioned embedded SQL installation. | `SRC-PGMQ-001` |
| Rejected jobs | `sqlxmq` | 0.6.0 | **Rejected default** | Stable release targets old SQLx line. | May be reconsidered after maintained compatible release. | `SRC-SQLXMQ-001` |
| Rejected jobs | `apalis-postgres` | 1.0 prerelease | **Rejected default** | Prerelease at verification time. | No RC in default profile. | `SRC-APALISPG-001` |
| Events | `async-nats` | 0.50.0 | **Optional** | Official async NATS client including JetStream. | Redis Pub/Sub remains ephemeral only. | `SRC-NATS-001` |
| Webhooks | `Svix client/service` | 1.99.1 | **Default production outbound** | Purpose-built, mature webhook delivery/retry platform. | Local fake only for tests/dev. | `SRC-SVIX-001` |
| Tracing | `tracing` | 0.1.x | **Default** | Rust standard structured instrumentation. | No parallel logging facade in application code. | `SRC-TRACING-001` |
| Trace subscriber | `tracing-subscriber` | 0.3.23 | **Default** | Filtering, formatting, layering. | Centralized bootstrap. | `SRC-TRACINGSUB-001` |
| OTel bridge | `tracing-opentelemetry` | 0.33.0 | **Default optional export** | Maintained bridge. | Version line pinned with OTel. | `SRC-TRACINGOTEL-001` |
| OTLP | `opentelemetry-otlp` | 0.32.0 | **Default optional export** | Standard exporter. | Exporter failure is best effort. | `SRC-OTLP-001` |
| Metrics | `metrics` | 0.24.6 | **Default** | Stable facade decouples instrumentation/exporter. | Avoid high-cardinality labels. | `SRC-METRICS-001` |
| Prometheus | `metrics-exporter-prometheus` | 0.18.3 | **Default metrics exporter** | Straightforward scrape endpoint/recorder. | Expose only on admin surface. | `SRC-PROM-001` |
| Integration tests | `testcontainers` | 0.28.0 | **Default test support** | Real disposable infrastructure. | Do not replace with mocks alone. | `SRC-TESTCONTAINERS-001` |
| Test runner | `cargo-nextest` | current stable CLI | **Default tool** | Isolation, groups, partitions, timeouts. | Retries only temporary diagnosed flakes. | `SRC-NEXTEST-001` |
| HTTP mocks | `wiremock` | current stable | **Default test support** | Behavioral provider contract tests. | No production dependency. | `SRC-WIREMOCK-001` |
| Property tests | `proptest` | current stable | **Default test support** | State/parser invariant generation. | Use selectively, not as replacement for examples. | `SRC-PROPTEST-001` |
| Fuzzing | `cargo-fuzz` | current stable CLI | **Default security tooling** | libFuzzer integration for untrusted parsers. | CI smoke plus scheduled longer runs. | `SRC-FUZZ-001` |
| GraphQL | `async-graphql` | 7.2.1 | **Optional** | Mature integrated GraphQL server. | Not included unless selected. | `SRC-GRAPHQL-001` |
| gRPC | `tonic` | 0.14.6 | **Optional** | Tokio/Tower-native gRPC. | Shares application services. | `SRC-TONIC-001` |
| Feature flags | `open-feature` | 0.3.x | **Optional** | Vendor-neutral evaluation API. | Provider selected separately; no auth bypass. | `SRC-OPENFEATURE-001` |
| Localization | `fluent-bundle` | 0.16.x | **Optional** | Project Fluent runtime localization. | Not in kernel. | `SRC-FLUENT-001` |
| Search | `meilisearch-sdk` | 0.33.x | **Optional default adapter** | Straightforward search projection client. | Search remains derived; OpenSearch by ADR. | `SRC-MEILI-001` |
| Generator | `cargo-generate` | current stable CLI | **Initial generation** | Established project templating. | Ongoing changes use owned xtask. | `SRC-GENERATE-001` |
| Advisories | `cargo-audit` | current stable CLI | **Required** | RustSec advisory scanning. | No unowned permanent ignores. | `SRC-AUDIT-001` |
| Policy | `cargo-deny` | current stable CLI | **Required** | Licenses, sources, advisories, duplicates. | CI blocking. | `SRC-DENY-001` |
| Supply-chain review | `cargo-vet` | current stable CLI | **Required release** | Audits/imports dependency reviews. | Policy maintained as code. | `SRC-VET-001` |
| SBOM | `cargo-cyclonedx` | current stable CLI | **Required release** | CycloneDX component inventory. | Attached to release. | `SRC-CYCLONEDX-001` |
| API compatibility | `cargo-semver-checks` | current stable CLI | **Required public crates** | Detects unintended breaking API changes. | Run against previous release. | `SRC-SEMVER-001` |

## Compatibility gates

### Foundational duplicate gate

`cargo tree -d` must show no unexplained duplicate major lines for Tokio, Hyper, Axum, Tower, SQLx, rustls, Serde, OpenTelemetry, or tower-sessions core. Duplicate utility crates are reviewed but not automatically prohibited.

### SQLx gate

The initial line is 0.8.6. Upgrading requires:

- Session store and auth stack compiling on one SQLx line.
- Job providers not forcing a conflicting line in shared types.
- Migration/query macro compatibility.
- Testcontainers and offline metadata workflow.
- Clean migration and performance tests.
- Accepted ADR and release note.

### Authentication gate

Resolve `axum-login`, `tower-sessions`, and selected store in a miniature workspace before core implementation. Use the versions that are mutually supported, even when their package version numbers differ.

### OpenTelemetry gate

Pin `tracing-opentelemetry`, `opentelemetry`, SDK, semantic conventions, and OTLP exporter as one tested set. They change together.

### Prerelease gate

A prerelease may be used only in an experimental non-default profile with an ADR, exact pin, and upgrade/removal plan.


<!-- END 21-crate-selection-matrix.md -->


---

<!-- BEGIN 22-recommendation-traceability.md -->

# Recommendation Traceability


This matrix verifies that every substantive recommendation in the original design is represented in a normative specification and a concrete acceptance criterion.

| ID | Recommendation | Specification | Verification |
|---|---|---|---|
| `REC-001` | Use workspace-level explicit composition instead of one enormous feature matrix | `RSK-001; RSK-002` | `AC-GEN-001` |
| `REC-002` | Reserve Cargo features for additive implementation details | `RSK-002` | `AC-GEN-005` |
| `REC-003` | Provide generated profiles, workspace crates, runtime config, and product flags as distinct toggle mechanisms | `RSK-002; RSK-019` | `AC-GEN-001` |
| `REC-004` | Use meaningful crate boundaries rather than one crate per table | `RSK-001` | `AC-GEN-001` |
| `REC-005` | Define module dependencies and conflicts | `RSK-002` | `AC-GEN-002` |
| `REC-006` | Define configuration and validation per module | `RSK-002; RSK-004` | `AC-CFG-005` |
| `REC-007` | Define initialization and startup ordering per module | `RSK-002; RSK-003` | `AC-CORE-002` |
| `REC-008` | Define routes, middleware, and extractors per module | `RSK-002; RSK-005` | `AC-GEN-001` |
| `REC-009` | Expose typed application capabilities rather than raw optional state | `RSK-001; RSK-002` | `AC-GEN-001` |
| `REC-010` | Supervise module background tasks | `RSK-002; RSK-003` | `AC-CORE-004` |
| `REC-011` | Register module liveness/readiness behavior | `RSK-002; RSK-014` | `AC-OBS-004` |
| `REC-012` | Register module metrics and trace attributes | `RSK-002; RSK-014` | `AC-OBS-002` |
| `REC-013` | Participate in graceful shutdown | `RSK-002; RSK-003` | `AC-CORE-004` |
| `REC-014` | Supply module test fixtures and fakes | `RSK-002; RSK-016` | `AC-TEST-002` |
| `REC-015` | Document failure semantics and criticality | `RSK-001; RSK-014` | `AC-OBS-004` |
| `REC-016` | Distinguish required, degraded, and best-effort dependencies | `RSK-001; RSK-014` | `AC-OBS-004` |
| `REC-017` | Avoid a global AppState full of Option handles | `RSK-001` | `AC-GEN-001` |
| `REC-018` | Use source-level modules, not a dynamic Rust plugin ABI | `RSK-001; RSK-002` | `AC-GEN-001` |
| `REC-019` | Layer typed configuration sources | `RSK-004` | `AC-CFG-001` |
| `REC-020` | Strictly validate config at startup | `RSK-004` | `AC-CFG-002` |
| `REC-021` | Separate local/test/staging/production configuration | `RSK-004` | `AC-CFG-003` |
| `REC-022` | Protect secrets from Debug and diagnostics | `RSK-004; RSK-015` | `AC-CFG-004` |
| `REC-023` | Expose build version, revision, and environment metadata | `RSK-003` | `AC-CORE-006` |
| `REC-024` | Detect unknown/misspelled configuration keys | `RSK-004` | `AC-CFG-002` |
| `REC-025` | Order initialization and fail fast | `RSK-003` | `AC-CORE-002` |
| `REC-026` | Implement startup timeout and signal handling | `RSK-003` | `AC-CORE-004` |
| `REC-027` | Propagate cancellation and track tasks | `RSK-003` | `AC-CORE-004` |
| `REC-028` | Drain HTTP, WebSocket, and worker workloads gracefully | `RSK-003; RSK-010; RSK-011` | `AC-CORE-004` |
| `REC-029` | Flush telemetry on shutdown | `RSK-003; RSK-014` | `AC-CORE-004` |
| `REC-030` | Use Axum/Tokio/Tower/tower-http | `RSK-021; ADR-0001` | `AC-CORE-001` |
| `REC-031` | Implement request/correlation IDs | `RSK-005` | `AC-HTTP-001` |
| `REC-032` | Use structured request logging and trace propagation | `RSK-005; RSK-014` | `AC-OBS-002` |
| `REC-033` | Bound bodies, headers, URLs, concurrency, and timeouts | `RSK-005` | `AC-HTTP-003` |
| `REC-034` | Provide compression, CORS, panic boundaries, and security headers | `RSK-005` | `AC-HTTP-005` |
| `REC-035` | Trust forwarded headers only from trusted proxies | `RSK-005` | `AC-HTTP-004` |
| `REC-036` | Use a stable Problem Details error contract | `RSK-005` | `AC-HTTP-002` |
| `REC-037` | Define cursor pagination, filters, sorting, IDs, UTC timestamps, and API versioning | `RSK-005` | `AC-HTTP-006` |
| `REC-038` | Support idempotency keys and optimistic concurrency | `RSK-005; RSK-006` | `AC-HTTP-007` |
| `REC-039` | Create canonical request context with principal and tenant | `RSK-001; RSK-005` | `AC-AUTH-009` |
| `REC-040` | Separate liveness, readiness, startup, diagnostics, and version endpoints | `RSK-014` | `AC-OBS-004` |
| `REC-041` | Reuse configured outbound HTTP clients | `RSK-005; RSK-013` | `AC-HTTP-010` |
| `REC-042` | Set outbound connect/request/idle timeouts and safe retries | `RSK-005; RSK-013` | `AC-WEBHOOK-004` |
| `REC-043` | Configure PostgreSQL URL/TLS and pool lifecycle | `RSK-006` | `AC-DB-005` |
| `REC-044` | Set DB pool min/max/acquire/idle/lifetime and init statements | `RSK-006` | `AC-DB-005` |
| `REC-045` | Define statement/transaction timeout and retry policy | `RSK-006` | `AC-DB-007` |
| `REC-046` | Use migrations with a coordinated production policy | `RSK-006; RSK-017` | `AC-DB-002` |
| `REC-047` | Instrument queries and pool utilization | `RSK-006; RSK-014` | `AC-DB-005` |
| `REC-048` | Support test database creation and deterministic fixtures | `RSK-006; RSK-016` | `AC-DB-009` |
| `REC-049` | Plan read replicas, backups, and restore | `RSK-006; RSK-017` | `AC-DEPLOY-003` |
| `REC-050` | Support rolling expand/migrate/contract migrations | `RSK-006; RSK-017` | `AC-DB-004` |
| `REC-051` | Split Redis by cache, session, rate-limit, pubsub, lock, stream, and jobs | `RSK-007; RSK-002` | `AC-GEN-002` |
| `REC-052` | Use Redis reconnection, TLS, namespace, TTL, serialization, and metrics policies | `RSK-007` | `AC-REDIS-001` |
| `REC-053` | Define cache stampede, negative caching, and invalidation | `RSK-007` | `AC-REDIS-003` |
| `REC-054` | Define fail-open versus fail-closed per Redis use | `RSK-007` | `AC-REDIS-004` |
| `REC-055` | Do not add an async Redis pool without need | `RSK-007; RSK-021` | `AC-REDIS-001` |
| `REC-056` | Provide no-op, in-process, and Redis cache implementations | `RSK-007` | `AC-REDIS-002` |
| `REC-057` | Provide local and S3-compatible object storage plus streaming, checksums, signed URLs, and cleanup | `RSK-012` | `AC-STORAGE-001` |
| `REC-058` | Add upload filename/MIME/malware and authorization controls | `RSK-012` | `AC-STORAGE-002` |
| `REC-059` | Provide transactional outbox | `RSK-010` | `AC-JOB-003` |
| `REC-060` | Provide inbox/deduplication | `RSK-010` | `AC-JOB-004` |
| `REC-061` | Provide an idempotency store | `RSK-005; RSK-006` | `AC-HTTP-007` |
| `REC-062` | Use distributed locks only when truly required | `RSK-007` | `AC-REDIS-008` |
| `REC-063` | Provide optimistic concurrency and audit history | `RSK-005; RSK-009` | `AC-HTTP-008` |
| `REC-064` | Decompose auth into core, session, JWT, password, OIDC, API key, passkey, and authorization modules | `RSK-008; RSK-002` | `AC-GEN-002` |
| `REC-065` | Map every credential mechanism to one Principal | `RSK-008` | `AC-AUTH-009` |
| `REC-066` | Use server-side sessions for first-party browser apps | `RSK-008` | `AC-AUTH-001` |
| `REC-067` | Implement secure cookie, expiry, rotation, device list, revoke, cleanup, and CSRF | `RSK-008` | `AC-AUTH-002` |
| `REC-068` | Use JWT primarily as a resource-server verifier | `RSK-008` | `AC-AUTH-006` |
| `REC-069` | Validate JWT algorithm/signature/issuer/audience/time/JWKS and token class | `RSK-008` | `AC-AUTH-006` |
| `REC-070` | Use short access tokens and rotating refresh tokens with reuse detection when self-issued | `RSK-008` | `AC-AUTH-007` |
| `REC-071` | Use Argon2id, PHC strings, rehash-on-login, and anti-enumeration | `RSK-008` | `AC-AUTH-003` |
| `REC-072` | Use random single-use hashed reset/verification tokens | `RSK-008` | `AC-AUTH-005` |
| `REC-073` | Use OIDC Authorization Code + PKCE, state, nonce, discovery, and safe linking | `RSK-008` | `AC-AUTH-008` |
| `REC-074` | Provide API key prefixes, hashes, scopes, expiry, rotation, last-used, revocation, and audit | `RSK-008` | `AC-AUTH-010` |
| `REC-075` | Support passkeys/WebAuthn as an optional module | `RSK-008` | `AC-AUTH-011` |
| `REC-076` | Keep authentication and authorization separate | `RSK-008; RSK-009` | `AC-AUTHZ-001` |
| `REC-077` | Authorize principal/action/resource/context at application boundary | `RSK-009` | `AC-AUTHZ-001` |
| `REC-078` | Start with RBAC, ownership, tenant membership, and default deny | `RSK-009` | `AC-AUTHZ-002` |
| `REC-079` | Offer Cedar for complex RBAC/ABAC/ReBAC | `RSK-009` | `AC-AUTHZ-005` |
| `REC-080` | Test horizontal, vertical, cross-tenant, list, bulk, and stale-claim access | `RSK-009; RSK-016` | `AC-AUTHZ-003` |
| `REC-081` | WebSocket upgrade auth, origin, frame limits, heartbeat, revalidation, and connection limits | `RSK-011` | `AC-RT-001` |
| `REC-082` | Authorize every WebSocket subscription and command | `RSK-011` | `AC-RT-002` |
| `REC-083` | Use bounded realtime queues and slow-consumer handling | `RSK-011` | `AC-RT-003` |
| `REC-084` | Support reconnect/resume only with real replay storage | `RSK-011` | `AC-RT-006` |
| `REC-085` | Separate domain events from WebSocket transport and include SSE | `RSK-011` | `AC-RT-005` |
| `REC-086` | Provide durable jobs with versioning, retry, timeout, dedupe, priority, scheduling, dead-letter, lease, metrics, and drain | `RSK-010` | `AC-JOB-005` |
| `REC-087` | Use an established job crate/backend rather than custom queue | `RSK-010; RSK-021` | `AC-JOB-001` |
| `REC-088` | Support in-process, Redis, Postgres outbox, NATS, and optional Kafka event adapters by explicit semantics | `RSK-010` | `AC-JOB-008` |
| `REC-089` | Standardize event ID/type/version/time/producer/tenant/correlation/causation/trace/idempotency | `RSK-010` | `AC-JOB-009` |
| `REC-090` | Define scheduler leader, misfire, and catch-up behavior | `RSK-010` | `AC-JOB-007` |
| `REC-091` | Provide signed/replay-protected outbound webhooks with retries, rotation, logs, replay, suspension, and SSRF protection | `RSK-013` | `AC-WEBHOOK-001` |
| `REC-092` | Verify inbound raw-body signatures before parsing and process asynchronously | `RSK-013` | `AC-WEBHOOK-002` |
| `REC-093` | Provide organizations/tenancy | `RSK-009; RSK-018` | `AC-AUTHZ-003` |
| `REC-094` | Provide append-only audit | `RSK-009` | `AC-AUTHZ-007` |
| `REC-095` | Provide protected admin/support and audited impersonation | `RSK-009; RSK-018` | `AC-AUTHZ-008` |
| `REC-096` | Provide email/notifications with providers, templates, retries, preferences, and unsubscribe | `RSK-012` | `AC-MAIL-002` |
| `REC-097` | Provide billing/entitlements with webhook reconciliation and grace policy | `RSK-018` | `AC-WEBHOOK-002` |
| `REC-098` | Provide feature flags by environment/tenant/user/cohort | `RSK-018` | `AC-OPT-001` |
| `REC-099` | Provide versioned derived search and backfills | `RSK-018` | `AC-OPT-002` |
| `REC-100` | Provide optional GraphQL with limits/loaders/authz | `RSK-018` | `AC-OPT-003` |
| `REC-101` | Provide optional gRPC with interceptors/deadlines/health | `RSK-018` | `AC-OPT-003` |
| `REC-102` | Provide localization, time zone, and currency handling | `RSK-018` | `AC-OPT-004` |
| `REC-103` | Provide data export/deletion/retention/anonymization/legal hold | `RSK-018` | `AC-OPT-004` |
| `REC-104` | Provide consent/legal records | `RSK-018` | `AC-OPT-004` |
| `REC-105` | Provide moderation reports/actions/appeals/evidence | `RSK-018` | `AC-AUTHZ-001` |
| `REC-106` | Make OpenAPI generation/validation first-class | `RSK-005` | `AC-HTTP-009` |
| `REC-107` | Separate boundary validation from domain invariants | `RSK-005` | `AC-HTTP-002` |
| `REC-108` | Use structured tracing with JSON production and human local logs | `RSK-014` | `AC-OBS-001` |
| `REC-109` | Propagate OpenTelemetry and redact PII/secrets | `RSK-014` | `AC-OBS-002` |
| `REC-110` | Provide HTTP/DB/Redis/outbound/jobs/realtime/auth/authz/process metrics | `RSK-014` | `AC-OBS-003` |
| `REC-111` | Rate-limit by IP/account/tenant/API key/route/auth state | `RSK-007` | `AC-REDIS-006` |
| `REC-112` | Provide multi-stage non-root container, resource limits, trusted proxy, migration deployment, separate roles, SBOM/provenance | `RSK-017; RSK-015` | `AC-DEPLOY-001` |
| `REC-113` | Provide operational executable modes for server/worker/scheduler/migrate/seed/backfill/reindex/replay/inspect | `RSK-001; RSK-017` | `AC-DEPLOY-002` |
| `REC-114` | Run fmt, clippy, tests, audit, deny, vet, semver, and SBOM checks | `RSK-015; RSK-016` | `AC-SEC-001` |
| `REC-115` | Build test architecture with unit, HTTP, real infra, authz, auth, realtime, job, contract, property, fuzz, and load tests | `RSK-016` | `AC-TEST-002` |
| `REC-116` | Use deterministic clock, IDs, random, and provider fakes | `RSK-016` | `AC-TEST-001` |
| `REC-117` | Test named profiles and pairwise combinations, not only all-features | `RSK-016; RSK-019` | `AC-TEST-001` |
| `REC-118` | Provide minimal/api/authenticated-api/saas/realtime/worker/full profiles | `RSK-019` | `AC-GEN-001` |
| `REC-119` | Use cargo-generate for initial templating and xtask for ongoing management | `RSK-002; RSK-021` | `AC-GEN-001` |
| `REC-120` | Avoid abstracting every database/provider behind lowest-common-denominator traits | `RSK-001; RSK-002` | `AC-GEN-001` |
| `REC-121` | Use traits only for genuinely volatile integrations | `RSK-002` | `AC-GEN-001` |
| `REC-122` | Do not pretend WebSockets, Socket.IO, SSE, and queues share transport semantics | `RSK-011` | `AC-RT-006` |
| `REC-123` | Adopt the researched baseline of Tokio/Axum/Tower/SQLx/Redis/sessions/JWT/Argon2/tracing/utoipa/garde/reqwest/testing/security tools | `RSK-021` | `AC-SEC-002` |
| `REC-124` | Implement in ordered phases and prove boundaries in reference applications before freezing generator | `RSK-020; RSK-023` | `AC-GEN-004` |

**Coverage:** 124 recommendations; 0 intentionally omitted.


<!-- END 22-recommendation-traceability.md -->


---

<!-- BEGIN 23-agent-task-graph.md -->

# Autonomous Agent Task Graph


Tasks are dependency-ordered. A task is complete only when its acceptance criterion and relevant profile commands pass.

| Task | Phase | Work | Depends on | Required output | Acceptance |
|---|---:|---|---|---|---|
| `T000` | 0 | Create repository/workspace skeleton | — | workspace manifests, rust-toolchain, CI stub | `AC-REPO-001` |
| `T001` | 0 | Resolve and record foundational dependency graph | T000 | compatibility workspace, cargo tree report, lockfile | `AC-DB-001` |
| `T002` | 0 | Resolve axum-login/tower-sessions/store stack | T001 | auth compatibility report | `AC-COMPAT-001` |
| `T003` | 0 | Spike Apalis Redis and PGMQ providers | T001 | provider compatibility report and ADR | `AC-JOB-001` |
| `T004` | 0 | Install dependency policy and supply-chain tooling | T001 | deny.toml, vet config, audit/SBOM CI | `AC-SEC-001` |
| `T005` | 0 | Implement spec/profile/catalog validators | T000 | xtask specs/profiles verify | `AC-GEN-005` |
| `T010` | 1 | Implement core IDs, clock, errors, build metadata | T001 | core crate | `AC-CORE-006` |
| `T011` | 1 | Implement layered config and secret wrappers | T010 | config crate and examples | `AC-CFG-001` |
| `T012` | 1 | Implement telemetry bootstrap | T010;T011 | tracing/metrics initialization | `AC-OBS-001` |
| `T013` | 1 | Implement runtime supervisor and cancellation | T010;T012 | runtime supervisor | `AC-CORE-004` |
| `T014` | 1 | Implement HTTP shell and middleware order | T010;T013 | Axum router shell | `AC-HTTP-003` |
| `T015` | 1 | Implement Problem Details and request IDs | T014 | error mapping/request ID | `AC-HTTP-002` |
| `T016` | 1 | Implement probes, readiness cache, and drain | T013;T014 | health endpoints and shutdown | `AC-OBS-004` |
| `T017` | 1 | Complete minimal reference service | T011;T012;T015;T016 | minimal profile app | `AC-CORE-001` |
| `T020` | 2 | Build deterministic test-support crate | T010;T011;T014 | deterministic clock, IDs/randomness, config builders, test server/client | `AC-TEST-001` |
| `T021` | 2 | Install nextest and test groups | T004;T020 | nextest config | `AC-TEST-001` |
| `T022` | 2 | Build Testcontainers harness | T020;T021 | container lifecycle and readiness | `AC-TEST-002` |
| `T023` | 2 | Build Wiremock/provider fake harness | T020 | HTTP contract test tools | `AC-TEST-002` |
| `T024` | 2 | Build profile-generation test harness | T005;T021 | clean-directory profile tests | `AC-GEN-001` |
| `T030` | 3 | Implement SQLx PostgreSQL pool and health | T022;T016 | postgres module | `AC-DB-005` |
| `T031` | 3 | Implement migration command and compatibility checks | T030 | migration runner/status | `AC-DB-002` |
| `T032` | 3 | Implement reference domain and checked queries | T030;T031 | CRUD domain/persistence | `AC-DB-006` |
| `T033` | 3 | Implement transaction and transient retry helpers | T032 | transaction services | `AC-DB-007` |
| `T034` | 3 | Implement idempotency and optimistic concurrency | T032;T033 | idempotency/ETag modules | `AC-HTTP-007` |
| `T035` | 3 | Implement cursor pagination and validation | T032 | pagination contracts | `AC-HTTP-006` |
| `T036` | 3 | Implement OpenAPI and outbound HTTP policies | T014;T015 | OpenAPI/reqwest module | `AC-HTTP-009` |
| `T037` | 3 | Complete API reference/profile | T031;T034;T035;T036 | api profile | `AC-DB-004` |
| `T040` | 4 | Implement identity schema and canonical Principal | T031 | identity core | `AC-AUTH-009` |
| `T041` | 4 | Implement password, verification, and recovery | T040 | password flows | `AC-AUTH-003` |
| `T042` | 4 | Implement sessions, cookie policy, CSRF, lifecycle | T002;T040;T041 | session auth | `AC-AUTH-001` |
| `T043` | 4 | Implement JWT/JWKS verification | T040;T023 | bearer auth | `AC-AUTH-006` |
| `T044` | 4 | Implement OIDC client/account linking | T040;T023 | OIDC adapter | `AC-AUTH-008` |
| `T045` | 4 | Implement API keys/service accounts | T040 | API key module | `AC-AUTH-010` |
| `T046` | 4 | Implement optional WebAuthn and TOTP | T040;T041 | MFA modules | `AC-AUTH-011` |
| `T047` | 4 | Complete authenticated API profile | T042;T043;T045 | authenticated profile | `AC-AUTH-002` |
| `T050` | 5 | Implement built-in authorization provider | T040 | authorization service | `AC-AUTHZ-002` |
| `T051` | 5 | Implement organizations/memberships/tenant context | T050;T031 | tenant module | `AC-AUTHZ-003` |
| `T052` | 5 | Implement audit log and security event sink | T050;T031 | audit module | `AC-AUTHZ-007` |
| `T053` | 5 | Implement protected admin and impersonation | T051;T052 | admin module | `AC-AUTHZ-008` |
| `T054` | 5 | Implement optional Cedar provider | T050 | Cedar adapter | `AC-AUTHZ-005` |
| `T055` | 5 | Run cross-transport authorization matrix | T050;T051;T052 | authorization conformance | `AC-AUTHZ-001` |
| `T060` | 6 | Implement Redis core and health | T001;T022 | Redis module | `AC-REDIS-001` |
| `T061` | 6 | Implement Moka/Redis/no-op cache | T060 | cache providers | `AC-REDIS-002` |
| `T062` | 6 | Implement local rate limits | T060;T014 | governor layers | `AC-REDIS-006` |
| `T063` | 6 | Implement optional Redis session store | T002;T060;T042 | session provider variant | `AC-REDIS-005` |
| `T064` | 6 | Implement Redis ephemeral pubsub | T060 | fan-out provider | `AC-REDIS-004` |
| `T070` | 7 | Implement typed job/event interfaces | T033 | jobs core | `AC-JOB-002` |
| `T071` | 7 | Implement transactional outbox/inbox | T070;T031 | outbox/inbox | `AC-JOB-003` |
| `T072` | 7 | Implement Apalis Redis job provider | T003;T060;T070 | Redis jobs | `AC-JOB-005` |
| `T073` | 7 | Implement optional PGMQ provider if gate passed | T003;T070 | PGMQ jobs | `AC-JOB-001` |
| `T074` | 7 | Implement scheduler and leases | T070;T071 | scheduler | `AC-JOB-007` |
| `T075` | 7 | Implement NATS JetStream provider | T070;T022 | NATS events | `AC-JOB-008` |
| `T076` | 7 | Implement worker/admin diagnostics and drain | T072;T074;T016 | worker profile | `AC-JOB-006` |
| `T080` | 8 | Define realtime protocol and registry | T040;T050 | realtime core | `AC-RT-002` |
| `T081` | 8 | Implement SSE | T080 | SSE adapter | `AC-RT-006` |
| `T082` | 8 | Implement WebSocket upgrade/message lifecycle | T080;T014 | WebSocket adapter | `AC-RT-001` |
| `T083` | 8 | Implement Redis/NATS fan-out providers | T064;T075;T080 | multi-instance fan-out | `AC-RT-005` |
| `T084` | 8 | Implement bounded queues, slow-consumer, drain | T082;T083 | backpressure/drain | `AC-RT-003` |
| `T090` | 9 | Implement object_store port/providers | T022;T051 | object storage | `AC-STORAGE-001` |
| `T091` | 9 | Implement upload quarantine/scanner/reconciliation | T090;T070 | upload workflow | `AC-STORAGE-002` |
| `T092` | 9 | Implement lettre/MiniJinja email module | T023;T070 | email adapter/templates | `AC-MAIL-001` |
| `T093` | 9 | Implement notification preferences/orchestration | T051;T052;T092 | notification module | `AC-MAIL-003` |
| `T094` | 9 | Implement Svix outbound adapter | T071;T023 | webhook delivery adapter | `AC-WEBHOOK-001` |
| `T095` | 9 | Implement inbound webhook framework | T071;T023 | signature/replay/inbox | `AC-WEBHOOK-002` |
| `T096` | 9 | Implement centralized SSRF/outbound policy | T036;T023 | URL policy | `AC-WEBHOOK-003` |
| `T100` | 10 | Implement OpenFeature provider interface | T011 | feature flags | `AC-OPT-001` |
| `T101` | 10 | Implement search projection provider | T071;T051 | search module | `AC-OPT-002` |
| `T102` | 10 | Implement billing/entitlement skeleton and reconciliation | T052;T095 | billing module | `AC-WEBHOOK-002` |
| `T103` | 10 | Implement optional GraphQL adapter | T050;T014 | GraphQL module | `AC-OPT-003` |
| `T104` | 10 | Implement optional tonic gRPC adapter | T050;T013 | gRPC module | `AC-OPT-003` |
| `T105` | 10 | Implement localization module | T011 | Fluent module | `AC-OPT-004` |
| `T106` | 10 | Implement privacy lifecycle/consent/moderation contracts | T051;T052;T070 | product modules | `AC-OPT-004` |
| `T110` | 11 | Implement cargo-generate base template | T017;T037;T047 | initial template | `AC-GEN-001` |
| `T111` | 11 | Implement module add/remove/doctor/diff | T005;T110 | xtask module manager | `AC-GEN-002` |
| `T112` | 11 | Implement managed-region ownership enforcement | T111 | safe generator edits | `AC-GEN-003` |
| `T113` | 11 | Implement upgrade engine and rehearsals | T112 | upgrade command/tests | `AC-GEN-004` |
| `T114` | 11 | Generate and verify every profile | T113 | profile fixtures | `AC-GEN-001` |
| `T120` | 12 | Run load, soak, and failure suite | T114 | performance/failure reports | `AC-TEST-003` |
| `T121` | 12 | Complete security/supply-chain review | T114;T004 | security report, vetted graph | `AC-SEC-002` |
| `T122` | 12 | Complete deployment/runbooks/recovery rehearsal | T114 | deployment artifacts/runbooks | `AC-DEPLOY-003` |
| `T123` | 12 | Complete traceability and release artifacts | T120;T121;T122 | SBOM, provenance, signed bundle | `AC-SEC-003` |

## Parallelism guidance

- Documentation, threat modeling, and test design may proceed alongside code after their interfaces are fixed.
- Provider spikes may run in parallel in Phase 0.
- Do not parallelize multiple changes to the composition root or generator manifests without serialized integration.
- A dependent phase may prepare tests but cannot merge production wiring before prerequisites pass.
- Every phase ends with a generated clean-directory profile run, not only workspace tests.


<!-- END 23-agent-task-graph.md -->


---

<!-- BEGIN 24-risk-register.md -->

# Risk Register


Likelihood and impact are qualitative initial ratings. Owners are capability owners, not individual names.

| ID | Risk | Trigger/indicator | Impact | Likelihood | Mitigation | Owner |
|---|---|---|---:|---:|---|---|
| `R-001` | Foundational version drift` | A crate update introduces duplicate Tokio/Hyper/Axum/Tower/SQLx/rustls/OTel lines` | High` | High` | Central pins, grouped updates, cargo tree gate, compatibility spike` | Platform |
| `R-002` | SQLx 0.9 pressure` | Agent chooses newest SQLx despite session-store 0.8 compatibility` | High` | Medium` | ADR-0003, exact baseline, negative dependency test` | Persistence |
| `R-003` | Session stack mismatch` | axum-login, tower-sessions core, and store versions do not align` | High` | Medium` | Phase 0 miniature workspace; use re-exported compatible versions; block implementation` | Identity |
| `R-004` | Job backend immaturity` | Stable Apalis uses an older Redis line and emits future-incompatibility warnings; PostgreSQL alternatives may require prerelease or operational SQL` | High` | High` | ADR-0011 isolation and review deadline; PGMQ opt-in; block toolchain drift; no custom queue` | Async |
| `R-005` | Module combinatorial explosion` | Too many theoretically supported combinations` | High` | High` | Named profiles, provider slots, selected pairwise tests, reject unsupported combinations` | Platform |
| `R-006` | Cargo feature misuse` | Mutually exclusive architectures unified unexpectedly` | High` | Medium` | Workspace composition, features only additive, profile validator` | Platform |
| `R-007` | Generator overwrites app code` | Upgrade/add/remove mutates application-owned files` | Critical` | Low` | Ownership classes, managed IDs, dry-run, backup patch, corruption refusal, rehearsals` | Generator |
| `R-008` | Migration destroys data` | Module removal/down migration drops tables or breaks rolling deployment` | Critical` | Medium` | Forward-only history, expand/contract, no automatic data removal, migration CI` | Persistence |
| `R-009` | Global optional state` | Option-filled AppState hides missing capabilities and runtime failures` | Medium` | Medium` | Typed route state and compile-time composition` | Platform |
| `R-010` | Secret leakage` | Config/debug/error/telemetry/provider payload exposes credentials` | Critical` | Medium` | secrecy, redaction tests, sensitive header marking, bounded diagnostics` | Security |
| `R-011` | High-cardinality telemetry` | User/tenant/URL/error values overload metrics/traces` | High` | Medium` | Label allowlist, cardinality tests/budget, aggregate classes` | Observability |
| `R-012` | Probe storm` | Readiness checks synchronously hit all dependencies` | High` | Medium` | Cached async dependency status, no fan-out per probe` | Operations |
| `R-013` | Proxy spoofing` | Untrusted forwarded headers bypass IP policy or generate wrong URLs` | Critical` | Medium` | Trusted immediate-peer ranges, bounded parser, security tests` | HTTP |
| `R-014` | Auth protocol reinvention` | Agent writes JWT/OIDC/WebAuthn logic to resolve integration friction` | Critical` | Low` | Explicit prohibition, approved crates, stop condition` | Identity |
| `R-015` | Session fixation/CSRF` | Browser session controls are incomplete` | Critical` | Medium` | Rotation, __Host cookie, tower-http CSRF/origin protection, conformance tests` | Identity |
| `R-016` | Stale authorization claims` | Long-lived JWT roles/scopes outlive permission changes` | High` | Medium` | Short tokens, authoritative checks for sensitive actions, session/revocation linkage` | Authorization |
| `R-017` | Tenant leakage` | Query/cache/job/object/search path omits tenant scope` | Critical` | Medium` | Canonical tenant context, constraints, permission matrix, cross-store tests` | Tenancy |
| `R-018` | Cedar overuse` | Policy engine absorbs business invariants and becomes opaque` | Medium` | Medium` | Built-in provider default; Cedar optional; invariants remain code/DB` | Authorization |
| `R-019` | Cache becomes source of truth` | Failure/miss semantics corrupt correctness` | High` | Medium` | Explicit cache port/results, fail policy, authoritative reads` | Cache |
| `R-020` | Redis lock stale owner` | Simple lock allows irreversible duplicate work` | Critical` | Low` | No default locks; fencing/ADR; prefer constraints/idempotency/queue` | Cache |
| `R-021` | At-least-once side effects` | Job/event retry duplicates email/payment/webhook/business action` | Critical` | High` | Idempotency, outbox/inbox/effect records, provider idempotency keys` | Async |
| `R-022` | Unbounded realtime queues` | Slow clients consume memory` | Critical` | Medium` | Bounded queues, coalesce/resync/disconnect, load tests` | Realtime |
| `R-023` | Revoked realtime identity persists` | Long-lived connection keeps access after session/role change` | High` | Medium` | Periodic/revocation revalidation, subscription invalidation` | Realtime |
| `R-024` | SSRF/DNS rebinding` | Webhook or integration URL reaches metadata/internal network` | Critical` | Medium` | Central resolver/address checks, redirect recheck, egress policy, tests` | Integrations |
| `R-025` | Unsafe uploads` | Uploaded content is trusted by MIME/name or served executable` | Critical` | Medium` | Random keys, limits, checksum, quarantine, scanner hook, safe disposition` | Storage |
| `R-026` | Webhook platform scope creep` | Kit implements retries, signatures, logs, replay, endpoint management itself` | High` | Medium` | Svix default and local fake only` | Integrations |
| `R-027` | OpenTelemetry version churn` | OTel crates update out of sync` | Medium` | High` | Pin as one set, grouped update, export compatibility test` | Observability |
| `R-028` | Testcontainer flakiness` | Tests use sleeps, shared state, or leaked containers` | Medium` | Medium` | Readiness conditions, per-test isolation, nextest groups, deterministic clocks` | Quality |
| `R-029` | All-features false confidence` | Unified features compile but real profiles fail` | High` | High` | Generate/compile/test every named profile and invalid combinations` | Quality |
| `R-030` | Over-abstraction` | Generic repositories/providers erase useful behavior and slow development` | Medium` | High` | Require two implementations/real boundary; thin adapter rule` | Architecture |
| `R-031` | Under-abstraction at volatile providers` | Provider types leak through application services` | Medium` | Medium` | Narrow ports for external providers only` | Architecture |
| `R-032` | Supply-chain compromise` | Malicious/compromised dependency or build script enters graph` | Critical` | Low` | vet, deny, source policy, review proc macros/build scripts, provenance` | Security |
| `R-033` | Prerelese dependency default` | Agent adopts RC to get a feature` | High` | Medium` | Prerelease gate and ADR; experimental profile only` | Security |
| `R-034` | Config hot reload partial state` | Security settings reload inconsistently` | High` | Low` | Very limited reload; atomic module support only` | Configuration |
| `R-035` | Backup exists but restore fails` | Operational assumptions not rehearsed` | Critical` | Medium` | Scheduled restore rehearsal and explicit RPO/RTO` | Operations |
| `R-036` | Reference profile becomes production recommendation` | Full composition carries unnecessary attack surface` | Medium` | Medium` | Label full-reference as CI/demo only; profile docs` | Platform |
| `R-037` | Specification task acceptance drift` | A task criterion requires capabilities implemented only by its descendants` | High` | Low` | Validate task-to-criterion phase ownership; correct mappings through an accepted ADR` | Platform |
| `R-038` | Inactive locked dependency advisory becomes reachable` | A feature or target adds an active path to `rsa 0.9.10` while RUSTSEC-2023-0071 is ignored` | Critical` | Low` | ADR-0012; all-target reachability gate; PostgreSQL-only SQLx; Security-owned exception expiring 2026-11-23` | Security |

## Risk handling

- Critical risks block release until controlled or explicitly accepted by the accountable owner.
- High risks require tests and an operational detection signal.
- A trigger observed during implementation updates this register and may require an ADR.
- Accepted residual risk has an expiry/review date.
- Dependency and security risks are re-evaluated on every baseline update.


<!-- END 24-risk-register.md -->


---

<!-- BEGIN adr/0001-rust-tokio-axum-tower.md -->

# Use Rust, Tokio, Axum, and Tower


## Context

The service kit needs one network/runtime model shared by HTTP, gRPC, middleware, background work, shutdown, and observability. Selecting multiple async runtimes or unrelated middleware models would increase dependency duplication and make module composition harder.

## Decision

Use:

- Rust 2024 edition.
- A pinned current stable Rust toolchain.
- Tokio as the sole async runtime.
- Axum as the default HTTP framework.
- Tower as the service and middleware abstraction.
- tower-http for standardized HTTP middleware.
- Hyper only when a lower-level need is not exposed by Axum.

The first baseline is Rust 1.98.0, Tokio 1.53.1, Axum 0.8.9, Tower 0.5.3, and tower-http 0.7.0.

## Consequences

- HTTP, gRPC through Tonic, retries, limits, tracing, and middleware share Tower semantics.
- Modules must not introduce Actix, async-std, smol, Rocket, or another runtime/framework into supported profiles.
- A specialized service may choose another framework only by forking the service-kit architecture or accepting a replacement ADR.
- Direct Hyper use is localized and does not leak into domain/application code.

## Validation

- Dependency policy rejects a second async runtime.
- Profile builds inspect duplicate Tokio/Hyper/Tower versions.
- The minimal reference service demonstrates startup, request handling, cancellation, and graceful drain.


<!-- END adr/0001-rust-tokio-axum-tower.md -->


---

<!-- BEGIN adr/0002-source-level-module-composition.md -->

# Use Source-Level Module Composition


## Context

The service kit must let teams opt into PostgreSQL, Redis, authentication, jobs, realtime, storage, and product modules. Cargo features are additive and unified across the graph. A dynamically loaded Rust plugin system would require an ABI, type erasure, version negotiation, and a larger security surface.

## Decision

Major capabilities are composed as workspace crates and generated source wiring.

- Named profiles select initial composition.
- Workspace dependencies include capabilities.
- Cargo features are limited to additive implementation details inside a crate.
- Runtime toggles enable behavior already compiled into the binary.
- Product feature flags govern user/tenant behavior and are not architecture toggles.
- No dynamically loaded Rust plugin ABI is provided.

## Consequences

- Supported combinations are explicit and testable.
- A disabled runtime module still exists in the binary; security-sensitive removal requires source composition.
- The generator owns manifests and declared managed regions.
- Mutually exclusive providers use provider slots and profile validation rather than Cargo feature tricks.

## Validation

- `cargo xtask profiles verify` resolves every named profile.
- The generator rejects provider-slot conflicts and missing dependencies.
- Removing a module never deletes historical migrations or application data automatically.


<!-- END adr/0002-source-level-module-composition.md -->


---

<!-- BEGIN adr/0003-sqlx-0-8-compatibility-baseline.md -->

# Pin SQLx 0.8.6 as the Initial Compatibility Baseline


## Context

SQLx 0.9.0 is current at the bundle verification date. Important integration crates, notably the selected SQLx-backed session store, still target SQLx 0.8. Selecting 0.9 solely because it is newest would create duplicate SQLx lines, incompatible pool/transaction types, or pressure to write a custom session store.

## Decision

The first supported persistence line is SQLx 0.8.6.

- PostgreSQL is the primary database.
- The lockfile pins the reviewed patch.
- SQLx checked queries and offline metadata are required.
- Adapter crates must resolve onto the same SQLx 0.8 line where their types cross boundaries.
- SQLx 0.9 remains an upgrade candidate, not a default.

## Upgrade gate

The upgrade ADR may be accepted only when:

1. Session-store, job/provider, and test integrations have stable compatible releases.
2. The resolved graph does not introduce duplicate foundational SQLx versions that cross APIs.
3. Empty-to-head and supported-version-to-head migration tests pass.
4. Compile-time query metadata is regenerated.
5. Pool, transaction, TLS, and feature behavior is reviewed.
6. All named profiles and upgrade fixtures pass.

## Consequences

- The baseline values ecosystem coherence over version novelty.
- Security patches on the supported line remain mandatory.
- Modules must not independently raise SQLx.
- SQLx 0.9 experiments are isolated to a non-default compatibility branch/profile.

## Validation

Phase 0 records `cargo tree -d`, feature resolution, and adapter compatibility. CI fails if a direct dependency changes the SQLx baseline without an accepted ADR.


<!-- END adr/0003-sqlx-0-8-compatibility-baseline.md -->


---

<!-- BEGIN adr/0004-canonical-principal-and-auth-mechanisms.md -->

# Normalize Authentication into a Canonical Principal


## Context

First-party browser sessions, bearer JWTs, OIDC identities, API keys, passkeys, and TOTP have different transport and lifecycle semantics. Application services should not duplicate authorization logic for each credential type.

## Decision

Every successful authentication mechanism produces the canonical `Principal`.

- Browser sessions use `axum-login` and its compatible `tower-sessions` stack.
- Passwords use RustCrypto Argon2id.
- JWT verification uses `jsonwebtoken`.
- OIDC/OAuth clients use `openidconnect` and `oauth2`.
- WebAuthn uses `webauthn-rs`.
- TOTP uses `totp-rs`.
- API keys are high-entropy opaque credentials stored by secure hash.
- Authorization consumes `Principal` and is enforced in application services.
- The service kit is a resource server and relying party; it is not an OAuth authorization server.

## Consequences

- Sessions and JWTs may coexist without duplicating business policy.
- Credential-specific fields do not leak into domain APIs.
- Assurance level and authentication time are explicit authorization inputs.
- Revocation semantics remain mechanism-specific.
- A user record may link multiple external identities.

## Validation

The conformance suite runs the same permission matrix using session, JWT, and API-key principals where applicable. Security tests cover rotation, revocation, expiration, CSRF, replay, issuer/audience validation, and cross-tenant access.


<!-- END adr/0004-canonical-principal-and-auth-mechanisms.md -->


---

<!-- BEGIN adr/0005-durable-work-and-event-providers.md -->

# Adopt Durable Work and Event Providers Instead of Building a Queue


## Context

A durable queue requires leasing, retries, visibility timeouts, deduplication, dead letters, scheduling, storage cleanup, metrics, and recovery. Implementing this inside a boilerplate would recreate mature infrastructure. The current Rust ecosystem also has compatibility differences among PostgreSQL queue crates.

## Decision

Approved default/provider choices are:

- Apalis 0.7.4 with `apalis-redis` for Redis-backed jobs.
- PGMQ and its maintained Rust client as an optional PostgreSQL queue when the extension is acceptable.
- NATS JetStream through `async-nats` for durable distributed event streaming.
- Tokio/in-process channels only for non-durable best-effort work and tests.
- Application-owned transactional outbox/inbox tables coordinate domain transactions with external delivery.

Excluded from defaults:

- `sqlxmq` because its stable line targets an old SQLx generation.
- Prerelease `apalis-postgres` releases.
- A custom `FOR UPDATE SKIP LOCKED` general queue.

## Consequences

- Profiles select one jobs provider.
- The outbox is not treated as a full queue; it is a transactional relay boundary.
- Operators accept the infrastructure requirements of the selected provider.
- Job handlers assume at-least-once execution and must be idempotent.

## Validation

Provider compatibility spikes precede admission. Failure, lease expiry, duplicate execution, dead-letter, drain, and replay tests are mandatory.


<!-- END adr/0005-durable-work-and-event-providers.md -->


---

<!-- BEGIN adr/0006-svix-for-outbound-webhooks.md -->

# Use Svix for Production Outbound Webhooks


## Context

Reliable outbound webhooks require endpoint and secret lifecycle, signing, retries, backoff, replay, suspension, delivery logs, observability, and abuse controls. These are a product in their own right and are not a sensible generic subsystem to recreate in this service kit.

## Decision

Use Svix, managed or self-hosted, for production outbound webhook delivery.

The service kit owns:

- A narrow event/delivery adapter.
- Public event schemas.
- Authorization and tenant mapping.
- Safe metadata correlation.
- Configuration, health, metrics, and test fake.

Svix owns delivery scheduling, signing, retries, endpoint lifecycle, replay, and delivery history.

## Consequences

- The service has a vendor/external-system dependency for production delivery.
- A local fake may demonstrate contracts but cannot be promoted to production.
- Product teams can replace Svix only behind the adapter and with an ADR proving equivalent operational behavior.
- Inbound provider webhooks remain provider-specific adapters.

## Validation

Contract tests cover enqueue, endpoint lifecycle, replay, signature examples, provider failure, redaction, and idempotency. Deployment policy verifies Svix availability and data-residency requirements.


<!-- END adr/0006-svix-for-outbound-webhooks.md -->


---

<!-- BEGIN adr/0007-object-store-default.md -->

# Use object_store as the Default Blob Abstraction


## Context

The service kit needs local development, tests, and production object storage without exposing provider SDKs throughout the application. Several broad storage abstraction crates exist.

## Decision

Use Apache Arrow's `object_store` crate as the default provider abstraction.

Default supported backends:

- In-memory.
- Local filesystem.
- S3-compatible.
- Google Cloud Storage.
- Azure Blob Storage.

OpenDAL is an optional replacement only when its broader service matrix is required and compatibility/security review passes.

The service kit adds a narrow product-facing `BlobStore` capability for ownership, authorization, signed access, quarantine, retention, and reconciliation.

## Consequences

- Provider-specific advanced features may require an escape hatch or dedicated adapter.
- Application code does not depend on AWS/GCS/Azure SDK types.
- Object/database consistency remains an application workflow, not a fake distributed transaction.
- Upload scanning and media processing are external worker/service hooks.

## Validation

The same contract suite runs against memory, local filesystem, and an S3-compatible Testcontainer/emulator where practical. Range requests, multipart limits, checksums, signed access, and orphan reconciliation are tested.


<!-- END adr/0007-object-store-default.md -->


---

<!-- BEGIN adr/0008-rfc9457-and-code-first-openapi.md -->

# Use RFC 9457 Problem Details and Code-First OpenAPI


## Context

A reusable service kit needs stable error and API-description conventions. Ad hoc JSON errors and manually maintained OpenAPI documents drift from handlers and make generated clients unreliable.

## Decision

- Public HTTP errors use an RFC 9457-compatible Problem Details shape with an additional stable `code`, request ID, and field-error extension.
- `utoipa` generates OpenAPI 3.1 from code and shared schemas.
- `garde` performs boundary validation where derive-based validation fits.
- Domain invariants and database constraints remain separate.
- CI generates, validates, and diffs the OpenAPI document.

The service kit defines the small Problem Details value type directly rather than depending on a niche wrapper crate; the protocol itself is standardized and the type is part of the service's public contract.

## Consequences

- Error codes become versioned API surface.
- Internal causes never cross the transport boundary.
- Breaking API changes are identified in CI.
- GraphQL and gRPC adapters map from the same canonical application errors but use transport-native representations.

## Validation

Every public route declares responses and authentication. Golden tests cover serialization, validation pointers, redaction, and unexpected errors. OpenAPI diffs are release artifacts.


<!-- END adr/0008-rfc9457-and-code-first-openapi.md -->


---

<!-- BEGIN adr/0009-phase0-task-acceptance-mapping.md -->

# Separate Repository Skeleton and Minimal Profile Acceptance

## Context

The original task graph assigned `AC-CORE-001`, “Minimal profile starts without external services,” to both `T000` and `T017`. `T000` is limited to the repository/workspace skeleton, while the runtime, configuration, telemetry, HTTP, Problem Details, probes, and shutdown implementation required by `AC-CORE-001` is dependency-ordered through `T010`–`T017`. Requiring the Phase 1 behavior at `T000` makes the graph cyclic in practice and contradicts the declared output of `T000` and the Phase 1 exit.

## Decision

`T000` uses `AC-REPO-001`: the repository skeleton compiles with the pinned toolchain. `T017` remains the sole task that satisfies `AC-CORE-001`.

No implementation requirement is removed or deferred. This change only associates each criterion with the first task whose declared dependencies can satisfy it.

## Consequences

- Phase 0 can resolve dependencies before production runtime modules exist.
- The minimal service remains mandatory at the Phase 1 exit.
- Task validators must reject criteria assigned before their required implementation dependencies.

## Validation

- `cargo check --workspace --all-targets` proves `AC-REPO-001` for `T000`.
- The bundle validator confirms both criterion IDs exist and task references resolve.
- `T017` and the minimal profile conformance suite prove `AC-CORE-001`.


<!-- END adr/0009-phase0-task-acceptance-mapping.md -->


---

<!-- BEGIN adr/0010-session-compatibility-task-acceptance.md -->

# Separate Session Dependency Compatibility from Principal Conformance

## Context

The original task graph assigned `AC-AUTH-009`, “Session and JWT map to the same canonical Principal,” to `T002`. The declared output of `T002` is a Phase 0 dependency compatibility report for `axum-login`, `tower-sessions`, its stores, and SQLx. Canonical `Principal`, session authentication, and JWT adapters are dependency-ordered through `T040`, `T042`, and `T043`; they cannot exist during `T002` without bypassing the implementation graph.

## Decision

`T002` uses `AC-COMPAT-001`: session and store dependencies resolve on coherent stable lines. `T040` retains `AC-AUTH-009`, and the authenticated profile later proves cross-mechanism principal conformance.

No identity requirement is removed or weakened. The new criterion verifies only the compatibility output that Phase 0 can produce.

## Consequences

- Phase 0 blocks on incompatible session, SQLx, Axum, Tower, or rustls lines.
- Identity conformance remains an implementation and contract-test requirement in Phase 4.
- Task validation must distinguish dependency evidence from behavioral conformance.

## Validation

- The Phase 0 compatibility member compiles both PostgreSQL and Redis session-store types with exact pins.
- `cargo tree` shows one `tower-sessions-core` line and one SQLx line.
- Phase 4 contract tests prove `AC-AUTH-009` using session and JWT credentials.


<!-- END adr/0010-session-compatibility-task-acceptance.md -->


---

<!-- BEGIN adr/0011-apalis-redis-stable-baseline-exception.md -->

# Isolate the Apalis Redis Stable Baseline

## Context

Phase 0 resolved `apalis-redis 0.7.4` against the current service-kit graph. It uses `redis 0.32.7`, while the general Redis capability uses `redis 1.6.0`; their connection types are incompatible. Cargo 1.98 also reports Rust 2024 never-type fallback warnings in four Apalis Redis methods that will become hard errors in a future Rust release. The available Apalis 1.0 releases are prereleases and cannot enter a default profile. PGMQ 0.33.7 is stable and SQLx 0.8.6-compatible, but requires an operational SQL installation and does not replace the Redis default for every profile.

## Decision

Keep `apalis 0.7.4` and `apalis-redis 0.7.4` as the default Redis jobs provider for the pinned Rust 1.98 baseline, subject to all of these controls:

- Isolate its `redis 0.32.7` client inside the jobs adapter; no Redis type crosses the provider port.
- Admit an explicitly aliased direct dependency only to enable Tokio, connection manager, ring rustls, and WebPKI roots on that line.
- Do not share pools or connection values with the general `redis 1.6.0` capability.
- Treat the future-incompatibility report as a toolchain-upgrade blocker.
- Upgrade only to a stable Apalis release that removes the warnings and passes the provider conformance suite; prereleases remain experimental-only.
- Re-evaluate this exception before every Rust baseline update and no later than 2026-11-23.

Keep PGMQ 0.33.7 as an explicitly selected optional PostgreSQL provider with embedded, versioned SQL installation and a project-owned supervised poll/drain adapter. Do not implement a custom durable queue.

## Consequences

- Default SaaS/worker profiles contain two Redis crate lines, but only behind separate provider boundaries.
- Binary size and advisory review include both lines.
- The Rust toolchain cannot advance if Apalis 0.7.4 stops compiling and no stable fixed release exists; that condition blocks the affected default profiles.
- PGMQ profiles carry extension/SQL lifecycle operations and do not silently replace Redis profiles.

## Validation

- The Phase 0 Apalis spike proves enqueue, processing, and bounded drain against Redis 8.
- The Phase 0 PGMQ spike proves embedded installation, enqueue, visibility read, archive, and cleanup against PostgreSQL 17.
- Dependency reports classify both Redis lines and retain one Tokio, Tower, SQLx, rustls, and Serde family.
- CI records Cargo future-incompatibility output and rejects an unreviewed Rust baseline change.


<!-- END adr/0011-apalis-redis-stable-baseline-exception.md -->


---

<!-- BEGIN adr/0012-inactive-sqlx-rsa-advisory-exception.md -->

# Bound the Inactive SQLx RSA Advisory Exception

## Context

`cargo-audit` scans every package recorded in `Cargo.lock`. SQLx 0.8.6 records its optional MySQL driver, which records `rsa 0.9.10` and therefore RUSTSEC-2023-0071, even when only the PostgreSQL driver is enabled. The advisory has no fixed release. `cargo tree --target all -i rsa@0.9.10` is empty for the all-feature workspace graph: no selected target or feature compiles the package, and the service kit performs no RSA operation through SQLx.

## Decision

Temporarily ignore RUSTSEC-2023-0071 in `.cargo/audit.toml` with Security ownership and an expiry of 2026-11-23. The exception is valid only while all of these statements remain true:

- SQLx is configured without MySQL features.
- The all-target active dependency graph has no path to `rsa 0.9.10`.
- `cargo-deny` independently reports no active advisory.
- No workspace crate adds a direct or transitive active use of the affected RSA release.

CI checks RSA reachability before running `cargo-audit`. An active path fails the build and invalidates this exception. Review the exception before its expiry and remove it as soon as SQLx stops locking the affected optional package or RustSec publishes a fixed compatible path.

## Consequences

The locked package remains visible in SBOM and audit output policy, but it is not shipped. The exception cannot be copied to another advisory or extended without a fresh applicability review, owner, mitigation, expiry, and ADR/risk update.


<!-- END adr/0012-inactive-sqlx-rsa-advisory-exception.md -->


---

<!-- BEGIN adr/0013-test-support-task-ownership.md -->

# ADR 0013: Test-support task ownership

## Context

T020 depended only on T010 while its catalog module requires both `core` and `config`, and its output named config builders. It also assigned principal fixtures before T040 defines the canonical `Principal`, despite the `auth-core` catalog entry owning the test-principal factory. The normative testing specification additionally requires a test server/client and deterministic randomness, but the T020 output omitted both.

Implementing a temporary principal DTO would create a second identity convention and force a later migration. Omitting the production config loader or HTTP shell from T020 dependencies would likewise hide real compile-time dependencies.

## Decision

T020 depends on T010, T011, and T014. Its output is the deterministic clock, deterministic ID/random source, hermetic config builder, and loopback test server/client. T040 owns the canonical `Principal` and its test-principal factory.

T021 continues to own runner policy. T022 depends on that policy and owns real infrastructure, T023 owns provider HTTP fakes, and T024 owns profile-generation tests. T020 does not add Testcontainers, Wiremock, or a parallel identity model.

## Consequences

The deterministic base crate can be completed without preempting authentication design. Later identity tests extend test support through the canonical auth-core type rather than adapting a temporary fixture. Task dependencies now match the module catalog and the types used by the implementation.


<!-- END adr/0013-test-support-task-ownership.md -->


---

<!-- BEGIN research/methodology.md -->

# Research and Dependency Selection Methodology


## Verification date

August 23, 2026.

## Research boundary

The review focused on crates and systems that directly affect the proposed service-kit architecture. It did not attempt to rank every Rust web crate. The goal was to identify a coherent, maintainable dependency graph with secure defaults and established ownership.

Primary sources were preferred:

1. Rust, Tokio, Tower, and project documentation.
2. docs.rs documentation and published crate manifests.
3. Official project repositories and release notes.
4. RustSec and official security advisories.
5. Protocol specifications and OWASP guidance.
6. Official provider documentation.

Search-result popularity, blog posts, and social media were not used as the controlling basis for a default dependency.

## Selection process

For each capability:

1. Define the actual capability and failure semantics.
2. Determine whether the standard library or an already selected crate covers it.
3. Identify established candidates.
4. Verify current stable releases.
5. Inspect runtime/framework/database compatibility.
6. Check whether the capability crosses a public type boundary.
7. Review maintenance, documentation, advisories, license, and unsafe-code implications.
8. Prefer a crate maintained by the relevant ecosystem team or standards-focused organization.
9. Reject unnecessary wrappers when the foundational crate already provides the behavior.
10. Record alternatives and an upgrade/removal path.

## Interpretation of “battle-hardened”

No crate is certified safe merely because it is popular. In this bundle, “battle-hardened/community approved” means the candidate has a strong combination of:

- Meaningful production adoption or ecosystem centrality.
- Maintained stable releases.
- Clear documentation and examples.
- Compatibility with the chosen runtime and foundational dependency lines.
- A credible maintainer/project organization.
- Security advisories handled transparently.
- Tests and an established public API.
- Permissive/approved licensing.
- No need to depend on an unreviewed git commit or prerelease for the default profile.

## Compatibility over novelty

The newest release is not automatically the best baseline.

The key example is SQLx. SQLx 0.9.0 is current, but the selected session-store integration still targets 0.8. The baseline therefore pins 0.8.6 and records an upgrade gate. This avoids:

- Duplicate SQLx lines.
- Incompatible pool or transaction types.
- Custom infrastructure written only to bridge versions.
- A default profile based on prerelease adapters.

## Thin adapters

Avoiding reinvention does not mean every ten-line policy needs a dependency. A thin adapter is preferred when it:

- Converts a mature crate into canonical application types.
- Adds config, health, tracing, metrics, or test fakes.
- Enforces domain-specific authorization/tenancy.
- Coordinates a database transaction and outbox.
- Normalizes a vendor/provider behind a narrow interface.

Examples of intentionally application-owned thin code include the canonical `Principal`, Problem Details type, event envelope, module lifecycle metadata, idempotency record, transactional outbox, tenant query conventions, and provider ports.

## Reverification

Before implementation and every baseline upgrade, the agent MUST:

- Resolve the exact dependency graph in a scratch workspace.
- Review duplicate foundational crates.
- Run advisories, license/source policy, and supply-chain checks.
- Compile every named profile.
- Run integration and upgrade tests.
- Update `research/sources.md`, `21-crate-selection-matrix.md`, and ADRs.


<!-- END research/methodology.md -->


---

<!-- BEGIN research/crate-evaluation-rubric.md -->

# Crate Evaluation Rubric


## Scoring model

Each direct dependency candidate is scored from 0 to 5 in each category. Scores guide review; they do not replace judgment.

| Category | Weight | A score of 5 means |
|---|---:|---|
| Ecosystem fit | 15 | Maintained by or naturally integrated with the selected ecosystem |
| Stable adoption | 15 | Broad production use or foundational transitive use |
| Maintenance | 15 | Active stable releases, issue handling, multiple maintainers/organization |
| Documentation | 10 | Complete API docs, examples, migration notes, semantics |
| Security posture | 15 | Transparent advisories, safe defaults, reviewable crypto/protocol boundary |
| Compatibility | 15 | Cleanly resolves with pinned Tokio/Axum/Tower/SQLx/rustls/OTel lines |
| API stability | 5 | Predictable semver and migration path |
| Testing | 5 | Strong test suite, conformance/fuzz/property tests where appropriate |
| License/provenance | 5 | Approved license and registry release from credible source |

Maximum weighted score: 500.

## Admission thresholds

- **Default:** normally at least 375 with no zero in security, compatibility, maintenance, or provenance.
- **Optional:** normally at least 325 with isolation to one module.
- **Experimental:** lower score or prerelease, only in a non-default profile with ADR.
- **Rejected:** incompatible, abandoned, insecure, redundant, unclear license, or no stable release for required behavior.

## Hard gates

A candidate is rejected from default profiles regardless of score when:

- It is yanked.
- It has an unmitigated applicable high/critical advisory.
- It requires an unapproved license/source.
- It introduces a conflicting runtime/framework/database line across public APIs.
- The required release is a prerelease.
- It silently performs network or filesystem behavior outside the module contract.
- It cannot be bounded, timed out, canceled, or observed where those properties are required.
- It has no credible maintenance path.

## Evidence record template

```yaml
crate: example
version: 1.2.3
capability: example
status: default|optional|experimental|rejected
source_ids: []
scores:
  ecosystem_fit: 0
  stable_adoption: 0
  maintenance: 0
  documentation: 0
  security_posture: 0
  compatibility: 0
  api_stability: 0
  testing: 0
  license_provenance: 0
risks: []
alternatives: []
decision: ""
reviewed_on: 2026-08-23
```

## Review cadence

- Every service-kit minor release: changed direct dependencies.
- Every service-kit major release: all direct dependencies.
- Immediately: security advisory, maintainer/archive event, license change, or foundational version upgrade.
- Quarterly: dependencies marked optional/experimental and provider SDKs.


<!-- END research/crate-evaluation-rubric.md -->


---

<!-- BEGIN research/compatibility-findings.md -->

# Compatibility Findings


## Findings that changed or constrained the design

### SQLx line

- SQLx 0.9.0 is current at verification time.
- SQLx 0.8.6 remains a supported stable release.
- The published SQLx-backed tower-sessions store reviewed for this bundle targets SQLx 0.8.
- The initial baseline is therefore SQLx 0.8.6.
- SQLx 0.9 is not considered rejected; it is gated until the session/job/test ecosystem resolves coherently.

Sources: `SRC-SQLX-001`, `SRC-SQLX-002`, `SRC-SESSIONS-002`.

### Sessions

- `axum-login` is selected for first-party login/session integration.
- `tower-sessions` provides the session framework and replaceable stores.
- The implementation MUST resolve the exact compatible trio of `axum-login`, `tower-sessions`, and the selected store in Phase 0.
- The application uses the version of tower-sessions exposed/accepted by axum-login instead of forcing an independent incompatible line.

Sources: `SRC-AXUMLOGIN-001`, `SRC-SESSIONS-001`, `SRC-SESSIONS-002`.

### Redis connections

The official Redis crate documents async multiplexed connections as cheap to clone and states that an async connection pool is generally unnecessary. The default therefore uses a multiplexed connection or `ConnectionManager`; a pool requires a concrete connection-affinity/blocking reason.

Source: `SRC-REDIS-001`.

### CSRF

tower-http 0.7.0 includes CSRF/cross-origin protection middleware. The baseline uses it rather than adding a smaller Axum-specific CSRF crate.

Source: `SRC-TOWERHTTP-001`.

### Durable jobs

- Apalis 0.7.4 is the latest stable jobs framework line, and its Redis adapter is selected under ADR-0011.
- `apalis-redis 0.7.4` forces an isolated `redis 0.32.7` line and emits Rust 2024 never-type fallback future-incompatibility warnings on Cargo 1.98; stable replacement releases are not yet available.
- The reviewed PostgreSQL Apalis line remains prerelease and is not a default.
- `sqlxmq` stable targets an old SQLx generation and is not selected.
- PGMQ 0.33.7 passed a PostgreSQL 17 runtime spike on SQLx 0.8.6 and is an optional provider with versioned embedded SQL installation.

Sources: `SRC-APALIS-001`, `SRC-APALISPG-001`, `SRC-PGMQ-001`, `SRC-SQLXMQ-001`.

### Webhooks

Svix already supplies endpoint lifecycle, signing, retries, replay, delivery history, and self-hosted/managed operation. Production outbound delivery therefore uses Svix instead of a new service-kit subsystem.

Sources: `SRC-SVIX-001`, `SRC-SVIX-002`.

### Object storage

`object_store` supports the default backend set and is part of the Apache Arrow ecosystem. OpenDAL is viable but broader than the initial requirement, so it remains an ADR-gated alternative.

Sources: `SRC-OBJECTSTORE-001`, `SRC-OPENDAL-001`.

### OpenTelemetry version coupling

Rust OpenTelemetry crates evolve as a versioned family. `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`, and `tracing-opentelemetry` MUST be selected as a tested set and updated together.

Sources: `SRC-TRACINGOTEL-001`, `SRC-OTLP-001`.

## Phase 0 experiments

The implementation agent MUST record results for:

1. Complete default dependency resolution.
2. Session stack against SQLx 0.8.6.
3. Rustls provider/root choices for SQLx, Redis, reqwest, and identity clients.
4. Apalis Redis worker shutdown and retry behavior.
5. PGMQ extension/client compatibility if the provider is included.
6. OpenTelemetry trace export and shutdown flush.
7. object_store S3-compatible multipart/signed URL behavior.
8. tower-http CSRF behavior with session cookies and approved origins.
9. Profile generation in clean directories.
10. Upgrade from SQLx 0.8 baseline fixture.


<!-- END research/compatibility-findings.md -->


---

<!-- BEGIN research/sources.md -->

# Primary Source Registry


All dependency facts should be rechecked during Phase 0. This registry favors official documentation, project repositories, standards, and security guidance.

| ID | Source | URL | Use |
|---|---|---|---|
| `SRC-RUST-001` | Rust 1.98.0 release | <https://blog.rust-lang.org/2026/08/20/Rust-1.98.0/> | Current stable toolchain at verification date. |
| `SRC-CARGO-001` | Cargo features | <https://doc.rust-lang.org/cargo/reference/features.html> | Feature unification and optional dependency behavior. |
| `SRC-CARGO-002` | Cargo workspaces | <https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html> | Workspace structure. |
| `SRC-TOKIO-001` | Tokio 1.53.1 docs | <https://docs.rs/tokio/1.53.1/tokio/> | Async runtime. |
| `SRC-TOKIO-002` | Tokio graceful shutdown | <https://tokio.rs/tokio/topics/shutdown> | Cancellation and task shutdown guidance. |
| `SRC-AXUM-001` | Axum 0.8.9 docs | <https://docs.rs/axum/0.8.9/axum/> | HTTP framework and Tower integration. |
| `SRC-TOWER-001` | Tower 0.5.3 docs | <https://docs.rs/tower/0.5.3/tower/> | Service/layer abstraction. |
| `SRC-TOWERHTTP-001` | tower-http 0.7.0 docs | <https://docs.rs/tower-http/0.7.0/tower_http/> | HTTP middleware, including CSRF/cross-origin protection. |
| `SRC-SQLX-001` | SQLx 0.8.6 docs | <https://docs.rs/sqlx/0.8.6/sqlx/> | Selected compatible database line. |
| `SRC-SQLX-002` | SQLx 0.9.0 docs | <https://docs.rs/sqlx/0.9.0/sqlx/> | Current release observed but compatibility-gated. |
| `SRC-REDIS-001` | redis 1.6.0 docs | <https://docs.rs/redis/1.6.0/redis/> | Official Redis client; async multiplexed connection guidance. |
| `SRC-MOKA-001` | Moka 0.12.16 docs | <https://docs.rs/moka/0.12.16/moka/> | Bounded concurrent in-memory cache. |
| `SRC-CONFIG-001` | config 0.15.25 docs | <https://docs.rs/config/0.15.25/config/> | Layered configuration. |
| `SRC-SECRECY-001` | secrecy 0.10.3 docs | <https://docs.rs/secrecy/0.10.3/secrecy/> | Secret wrappers and explicit exposure. |
| `SRC-CLAP-001` | clap 4.6.6 docs | <https://docs.rs/clap/4.6.6/clap/> | CLI parsing. |
| `SRC-GARDE-001` | garde 0.23.0 docs | <https://docs.rs/garde/0.23.0/garde/> | Validation. |
| `SRC-UTOIPA-001` | utoipa 5.5.0 docs | <https://docs.rs/utoipa/5.5.0/utoipa/> | OpenAPI generation. |
| `SRC-REQWEST-001` | reqwest 0.13.4 docs | <https://docs.rs/reqwest/0.13.4/reqwest/> | Outbound HTTP client. |
| `SRC-SESSIONS-001` | tower-sessions 0.15.0 docs | <https://docs.rs/tower-sessions/0.15.0/tower_sessions/> | Session middleware. |
| `SRC-SESSIONS-002` | tower-sessions SQLx store source | <https://docs.rs/crate/tower-sessions-sqlx-store/0.15.0/source/Cargo.toml> | Shows SQLx 0.8 dependency and compatibility constraint. |
| `SRC-AXUMLOGIN-001` | axum-login 0.18.0 docs | <https://docs.rs/axum-login/0.18.0/axum_login/> | Authentication/session integration. |
| `SRC-ARGON2-001` | RustCrypto Argon2 0.5.3 docs | <https://docs.rs/argon2/0.5.3/argon2/> | Argon2id password hashing. |
| `SRC-JWT-001` | jsonwebtoken 11 docs | <https://docs.rs/jsonwebtoken/11.0.0/jsonwebtoken/> | JWT signing/verifying. |
| `SRC-OIDC-001` | openidconnect 4.0.1 docs | <https://docs.rs/openidconnect/4.0.1/openidconnect/> | OIDC client and verification. |
| `SRC-OAUTH-001` | oauth2 5 docs | <https://docs.rs/oauth2/5.0.0/oauth2/> | OAuth 2 client and PKCE. |
| `SRC-WEBAUTHN-001` | webauthn-rs 0.5.5 docs | <https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/> | WebAuthn/passkeys. |
| `SRC-TOTP-001` | totp-rs 6.0.0 docs | <https://docs.rs/totp-rs/6.0.0/totp_rs/> | TOTP. |
| `SRC-CEDAR-001` | cedar-policy 4.12 docs | <https://docs.rs/cedar-policy/4.12.0/cedar_policy/> | Optional policy engine. |
| `SRC-OBJECTSTORE-001` | object_store 0.14.1 docs | <https://docs.rs/object_store/0.14.1/object_store/> | Apache object storage abstraction. |
| `SRC-OPENDAL-001` | OpenDAL docs | <https://docs.rs/opendal/latest/opendal/> | Optional broad object-storage provider matrix. |
| `SRC-LETTRE-001` | lettre 0.11.23 docs | <https://docs.rs/lettre/0.11.23/lettre/> | Email construction and SMTP. |
| `SRC-MINIJINJA-001` | MiniJinja 2.24 docs | <https://docs.rs/minijinja/2.24.0/minijinja/> | Runtime templates. |
| `SRC-APALIS-001` | Apalis 0.7.4 docs | <https://docs.rs/apalis/0.7.4/apalis/> | Stable job framework line. |
| `SRC-APALISPG-001` | apalis-postgres prerelease docs | <https://docs.rs/apalis-postgres/latest/apalis_postgres/> | Prerelease adapter excluded from defaults. |
| `SRC-PGMQ-001` | pgmq 0.33.7 docs | <https://docs.rs/pgmq/0.33.7/pgmq/> | Optional PostgreSQL queue client. |
| `SRC-SQLXMQ-001` | sqlxmq 0.6.0 crate | <https://crates.io/crates/sqlxmq/0.6.0> | Targets old SQLx line; rejected default. |
| `SRC-NATS-001` | async-nats 0.50.0 docs | <https://docs.rs/async-nats/0.50.0/async_nats/> | NATS and JetStream. |
| `SRC-SVIX-001` | Svix Rust 1.99.1 docs | <https://docs.rs/svix/1.99.1/svix/> | Webhook delivery client. |
| `SRC-SVIX-002` | Svix webhook reliability docs | <https://docs.svix.com/retries> | Delivery retry behavior. |
| `SRC-TRACING-001` | tracing docs | <https://docs.rs/tracing/latest/tracing/> | Structured diagnostics. |
| `SRC-TRACINGSUB-001` | tracing-subscriber 0.3.23 docs | <https://docs.rs/tracing-subscriber/0.3.23/tracing_subscriber/> | Subscriber/filter/formatting. |
| `SRC-TRACINGOTEL-001` | tracing-opentelemetry 0.33 docs | <https://docs.rs/tracing-opentelemetry/0.33.0/tracing_opentelemetry/> | Trace bridge. |
| `SRC-OTLP-001` | opentelemetry-otlp 0.32 docs | <https://docs.rs/opentelemetry-otlp/0.32.0/opentelemetry_otlp/> | OTLP exporter. |
| `SRC-METRICS-001` | metrics 0.24.6 docs | <https://docs.rs/metrics/0.24.6/metrics/> | Metrics facade. |
| `SRC-PROM-001` | metrics-exporter-prometheus 0.18.3 docs | <https://docs.rs/metrics-exporter-prometheus/0.18.3/metrics_exporter_prometheus/> | Prometheus exporter. |
| `SRC-GOVERNOR-001` | governor 0.10.4 docs | <https://docs.rs/governor/0.10.4/governor/> | Rate-limiting algorithm. |
| `SRC-TOWERGOV-001` | tower-governor 0.8.0 docs | <https://docs.rs/tower_governor/0.8.0/tower_governor/> | Tower/Axum integration. |
| `SRC-TESTCONTAINERS-001` | testcontainers 0.28 docs | <https://docs.rs/testcontainers/0.28.0/testcontainers/> | Disposable integration infrastructure. |
| `SRC-NEXTEST-001` | cargo-nextest docs | <https://nexte.st/> | Test runner and groups. |
| `SRC-WIREMOCK-001` | wiremock docs | <https://docs.rs/wiremock/latest/wiremock/> | HTTP integration fakes. |
| `SRC-PROPTEST-001` | proptest docs | <https://docs.rs/proptest/latest/proptest/> | Property testing. |
| `SRC-FUZZ-001` | Rust Fuzz Book | <https://rust-fuzz.github.io/book/> | cargo-fuzz guidance. |
| `SRC-AUDIT-001` | RustSec cargo-audit | <https://rustsec.org/> | Advisory scanning. |
| `SRC-DENY-001` | cargo-deny docs | <https://embarkstudios.github.io/cargo-deny/> | License/source/advisory/duplicate policy. |
| `SRC-VET-001` | cargo-vet docs | <https://mozilla.github.io/cargo-vet/> | Supply-chain review. |
| `SRC-CYCLONEDX-001` | cargo-cyclonedx | <https://github.com/CycloneDX/cyclonedx-rust-cargo> | SBOM. |
| `SRC-SEMVER-001` | cargo-semver-checks | <https://github.com/obi1kenobi/cargo-semver-checks> | Rust API compatibility. |
| `SRC-GRAPHQL-001` | async-graphql 7.2.1 docs | <https://docs.rs/async-graphql/7.2.1/async_graphql/> | Optional GraphQL. |
| `SRC-TONIC-001` | tonic 0.14.6 docs | <https://docs.rs/tonic/0.14.6/tonic/> | Optional gRPC. |
| `SRC-OPENFEATURE-001` | OpenFeature Rust SDK 0.3 docs | <https://docs.rs/open-feature/0.3.0/open_feature/> | Feature flag API. |
| `SRC-FLUENT-001` | fluent-bundle 0.16 docs | <https://docs.rs/fluent-bundle/0.16.0/fluent_bundle/> | Localization. |
| `SRC-MEILI-001` | meilisearch-sdk 0.33 docs | <https://docs.rs/meilisearch-sdk/0.33.0/meilisearch_sdk/> | Optional search. |
| `SRC-GENERATE-001` | cargo-generate docs | <https://cargo-generate.github.io/cargo-generate/> | Initial project templating. |
| `SRC-OWASP-AUTH` | OWASP Authentication Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> | Authentication controls. |
| `SRC-OWASP-SESSION` | OWASP Session Management Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html> | Session/cookie controls. |
| `SRC-OWASP-REST` | OWASP REST Security Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> | API security. |
| `SRC-OWASP-SSRF` | OWASP SSRF Prevention Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> | Outbound URL controls. |
| `SRC-RFC9457` | RFC 9457 Problem Details | <https://www.rfc-editor.org/rfc/rfc9457.html> | HTTP error contract. |


<!-- END research/sources.md -->


---

<!-- BEGIN VALIDATION_REPORT.md -->

# Specification Bundle Validation Report


## Result

**PASS**

Validated on 2026-08-23 using `tools/validate_bundle.py`.

## Inventory validated

- 58 module descriptors.
- 9 supported named profiles.
- 111 acceptance criteria.
- 81 implementation tasks.
- 124 recommendations traced to specifications and acceptance criteria.
- 12 accepted architecture decision records.
- 68 primary-source research entries.
- Structured examples for Problem Details, events, jobs, profiles, modules, configuration, and workspace dependencies.

## Checks performed

- YAML, JSON, and TOML parse successfully.
- Every Markdown artifact has unique frontmatter metadata.
- Every module conforms to the module JSON Schema.
- Every profile conforms to the profile JSON Schema.
- Profile inheritance has no cycles.
- Every module requirement is present in each resolved profile.
- No profile contains a declared module conflict.
- Provider slots contain at most one provider.
- Every module, task, and recommendation references existing specifications and acceptance criteria.
- The task graph is acyclic.
- Research source references resolve.
- Problem Details, event, and job examples validate against their schemas.
- Normative files contain no unresolved placeholder markers.

## Important limitation

This validates the **specification bundle**, not a Rust implementation. The included Cargo workspace manifest is illustrative. The implementation agent must execute Phase 0 with Rust/Cargo, resolve the exact crate graph, compile every profile, run security tooling, and update ADR-0003 if the compatibility baseline cannot be maintained.


<!-- END VALIDATION_REPORT.md -->
