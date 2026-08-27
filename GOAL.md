/goal Completely implement the production-quality modular Rust backend service kit defined by the specification bundle in `./specs/`.

The goal is a finished, validated, usable service-kit repository — not a prototype, partial scaffold, demonstration, collection of interfaces, or implementation plan. Continue autonomously across turns until the entire specification is implemented and directly verified.

## Source of truth

Treat the complete contents of `./specs/` as the authoritative implementation contract.

Begin by reading, at minimum:

* `specs/AGENTS.md`
* `specs/README.md`
* `specs/SPEC_INDEX.md`
* `specs/AUTONOMOUS_AGENT_HANDOFF.md`
* `specs/00-scope-and-principles.md`
* `specs/01-system-architecture.md`
* `specs/02-module-system-and-generator.md`
* `specs/20-implementation-roadmap.md`
* `specs/21-crate-selection-matrix.md`
* `specs/22-recommendation-traceability.md`
* `specs/23-agent-task-graph.md`
* `specs/24-risk-register.md`
* every accepted ADR under `specs/adr/`
* `specs/machine/module-catalog.yaml`
* `specs/machine/profiles.yaml`
* `specs/machine/acceptance-criteria.yaml`
* `specs/machine/tasks.yaml`
* `specs/machine/dependency-baseline.toml`

Read each relevant numbered specification, ADR, machine-readable contract, example, and research artifact before implementing the task it governs.

`specs/COMPLETE_SPEC.md` may be used for broad indexing, but the individual normative documents and machine-readable artifacts remain authoritative according to the precedence rules defined by the specifications.

Before implementation, run the supplied specification-bundle validator and confirm the input specification is internally valid.

## Execution model

Use `specs/machine/tasks.yaml` as the canonical implementation task graph and `specs/20-implementation-roadmap.md` as the phase structure.

Maintain a live todo/work plan corresponding to the task graph so progress survives long autonomous execution and compaction.

For each task:

1. Confirm all dependencies are satisfied.
2. Read the governing specifications and ADRs.
3. Identify the relevant acceptance criteria.
4. Add or update tests that prove the required behavior.
5. Implement the smallest complete production-quality vertical slice.
6. Run the narrow relevant checks.
7. Update documentation, generated artifacts, manifests, traceability, and evidence as required.
8. Commit the completed task atomically using its task ID and the commit convention from `specs/AGENTS.md`.
9. At each phase boundary, execute the full phase/profile verification required by the specifications before advancing.

Use parallel subagents or specialist agents where doing so improves research quality, independent review, testing, or implementation throughput, but keep integration, architectural consistency, canonical task state, and final verification under the parent agent's control. Do not allow parallel agents to independently make conflicting changes to composition roots, dependency baselines, generator manifests, migrations, or other shared contracts.

Do not stop after planning. Do not wait for additional user approval for ordinary implementation choices that the specifications already authorize. Research, decide, implement, test, and continue.

## Phase 0 is mandatory

Do not begin production implementation until Phase 0 has been completed.

Perform the compatibility and dependency research required by the specifications using current primary sources and actual Cargo resolution.

In particular:

* establish the exact supported Rust/Cargo toolchain;
* resolve exact direct dependency versions;
* generate and inspect `cargo tree -d`;
* identify duplicate foundational Tokio, Hyper, Axum, Tower, SQLx, rustls, Serde, and OpenTelemetry families;
* select and verify the rustls crypto provider and root strategy;
* prove the `axum-login` / `tower-sessions` / session-store compatibility family;
* prove the SQLx 0.8.6 baseline and offline metadata workflow;
* spike and verify the selected Apalis Redis integration;
* evaluate PGMQ as specified if it remains supported;
* verify the OpenTelemetry dependency family and exporter shutdown/flush behavior;
* run advisory, maintenance, license, MSRV, source, and unsafe-code checks for proposed direct dependencies;
* produce the dependency-admission evidence required by `specs/AGENTS.md`.

Prefer the battle-hardened, community-approved crates selected by the specification research. Do not reinvent capabilities already provided reliably by the Rust ecosystem or an approved external service.

If current evidence shows that a specified crate/version combination is no longer coherent, insecure, yanked, incompatible, or otherwise unsuitable, do not silently substitute it. Research the best maintained alternative using primary documentation, Cargo metadata, upstream repositories/releases, RustSec/advisory information, and ecosystem evidence. Record the decision through the ADR, risk, dependency-admission, and traceability mechanisms required by the specs before proceeding.

## No reinvention

Strictly honor the no-reinvention policy.

Do not implement custom substitutes for established:

* HTTP frameworks or middleware systems;
* SQL migration engines;
* connection pools;
* session engines;
* JWT/JWK parsing or validation;
* OAuth2 or OIDC protocols;
* password hashing;
* WebAuthn;
* TOTP cryptography;
* durable job queues;
* object-storage clients;
* outbound webhook delivery platforms;
* observability protocols;
* cryptography or TLS primitives.

Use thin internal adapters where the specifications call for them so third-party types do not leak into domain/application contracts.

Every new direct dependency must pass the dependency-admission gate. Avoid adding crates when an already-approved dependency or the standard library solves the problem adequately.

## Required architecture

Implement the complete architecture specified under `./specs`, including the small stable runtime kernel, source-level capability crates, provider slots, coherent named profiles, generator/module management, reference applications, conformance suite, upgrade system, and operational tooling.

Do not collapse the design into one monolithic application.

Do not use one global `AppState` containing optional integrations.

Do not misuse Cargo features to represent mutually exclusive architectural compositions.

Do not create a dynamic Rust plugin ABI.

Do not weaken domain boundaries by leaking Axum, SQLx, provider SDK, authentication-crate, or transport-specific types into domain/application services.

Do not introduce generic abstractions without a demonstrated need consistent with the specifications.

## Complete module scope

Implement every capability required by the bundle, including all baseline and optional modules defined by the module catalog and specifications.

This includes, without omission:

* typed layered configuration and secret handling;
* runtime lifecycle, supervision, cancellation, startup and graceful shutdown;
* Axum/Tower HTTP server foundation and middleware;
* correlation/request IDs and canonical request context;
* RFC 9457 Problem Details and stable API error conventions;
* liveness, readiness, startup, diagnostics, and build/version metadata;
* bounded and instrumented outbound HTTP clients;
* PostgreSQL/SQLx pools, migrations, transactions, retries, checked queries, offline metadata, testing, and upgrade compatibility;
* idempotency and optimistic concurrency;
* cursor pagination, validation, OpenAPI, ETags and API conventions;
* Redis core plus separate cache, session, rate-limit, Pub/Sub, and other specified roles;
* canonical `Principal`;
* password authentication and recovery;
* server-side session authentication, cookie security, CSRF, rotation, expiration and revocation;
* JWT/JWKS verification;
* OIDC/OAuth client integration and account linking;
* API keys and service identities;
* optional WebAuthn and TOTP;
* authorization enforced in application services;
* RBAC, ownership, tenant boundaries and optional Cedar;
* organizations, memberships and tenant context;
* audit logging, security events, administration and audited impersonation;
* transactional outbox and inbox/deduplication;
* typed jobs and events;
* approved durable job providers;
* schedulers and leases;
* NATS JetStream where specified;
* worker diagnostics, retries, idempotency, dead-letter handling and graceful drain;
* SSE;
* WebSockets with authentication, authorization, bounded queues, backpressure, heartbeats, slow-consumer policy, fan-out and graceful drain;
* object storage;
* upload quarantine/scanning lifecycle;
* email/templates and notification orchestration;
* outbound webhooks through the approved Svix approach;
* inbound webhook signature/replay handling;
* centralized SSRF protection and outbound URL policy;
* structured logging, tracing, OpenTelemetry, metrics and redaction;
* rate limiting and abuse controls;
* feature flags;
* search projection;
* billing/entitlement integration contracts;
* GraphQL and gRPC optional adapters;
* localization;
* privacy/data-lifecycle, consent and moderation contracts;
* deployment/runtime topology;
* containers and local development infrastructure;
* SBOM, provenance and dependency/supply-chain controls;
* backup, recovery and rollout documentation;
* comprehensive test support, real-infrastructure integration testing, property testing, fuzz smoke testing, load/failure testing and conformance testing;
* generator/template support;
* module add/remove/doctor/diff operations;
* managed-region ownership protection;
* upgrade/reconciliation support;
* all named service profiles and clean-directory generation tests;
* both independently shaped reference applications required before generator interfaces are frozen.

A module is not considered implemented merely because its public trait or configuration type exists. Every module must satisfy its specified configuration, initialization, lifecycle, health, failure semantics, observability, security, testing, local-development, documentation, and integration requirements.

## Security and correctness invariants

Maintain all security and data-integrity requirements in the specs.

In particular:

* default deny for identity, authorization, tenant scope, signatures, forwarded headers and ambiguous security configuration;
* authorization must not exist only at the HTTP layer;
* test horizontal, vertical and cross-tenant access through every applicable invocation path;
* production configuration must fail securely;
* trust forwarded headers only through configured trusted proxies;
* bound bodies, frames, pagination, queues, concurrency, retries and retention;
* explicitly document fail-open versus fail-closed behavior;
* retries must be safe/idempotent;
* durable events must not be published before the state transaction commits;
* long-lived work must be supervised, observable, cancellable and drainable;
* externally supplied URLs must pass centralized SSRF controls;
* secrets and sensitive data must not leak through logs, traces, metrics, errors, diagnostics, generated examples or source control;
* no project-authored unsafe Rust without the ADR/security-review process required by the specs;
* no production `unwrap()` or placeholder production paths;
* removing modules must never automatically destroy persisted user data;
* migrations must support the rollout/compatibility policy;
* application-owned code must survive generator upgrades.

## Real verification, not simulated completeness

Do not satisfy infrastructure acceptance criteria solely with mocks.

Where the specifications require PostgreSQL, Redis, NATS, object storage, cookies/browser semantics, auth flows, job workers, migrations, realtime behavior, shutdown behavior, or other infrastructure, run real integration tests using the approved local/containerized test strategy.

Never mark a task complete because code appears reasonable.

Never mark a phase complete because only compilation succeeds.

Never mark the overall goal complete because most modules exist.

## Generator and profile requirements

Do not freeze the generator architecture until at least two independently shaped reference applications have exercised and validated the module boundaries, as required by the specs.

The finished generator/module-management system must generate all nine named profiles into clean temporary directories and verify them independently.

Profile verification must not be replaced with only `--all-features` testing.

Prove:

* each profile contains exactly its allowed modules/providers;
* generated projects compile and test independently;
* module add/remove operations are idempotent;
* invalid dependency/conflict/provider combinations are rejected;
* module removal preserves data;
* application-owned code is never overwritten;
* upgrade rehearsals preserve application modifications and persisted data;
* generated applications contain no placeholder or disabled production paths.

## Required repository quality gates

Expose and successfully execute the equivalent of all commands required by `specs/AGENTS.md`, including:

`cargo fmt --all -- --check`

`cargo clippy --workspace --all-targets --all-features -- -D warnings`

`cargo nextest run --workspace`

`cargo test --doc --workspace`

`cargo check --workspace --all-targets`

`cargo deny check`

`cargo audit`

`cargo vet`

`cargo cyclonedx --all`

`cargo semver-checks`

`cargo xtask profiles verify`

`cargo xtask specs verify`

`cargo xtask migrations verify`

Also execute every additional test, security, fuzz, load, profile, migration, upgrade, container, SBOM, provenance and conformance gate required by the specifications.

Do not suppress warnings or weaken gates simply to obtain a green build.

## Documentation and developer experience

The result must be usable by another engineer without reading implementation internals.

Provide and verify the developer-facing documentation required by the specs, including:

* repository architecture;
* supported profiles and modules;
* module compatibility and dependencies;
* configuration reference;
* local setup;
* database/migration workflows;
* auth modes;
* authorization and tenancy model;
* jobs/events/realtime;
* observability;
* testing;
* deployment;
* generator/module-management commands;
* upgrades;
* security considerations;
* operational runbooks;
* dependency policy;
* support/version policy.

Examples must be executable or validated where practical and must contain no plausible production credentials.

## Autonomous decision policy

When ordinary implementation uncertainty occurs:

1. inspect the specification and accepted ADRs;
2. inspect the existing repository implementation;
3. research current primary upstream sources where necessary;
4. prefer established ecosystem solutions over bespoke code;
5. choose the smallest approach satisfying all constraints;
6. test the decision;
7. record non-obvious architectural decisions.

Do not ask the user to choose routine implementation details already bounded by the specifications.

If a specification-defined stop condition occurs, investigate it thoroughly first. If a safe resolution exists within the architecture, record the required ADR/risk/traceability changes and continue.

Only report the goal as blocked when completion genuinely requires unavailable external credentials, inaccessible infrastructure, a user-owned business decision not determined by the specs, or an irreconcilable requirement. A blocker must include concrete evidence, attempted resolutions, exact remaining work, and the smallest user action required. Do not redefine or shrink the goal to avoid a blocker.

## Final completion audit

Before invoking the goal-completion mechanism, perform a fresh audit of the actual repository state against the entire specification bundle.

At minimum:

1. Re-read the complete task graph and confirm every required task is complete.
2. Check every acceptance criterion in `specs/machine/acceptance-criteria.yaml` against direct current-state evidence.
3. Verify every module in `specs/machine/module-catalog.yaml`.
4. Generate and independently verify every profile in `specs/machine/profiles.yaml`.
5. Verify all accepted ADR requirements.
6. Re-run specification validation.
7. Re-run the complete formatting, linting, compilation, unit, integration, documentation, profile, migration, security, advisory, license, source-policy, semver, fuzz-smoke and supply-chain gates.
8. Run required load, failure, shutdown, restart and recovery scenarios.
9. Rehearse migrations and generator upgrades from clean/previous states as specified.
10. Inspect the final dependency tree for prohibited or unexplained foundational duplicates.
11. Verify no prerelease, yanked, git-sourced, denied-license or vulnerable dependency has entered a default profile without the explicitly permitted ADR process.
12. Search production code for placeholders, TODO implementations, panic-based normal control flow, plausible secrets, disabled security controls and unbounded resources.
13. Confirm both reference applications work end to end.
14. Confirm all nine named profiles generate and pass their independent conformance gates.
15. Confirm all public APIs and generated artifacts are documented.
16. Confirm SBOM, provenance, container and release artifacts exist and validate.
17. Confirm the risk register accurately reflects any remaining accepted non-blocking risks.
18. Confirm every recommendation in `specs/22-recommendation-traceability.md` and `specs/machine/recommendation-traceability.csv` is implemented and directly verified. There must be no dropped recommendation and no recommendation marked complete merely because a related component exists.
19. Produce a final evidence report mapping each specification area, task, acceptance criterion and `REC-*` recommendation to its implementation and verification evidence.
20. Run the complete verification suite again from the final repository state.

The goal is complete only if this fresh audit demonstrates that the whole specified service kit is implemented and operational.

Do not call the goal complete for a subset, a milestone, a single profile, or a partially passing repository. Budget exhaustion, context compaction, elapsed time, or substantial progress are not completion criteria.

When and only when every required deliverable has direct current-state evidence, invoke the goal completion mechanism and report:

* final repository state/commit;
* all generated profiles;
* dependency and license reports;
* test and conformance results;
* migration and upgrade results;
* security/threat-model results;
* performance baseline;
* container, SBOM and provenance artifacts;
* recommendation traceability status;
* remaining accepted risks, if any.
