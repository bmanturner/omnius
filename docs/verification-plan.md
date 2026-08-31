---
title: Documentation verification plan
description: Independent, table-driven verification scenarios for every documentation writing unit and required end-to-end journey.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - contributor
  - operator
  - security-reviewer
topics:
  - documentation
  - verification
  - release-evidence
capabilities:
  - docs-verification-plan
source:
  - DOCS_PROMPT.md
  - docs/evidence-inventory.md
evidence:
  - package.json
  - xtask/src/main.rs
  - release/web-suite-runbook.md
  - release/ai-mcp-suite-runbook.md
  - .github/workflows/ci.yml
last_verified: 2026-08-30
---

# Documentation verification plan

This plan starts every result at `not run`. Only the orchestrator may replace that value after preserving the command output, browser record, or review record named by the scenario. Source, specification, profile selection, generated artifacts, and focused tests never by themselves promote a capability to runtime exposure.

A verification owner is the independent reviewer for the row. The orchestrator must assign a different person from the writing owner recorded in [navigation](navigation.md); an owner collision fails the gate. Commands run from a clean checkout at the candidate revision unless a row says otherwise. Repository-owned fixture paths and module IDs are expanded below; an environment-dependent step with no first-party entry point must be recorded as blocked rather than replaced with a speculative command.

## Writing-unit verification

| Writing unit | Verification owner | Command or scenario | Prerequisites | Expected result | Failure-path check | Current result |
|---|---|---|---|---|---|---|
| `shared-concepts` | `DocsConsistencyVerifier` | Run `cargo xtask docs verify` after the documentation verifier is available; inspect the capability rows against `docs/evidence-inventory.md` and the machine catalogs. | Complete page set, `docs/navigation.md`, `docs/journeys.md`, validator implementation, clean checkout. | Links, anchors, required frontmatter, navigation reachability, capability ownership, source paths, terminology, and classifications agree with the central artifacts. | Introduce one disposable broken fragment, missing evidence path, invalid classification, or navigation orphan in an isolated copy and confirm fail-closed diagnostics; discard the copy. | not run |
| `backend-identity` | `IdentitySecurityVerifier` | Run `cargo xtask contracts check`; run the focused package/API tests named by each page, including `cargo test -p omnius-api-server --test authenticated_profile --test browser_auth --test oauth_provider`. Exercise unauthenticated, wrong-tenant, insufficient-scope, replay, and redacted-error cases. | PostgreSQL and all reference configuration secrets supplied through the documented secret mechanism; migrations applied; no production data. | Documented HTTP, identity, tenancy, OAuth, persistence, readiness, and error behavior matches the `oauth-provider` composition and checked-in contracts. | Invalid issuer/audience/PKCE, cross-tenant access, stale session, duplicate idempotency key with changed input, and unavailable dependency fail closed without secret or policy disclosure. | not run |
| `async-integrations` | `DistributedSystemsVerifier` | Run the focused tests cited by the owned pages, including `cargo test -p omnius-jobs-core --test contracts`, then exercise the selected Redis, PostgreSQL/PGMQ, NATS, storage, SMTP, and webhook adapters only where their page declares them. | Disposable provider services and credentials; composed worker/relay where required; deterministic fixtures; isolated tenant data. | Envelopes, leases, retries, outbox/inbox effects, scheduling, realtime delivery, uploads, notifications, and webhooks match the documented provider boundary and durability label. | Duplicate/mutated replay, expired lease, provider disconnect, slow consumer, failed scan, invalid signature, and drain timeout produce the documented bounded or degraded outcome. | not run |
| `web` | `WebJourneyVerifier` | Run `pnpm install --frozen-lockfile`, `pnpm sdk:check:generated`, `pnpm sdk:test:boundaries`, `pnpm web:typecheck`, `pnpm web:test`, `pnpm web:build`, and `pnpm web:test:e2e:full`; complete `pnpm web:check:a11y:manual` when release evidence is required. | Node `24.19.0`, pnpm `11.23.0`, installed Playwright browsers, generated web-enabled profile and matching backend contracts; browser fixtures may prove only fixture behavior. | Generated SDK drift checks pass; supported browser journeys cover authentication, tenant selection, records, errors, realtime, uploads, static delivery, accessibility, and release build behavior. | Run `pnpm web:test:e2e:security`; also check expired session, forbidden tenant, RFC 9457 error, offline/reconnect, rejected upload, missing capability, CSP/base-path error, and keyboard-only recovery. | not run |
| `llm` | `AIQualityVerifier` | Run `cargo xtask ai verify` and `cargo test -p omnius-llm-evals --test evaluation --test report_admission --test corpus_replay --test properties --test offline_fixtures`; replay repository cassettes without live credentials. | Checked-in deterministic fixtures, no network provider dependency, immutable model/prompt/price revisions, redacted artifact destination. | Provider-neutral request/response, routing, structured output, tools, streaming, usage, safety, and evaluation claims are deterministic and remain library-only or unassembled where composition is absent. | Corrupt a disposable cassette or schema and exercise unauthorized tool, exhausted budget, capability mismatch, malformed stream, missing usage, and prohibited raw retention; each fails closed or is conservatively reconciled. | not run |
| `mcp` | `MCPInteropVerifier` | Run `cargo xtask ai verify`; run `cargo test --tests -p omnius-mcp-server-core -p omnius-mcp-transport-http -p omnius-mcp-transport-stdio -p omnius-mcp-tools -p omnius-mcp-resources -p omnius-mcp-prompts -p omnius-mcp-auth-oauth`. When a server is assembled, execute the command plan emitted by `omnius-mcp-conformance` for the pinned official HTTP runner and Inspector. | Generated MCP profile, concrete registry and authorization policy, mounted HTTP or executable stdio composition, pinned Node/conformance tools, disposable identity and tenant. | Revision `2026-07-28` discovery is filtered and deterministic; HTTP and stdio framing, tools, resources, prompts, OAuth, cancellation, interactive/task flows, and extension negotiation match the documented surface. | Unknown revision/extension, unauthorized or cross-tenant catalog entry, schema oracle attempt, bad Origin/Host/bearer audience, oversized frame, cancellation, replay, and drain are rejected without capability leakage. | not run |
| `reference` | `ContractCompatibilityVerifier` | Run `cargo xtask specs verify`, `cargo xtask profiles verify`, `cargo xtask contracts check`, and `cargo xtask contracts diff --against fixtures/contract-compatibility/baseline`; compare every reference table and example with its cited source. | Recorded baseline revision/path, current generated contracts, composed extension catalogs, complete capability matrix. | IDs, defaults, limits, protocol revisions, CLI syntax, generated contracts, and compatibility labels are current and internally linked. | Use the checked-in incompatible fixtures under `fixtures/contract-compatibility/` and confirm drift, removed operations/schemas, unknown IDs, and missing sources are rejected. | not run |
| `ops-security-troubleshooting` | `SRESecurityVerifier` | Run `cargo xtask profiles generate-verify --jobs 2 --automated-evidence-only`; in an approved disposable environment run `scripts/recovery/rehearse-local`; inspect CI supply-chain and release artifacts rather than inferring a pass from workflow YAML. Execute each deployment, probe, migration, rollback, observability, incident, and secret-rotation scenario only against its named disposable target; record it blocked when the concrete composition or platform owner is absent. Check configuration redaction separately and never present it as rotation. | Docker-capable local host, ephemeral services, test-only credentials, release candidate revision, retained matrix/security/SBOM/provenance inputs, authorized operator, and a concrete platform-owned target for environment-dependent checks. No production credential, endpoint, or database route may be present. | Matrix, recovery, and repository artifacts prove only their named boundaries. Every live operational claim has revision-bound, environment-scoped evidence; a rotation rehearsal additionally records the new test secret accepted and the old one rejected without disclosure. | Unready dependency, migration incompatibility, failed restore fingerprint/RTO, stale contract, secret-like output, mismatched digest, missing concrete target or manual approval, old test secret still accepted after rotation, and unsafe rollback block release. | not run |
| `development` | `ContributorWorkflowVerifier` | Run `cargo xtask specs verify` and `cargo xtask profiles generate-verify --matrix-only`; against the freshly rendered disposable project run `cargo xtask service doctor --project target/profile-matrix/work/minimal --json`, `cargo xtask service diff --project target/profile-matrix/work/minimal`, `cargo xtask service add openapi --dry-run --project target/profile-matrix/work/minimal`, and `cargo xtask service upgrade --to 0.1.0 --dry-run --project target/profile-matrix/work/minimal`; compile or run each owned example by its nearest package script or focused Cargo target. | Fresh `target/profile-matrix/work/minimal` generated by the preceding matrix command; no application-owned changes; catalog and kit version `0.1.0`. | Authoring, extension, generator, contract, testing, and contribution instructions use commands exposed by `xtask`; dry runs preserve ownership and released migrations. | Run `cargo xtask service add rate-limit-redis --dry-run --project target/profile-matrix/work/minimal`; the existing `rate-limit-local` provider must cause a conflict without mutation. Corrupt only a disposable managed-region hash and confirm doctor fails before any apply. | not run |

## Required end-to-end journeys

These rows separate repository source, fixture, generated-project, and library evidence from an observation across an assembled runtime boundary. A generated process proves only that generated process. A live LLM provider, MCP endpoint, browser/backend composition, deployment, or secret-rotation check remains blocked until the named external owner and environment exist.

### Journey 1 verification

**Journey:** Understand, select, generate or configure, run, and verify health.

| Field | Required record |
|---|---|
| Verification owner | `ReleaseProfileVerifier` |
| Command or scenario | Run `cargo xtask profiles generate-verify --matrix-only`. For the concrete checked-in API run `cargo run --bin omnius-api-server -- profile-info`, then start `cargo run --bin omnius-api-server -- server --config config/reference.toml --environment development`. While it is running, execute `curl --fail --silent --show-error http://127.0.0.1:8080/live`, `curl --fail --silent --show-error http://127.0.0.1:8080/ready`, `curl --fail --silent --show-error http://127.0.0.1:8080/startup`, and `curl --fail --silent --show-error http://127.0.0.1:8080/version`. |
| Prerequisites | Required substitutions in `config/reference.toml`; a disposable development PostgreSQL database already migrated to a compatible schema; test-only credentials; port `8080` free. The matrix command needs the pinned Rust and Node toolchains plus the pinned package-manager version and is local diagnostic evidence, not CI release readiness. |
| Expected observation | The matrix report records each generated profile and its generated-process checks. Separately, `profile-info` reports the compiled `oauth-provider` profile, the reference API starts, and all four concrete runtime probes return their documented success semantics. Neither result proves another generated profile is deployed. |
| Failure-path check | In a disposable run, withhold one required environment substitution or make PostgreSQL unavailable. Startup must fail closed with a stable, redacted error; `/ready` must not report ready. |
| Current result | not run |

### Journey 2 verification

**Journey:** Add, expose, test, and operate a backend capability.

| Field | Required record |
|---|---|
| Verification owner | `BackendCapabilityVerifier` |
| Command or scenario | First create a disposable managed project with `cargo xtask profiles generate-verify --matrix-only`. Run `cargo xtask service add openapi --dry-run --project target/profile-matrix/work/minimal`; after reviewing the plan, apply `cargo xtask service add openapi --project target/profile-matrix/work/minimal`. Then run `cargo xtask service doctor --project target/profile-matrix/work/minimal`, `cargo xtask service diff --project target/profile-matrix/work/minimal`, `cargo test --manifest-path target/profile-matrix/work/minimal/Cargo.toml --package matrix-minimal`, `cargo run --manifest-path target/profile-matrix/work/minimal/Cargo.toml --package matrix-minimal -- profile-info`, and `cargo xtask contracts check`. |
| Prerequisites | The freshly generated `target/profile-matrix/work/minimal` project only; `openapi` and its transitive `validation` dependency from the checked-in catalog; no edits worth preserving in the disposable target. If a selected capability carries persistence, its forward-only migrations, disposable development database, rollback/roll-forward decision, and cleanup owner are required before any runtime exercise. |
| Expected observation | The reviewed plan and `profile-info` show `openapi` plus its dependency closure; doctor and diff are clean and the generated package test passes. This is generated-project metadata and test evidence. The stock base-service template does not mount module-specific OpenAPI routes, so `/openapi.json` exposure and capability-specific health/telemetry observations are blocked until an application composes that route. |
| Failure-path check | Run `cargo xtask service add rate-limit-redis --dry-run --project target/profile-matrix/work/minimal`; the existing `rate-limit-local` provider must make the plan fail without changing the project. A module-specific runtime failure check is blocked for the same missing composition reason. |
| Current result | not run |

### Journey 3 verification

**Journey:** Run and extend the web application through a releasable build.

| Field | Required record |
|---|---|
| Verification owner | `BrowserJourneyVerifier` |
| Command or scenario | Run `pnpm install --frozen-lockfile`, `pnpm sdk:check:generated`, `pnpm web:build`, and `pnpm web:release:gates`. `pnpm web:dev` can serve the checked-in source for inspection. The runtime scenario must browser-drive sign-in, tenant selection, generated-client record calls, RFC 9457 handling, realtime reconnect, upload, and sign-out only against a separately assembled compatible backend. |
| Prerequisites | Pinned Node and package-manager versions; Playwright browsers and the managed fixture dependencies for release gates. The live scenario additionally requires a matching generated web/backend profile, test accounts and tenants, realtime and storage providers for those claims, and a manual accessibility reviewer. |
| Expected observation | Generated-client drift, the web build, fixture-backed browser checks, base-path handling, and manual accessibility evidence are recorded at the candidate revision. These commands do not prove checked-in browser source is exposed by a production service. Live authentication, tenancy, realtime, and upload observations are blocked until the matching backend composition is supplied. |
| Failure-path check | Release fixtures must cover expired session, denied tenant, disconnected realtime, rejected upload, wrong base path or CSP, and keyboard failure. The corresponding live-backend failures remain blocked until that environment exists. |
| Current result | not run |

### Journey 4 verification

**Journey:** Configure and use an LLM safely and observably.

| Field | Required record |
|---|---|
| Verification owner | `LLMDeterminismVerifier` |
| Command or scenario | Run `cargo xtask ai verify` and `cargo test -p omnius-llm-evals --test evaluation --test report_admission --test corpus_replay --test properties --test offline_fixtures`. A live observation requires an application-owned assembled LLM entry point; no first-party repository command currently supplies one. |
| Prerequisites | Checked-in deterministic fixtures with no provider credential for the repository commands. A live run additionally requires an approved test provider, model and region, secret injection, immutable capability/price revision, budget, tenant/principal, safety policy, and redacted evidence sink. |
| Expected observation | Fixture replay is deterministic and verifies library contracts for structured output, tools, streaming, usage, safety, and evaluation. It does not prove a live request, assembled routing, secret injection, provider behavior, or runtime telemetry. Those observations are blocked until the application owner supplies the assembled command and environment. |
| Failure-path check | Repository tests must reject unauthorized tools, exhausted budgets, capability mismatches, malformed streams, missing usage, and prohibited raw prompt/response retention. Provider timeout, cancellation, and credential-revocation checks are environment-dependent and remain blocked without the live target. |
| Current result | not run |

### Journey 5 verification

**Journey:** Expose and diagnose an authorized MCP capability.

| Field | Required record |
|---|---|
| Verification owner | `MCPProtocolVerifier` |
| Command or scenario | Run `cargo xtask ai verify`, `cargo test --tests -p omnius-mcp-server-core -p omnius-mcp-transport-http -p omnius-mcp-transport-stdio -p omnius-mcp-tools -p omnius-mcp-resources -p omnius-mcp-prompts -p omnius-mcp-auth-oauth`, and `cargo run -p omnius-mcp-conformance --bin mcp-conformance -- synthetic`. `cargo run -p omnius-mcp-conformance --bin mcp-conformance -- official-plan-http http://127.0.0.1:9010/mcp` can inspect the pinned official HTTP plan, but there is no first-party process at that endpoint. |
| Prerequisites | Repository fixtures for the commands above. A runtime run additionally requires a concrete capability registry, deny-by-default authorizer, identity and tenant, mounted `/mcp` or an executable stdio binary, negotiated extensions, and persistence/backplane where durable behavior is claimed. MRTR and Tasks migrations are checked in and embedded by the common migrator, but an application that composes those capabilities must apply them to its disposable database and prove the applied version. |
| Expected observation | Focused tests and synthetic output verify library, framing, authorization, redaction, and harness contracts only. The plan command emits pinned conformance arguments only. Discovery, authorized invocation, MRTR/Tasks behavior, official conformance, and Inspector observations are blocked because the repository has no assembled first-party MCP server entry point. |
| Failure-path check | Focused tests must cover wrong OAuth audience, unauthorized or cross-tenant access, invalid cursor/schema, cancellation and timeout. Transport-close, task replay, worker restart, and live external-client failures remain blocked until a server, repository/worker composition, and applied runtime state exist. |
| Current result | not run |

### Journey 6 verification

**Journey:** Deploy, migrate, observe, recover, rotate, and upgrade.

| Field | Required record |
|---|---|
| Verification owner | `DeploymentRecoveryVerifier` |
| Command or scenario | Only in an explicitly disposable development environment, run `cargo run --bin omnius-api-server -- migrate --config config/reference.toml --environment development`, then `cargo run --bin omnius-api-server -- migration-status --config config/reference.toml --environment development`. Start the same target with `cargo run --bin omnius-api-server -- server --config config/reference.toml --environment development` and request `curl --fail --silent --show-error http://127.0.0.1:8080/ready`. Run the synthetic recovery rehearsal with `scripts/recovery/rehearse-local`, the configuration-redaction check with `cargo test -p omnius-config tests::unknown_fields_and_invalid_values_fail_safely -- --exact`, and the compatibility check with `cargo xtask contracts diff --against fixtures/contract-compatibility/baseline`. This documentation workflow must never target production. |
| Prerequisites | An isolated disposable development PostgreSQL database with `POSTGRES_URL` pointing only to it; test-only configuration substitutions and credentials; explicit rehearsal authorization; schema range `2026082301` through `2026082808`; Docker for the local synthetic recovery script; free port `8080`; recorded baseline fixture and cleanup owner. No production credential, endpoint, or database route may be present. |
| Expected observation | Migration status reports target version `2026082808`, the concrete reference API reports ready, the local recovery artifact meets its synthetic fingerprint and timing checks, configuration failures omit secret values, and the contract diff is compatible. Redaction is not rotation. Deployment and secret rotation require separate platform-owned test-environment rehearsals with revision-bound, redacted evidence; without those owners and environments, those parts remain blocked. |
| Failure-path check | Against disposable fixtures only, confirm an incompatible schema or failed migration blocks startup/readiness, a bad restore fingerprint or recovery deadline fails the rehearsal, configuration diagnostics remain redacted, and a breaking contract fixture is rejected. A platform rotation rehearsal must prove the new test secret is accepted and the old value is rejected without disclosure; no repository command is claimed for that external action. |
| Current result | not run |

## Cross-cutting evidence gates

| Gate | Independent owner | Verification scenario | Required evidence | Rejection condition | Current result |
|---|---|---|---|---|---|
| Links, frontmatter, navigation, sources, and examples | `DocsConsistencyVerifier` | `cargo xtask docs verify` plus review of every documented command against `xtask/src/main.rs` or the nearest `package.json`. | Validator log tied to revision; zero unresolved links/anchors/paths; command owner recorded. | Missing target, local/absolute path, stale direct evidence, unknown command/script, malformed fence, placeholder, or navigation orphan. | not run |
| Profile and exposure classification | `ArchitectureClassificationVerifier` | Compare every page and coverage row to composed base/extension profiles and a concrete non-test composition root. | Exact profile IDs; module selection evidence; separate composition/entry-point evidence for exposure. | Selection, spec, library, fixture, generated contract, or router factory is used alone to claim a mounted runtime. | not run |
| Security and privacy | `SecurityPrivacyVerifier` | Review authentication, authorization, tenancy, SSRF, secrets, prompt/tool/resource trust, audit, retention, and example data; exercise representative negative paths above. | Threat-boundary review and redacted negative-path outputs. | Secret/personal/private-prompt leakage, cross-tenant access, permissive fallback, unsafe production default, unbounded input/work, or missing audit/data-governance boundary. | not run |
| Environment-dependent evidence | `EnvironmentEvidenceVerifier` | Execute only in the named disposable environment: PostgreSQL/PGMQ, Redis, NATS, object storage/scanner, SMTP, webhook provider, browser, Docker recovery, live LLM provider, and assembled MCP transports. | Tool/provider versions, configuration class, candidate revision, timestamps, sanitized logs, artifact digests, cleanup record, and explicit environment scope. | Missing dependency is reported as pass; fixture/library/profile evidence is promoted to live exposure; credentials or user data enter artifacts; result cannot be reproduced or tied to the revision. | not run |
| Release evidence | `ReleaseEvidenceVerifier` | Produce the matrix inputs and run `python3 scripts/release/ai_mcp_evidence.py --result target/web-release-inputs/ai-architecture.json --result target/web-release-inputs/ai-suite-static.json --result target/web-release-inputs/lifecycle-upgrade.json --result target/web-release-inputs/profile-matrix.json --output target/ai-mcp-release-evidence/evidence.json`; apply the web runbook's manual accessibility decision separately. | All command-result inputs, matrix report, candidate revision/run ID, contract/spec hashes, manual records where required. | Skipped required check, mismatched revision/hash/digest, absent artifact, synthetic conformance presented as official, or automated evidence presented as deployment approval. | not run |

## Result recording

For each executed row, preserve the exact expanded command or browser scenario, candidate commit, owner, start/end time, prerequisite versions, exit status, sanitized log or recording path, artifact digest, expected/failure-path observations, and environment scope. Use only `passed`, `failed`, `blocked`, or `not applicable` after execution; include the reason for `blocked` or `not applicable`. A partial run does not change this plan's `not run` result until both the expected and failure-path checks are recorded.