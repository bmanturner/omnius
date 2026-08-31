---
title: Documentation evidence inventory
description: Source authority, capability registry, evidence boundaries, contradictions, and exclusions for the Omnius documentation program.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - contributor
topics:
  - documentation
  - evidence
  - architecture
capabilities:
  - docs-evidence-inventory
source:
  - DOCS_PROMPT.md
  - specs/machine/module-catalog.yaml
  - specs/machine/profiles.yaml
evidence:
  - Cargo.toml
  - apps/api-server/src/contracts.rs
  - specs/machine/extensions/web-application-suite/profiles.yaml
  - specs/machine/extensions/llm-mcp-suite/profiles.yaml
  - migrations/2026082807_create_mcp_mrtr_state.sql
  - migrations/2026082808_create_mcp_tasks.sql
  - packages/web-sdk/src/react/capabilities.ts
  - packages/web-sdk/src/react/local-state.ts
last_verified: 2026-08-30
---

# Documentation evidence inventory

This is the source-of-truth inventory for the architecture gate. It records what the twelve Wave 1 evidence owners found without turning a specification, catalog entry, library, generated artifact, or test fixture into a runtime claim. The normalized row-level decisions are in the [coverage matrix](coverage-matrix.md); final files and assignments are in [navigation](navigation.md).

## Evidence model

Every documentation claim must keep these classifications independent:

| Classification | Allowed values | What proves it |
|---|---|---|
| `status` | `experimental`, `stable`, `deprecated` | Public API maturity evidence; version `0.1.0` is treated as experimental. |
| `implementation` | `implemented`, `partial`, `source-only`, `specified-only`, `unavailable` | Source, focused tests, schemas, migrations, or the absence of the promised implementation. |
| `profile_availability` | Exact profile IDs or `[]` | Selection in `specs/machine/profiles.yaml` or an extension profile file. Selection is not assembly. |
| `public_exposure` | `assembled`, `generated-only`, `library-only`, `unassembled`, `not-applicable` | A concrete non-test composition root and public or operator entry point. |

Evidence precedence is: exercised runtime result; concrete composition and focused tests; implemented library or tool source; checked-in generated artifact with its generation path; machine profile selection; normative specification. Lower layers may explain intent but never upgrade a higher-layer classification.

`apps/api-server/src/contracts.rs` identifies the checked-in public application as `oauth-provider`. The generated base-service template, web/AI/MCP profile catalogs, checked-in OpenAPI, browser fixtures, and release definitions therefore do not prove those surfaces are mounted in that application.

## Wave 1 evidence owners

| Evidence owner | Assigned domain | Brief |
|---|---|---|
| `CoreInventory` | Foundation, configuration, process lifecycle, probes | `agent://CoreInventory` |
| `HttpInventory` | HTTP, validation, contracts, pagination, idempotency, GraphQL, gRPC | `agent://HttpInventory` |
| `DataInventory` | PostgreSQL, Redis, cache, rate limiting, search, lifecycle, recovery intent | `agent://DataInventory` |
| `IdentityInventory` | Identity, authentication, authorization, tenancy, audit, privacy | `agent://IdentityInventory` |
| `AsyncInventory` | Jobs, outbox/inbox, scheduler, workers, events, feature flags | `agent://AsyncInventory` |
| `IntegrationsInventory` | Realtime, storage, uploads, messaging, webhooks, optional product modules | `agent://IntegrationsInventory` |
| `WebSdkInventory` | Web package, contracts, framework-neutral SDK, React state, generated capabilities | `agent://WebSdkInventory` |
| `WebJourneyInventory` | Browser journeys, accessibility, security, testing, release ceiling | `agent://WebJourneyInventory` |
| `LlmCoreInventory` | Provider-neutral LLM contracts, providers, routing, usage, APIs | `agent://LlmCoreInventory` |
| `LlmAdvancedInventory` | Prompts, tools, streaming, media, safety, conversations, evaluations | `agent://LlmAdvancedInventory` |
| `McpInventory` | MCP server, discovery, transports, protocol surfaces, extensions, conformance | `agent://McpInventory` |
| `DeliveryInventory` | Generator lifecycle, deployment, recovery, release evidence, CI, supply chain | `agent://DeliveryInventory` |

The `agent://` briefs are architecture inputs, not publishable source links. Writer-facing claims must cite the repo-relative paths recorded in the matrix.

## Canonical capability registry

The following registry is exhaustive for the twelve briefs. Compound entries group stable IDs only when their evidence classifications and owning explanation are the same. Each entry has a row in the [coverage matrix](coverage-matrix.md) unless the exclusion table below redirects an aggregate or duplicate name to canonical rows.

### Foundation and HTTP

- `foundation-architecture`
- `profile-selection`
- `core-primitives` (`core-types`, `core-errors`, `core-identifiers`, `core-clock`, `build-metadata`)
- `configuration` (`configuration-loader`, `configuration-secrets`)
- `inspect-config` — specified-only; no implemented inspection command was found.
- `minimal-reference-service` (`minimal-reference-service`, `minimal-http-surface`)
- `runtime-lifecycle` (`runtime-lifecycle`, `health-readiness-shutdown`)
- `http`
- `http-request-semantics` (`validation`, `rfc9457-problems`, `conditional-etag`)
- `pagination`
- `idempotency`
- `openapi-contracts` (`openapi`, `contracts.openapi`)
- `static-delivery`
- `graphql`
- `grpc`

### Data, identity, and asynchronous processing

- `postgres`
- `migrations`
- `reference-postgres`
- `redis-core`
- `cache` (`cache-local`, `cache-redis`)
- `rate-limit-local`
- `rate-limit-redis`
- `search-meilisearch`
- `data-lifecycle`
- `backup-recovery`
- `identity-principal`
- `local-account-password`
- `browser-sessions-postgres`
- `browser-sessions-redis`
- `jwt-resource-server`
- `api-keys-service-accounts`
- `oauth-oidc-provider`
- `oidc-client-external-identities`
- `mfa-totp`
- `mfa-webauthn-passkeys`
- `authorization-policy-basic`
- `authorization-policy-cedar`
- `organizations-tenancy`
- `audit-security-events`
- `privacy-lifecycle-consent-moderation`
- `web-account-and-oauth-workflows`
- `typed-jobs-and-domain-events`
- `jobs-apalis-redis`
- `jobs-pgmq`
- `transactional-outbox`
- `transactional-inbox`
- `durable-scheduler`
- `worker-composition-and-operations`
- `durable-nats-events`
- `ephemeral-redis-events`
- `feature-flag-evaluation`

### Integrations and web

- `realtime-delivery` (`realtime-core`, `sse`, `websockets`)
- `object-storage`
- `upload-workflow`
- `email`
- `notifications`
- `webhooks-svix`
- `webhooks-inbound`
- `outbound-http`
- `localization`
- `billing`
- `admin`
- `consent`
- `moderation`
- `web-application`
- `web-contracts`
- `web-sdk-transport`
- `web-auth`
- `web-react-state`
- `web-realtime`
- `web-uploads`
- `web-capabilities`
- `web-feature-flags`
- `web-local-state`
- `web-app-composition-and-routing`
- `web-identity-and-account-journeys`
- `web-tenant-context-and-authorization-presentation`
- `web-data-forms-errors-and-reference-records`
- `web-accessibility-and-browser-support`
- `web-static-delivery-and-browser-security`
- `web-testing-build-and-release`
- `web-reference-application-runtime-ceiling`

### LLM

- `llm-core`
- `llm-provider-rig`
- `llm-provider-bedrock`
- `llm-provider-vertex`
- `llm-routing`
- `llm-structured-output`
- `llm-tool-runtime`
- `llm-streaming`
- `llm-prompt-catalog`
- `llm-conversations`
- `llm-media`
- `llm-safety-policy`
- `llm-usage-ledger`
- `llm-budgeting`
- `llm-http-api`
- `web-llm`
- `llm-evals`
- `llm-embeddings`

### MCP

- `mcp-server-core` and `agent-capability-registry`
- `mcp-discovery-versioning`
- `mcp-transport-http`
- `mcp-transport-stdio`
- `mcp-tools`
- `mcp-resources`
- `mcp-prompts`
- `mcp-completion`
- `mcp-auth-oauth`
- `mcp-auth-client-credentials`
- `mcp-auth-enterprise`
- `mcp-elicitation`
- `mcp-tasks`
- `mcp-subscriptions-local`
- `mcp-subscriptions-redis`
- `mcp-subscriptions-nats`
- `mcp-progress`
- `mcp-apps`
- `mcp-skills`
- `mcp-server-card-preview`
- `mcp-progressive-discovery-preview`
- `mcp-conformance`
- `mcp-profiles`

### Delivery and release

- `generator-module-lifecycle` (`generator`, `service-management`)
- `base-service-template` (`base-service-template`, `health`, `web-static`)
- `api-reference` (`api-reference`, `oauth-provider`)
- `recovery-rehearsal`
- `release-evidence` (`profile-matrix`, `contract-compatibility`, `web-release-evidence`, `ai-mcp-release-evidence`)
- `ci-quality`
- `supply-chain`

## Evidence-backed exclusions and aliases

These names are not dropped. They are excluded as separate rows because a separate row would double-count the same capability or mix an aggregate with its independently classified components.

| Discovered name | Disposition | Evidence-backed reason |
|---|---|---|
| Async brief `HTTP idempotency` | Redirect to `idempotency` | Same `crates/idempotency/src/lib.rs`, API composition, and migration evidence as the HTTP brief. |
| Integrations brief `feature-flags` | Redirect to `feature-flag-evaluation` | Same `crates/feature-flags/src/lib.rs` implementation and profile selection. |
| Integrations brief `search-meilisearch` | Redirect to `search-meilisearch` | Same crate, migration, and `full-reference` selection as the data brief. |
| Integrations brief `graphql` | Redirect to `graphql` | Same `crates/graphql/src/lib.rs`; no separate integration implementation. |
| Integrations brief `grpc` | Redirect to `grpc` | Same `crates/grpc/src/lib.rs` and generated protocol evidence. |
| Integrations brief `data-lifecycle` | Redirect to `data-lifecycle` | Same catalog/spec/migration evidence; the duplicate brief supplies no runtime assembly. |
| Web journey `WEB-REALTIME-AND-UPLOADS` | Redirect to `web-realtime` and `web-uploads` | Aggregate journey has two components with different generated-artifact evidence and must not collapse their classifications. |
| LLM core and advanced duplicate names | Merge evidence owners on canonical LLM rows | Both briefs inspected the same stable IDs; advanced evidence adds behavior and gaps rather than a second capability. |
| MCP “tools/resources/prompts” aggregate | Use three canonical rows | Their modules and protocol surfaces are independently selectable and reviewable. |
| MCP “interactive and long-running flows” aggregate | Use elicitation, tasks, subscriptions, and progress rows | The components have different implementation and profile evidence; in particular `mcp-progress` is unavailable. |

## Canonical terminology and glossary candidates

| Term | Canonical meaning | Avoid |
|---|---|---|
| profile | A named generator selection resolved from authoritative machine profile data. | Calling it a deployed edition or runtime. |
| module | A stable catalog unit with dependencies, conflicts, ownership, and optional persistence or route declarations. | Treating a crate name, route, or profile as synonymous. |
| capability | A user-facing behavior or protocol surface; it may span modules and composition roots. | A crate-by-crate encyclopedia. |
| selected | Proven present in resolved profile data. | “Enabled,” “running,” or “available” without runtime evidence. |
| assembled | Mounted in a concrete non-test application composition with a public or operator entry point. | Inferring assembly from a router factory, library, test fixture, or contract. |
| generated-only | Materialized only through the generator/template or an ephemeral profile build. | Calling the checked-in reference API a generated profile. |
| library-only | Implemented reusable code with no public application composition promised by the evidence. | “Unsupported” when the library is usable by a composer. |
| unassembled | Source or declarations exist, but the inspected concrete application does not mount the surface. | “Implemented API” when only a router factory exists. |
| public contract | Emitted OpenAPI, AsyncAPI, permissions, capabilities, or SDK material tied to a specific contract profile and generation check. | Assuming artifact presence proves drift protection or deployment. |
| reference application | The checked-in `apps/api-server` application compiled as `oauth-provider`. | “Full reference” unless generated-profile evidence proves it. |
| reference service | The minimal checked-in `apps/server` process or a generated base-service instance, named explicitly. | Using “reference app” ambiguously. |
| readiness | Whether the process is ready to serve according to registered checks; meanings differ between minimal/template and API app. | Treating `/ready` as universal dependency health. |
| durable | Persistence and restart semantics proven by a provider and worker composition. | Applying it to an interface, schema, or selected module alone. |
| provider-neutral LLM request | Canonical Omnius request/response contracts without provider SDK types. | Claiming provider availability or credential wiring. |
| MCP exposure | A registry capability projected through a mounted MCP transport with authorization. | Equating a capability registry entry with a reachable MCP server. |
| release evidence | Revision-bound automated and manual records admitted by the release schemas/runbooks. | Calling a workflow definition a passing release. |

## Contradictions and unresolved evidence

1. `specs/02-module-system-and-generator.md` names `cargo service new` and `profile set`; `xtask/src/main.rs` exposes only `cargo xtask service add`, `remove`, `upgrade`, `doctor`, and `diff`. The render implementation also does not itself perform every formatting/validation step claimed by the spec.
2. The minimal checked-in application and the generator catalog disagree on the apparent module set. The minimal app must be documented from its composition root, not catalog inheritance.
3. Catalog route declarations, including realtime and MCP paths, do not prove mounting. The realtime catalog path and router-local path also differ (`/realtime/events` versus `/events`).
4. The HTTP idempotency implementation uses an unscoped identity where normative material expects tenant/principal scoping.
5. `rate-limit-redis` is implemented but not selected by a verified base profile.
6. `data-lifecycle`, backup/retention intent, consent, and moderation have catalog/spec/schema evidence that is stronger than their runtime exposure. `crates/privacy` implements separate privacy workflows; it does not prove the catalogued data-lifecycle worker.
7. `worker-composition-and-operations` has `profile_availability: []`: selection of job and event modules by the `worker` profile does not prove a runnable worker binary or the composition described by `WorkerBuilder`.
8. The current web capability artifact reports backend `auth-oauth-server` while `web-auth` is false. Browser fixtures and extension profiles are generated/fixture evidence, not current application assembly.
9. Web realtime has no verified generated AsyncAPI artifact. Its drift check can therefore exit successfully without comparing an AsyncAPI artifact, so success does not prove realtime contract drift protection.
10. The LLM catalog names nonexistent standalone paths for `llm-http-api`, `web-llm`, and `llm-budgeting`. Actual implementations are an API router factory, a web SDK module, and a budget port plus usage ledger.
11. The LLM catalog declares tool-approval and eval-run persistence without corresponding inspected migrations or repositories. `llm-embeddings` is selected in profiles but no standalone crate implementation was found.
12. Checked-in AI OpenAPI operations do not prove `llm_http_router` is mounted; non-test construction was not found.
13. MCP catalog/profile support does not prove an MCP listener or stdio binary. `mcp-completion` and dedicated `mcp-progress` implementations were not found, and catalogued subscription module paths conflict with the inspected source layout. Checked-in migrations `migrations/2026082807_create_mcp_mrtr_state.sql` and `migrations/2026082808_create_mcp_tasks.sql` define `public.mcp_mrtr_states`, `public.mcp_mrtr_audit_events`, `public.mcp_tasks`, `public.mcp_task_idempotency`, `public.mcp_task_input_keys`, `public.mcp_task_input_rounds`, `public.mcp_task_payload_nonces`, and `public.mcp_task_events`; the common migrator embeds the migrations directory and declares `2026082808` as the current schema version. That schema evidence does not prove repository, worker, transport, or application assembly. Persistence remains incomplete: enterprise identity links have no verified migration or composed adapter; Redis subscriptions are explicitly ephemeral; NATS subscriptions have no proven JetStream durability; Apps lacks object-store/audit repositories; and Skills artifact persistence lacks a proven migration or adapter.
14. The generated base template has unconditional readiness and local container hardening, not dependency-aware production deployment behavior.
15. The local recovery rehearsal uses `postgres:17.6-alpine` without a digest despite release language requiring digest-pinned containers; no CI invocation was found.
16. CI and release workflows define gates but no retained matrix, release approval, deployment, SBOM publication, signing, or production promotion result was inspected. Ordinary web CI remains non-release-ready until manual accessibility evidence is approved.
17. Rust advisory exceptions differ between workflow policy and `deny.toml`; Node license output exists without an inspected allow/deny policy.

## Program non-goals

- Do not write exhaustive crate, TypeScript declaration, OpenAPI operation, schema, or generated-contract reference by hand.
- Do not claim production deployment topology, Kubernetes/Helm support, automatic promotion, image signing, or remote backup behavior without new evidence.
- Do not present secret placeholders as defaults or include real credentials, private prompts, reasoning, or personal data.
- Do not invent adapter composition for Redis, jobs, events, storage, LLM providers, MCP transports, workers, or browser surfaces.
- Do not promise roadmap dates or silently resolve contradictions. Specified-only material stays visibly separate from runnable guidance.
- Do not publish runnable quickstarts for unassembled surfaces. Use integration-boundary guides and deterministic library/contract verification instead.

## Architecture gate

Page writing may begin only when:

1. every registry item above has a matrix row or appears in the exclusion table;
2. every owner page in the matrix appears exactly once in the canonical page inventory;
3. the four classifications use only the allowed vocabularies;
4. each page has one writing unit and a different independent reviewer;
5. each audience and all six required journeys have a path through the inventory; and
6. each row has an executable or inspectable verification method whose result begins as `not run` rather than an inferred pass.
