# Omnius documentation program

Create extensive, evidence-driven documentation for the complete Omnius platform. Cover every implemented user-facing capability and every important operational or extension surface, including the web application, web SDK, LLM services, and MCP server support. Preserve a coherent learning path across concepts, guides, reference, operations, security, troubleshooting, and development; do not produce a crate-by-crate encyclopedia.

Agents may gather evidence and write independent pages in parallel, but one integration owner must control information architecture, terminology, navigation, shared pages, and final truth.

## 1. Establish the documentation contract

Use plain Markdown with portable YAML frontmatter:

```yaml
---
title: LLM routing and fallback
description: Selecting models and handling provider failures without silent capability downgrades.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: unassembled
audience:
  - ai-application-developer
topics:
  - llm
  - routing
  - reliability
capabilities:
  - llm-routing
source:
  - crates/llm-routing/src/lib.rs
  - specs/39-llm-routing-reliability-cost-and-quotas.md
evidence:
  - crates/llm-routing/src/fallback.rs
last_verified: 2026-08-30
---
```

Use independent classifications for distinct evidence layers:

- `status`: `experimental`, `stable`, or `deprecated` describes API maturity.
- `implementation`: `implemented`, `partial`, `source-only`, `specified-only`, or `unavailable` describes source and test evidence.
- `profile_availability`: lists only generator profiles proven to select the capability; an empty list means none were verified.
- `public_exposure`: `assembled`, `generated-only`, `library-only`, `unassembled`, or `not-applicable` describes whether a concrete application exposes it.

Documentation rules:

1. Document behavior as available only when code, tests, schemas, generated artifacts, examples, or exercised runtime behavior prove it.
2. Use specifications and ADRs to explain architectural intent and constraints. They are not proof that a feature is implemented.
3. Mark partial, source-only, specified-only, profile-unavailable, and unassembled behavior conspicuously. State the missing pieces and never invent a workaround or roadmap date.
4. Record contradictions and unverifiable claims in the evidence inventory for resolution; do not silently choose the more convenient source.
5. Exercise every documented command and runnable example in an appropriate clean environment. Record prerequisites and meaningful expected results.
6. Use relative Markdown links. Link to canonical explanations rather than duplicating them.
7. Give each concept one owning page. Guides may summarize and link; reference pages must not retell tutorials.
8. Do not reproduce exhaustive Rust APIs, TypeScript declarations, OpenAPI operations, schemas, or generated contracts by hand. Explain how to use them and link to rustdoc or generated reference artifacts.
9. Never expose real secrets, credentials, private prompts, hidden reasoning, personal data, or unsafe production defaults in examples.
10. Treat checked-in generated artifacts as evidence only after confirming how they are produced and checked for drift.

## 2. Serve explicit audiences and journeys

The documentation must support these audiences without requiring them to reverse-engineer the repository:

- evaluators deciding whether Omnius fits a service or product
- Rust application developers composing backend capabilities
- web developers building or extending the browser application and consuming the web SDK
- AI application developers integrating models, prompts, tools, streaming, media, and evaluations
- MCP developers exposing Omnius capabilities or connecting external MCP clients
- module and provider authors extending Omnius
- operators deploying, observing, securing, upgrading, and recovering services
- security and privacy reviewers validating trust boundaries and data handling
- contributors changing contracts, generators, SDKs, tests, and release processes

Required end-to-end journeys include:

1. Understand Omnius, select a profile, generate or configure a service, run it, and verify health.
2. Add a backend capability, expose it through the intended API surface, test it, and operate it.
3. Run and extend the web application, authenticate, select tenant context, call generated clients, handle errors, use realtime updates and uploads, and produce a releasable build.
4. Configure an LLM provider, submit a provider-neutral request, stream or consume the result, use structured output or tools, observe usage and failures, and apply safety/data-governance policy.
5. Expose an authorized capability through MCP, inspect discovery, use the supported transport, invoke tools/resources/prompts, handle long-running or interactive flows, and diagnose protocol errors.
6. Deploy a composed service, migrate safely, validate readiness, observe it, respond to failures, recover data, rotate secrets, and upgrade without contract drift.

If evidence shows that part of a journey is not implemented, retain the journey but label the boundary accurately and link to specified-only material separately.

## 3. Build the evidence inventory before writing

Inspect, at minimum:

- `specs/`, including numbered specifications, accepted ADRs, suite manifests, machine catalogs, risk registers, acceptance criteria, traceability files, examples, and validation reports
- `Cargo.toml`, `crates/`, `apps/`, `templates/`, migrations, configuration, tests, and examples
- `web/`, `packages/web-sdk/`, root package scripts, browser/E2E tests, accessibility and release gates
- `contracts/` and the generation paths for OpenAPI, permissions, capabilities, realtime contracts, and SDK output
- `config/`, `.sqlx/`, `ops/`, `scripts/`, `release/`, deployment assets, and CI workflows
- executable CLIs, `xtask` commands, profile/module manifests, generated fixtures, compatibility baselines, and supply-chain controls

Evaluate four layers independently: normative specification, implemented source and focused tests, generator/profile selection, and concrete application/runtime exposure. A crate, catalog entry, generated contract, or SDK method does not by itself prove that a route or workflow is assembled in the current reference application.

For each capability, capture this structured brief:

```text
Capability and stable identifiers:
User goals and supported journeys:
Maturity:
Implementation evidence and gaps:
Verified generator/profile availability:
Verified concrete application/runtime exposure:
Implemented behavior:
Explicit non-goals:
Public entry points and generated contracts:
Configuration and secrets:
Authorization, tenancy, privacy, and trust boundaries:
Persistence and migration impact:
Runtime lifecycle, health, telemetry, and shutdown:
Failure modes and troubleshooting evidence:
Runnable examples and commands:
Relevant tests and acceptance criteria:
Specifications, ADRs, schemas, and source paths:
Web, HTTP, jobs, LLM, MCP, and operator exposure:
Claims or contradictions that could not be verified:
Recommended owning page and cross-links:
Verification method and reviewer specialty:
```

Create a coverage matrix from these briefs. Every discovered capability must have a documentation destination, maturity, implementation state, verified profile availability, verified public exposure, evidence owner, writing owner, reviewer, and final verification method before parallel writing begins.

## 4. Inventory all capability domains

The inventory must not stop at the current page list or workspace crate names. Group collaborating crates and packages into user-facing capabilities, and explicitly examine the following domains.

### Foundation and service composition

- system architecture, scope, design principles, and explicit source composition
- modules, profiles, generator behavior, feature selection, capability exposure, and removal
- core types, runtime lifecycle, startup ordering, health, graceful shutdown, and workers
- typed configuration, layering, environment expansion, validation, secrets, and safe defaults
- HTTP conventions, validation, Problem Details errors, pagination, idempotency, OpenAPI, GraphQL, and gRPC where implemented
- PostgreSQL, migrations, transaction behavior, Redis, local/distributed caching, search, and rate limiting
- telemetry, logs, metrics, traces, audit, feature flags, testing support, and compatibility contracts

### Identity, security, and multi-tenancy

- canonical principals; passwords, sessions, JWTs, API keys, OAuth/OIDC, TOTP, and WebAuthn
- authorization models, permissions, Cedar/basic policy, tenancy propagation, and audit trails
- service accounts, connected applications, account/session/key management, registration, verification, and recovery
- privacy, retention, redaction, encryption boundaries, outbound request policy, and supply-chain controls

### Asynchronous work and integrations

- jobs, scheduling, events, outbox/inbox, retries, idempotency, and worker operations
- realtime WebSocket and SSE behavior, fanout, reconnect/resume, ordering, and authorization
- object storage, upload workflows, email, notifications, localization, and billing where available
- inbound and outbound webhooks, outbound HTTP, signing, SSRF defenses, delivery/retry behavior, and provider operations
- admin and optional product modules, clearly separated from platform guarantees

### Web application and web SDK

- browser application architecture, repository topology, supported browsers, local setup, and same-origin deployment model
- backend consumer-contract generation, OpenAPI-derived clients, capabilities and permissions metadata, realtime schemas, deterministic generation, and drift checks
- framework-neutral SDK transport, authentication strategies, retries, pagination, ETags, idempotency, errors, uploads, capability negotiation, and testing utilities
- React integration, query scoping, tenant changes, authorization presentation, forms, server/URL/client state boundaries, request states, and local state
- login, registration, verification, password recovery, account security, sessions, API keys, connected applications, authorization flows, and route protection
- realtime SSE/WebSocket lifecycle, cache/query effects, reconnection, resumption, and degraded behavior
- uploads, validation, accessibility, localization, responsive behavior, security headers, CSP, static delivery, base paths, SPA fallback, caching, compression, and asset metadata
- unit, integration, contract, E2E, accessibility, security, performance, browser-compatibility, build, and release workflows
- profiles, generator output, upgrades, contract compatibility, frontend dependency policy, and backend/frontend deployment coordination
- reference-application routes and account/OAuth workflows, compared with the active profile's emitted capability contract and actually mounted backend routes
- clear separation among implemented UI behavior, SDK-ready surfaces, generated/specification-only surfaces, and capabilities intentionally absent from the reference runtime

### LLM capabilities

- provider-neutral request/response and content contracts, schema versioning, unknown variants, citations, refusals, reasoning privacy, usage, and finish metadata
- provider adapters, model capability registry, explicit capability requirements, embeddings, reranking, transcription, speech, media generation, and classification where supported
- routing, model selection, fallback, retries, deadlines, cancellation, quotas, budgets, cost accounting, provider health, and prevention of silent downgrades
- prompt catalog, versioning, variables, context assembly, conversation persistence, caching, data governance, retention, redaction, and prompt-injection boundaries
- structured output and JSON Schema, validation/repair behavior, tool declarations, tool execution, authorization, side effects, idempotency, recursion/step limits, and result handling
- streaming lifecycle, backpressure, disconnect/cancellation behavior, usage completion, and HTTP/web SDK integration
- media and file handling, object references, MIME/size limits, outbound access, and storage policy
- synchronous HTTP, asynchronous jobs, browser integration, telemetry, usage ledger, audit, operator controls, and failure diagnosis
- safety policy, evaluations, fixtures, conformance, regression testing, provider test doubles, and production rollout controls
- composition evidence: provider bootstrap, configuration loading, router mounting, durable workers, credentials, and whether an actual application exposes each tested library or HTTP factory

### MCP capabilities

- server architecture, shared agent-capability registry, mapping application operations into protocol surfaces, and explicit non-goals
- supported protocol revision, capability negotiation, discovery-first lifecycle, versioning, pagination, caching, invalidation, compatibility, and deprecations
- supported authenticated Streamable HTTP topology, limits, cancellation, shutdown, and deployment
- tools, resources, resource templates, prompts, completion, content/result contracts, errors, annotations, and schema handling
- authentication, OAuth/client credentials where implemented, canonical-principal mapping, authorization, permissions, tenancy, audit, privacy, confused-deputy defenses, and least privilege
- multi-round-trip requests, elicitation, tasks, progress, subscriptions, notifications, long-running operations, persistence, resumption, and abandonment
- Apps/UI extensions, skills, progressive discovery, isolation, feature gates, maturity labels, and roadmap seams
- interoperability with external MCP clients, conformance tests, protocol inspection, debugging, operational limits, health, telemetry, scaling, and incident response
- profiles, generator output, extension authoring, compatibility testing, and removal behavior
- workspace membership and composition status for experimental Apps, Skills, previews, subscriptions/progress, authentication variants, evaluations, and other incubation surfaces
- whether Omnius implements an MCP client or only supports interoperability with external clients; never imply a built-in client from server conformance evidence

Do not turn this checklist into claims. The evidence inventory decides which items are implemented, partial, specified-only, unavailable, deprecated, or explicit non-goals.

## 5. Create a scalable information architecture

Use this as the starting structure, then adjust it from the evidence inventory. Add pages when a capability has a distinct user goal, operational lifecycle, or reference contract; combine pages when separation would only mirror crate boundaries.

```text
docs/
├── README.md
├── getting-started/
│   ├── overview.md
│   ├── quickstart.md
│   ├── choose-a-profile.md
│   ├── project-layout.md
│   ├── web-quickstart.md
│   ├── llm-quickstart.md
│   └── mcp-server-quickstart.md
├── concepts/
│   ├── architecture.md
│   ├── modules-profiles-and-composition.md
│   ├── runtime-lifecycle.md
│   ├── capability-and-consumer-contracts.md
│   ├── identity-authorization-and-tenancy.md
│   ├── reliability-and-idempotency.md
│   ├── asynchronous-processing.md
│   ├── data-and-privacy-boundaries.md
│   └── observability-model.md
├── guides/
│   ├── backend/
│   │   ├── configuration-and-secrets.md
│   │   ├── http-apis.md
│   │   ├── persistence-and-migrations.md
│   │   ├── caching-search-and-rate-limits.md
│   │   ├── authentication.md
│   │   ├── authorization-and-tenancy.md
│   │   ├── jobs-events-and-scheduling.md
│   │   ├── realtime.md
│   │   ├── files-notifications-and-webhooks.md
│   │   └── optional-product-modules.md
│   ├── web/
│   │   ├── application-architecture.md
│   │   ├── generated-contracts-and-sdk.md
│   │   ├── authentication-and-route-protection.md
│   │   ├── authorization-and-tenant-context.md
│   │   ├── data-state-forms-and-errors.md
│   │   ├── realtime-and-uploads.md
│   │   ├── accessibility-and-browser-support.md
│   │   ├── static-delivery-and-security.md
│   │   ├── testing-building-and-releasing.md
│   │   └── reference-application-workflows.md
│   ├── ai/
│   │   ├── model-requests-and-content.md
│   │   ├── providers-capabilities-and-routing.md
│   │   ├── prompts-context-and-conversations.md
│   │   ├── structured-output-and-tools.md
│   │   ├── streaming-media-and-files.md
│   │   ├── safety-privacy-and-governance.md
│   │   ├── usage-costs-and-quotas.md
│   │   ├── http-jobs-and-web-sdk.md
│   │   └── evaluations-and-production-rollout.md
│   └── mcp/
│       ├── server-architecture.md
│       ├── expose-a-capability.md
│       ├── discovery-versioning-and-transports.md
│       ├── tools-resources-and-prompts.md
│       ├── authentication-authorization-and-tenancy.md
│       ├── elicitation-tasks-progress-and-subscriptions.md
│       ├── apps-skills-and-extensions.md
│       ├── client-interoperability-and-conformance.md
│       └── experimental-and-unassembled-surfaces.md
├── reference/
│   ├── generator-cli.md
│   ├── profiles.md
│   ├── modules-and-capabilities.md
│   ├── configuration.md
│   ├── environment-and-secrets.md
│   ├── error-model.md
│   ├── permissions.md
│   ├── contracts-and-code-generation.md
│   ├── web-sdk.md
│   ├── llm-contracts.md
│   ├── llm-providers-and-model-capabilities.md
│   ├── mcp-protocol-support.md
│   ├── mcp-capability-matrix.md
│   ├── availability-and-exposure-matrix.md
│   └── compatibility-and-deprecations.md
├── operations/
│   ├── deployment-topologies.md
│   ├── migrations.md
│   ├── health-readiness-and-shutdown.md
│   ├── observability.md
│   ├── backup-recovery-and-data-retention.md
│   ├── scaling-workers-realtime-and-mcp.md
│   ├── web-release-and-static-delivery.md
│   ├── llm-provider-operations.md
│   ├── usage-budgets-and-quotas.md
│   ├── incident-response.md
│   └── upgrades-and-rollbacks.md
├── security/
│   ├── security-model.md
│   ├── deployment-hardening.md
│   ├── browser-security.md
│   ├── llm-and-tool-security.md
│   ├── mcp-security.md
│   ├── privacy-and-data-governance.md
│   └── supply-chain.md
├── troubleshooting/
│   ├── startup-and-configuration.md
│   ├── database-cache-and-jobs.md
│   ├── identity-and-permissions.md
│   ├── web-sdk-auth-and-realtime.md
│   ├── llm-providers-streaming-and-tools.md
│   └── mcp-discovery-transports-and-auth.md
├── development/
│   ├── workspace-and-tooling.md
│   ├── testing-strategy.md
│   ├── creating-a-module.md
│   ├── generator-and-profile-development.md
│   ├── web-application-development.md
│   ├── contract-and-sdk-generation.md
│   ├── adding-an-llm-provider.md
│   ├── authoring-llm-evaluations.md
│   ├── extending-mcp.md
│   ├── compatibility-and-release-gates.md
│   └── contributing.md
└── glossary.md
```

The final inventory may be larger. Do not impose an arbitrary page-count ceiling. Avoid both extremes: one enormous page per domain and dozens of shallow crate pages.

## 6. Define page types and ownership boundaries

Use a consistent purpose for each section:

- **Getting started:** shortest verified path to a meaningful result, with prerequisites, commands, expected observations, and the next three relevant links.
- **Concept:** mental model, invariants, boundaries, and why the design behaves this way; no exhaustive setup procedure.
- **Guide:** one user goal completed end to end, including failure recovery and production caveats.
- **Reference:** precise supported values, contracts, defaults, limits, compatibility, and links to generated API material.
- **Operations:** deployment state, lifecycle, observability, alerts, capacity, failure modes, recovery, rollback, and safe changes.
- **Security:** assets, actors, trust boundaries, threats, required controls, unsafe patterns, and verification evidence.
- **Troubleshooting:** symptom, discriminating evidence, likely cause, safe diagnostic procedure, resolution, and escalation data.
- **Development:** repository workflow, extension contract, tests, generators, compatibility requirements, and release gates.

Shared concepts such as principals, capabilities, contracts, tenancy, idempotency, and telemetry must have one canonical owner. Web, LLM, and MCP pages should explain how the shared concept applies to their surface and link back rather than redefining it.

## 7. Use a wave-based agent swarm

### Wave 1: Evidence inventory

Run read-only agents concurrently with non-overlapping primary domains:

1. architecture, core, runtime, configuration, health, and composition
2. HTTP, validation, errors, pagination, contracts, OpenAPI, GraphQL, and gRPC
3. PostgreSQL, Redis, caching, search, migrations, rate limits, and data lifecycle
4. authentication, authorization, tenancy, audit, privacy, and account workflows
5. jobs, events, scheduling, outbox/inbox, workers, and feature flags
6. realtime, storage, uploads, email, notifications, webhooks, outbound HTTP, localization, and billing
7. web architecture, contract generation, framework-neutral SDK, and React integrations
8. web identity journeys, state/forms/errors, realtime/uploads, accessibility, static delivery, testing, and release
9. LLM contracts, providers, model capabilities, routing, reliability, usage, and cost
10. prompts, context, conversations, structured output, tools, streaming, media, safety, and evaluations
11. MCP architecture, discovery, transports, tools/resources/prompts, identity/security, interactive and long-running flows, extensions, and conformance
12. generator, modules, profiles, deployment, recovery, upgrades, CI, compatibility, and supply chain

Each agent returns the structured brief from section 3 and does not write documentation yet.

### Wave 2: Information architecture and coverage gate

The integration owner consolidates the briefs into:

- final page inventory and navigation hierarchy
- capability-to-page coverage matrix
- canonical terminology and glossary candidates
- page ownership and non-overlapping source assignments
- cross-link map and shared-concept ownership
- availability/maturity classifications with evidence
- audience journey map
- explicit non-goals, specified-only areas, contradictions, and unresolved evidence
- executable-example and verification plan

Writing must not begin until every discovered capability is represented in the coverage matrix or explicitly excluded with an evidence-backed reason.

### Wave 3: Parallel writing

Assign non-overlapping files or directories to writers. Separate backend foundations, identity/security, asynchronous integrations, web, LLM, MCP, reference, operations, troubleshooting, and development where the inventory justifies it.

Parallel writers must not modify:

- `docs/README.md`
- `docs/glossary.md`
- navigation or page manifests
- shared terminology or coverage matrices
- another writer's assigned files

Those remain owned by the integration owner.

Each writer must:

1. Read the evidence brief and all assigned primary sources.
2. Confirm every `status`, `implementation`, `profile_availability`, and `public_exposure` claim against code, tests, contracts, composition roots, or exercised behavior.
3. Follow the relevant page-type contract.
4. Exercise commands and examples, recording exact prerequisites and meaningful expected results.
5. Cover configuration, security, tenancy, observability, failure modes, and lifecycle when relevant.
6. Link to canonical shared concepts instead of duplicating them.
7. Report contradictions, missing evidence, unsafe defaults, and generated-artifact drift immediately.
8. Update the coverage matrix for completed pages without changing centrally owned terminology.

### Wave 4: Independent specialist review

Writers never approve their own pages. Use independent reviewers with distinct mandates:

- **Accuracy:** claims, defaults, limits, examples, `status`, `implementation`, `profile_availability`, and `public_exposure` match current evidence.
- **User journeys:** quickstarts and guides can be completed from a clean checkout by their named audience.
- **Architecture and consistency:** terminology, conceptual ownership, cross-links, frontmatter, and navigation remain coherent.
- **Security and privacy:** examples respect trust boundaries, least privilege, tenancy, secret handling, data governance, and production safety.
- **Web quality:** SDK usage, browser behavior, accessibility, responsive behavior, security headers, contract generation, and release workflows are accurate.
- **LLM safety and operations:** provider behavior, capability requirements, tool authorization, reasoning privacy, prompt/data boundaries, usage, quotas, evaluation, and failure semantics are accurate.
- **MCP protocol and security:** supported revision, discovery, transports, authentication, authorization, protocol capabilities, extensions, long-running flows, and interop claims are accurate.
- **Operator readiness:** deployment, health, telemetry, capacity, migration, incident, recovery, upgrade, and rollback guidance is executable.

### Wave 5: Integration and end-to-end verification

The integration owner:

- resolves all review findings and source/documentation contradictions
- creates `docs/README.md`, navigation, and `docs/glossary.md`
- enforces canonical terminology and removes duplicate explanations
- completes cross-links and journey paths
- verifies `status`, `implementation`, `profile_availability`, and `public_exposure` labels against the evidence matrix
- runs documented quickstarts, commands, examples, generation workflows, and representative failure paths
- validates web journeys in supported browsers where practical
- verifies representative LLM flows using repository-supported deterministic test facilities rather than requiring real credentials unless explicitly documented
- verifies MCP discovery and representative tool/resource/prompt flows over each supported transport when that transport can be assembled; otherwise verifies the strongest available library/contract boundary and labels the missing composition explicitly
- runs link, frontmatter, source, navigation, example, and stale-evidence checks
- records any environment-dependent verification that could not be completed and why

## 8. Add a documentation validator

Provide a repository-standard command, such as `cargo xtask docs verify`, using existing tooling conventions rather than creating a second validation system. It should check:

- every documentation page has valid required frontmatter
- `status`, `implementation`, `profile_availability`, and `public_exposure` values use the allowed vocabularies and agree with the coverage matrix
- titles, paths, anchors, and capability ownership are unique where required
- referenced source, evidence, schema, contract, example, and command paths exist
- relative links and navigation entries resolve
- no page or capability is orphaned
- every implemented capability in the coverage matrix has an owning page
- every specified-only or partial claim is visibly labeled
- `profile_availability` claims exist in authoritative profile data and `public_exposure` claims correspond to concrete composition roots and emitted contracts
- fenced Rust, TOML, JSON, YAML, shell, TypeScript, and JSX/TSX examples are syntactically valid where practical
- documented CLI commands and package scripts exist
- generated OpenAPI, permissions, capabilities, realtime, SDK, and protocol references are linked rather than manually forked
- configuration keys, defaults, environment variables, profile/module identifiers, permission identifiers, and protocol versions match authoritative sources
- no placeholder markers, dead source references, accidental absolute local paths, secrets, or unreviewed unsafe examples remain
- glossary terms and canonical names are used consistently
- pages become stale when relevant source evidence changes after `last_verified`

The validator complements runtime verification; passing static checks does not prove a quickstart or protocol workflow works.

## 9. Roll out by complete user journeys, not a fixed page count

Prioritize delivery without shrinking final coverage:

1. **Foundation:** overview, architecture, profile selection, backend quickstart, configuration, HTTP/error model, identity, persistence, observability, deployment, testing, security model, and glossary.
2. **First-class surfaces:** complete web, LLM, and MCP journeys plus the concepts, guides, reference, security, operations, and troubleshooting required to use them safely. Provide runnable quickstarts only for assembled surfaces; use explicit status and integration-boundary pages for library-only or unassembled surfaces.
3. **Capability breadth:** asynchronous processing, realtime, storage, notifications, webhooks, optional product modules, advanced providers/transports/extensions, and all remaining implemented capabilities.
4. **Deep operations and extension:** scaling, recovery, incident response, compatibility, upgrades, provider/module/extension authoring, evaluations, release gates, and supply chain.

A rollout increment is releasable only when its journeys, reference material, security constraints, operations, troubleshooting, links, and verification evidence are complete. Do not publish isolated happy-path guides that lack the information needed to operate or debug them.

## 10. Final completion gate

Before declaring the documentation program complete, compare the final coverage matrix with the current specifications, workspace members, web and SDK packages, application entry points, contracts, migrations, configuration, tests, examples, profiles, generator outputs, operations assets, and release workflows.

Confirm that:

- every discovered capability has an explicit destination, evidence owner, maturity, implementation state, verified profile availability, verified public exposure, writer, reviewer, and verification result
- every named audience can complete its primary journey without reading source code
- web application and SDK behavior is covered from local development through authentication, runtime integration, accessibility, release, deployment, and troubleshooting
- LLM behavior is covered from provider-neutral contracts through providers, routing, prompts/context, tools, streaming/media, safety, usage, evaluations, operations, and troubleshooting
- MCP behavior is covered from capability exposure through discovery, transports, protocol surfaces, identity/security, interactive or long-running flows, extensions, conformance, operations, and troubleshooting
- shared backend, security, operational, and development capabilities remain fully covered rather than being displaced by web or AI material
- source-only, specified-only, partial, profile-unavailable, unassembled, deprecated, unavailable, contradictory, and unverifiable areas are explicit and never presented as working features
- all documented commands and representative workflows have concrete verification evidence

Recommended orchestration principle:

> Agents gather and write in parallel; one owner controls structure, terminology, navigation, coverage, and final truth.
