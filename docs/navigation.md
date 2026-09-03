---
title: Documentation navigation and ownership
description: Canonical page hierarchy, writing and review assignments, concept ownership, non-overlap rules, and primary cross-links for the Omnius documentation program.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - contributor
  - platform-maintainer
  - evaluator
topics:
  - documentation
  - architecture
  - navigation
  - ownership
capabilities:
  - docs-navigation
source:
  - DOCS_PROMPT.md
  - docs/evidence-inventory.md
  - docs/coverage-matrix.md
  - docs/README.md
  - docs/glossary.md
evidence:
  - specs/machine/module-catalog.yaml
  - specs/machine/profiles.yaml
  - apps/mcp-server/src/lib.rs
last_verified: 2026-09-03
---

# Documentation navigation and ownership

This is the canonical final page inventory for the documentation program. Paths are relative to `docs/`, so `README.md` is the documentation home. Start with [Modules, profiles, and composition](concepts/modules-profiles-and-composition.md) for the canonical concept and use the [glossary](glossary.md) as the terminology index. The inventory starts from `DOCS_PROMPT.md` section 5 and applies only evidence-backed changes from the evidence inventory and coverage matrix. A profile, specification, catalog entry, library, generated artifact, or test fixture never establishes runtime or public exposure by itself.

## Writing units and review ring

Each page below has exactly one writing owner and one independent reviewer. The nine page-writing units are also the reviewer pool, but no unit reviews a page it writes.

| Writing owner | Primary scope | Default independent reviewer |
|---|---|---|
| `shared-concepts` | Entry paths, shared architecture, and canonical concepts | `reference` |
| `backend-identity` | Backend, identity, authorization, and tenancy guides | `ops-security-troubleshooting` |
| `async-integrations` | Jobs, events, realtime, files, notifications, webhooks, and optional modules | `development` |
| `web` | Browser application, Web SDK integration, accessibility, and browser security | `backend-identity` |
| `llm` | LLM contracts, providers, workflows, safety, usage, and evaluations | `ops-security-troubleshooting` |
| `mcp` | MCP architecture, protocol surfaces, identity, extensions, and conformance | `development` |
| `reference` | Generator and shared exact-value/contract reference | `shared-concepts` |
| `ops-security-troubleshooting` | Operations, security, deployment hardening, and diagnostics | `development` |
| `development` | Repository, extension, testing, compatibility, and contribution workflows | `reference` |

## Final page hierarchy

The owner and reviewer columns are normative. Paths not listed here are not part of the approved Wave 3 writing inventory.

### Root

| Page | Owner | Reviewer |
|---|---|---|
| `README.md` | `shared-concepts` | `reference` |
| `navigation.md` | `shared-concepts` | `reference` |
| `journeys.md` | `shared-concepts` | `reference` |
| `evidence-inventory.md` | `shared-concepts` | `reference` |
| `coverage-matrix.md` | `shared-concepts` | `reference` |
| `verification-plan.md` | `shared-concepts` | `reference` |
| `glossary.md` | `shared-concepts` | `reference` |

### Getting started

| Page | Owner | Reviewer |
|---|---|---|
| `getting-started/overview.md` | `shared-concepts` | `reference` |
| `getting-started/quickstart.md` | `shared-concepts` | `reference` |
| `getting-started/choose-a-profile.md` | `shared-concepts` | `reference` |
| `getting-started/project-layout.md` | `shared-concepts` | `reference` |
| `getting-started/web-quickstart.md` | `web` | `backend-identity` |
| `getting-started/llm-quickstart.md` | `llm` | `ops-security-troubleshooting` |
| `getting-started/mcp-server-quickstart.md` | `mcp` | `development` |

The web, LLM, and MCP quickstarts must be integration-boundary or deterministic contract/library verification paths until a concrete non-test composition proves the relevant runtime surface. They must not imply exposure from profile selection.

### Concepts

| Page | Owner | Reviewer |
|---|---|---|
| `concepts/architecture.md` | `shared-concepts` | `reference` |
| `concepts/modules-profiles-and-composition.md` | `shared-concepts` | `reference` |
| `concepts/runtime-lifecycle.md` | `shared-concepts` | `reference` |
| `concepts/capability-and-consumer-contracts.md` | `shared-concepts` | `reference` |
| `concepts/identity-authorization-and-tenancy.md` | `shared-concepts` | `reference` |
| `concepts/reliability-and-idempotency.md` | `shared-concepts` | `reference` |
| `concepts/asynchronous-processing.md` | `shared-concepts` | `reference` |
| `concepts/data-and-privacy-boundaries.md` | `shared-concepts` | `reference` |
| `concepts/observability-model.md` | `shared-concepts` | `reference` |

### Guides: backend

| Page | Owner | Reviewer |
|---|---|---|
| `guides/backend/configuration-and-secrets.md` | `backend-identity` | `ops-security-troubleshooting` |
| `guides/backend/http-apis.md` | `backend-identity` | `ops-security-troubleshooting` |
| `guides/backend/persistence-and-migrations.md` | `backend-identity` | `ops-security-troubleshooting` |
| `guides/backend/caching-search-and-rate-limits.md` | `backend-identity` | `ops-security-troubleshooting` |
| `guides/backend/authentication-and-sessions.md` | `backend-identity` | `ops-security-troubleshooting` |
| `guides/backend/authorization-and-tenancy.md` | `backend-identity` | `ops-security-troubleshooting` |
| `guides/backend/jobs-events-and-scheduling.md` | `async-integrations` | `development` |
| `guides/backend/realtime.md` | `async-integrations` | `development` |
| `guides/backend/files-notifications-and-webhooks.md` | `async-integrations` | `development` |
| `guides/backend/optional-product-modules.md` | `async-integrations` | `development` |

`authentication-and-sessions.md` replaces the narrower proposed `authentication.md`; session providers and their different assembly states are inseparable from the verified authentication journey. GraphQL and gRPC remain in `optional-product-modules.md` because their current evidence is library-only and separate pages would create shallow crate-oriented guides.

### Guides: web

| Page | Owner | Reviewer |
|---|---|---|
| `guides/web/application-architecture.md` | `web` | `backend-identity` |
| `guides/web/generated-contracts-and-sdk.md` | `web` | `backend-identity` |
| `guides/web/authentication-and-account-flows.md` | `web` | `backend-identity` |
| `guides/web/authorization-tenancy-and-capabilities.md` | `web` | `backend-identity` |
| `guides/web/data-fetching-forms-and-errors.md` | `web` | `backend-identity` |
| `guides/web/realtime-and-uploads.md` | `web` | `backend-identity` |
| `guides/web/accessibility-i18n-and-browser-support.md` | `web` | `backend-identity` |
| `guides/web/static-delivery-and-browser-security.md` | `web` | `backend-identity` |
| `guides/web/testing-build-and-release.md` | `web` | `backend-identity` |
| `guides/web/reference-application-workflows.md` | `web` | `backend-identity` |

These names reflect the inspected browser journeys and distinguish account workflows, generated capability metadata, localization behavior, and browser security from backend assembly.

### Guides: AI and LLM

| Page | Owner | Reviewer |
|---|---|---|
| `guides/ai/model-requests-and-responses.md` | `llm` | `ops-security-troubleshooting` |
| `guides/ai/providers-and-routing.md` | `llm` | `ops-security-troubleshooting` |
| `guides/ai/prompts-and-conversations.md` | `llm` | `ops-security-troubleshooting` |
| `guides/ai/structured-output.md` | `llm` | `ops-security-troubleshooting` |
| `guides/ai/tools-and-approvals.md` | `llm` | `ops-security-troubleshooting` |
| `guides/ai/streaming.md` | `llm` | `ops-security-troubleshooting` |
| `guides/ai/safety-and-media.md` | `llm` | `ops-security-troubleshooting` |
| `guides/ai/usage-budgets-and-cost-control.md` | `llm` | `ops-security-troubleshooting` |
| `guides/ai/http-and-web-integration.md` | `llm` | `ops-security-troubleshooting` |
| `guides/ai/evaluations-and-conformance.md` | `llm` | `ops-security-troubleshooting` |

Structured output and tool execution are separate because they have distinct authorization, approval, and failure boundaries. Streaming is separate from media because its lifecycle and transport contract is independently inspectable. No page may claim that the unmounted LLM router or generated OpenAPI operations are publicly exposed.

### Guides: MCP

| Page | Owner | Reviewer |
|---|---|---|
| `guides/mcp/server-architecture.md` | `mcp` | `development` |
| `guides/mcp/discovery-versioning-and-transports.md` | `mcp` | `development` |
| `guides/mcp/tools-resources-and-prompts.md` | `mcp` | `development` |
| `guides/mcp/authentication-authorization-and-tenancy.md` | `mcp` | `development` |
| `guides/mcp/elicitation-tasks-progress-and-subscriptions.md` | `mcp` | `development` |
| `guides/mcp/apps-skills-and-extensions.md` | `mcp` | `development` |
| `guides/mcp/client-interoperability-and-conformance.md` | `mcp` | `development` |
| `guides/mcp/experimental-and-unassembled-surfaces.md` | `mcp` | `development` |

The proposed `expose-a-capability.md` is folded into `server-architecture.md`: registry projection is part of server composition, and the checked-in reference runtime exposes only `reference_records.list.v1`. Optional primitives remain in their owning limitation guides. Dedicated completion and progress implementations are unavailable and belong in protocol support/reference rather than new runnable journeys.

### Reference

| Page | Owner | Reviewer |
|---|---|---|
| `reference/generator-cli.md` | `reference` | `shared-concepts` |
| `reference/profiles.md` | `reference` | `shared-concepts` |
| `reference/modules-and-capabilities.md` | `reference` | `shared-concepts` |
| `reference/configuration.md` | `reference` | `shared-concepts` |
| `reference/environment-and-secrets.md` | `reference` | `shared-concepts` |
| `reference/error-model.md` | `reference` | `shared-concepts` |
| `reference/permissions.md` | `reference` | `shared-concepts` |
| `reference/contracts-and-code-generation.md` | `reference` | `shared-concepts` |
| `reference/web-sdk.md` | `reference` | `shared-concepts` |
| `reference/llm-contracts.md` | `reference` | `shared-concepts` |
| `reference/llm-providers-and-model-capabilities.md` | `reference` | `shared-concepts` |
| `reference/mcp-protocol-support.md` | `reference` | `shared-concepts` |
| `reference/mcp-capability-matrix.md` | `reference` | `shared-concepts` |
| `reference/availability-and-exposure-matrix.md` | `reference` | `shared-concepts` |
| `reference/compatibility-and-deprecations.md` | `reference` | `shared-concepts` |

### Operations

| Page | Owner | Reviewer |
|---|---|---|
| `operations/deployment-topologies.md` | `ops-security-troubleshooting` | `development` |
| `operations/migrations.md` | `ops-security-troubleshooting` | `development` |
| `operations/health-readiness-and-shutdown.md` | `ops-security-troubleshooting` | `development` |
| `operations/observability.md` | `ops-security-troubleshooting` | `development` |
| `operations/backup-recovery-and-data-retention.md` | `ops-security-troubleshooting` | `development` |
| `operations/scaling-jobs-realtime-and-mcp.md` | `ops-security-troubleshooting` | `development` |
| `operations/web-release-and-static-delivery.md` | `ops-security-troubleshooting` | `development` |
| `operations/llm-provider-operations.md` | `ops-security-troubleshooting` | `development` |
| `operations/usage-budgets-and-quotas.md` | `ops-security-troubleshooting` | `development` |
| `operations/incident-response.md` | `ops-security-troubleshooting` | `development` |
| `operations/upgrades-and-rollbacks.md` | `ops-security-troubleshooting` | `development` |

`scaling-jobs-realtime-and-mcp.md` replaces the proposed worker-focused name because the evidence does not prove a runnable worker binary; the page must cover the verified composition boundaries and operational gaps without implying one.

### Security

| Page | Owner | Reviewer |
|---|---|---|
| `security/security-model.md` | `ops-security-troubleshooting` | `development` |
| `security/deployment-hardening.md` | `ops-security-troubleshooting` | `development` |
| `security/browser-security.md` | `ops-security-troubleshooting` | `development` |
| `security/llm-safety-and-data-governance.md` | `ops-security-troubleshooting` | `development` |
| `security/mcp-security.md` | `ops-security-troubleshooting` | `development` |
| `security/privacy-consent-and-moderation.md` | `ops-security-troubleshooting` | `development` |
| `security/supply-chain.md` | `ops-security-troubleshooting` | `development` |

The LLM and privacy titles replace the broader proposed names so that LLM safety policy and the partially implemented privacy/consent/moderation boundary each have one evidence-qualified destination.

### Troubleshooting

| Page | Owner | Reviewer |
|---|---|---|
| `troubleshooting/startup-and-configuration.md` | `ops-security-troubleshooting` | `development` |
| `troubleshooting/database-cache-and-jobs.md` | `ops-security-troubleshooting` | `development` |
| `troubleshooting/identity-and-permissions.md` | `ops-security-troubleshooting` | `development` |
| `troubleshooting/web-sdk-auth-and-realtime.md` | `ops-security-troubleshooting` | `development` |
| `troubleshooting/llm-providers-streaming-and-tools.md` | `ops-security-troubleshooting` | `development` |
| `troubleshooting/mcp-discovery-transports-and-auth.md` | `ops-security-troubleshooting` | `development` |

### Development

| Page | Owner | Reviewer |
|---|---|---|
| `development/workspace-and-tooling.md` | `development` | `reference` |
| `development/testing-strategy.md` | `development` | `reference` |
| `development/creating-a-module.md` | `development` | `reference` |
| `development/generator-and-profile-development.md` | `development` | `reference` |
| `development/web-application-development.md` | `development` | `reference` |
| `development/contract-and-sdk-generation.md` | `development` | `reference` |
| `development/adding-an-llm-provider.md` | `development` | `reference` |
| `development/authoring-llm-evaluations.md` | `development` | `reference` |
| `development/extending-mcp.md` | `development` | `reference` |
| `development/compatibility-and-release-gates.md` | `development` | `reference` |
| `development/contributing.md` | `development` | `reference` |

## Canonical concept ownership

A canonical owner defines the term, invariants, and boundaries. Every other page applies the concept to its surface and links back; it must not restate or weaken the definition.

| Concept | Canonical page | Application pages must do |
|---|---|---|
| System boundaries, composition roots, and reference applications | `concepts/architecture.md` | Name the concrete application or library boundary; never generalize from a catalog or fixture. |
| Module, profile, selection, generation, assembly, and exposure | `concepts/modules-profiles-and-composition.md` | Link here before making availability claims and preserve selection-versus-assembly language. |
| Startup, readiness, liveness, draining, and shutdown | `concepts/runtime-lifecycle.md` | Describe only surface-specific hooks; link operational procedures to health/readiness operations. |
| Capability, consumer contract, generated contract, and compatibility | `concepts/capability-and-consumer-contracts.md` | Treat capability metadata as a contract, not authorization or runtime proof. |
| Principal, authentication mechanism, authorization, tenant context, and active membership | `concepts/identity-authorization-and-tenancy.md` | Map the surface to the canonical principal and tenant; do not invent a parallel identity model. |
| Idempotency, retries, effect identity, and replay safety | `concepts/reliability-and-idempotency.md` | State scope and failure boundaries, then link rather than redefine semantics. |
| Job/event envelopes, delivery semantics, leases, and durable processing | `concepts/asynchronous-processing.md` | Distinguish interfaces, provider persistence, and verified worker composition. |
| Data classification, retention, privacy, consent, and trust boundaries | `concepts/data-and-privacy-boundaries.md` | Link security controls and clearly label schema-only or unassembled workflows. |
| Telemetry, correlation, health signals, audit events, and accountable state change | `concepts/observability-model.md` | Document emitted surface-specific signals without inventing a universal sink or mounted telemetry. |
| Error codes, RFC 9457 problems, safe diagnostics, and field errors | `reference/error-model.md` | Link exact wire shapes and avoid copying generated schemas. |
| Permission identifiers and authorization vocabulary | `reference/permissions.md` | Link the contract and state when the emitted vocabulary is empty; never infer permissions from UI roles. |
| Availability, implementation, maturity, and public exposure classifications | `reference/availability-and-exposure-matrix.md` | Use only the matrix vocabulary and link the applicable row. |
| Security assets, actors, trust boundaries, and cross-surface controls | `security/security-model.md` | Keep browser-, LLM-, MCP-, and deployment-specific threats on their assigned security pages. |
| Canonical terminology index | `glossary.md` | Link each term to its sole canonical concept owner without restating the definition. |

## Non-overlap rules

1. A path has one writing owner from the hierarchy above. Reassignment requires changing this manifest and the coverage matrix together before editing begins.
2. Writers may edit only their assigned pages. Shared navigation, coverage, inventory, terminology, and ownership artifacts remain centrally controlled and are not Wave 3 pages.
3. Concept pages own mental models and invariants. Guides complete one user goal; reference pages own exact values and contracts; operations pages own lifecycle procedures; security pages own threats and controls; troubleshooting pages begin from symptoms; development pages own contributor workflows.
4. Web, LLM, and MCP pages apply shared principal, tenant, capability, contract, reliability, telemetry, privacy, and lifecycle concepts by linking to their canonical pages. They must not define competing surface-local versions.
5. Backend guides own reusable service behavior. Web pages own browser and SDK behavior. LLM pages own provider-neutral and provider-specific AI behavior. MCP pages own protocol projection and transport behavior. A cross-surface page links across these boundaries rather than copying another owner's procedure.
6. Operations pages may summarize a capability's operational consequence but must link to its guide/reference for configuration and contracts. Troubleshooting pages may give safe diagnostics and resolutions but must not become alternate setup guides.
7. Security pages define required controls and unsafe patterns; implementation steps stay in the relevant guide or operations page. Domain-specific security pages link back to `security/security-model.md`.
8. Generated OpenAPI, permissions, capabilities, realtime, SDK, and protocol artifacts are linked, not transcribed. Specifications explain intent; profile selection, libraries, fixtures, schemas, migrations, and generated artifacts never by themselves prove public exposure.
9. Unavailable, specified-only, source-only, partial, generated-only, library-only, and unassembled surfaces stay visibly labeled. A quickstart is runnable only for an assembled surface; all others use an explicit integration-boundary or deterministic verification path.
10. Organize around user goals and contracts, not crate boundaries. Duplicate discoveries and aggregates use the canonical redirects in the evidence inventory and coverage matrix rather than receiving another page.

## Primary cross-link map

These are the minimum navigation edges. Writers may add contextual links, but must not replace these primary paths with duplicate explanations.

| From | Primary links | Purpose |
|---|---|---|
| `README.md` | `getting-started/overview.md`; `getting-started/quickstart.md`; `getting-started/web-quickstart.md`; `getting-started/llm-quickstart.md`; `getting-started/mcp-server-quickstart.md`; `reference/availability-and-exposure-matrix.md`; `glossary.md` | Enter by the backend, web, LLM, or MCP journey; check evidence-qualified availability; resolve terminology. |
| `getting-started/overview.md` | `getting-started/quickstart.md`; `getting-started/choose-a-profile.md`; `getting-started/project-layout.md`; `getting-started/web-quickstart.md`; `getting-started/llm-quickstart.md`; `getting-started/mcp-server-quickstart.md` | Move from the product boundary to the verified backend path, consumer integration boundaries, and project shape. |
| `getting-started/quickstart.md` | `guides/backend/configuration-and-secrets.md`; `guides/backend/http-apis.md`; `operations/health-readiness-and-shutdown.md` | Continue from startup to configuration, first API use, and lifecycle operation. |
| `getting-started/choose-a-profile.md` | `concepts/modules-profiles-and-composition.md`; `reference/profiles.md`; `reference/availability-and-exposure-matrix.md` | Separate profile resolution from generated or assembled availability. |
| `concepts/architecture.md` | `concepts/modules-profiles-and-composition.md`; `concepts/runtime-lifecycle.md`; `concepts/capability-and-consumer-contracts.md` | Establish the shared system model before surface-specific guidance. |
| `concepts/identity-authorization-and-tenancy.md` | `guides/backend/authentication-and-sessions.md`; `guides/backend/authorization-and-tenancy.md`; `security/security-model.md` | Trace principal establishment through authorization and trust boundaries. |
| `concepts/reliability-and-idempotency.md` | `guides/backend/http-apis.md`; `concepts/asynchronous-processing.md`; `reference/error-model.md` | Connect HTTP replay safety, async effect identity, and failure contracts. |
| `concepts/asynchronous-processing.md` | `guides/backend/jobs-events-and-scheduling.md`; `guides/backend/realtime.md`; `operations/scaling-jobs-realtime-and-mcp.md` | Move from delivery semantics to integration and operational limits. |
| `concepts/data-and-privacy-boundaries.md` | `security/privacy-consent-and-moderation.md`; `operations/backup-recovery-and-data-retention.md`; `security/llm-safety-and-data-governance.md` | Apply classification and retention boundaries to privacy, recovery, and AI data. |
| `concepts/observability-model.md` | `operations/observability.md`; `operations/health-readiness-and-shutdown.md`; `operations/incident-response.md` | Connect signal semantics to operation and incident use. |
| `guides/web/application-architecture.md` | `guides/web/generated-contracts-and-sdk.md`; `guides/web/authentication-and-account-flows.md`; `guides/web/data-fetching-forms-and-errors.md` | Follow the browser application from contracts through identity and state. |
| `guides/web/generated-contracts-and-sdk.md` | `reference/contracts-and-code-generation.md`; `reference/web-sdk.md`; `reference/availability-and-exposure-matrix.md` | Keep generated clients tied to exact contracts and exposure status. |
| `guides/web/testing-build-and-release.md` | `operations/web-release-and-static-delivery.md`; `security/browser-security.md`; `development/compatibility-and-release-gates.md` | Join automated checks, manual accessibility approval, deployment, and release evidence. |
| `guides/ai/model-requests-and-responses.md` | `guides/ai/providers-and-routing.md`; `guides/ai/structured-output.md`; `reference/llm-contracts.md` | Start from provider-neutral contracts before provider or output specialization. |
| `guides/ai/prompts-and-conversations.md` | `guides/ai/safety-and-media.md`; `security/llm-safety-and-data-governance.md`; `concepts/data-and-privacy-boundaries.md` | Connect stored context and media to safety, retention, and privacy. |
| `guides/ai/tools-and-approvals.md` | `concepts/identity-authorization-and-tenancy.md`; `security/llm-safety-and-data-governance.md`; `guides/ai/usage-budgets-and-cost-control.md` | Require authorization, approval, safety, and bounded usage for tool execution. |
| `guides/ai/http-and-web-integration.md` | `guides/ai/streaming.md`; `reference/web-sdk.md`; `reference/availability-and-exposure-matrix.md` | Keep the unassembled router/SDK boundary explicit while linking stream contracts. |
| `guides/mcp/server-architecture.md` | `guides/mcp/discovery-versioning-and-transports.md`; `guides/mcp/tools-resources-and-prompts.md`; `reference/mcp-capability-matrix.md` | Follow registry projection into discovery and protocol surfaces without implying a mount. |
| `guides/mcp/authentication-authorization-and-tenancy.md` | `concepts/identity-authorization-and-tenancy.md`; `security/mcp-security.md`; `reference/mcp-protocol-support.md` | Reuse canonical identity and connect MCP auth to protocol and security limits. |
| `guides/mcp/elicitation-tasks-progress-and-subscriptions.md` | `concepts/asynchronous-processing.md`; `operations/scaling-jobs-realtime-and-mcp.md`; `guides/mcp/client-interoperability-and-conformance.md` | Connect long-running state to durability, scaling, and interoperation evidence. |
| `reference/contracts-and-code-generation.md` | `guides/backend/http-apis.md`; `guides/web/generated-contracts-and-sdk.md`; `development/contract-and-sdk-generation.md` | Link the contract authority to producer, consumer, and contributor workflows. |
| `reference/availability-and-exposure-matrix.md` | `reference/profiles.md`; `reference/modules-and-capabilities.md`; `reference/compatibility-and-deprecations.md` | Interpret profile selection, module inventory, exposure, and compatibility together. |
| `operations/deployment-topologies.md` | `operations/migrations.md`; `operations/health-readiness-and-shutdown.md`; `security/deployment-hardening.md`; `operations/upgrades-and-rollbacks.md` | Provide the safe deployment lifecycle without inventing unsupported topology. |
| `operations/incident-response.md` | `operations/observability.md`; `troubleshooting/startup-and-configuration.md`; `troubleshooting/database-cache-and-jobs.md`; `operations/upgrades-and-rollbacks.md` | Move from detection to diagnosis, containment, and rollback. |
| `development/creating-a-module.md` | `concepts/modules-profiles-and-composition.md`; `reference/modules-and-capabilities.md`; `development/compatibility-and-release-gates.md` | Keep extension work tied to canonical module semantics and release gates. |
| `development/adding-an-llm-provider.md` | `reference/llm-providers-and-model-capabilities.md`; `guides/ai/evaluations-and-conformance.md`; `security/llm-safety-and-data-governance.md` | Require capability declaration, deterministic evaluation, and safety review. |
| `development/extending-mcp.md` | `reference/mcp-protocol-support.md`; `guides/mcp/client-interoperability-and-conformance.md`; `security/mcp-security.md` | Require protocol, conformance, and security review for extensions. |
