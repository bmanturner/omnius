---
title: Availability and exposure matrix
description: Canonical implementation, profile-selection, and public-exposure classifications for every documented capability group.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - evaluator
  - service-developer
  - operator
  - release-engineer
topics:
  - availability
  - exposure
  - profiles
capabilities: []
source:
  - docs/coverage-matrix.md
  - specs/machine/profiles.yaml
  - specs/machine/extensions/web-application-suite/profiles.yaml
  - specs/machine/extensions/llm-mcp-suite/profiles.yaml
evidence:
  - apps/api-server/tests/api_service.rs
  - packages/web-sdk/test/capabilities.test.ts
  - crates/mcp-server-core/tests/discovery_contracts.rs
  - contracts/contract-manifest.json
  - contracts/capabilities.json
  - apps/api-server/src/main.rs
  - config/reference.toml
  - migrations/2026082807_create_mcp_mrtr_state.sql
  - migrations/2026082808_create_mcp_tasks.sql
  - packages/web-sdk/src/react/capabilities.ts
  - packages/web-sdk/src/react/local-state.ts
last_verified: 2026-08-30
---

# Availability and exposure matrix

This page is the compact classification view of the canonical [coverage matrix](../coverage-matrix.md). All entries currently have maturity `experimental`. Implementation, profile availability, and public exposure are independent axes:

- the canonical [module, profile, selection, generation, assembly, and exposure model](../concepts/modules-profiles-and-composition.md) defines a profile as generator selection, not runtime assembly;
- `implemented` can still be `library-only`, `generated-only`, `unassembled`, or `not-applicable`;
- specifications, catalogs, source, schemas, fixtures, tests, generated artifacts, workflows, and runbooks never raise exposure by themselves;
- a successful release or compatibility result requires retained run evidence; no such result is reported here.

## Profile-set abbreviations

Tables use these exact sets to remain readable:

| Set | Profiles |
|---|---|
| **Base** | `minimal`, `api`, `authenticated-api`, `oauth-provider`, `saas`, `saas-pgmq`, `realtime`, `realtime-durable`, `worker`, `full-reference` |
| **API** | `api`, `authenticated-api`, `oauth-provider`, `saas`, `saas-pgmq`, `realtime`, `realtime-durable`, `full-reference` |
| **Identity** | `authenticated-api`, `oauth-provider`, `saas`, `saas-pgmq`, `realtime`, `realtime-durable`, `full-reference` |
| **Web all** | `web-sdk-only`, `web`, `realtime-web`, `saas-web`, `full-reference-web` |
| **Web app** | `web`, `realtime-web`, `saas-web`, `full-reference-web` |
| **LLM all** | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` |
| **MCP all** | `mcp-local`, `mcp-http`, `mcp-enterprise`, `ai-platform`, `full-reference-ai` |

`none` below means the matrix's exact empty profile list `[]`.

## Foundation, configuration, runtime, HTTP, and data

| Capability IDs | Implementation | Profiles | Exposure |
|---|---|---|---|
| `foundation-architecture`; `profile-selection` | implemented | none | not-applicable |
| `core-primitives`; `core-types`; `core-errors`; `core-identifiers`; `core-clock`; `build-metadata` | implemented | Base | library-only |
| `configuration`; `configuration-loader`; `configuration-secrets` | implemented | Base | assembled |
| `inspect-config` | specified-only | none | unassembled |
| `minimal-reference-service`; `minimal-http-surface` | implemented | `minimal` | assembled |
| `runtime-lifecycle`; `health-readiness-shutdown`; `http` | implemented | Base | assembled |
| `http-request-semantics`; `validation`; `rfc9457-problems`; `conditional-etag` | implemented | API | assembled |
| `pagination` | implemented | none | assembled |
| `idempotency` | implemented | API plus `ai-worker` | assembled |
| `openapi` | implemented | API | assembled |
| `openapi-contracts`; `contracts.openapi` | implemented | API | generated-only |
| `static-delivery` | implemented | `web`, `realtime-web`, `saas-web`, `full-reference-web` | assembled |
| `graphql`; `grpc` | implemented | `full-reference` | library-only |
| `postgres`; `migrations` | implemented | `api`, `authenticated-api`, `oauth-provider`, `saas`, `saas-pgmq`, `realtime`, `realtime-durable`, `worker`, `full-reference` | assembled |
| `reference-postgres` | implemented | `oauth-provider` | assembled |

## Cache, search, and data lifecycle

| Capability IDs | Implementation | Profiles | Exposure |
|---|---|---|---|
| `redis-core` | implemented | `saas`, `realtime`, `worker`, `full-reference` | library-only |
| `cache`; `cache-local`; `cache-redis` | implemented | `saas`, `saas-pgmq`, `realtime`, `realtime-durable`, `full-reference` | library-only |
| `rate-limit-local` | implemented | Base except `worker`, plus `ai-worker` | assembled |
| `rate-limit-redis` | implemented | none | library-only |
| `search-meilisearch` | implemented | `full-reference` | library-only |
| `data-lifecycle` | partial | `full-reference` | unassembled |
| `backup-recovery` | specified-only | none | unassembled |

## Identity and authorization

| Capability IDs | Implementation | Profiles | Exposure |
|---|---|---|---|
| `identity-principal` | implemented | Identity | library-only |
| `local-account-password`; `browser-sessions-postgres`; `api-keys-service-accounts`; `authorization-policy-basic` | implemented | Identity | assembled |
| `browser-sessions-redis`; `authorization-policy-cedar` | implemented | none | library-only |
| `jwt-resource-server` | implemented | Identity | unassembled |
| `oauth-oidc-provider` | implemented | `oauth-provider` | assembled |
| `oidc-client-external-identities`; `mfa-totp`; `mfa-webauthn-passkeys` | implemented | `full-reference` | library-only |
| `organizations-tenancy` | implemented | `oauth-provider`, `saas`, `saas-pgmq`, `full-reference` | assembled |
| `audit-security-events` | implemented | Identity plus `ai-worker` | library-only |
| `privacy-lifecycle-consent-moderation` | partial | none | unassembled |
| `web-account-and-oauth-workflows` | source-only | Web app | unassembled |

## Async work, events, and integrations

| Capability IDs | Implementation | Profiles | Exposure |
|---|---|---|---|
| `typed-jobs-and-domain-events` | implemented | Identity plus `worker` | library-only |
| `jobs-apalis-redis` | implemented | `saas`, `worker`, `full-reference` | unassembled |
| `jobs-pgmq` | implemented | `saas-pgmq` | unassembled |
| `transactional-outbox`; `transactional-inbox` | implemented | `saas`, `saas-pgmq`, `realtime-durable`, `worker`, `full-reference` | unassembled |
| `durable-scheduler` | implemented | `saas`, `saas-pgmq`, `worker`, `full-reference` | unassembled |
| `worker-composition-and-operations`; `upload-workflow` | implemented | none | unassembled |
| `durable-nats-events` | implemented | `realtime-durable`, `full-reference` | unassembled |
| `ephemeral-redis-events` | implemented | `realtime`, `full-reference` | unassembled |
| `feature-flag-evaluation` | implemented | `saas`, `saas-pgmq`, `full-reference` | unassembled |
| `realtime-delivery`; `realtime-core`; `sse`; `websockets` | implemented | `realtime`, `realtime-durable`, `full-reference` | unassembled |
| `object-storage` | implemented | `saas`, `saas-pgmq`, `full-reference` | library-only |
| `email` | implemented | Identity | assembled |
| `notifications`; `webhooks-svix`; `webhooks-inbound` | implemented | `saas`, `saas-pgmq`, `full-reference` | unassembled |
| `outbound-http` | implemented | `api`, `authenticated-api`, `oauth-provider`, `saas`, `saas-pgmq`, `realtime`, `realtime-durable`, `worker`, `full-reference` | library-only |
| `localization` | implemented | `full-reference` | library-only |
| `billing`; `consent` | partial | `full-reference` | unassembled |
| `admin` | implemented | `saas`, `saas-pgmq`, `full-reference` | unassembled |
| `moderation` | specified-only | `full-reference` | unassembled |

## Web

| Capability IDs | Implementation | Profiles | Exposure |
|---|---|---|---|
| `web-application` | source-only | Web app | unassembled |
| `web-contracts`; `web-capabilities` | implemented | Web all | generated-only |
| `web-sdk-transport` | implemented | Web all | library-only |
| `web-react-state` | implemented | Web app | library-only |
| `web-feature-flags` | implemented | `saas-web`, `full-reference-web` | library-only |
| `web-local-state` | implemented | `full-reference-web` | library-only |
| `web-auth` | implemented | Web app | unassembled |
| `web-realtime` | source-only | `realtime-web`, `saas-web`, `full-reference-web` | unassembled |
| `web-uploads` | implemented | `saas-web`, `full-reference-web` | unassembled |
| `web-app-composition-and-routing`; `web-identity-and-account-journeys`; `web-accessibility-and-browser-support` | implemented | Web app | unassembled |
| `web-tenant-context-and-authorization-presentation` | source-only | `saas-web`, `full-reference-web` | unassembled |
| `web-data-forms-errors-and-reference-records` | implemented | none | unassembled |
| `web-static-delivery-and-browser-security` | implemented | Web app | generated-only |
| `web-testing-build-and-release` | implemented | Web app | not-applicable |
| `web-reference-application-runtime-ceiling` | partial | `oauth-provider` | unassembled |

## LLM

| Capability IDs | Implementation | Profiles | Exposure |
|---|---|---|---|
| `llm-core`; `llm-provider-rig`; `llm-routing`; `llm-structured-output`; `llm-prompt-catalog`; `llm-safety-policy`; `llm-usage-ledger` | implemented | LLM all | library-only |
| `llm-provider-bedrock`; `llm-provider-vertex` | implemented | `llm-agent`, `full-reference-ai` | library-only |
| `llm-tool-runtime` | implemented | `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-streaming` | implemented | LLM all | unassembled |
| `llm-conversations` | implemented | `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | unassembled |
| `llm-budgeting` | partial | `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | unassembled |
| `llm-media` | implemented | `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-http-api` | implemented | `llm-api`, `llm-agent`, `ai-platform`, `full-reference-ai` | unassembled |
| `web-llm` | implemented | `ai-platform`, `full-reference-ai` | library-only |
| `llm-evals` | implemented | LLM all | not-applicable |
| `llm-embeddings` | specified-only | LLM all | unassembled |

## MCP

| Capability IDs | Implementation | Profiles | Exposure |
|---|---|---|---|
| `mcp-server-core`; `agent-capability-registry`; `mcp-discovery-versioning`; `mcp-tools`; `mcp-resources`; `mcp-prompts`; `mcp-elicitation` | implemented | MCP all | unassembled |
| `mcp-transport-http`; `mcp-auth-oauth` | implemented | `mcp-http`, `mcp-enterprise`, `ai-platform`, `full-reference-ai` | unassembled |
| `mcp-transport-stdio` | implemented | `mcp-local`, `full-reference-ai` | unassembled |
| `mcp-completion`; `mcp-progress` | unavailable | none | unassembled |
| `mcp-auth-client-credentials`; `mcp-auth-enterprise` | implemented | `mcp-enterprise`, `full-reference-ai` | unassembled |
| `mcp-tasks`; `mcp-apps` | implemented | `mcp-enterprise`, `ai-platform`, `full-reference-ai` | unassembled |
| `mcp-subscriptions-local` | implemented | `mcp-local`, `mcp-http` | unassembled |
| `mcp-subscriptions-redis` | implemented | `ai-platform` | unassembled |
| `mcp-subscriptions-nats` | implemented | `mcp-enterprise`, `full-reference-ai` | unassembled |
| `mcp-skills` | implemented | `full-reference-ai` | unassembled |
| `mcp-server-card-preview`; `mcp-progressive-discovery-preview` | source-only | `full-reference-ai` | unassembled |
| `mcp-conformance` | implemented | MCP all | not-applicable |
| `mcp-profiles` | implemented | MCP all | generated-only |

The common migrator embeds the migrations directory and declares `2026082808` as the current schema version. `migrations/2026082807_create_mcp_mrtr_state.sql` defines `public.mcp_mrtr_states` and `public.mcp_mrtr_audit_events`; `migrations/2026082808_create_mcp_tasks.sql` defines `public.mcp_tasks`, `public.mcp_task_idempotency`, `public.mcp_task_input_keys`, `public.mcp_task_input_rounds`, `public.mcp_task_payload_nonces`, and `public.mcp_task_events`. Those migrations are schema evidence only: no first-party MCP application composes the repositories, task worker, transports, or long-running lifecycle.

## Delivery and release

| Capability IDs | Implementation | Profiles | Exposure |
|---|---|---|---|
| `generator-module-lifecycle`; `generator`; `service-management`; `recovery-rehearsal`; `release-evidence`; `profile-matrix`; `contract-compatibility`; `web-release-evidence`; `ai-mcp-release-evidence`; `ci-quality`; `supply-chain` | implemented | none | not-applicable |
| `base-service-template`; `health`; `web-static` | implemented | Base plus `web`, `realtime-web`, `saas-web`, `full-reference-web` | generated-only |
| `api-reference`; `oauth-provider` | implemented | `oauth-provider` | assembled |

## Concrete current contract ceiling

The current generated manifest identifies `oauth-provider`, its 26 modules, and reproducibly generated OpenAPI, permissions, and capability artifacts. The reference API mounts the enabled OpenAPI document and documentation catalog routes; that assembled catalog does not establish that every operation represented in the generated document is mounted. The capability artifact exposes API base `/api`, marks only `auth-oauth-server` compiled/runtime-available, and marks `web-auth` unavailable. The permission catalog is empty.

Those are current generated-contract and concrete catalog-route facts. The reference application does not materialize realtime, web, LLM, MCP, SaaS, or full-reference profile claims. Follow the applicable row above rather than promoting availability from a broader catalog or generated fixture.

## Related reference

- [Profiles](profiles.md) defines the exact profile selections.
- [Modules and capabilities](modules-and-capabilities.md) lists the exact catalog IDs.
- [Compatibility and deprecations](compatibility-and-deprecations.md) defines compatibility and change policy.
