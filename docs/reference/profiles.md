---
title: Profiles
description: Exact base, web, LLM, and MCP profile inheritance and direct module selections.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - platform-developer
  - service-developer
topics:
  - profiles
  - composition
  - generator
capabilities: []
source:
  - specs/machine/profiles.yaml
  - specs/machine/extensions/web-application-suite/profiles.yaml
  - specs/machine/extensions/llm-mcp-suite/profiles.yaml
  - crates/generator/src/catalog.rs
evidence:
  - crates/generator/tests/base_service.rs
last_verified: 2026-09-02
---

# Profiles

The canonical profile meaning and its selection-versus-assembly boundaries are defined in [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md#profile). In this exact-value selection reference, `extends` contributes the ancestor's resolved modules before the profile's own declaration. The tables below list **direct** modules exactly as declared; they do not flatten inheritance. Profile resolution requires the final selection to contain every declared dependency and rejects conflicts, duplicate modules, and provider-slot collisions. It does not silently add missing dependencies.

These three catalogs are the sole profile-selection authority. This page neither classifies implementation nor records runtime evidence; [Availability and exposure](availability-and-exposure-matrix.md#authoritative-profile-implementation-map) is the exhaustive implementation map and binds profile-level claims to its matrix report.

The evidence report classifies these 23 selections as 10 `base`, 5 `web`, 4 `ai`, 2 `mcp`, and 2 `ai_mcp` rows. Family is derived from resolved `llm-*` and `mcp-*` modules, not a profile-name allowlist. An untouched generated root with any typed `application_requirements` remains application-required; `llm-embeddings` is additionally specified-only. Required process/protocol skips and runtime-contract mismatches prevent assembly. The only MCP profiles are `mcp-http` and `mcp-enterprise`.

Generated topology is independent of profile family. `minimal` renders an application-only Compose topology. Profiles selecting PostgreSQL render the repository-owned local PostgreSQL and one-shot migration topology. Other selected runtime dependencies remain external unless their closed descriptor provides a repository-owned, digest-pinned, health-checked Compose service. Typed application requirements, provider credentials, and external endpoints are therefore startup prerequisites rather than runnable defaults.

## Base profiles

The base catalog has schema version `1`, bundle version `0.2.0`, and ten authoritative base profiles.

| Profile | Extends | Direct modules |
|---|---|---|
| `minimal` | — | `core`, `config`, `telemetry`, `runtime`, `http`, `health`, `test-support`, `rate-limit-local`, `generator` |
| `api` | `minimal` | `postgres`, `migrations`, `validation`, `openapi`, `idempotency`, `outbound-http` |
| `authenticated-api` | `api` | `auth-core`, `auth-password`, `auth-session-postgres`, `auth-jwt`, `auth-api-key`, `authz-basic`, `audit`, `email`, `jobs-core` |
| `oauth-provider` | `authenticated-api` | `auth-oauth-server`, `tenancy` |
| `saas` | `authenticated-api` | `redis-core`, `cache-redis`, `tenancy`, `admin`, `jobs-apalis-redis`, `outbox`, `inbox`, `scheduler`, `object-storage`, `notifications`, `webhooks-svix`, `webhooks-inbound`, `feature-flags` |
| `saas-pgmq` | `authenticated-api` | `cache-local`, `tenancy`, `admin`, `jobs-pgmq`, `outbox`, `inbox`, `scheduler`, `object-storage`, `notifications`, `webhooks-svix`, `webhooks-inbound`, `feature-flags` |
| `realtime` | `authenticated-api` | `redis-core`, `cache-redis`, `events-redis-ephemeral`, `realtime-core`, `sse`, `websockets` |
| `realtime-durable` | `authenticated-api` | `cache-local`, `events-nats`, `realtime-core`, `sse`, `websockets`, `outbox`, `inbox` |
| `worker` | — | `core`, `config`, `telemetry`, `runtime`, `http`, `health`, `test-support`, `postgres`, `migrations`, `redis-core`, `jobs-core`, `jobs-apalis-redis`, `outbox`, `inbox`, `scheduler`, `outbound-http`, `generator` |
| `full-reference` | `saas` | `auth-oidc`, `auth-webauthn`, `auth-totp`, `events-nats`, `realtime-core`, `sse`, `websockets`, `search-meilisearch`, `billing`, `graphql`, `grpc`, `localization`, `data-lifecycle`, `consent`, `moderation` |

The checked-in `apps/server` is composition ID `minimal-reference`: it truthfully reports seven compiled module IDs and is not proof of the catalog `minimal` selection, whose nine direct modules include `rate-limit-local` and `generator`. The checked-in `apps/api-server` and current generated contract set identify `oauth-provider`; their concrete evidence does not materialize any other profile.

## Web extension profiles

The web extension declares schema version `1.0.0`, extension version `0.2.0`, and base bundle version `0.2.0`.

| Profile | Extends | Direct modules |
|---|---|---|
| `web-sdk-only` | `api` | `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core` |
| `web` | `authenticated-api` | `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-forms`, `web-static`, `web-testing` |
| `realtime-web` | `realtime` | `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-realtime`, `web-forms`, `web-static`, `web-testing` |
| `saas-web` | `saas` | `events-redis-ephemeral`, `realtime-core`, `sse`, `websockets`, `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-realtime`, `web-uploads`, `web-feature-flags`, `web-tenancy`, `web-forms`, `web-static`, `web-testing` |
| `full-reference-web` | `full-reference` | `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-realtime`, `web-uploads`, `web-feature-flags`, `web-tenancy`, `web-forms`, `web-local-state`, `web-static`, `web-testing` |

## LLM and MCP extension profiles

The LLM/MCP extension declares schema version `1.0.0`, extension version `0.2.0`, base bundle version `0.2.0`, and web extension version `0.2.0`.

| Profile | Extends | Direct modules |
|---|---|---|
| `llm-runtime` | `api` | `auth-core`, `authz-basic`, `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-embeddings`, `llm-prompt-catalog`, `llm-usage-ledger`, `llm-safety-policy`, `llm-evals` |
| `llm-api` | `authenticated-api` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, `llm-evals` |
| `llm-agent` | `saas` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-provider-bedrock`, `llm-provider-vertex`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, `llm-evals` |
| `ai-worker` | `worker` | `validation`, `rate-limit-local`, `idempotency`, `object-storage`, `auth-core`, `authz-basic`, `audit`, `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-evals` |
| `mcp-http` | `authenticated-api` | `tenancy`, `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-subscriptions-local`, `mcp-conformance` |
| `mcp-enterprise` | `saas` | `events-nats`, `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-nats`, `mcp-apps`, `mcp-conformance` |
| `ai-platform` | `saas-web` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, `web-llm`, `llm-evals`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-redis`, `mcp-apps`, `mcp-conformance` |
| `full-reference-ai` | `full-reference-web` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-provider-bedrock`, `llm-provider-vertex`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, `web-llm`, `llm-evals`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-nats`, `mcp-apps`, `mcp-skills`, `mcp-server-card-preview`, `mcp-progressive-discovery-preview`, `mcp-conformance` |

## Inspecting profile definitions

Run `cargo xtask profiles verify` from the repository root with the Rust/Cargo toolchain and workspace dependencies available. The expected result is that the composed catalogs parse and satisfy module/profile validation; extra arguments, parse errors, invalid inheritance, missing requirements, conflicts, or provider-slot collisions return nonzero. See [Generator CLI](generator-cli.md) for the rest of the executable command surface. Runtime evidence comes only from the schema-version-5 report produced by `cargo xtask profiles generate-verify --jobs 1`.
