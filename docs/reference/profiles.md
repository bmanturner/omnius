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
last_verified: 2026-08-30
---

# Profiles

The canonical profile meaning and its selection-versus-assembly boundaries are defined in [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md#profile). In this exact-value reference, `extends` contributes the ancestor's resolved modules before the profile's own declaration. The tables below list **direct** modules exactly as declared; they do not flatten inheritance. Profile resolution requires the final selection to contain every declared dependency and rejects conflicts, duplicate modules, and provider-slot collisions. It does not silently add missing dependencies.

Profile catalogs and generated artifacts do not prove that an application assembles a selected listener, worker, route, database, provider, or web application. Runtime status belongs in [Availability and exposure](availability-and-exposure-matrix.md).

## Base profiles

The base catalog has schema version `1`, bundle version `0.1.0`, and ten profiles.

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

The checked-in `apps/server` calls itself `minimal` but does not include the catalog's `rate-limit-local` and `generator` entries. The checked-in `apps/api-server` and current generated contract set identify `oauth-provider`. Neither composition root materializes all other profiles.

## Web extension profiles

The web extension declares schema version `1.0.0`, extension version `0.1.0`, and base bundle version `0.1.0`.

| Profile | Extends | Direct modules |
|---|---|---|
| `web-sdk-only` | `api` | `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core` |
| `web` | `authenticated-api` | `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-forms`, `web-static`, `web-testing` |
| `realtime-web` | `realtime` | `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-realtime`, `web-forms`, `web-static`, `web-testing` |
| `saas-web` | `saas` | `events-redis-ephemeral`, `realtime-core`, `sse`, `websockets`, `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-realtime`, `web-uploads`, `web-feature-flags`, `web-tenancy`, `web-forms`, `web-static`, `web-testing` |
| `full-reference-web` | `full-reference` | `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-realtime`, `web-uploads`, `web-feature-flags`, `web-tenancy`, `web-forms`, `web-local-state`, `web-static`, `web-testing` |

## LLM and MCP extension profiles

The LLM/MCP extension declares schema version `1.0.0`, extension version `0.1.0`, base bundle version `0.1.0`, and web extension version `0.1.0`.

| Profile | Extends | Direct modules |
|---|---|---|
| `llm-runtime` | `api` | `auth-core`, `authz-basic`, `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-embeddings`, `llm-prompt-catalog`, `llm-usage-ledger`, `llm-safety-policy`, `llm-evals` |
| `llm-api` | `authenticated-api` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, `llm-evals` |
| `llm-agent` | `saas` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-provider-bedrock`, `llm-provider-vertex`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, `llm-evals` |
| `ai-worker` | `worker` | `validation`, `rate-limit-local`, `idempotency`, `object-storage`, `auth-core`, `authz-basic`, `audit`, `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-evals` |
| `mcp-local` | `minimal` | `auth-core`, `authz-basic`, `agent-capability-registry`, `mcp-server-core`, `mcp-transport-stdio`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-subscriptions-local`, `mcp-conformance` |
| `mcp-http` | `authenticated-api` | `tenancy`, `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-subscriptions-local`, `mcp-conformance` |
| `mcp-enterprise` | `saas` | `events-nats`, `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-nats`, `mcp-apps`, `mcp-conformance` |
| `ai-platform` | `saas-web` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, `web-llm`, `llm-evals`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-redis`, `mcp-apps`, `mcp-conformance` |
| `full-reference-ai` | `full-reference-web` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-provider-bedrock`, `llm-provider-vertex`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, `web-llm`, `llm-evals`, `mcp-server-core`, `mcp-transport-http`, `mcp-transport-stdio`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-nats`, `mcp-apps`, `mcp-skills`, `mcp-server-card-preview`, `mcp-progressive-discovery-preview`, `mcp-conformance` |

## Inspecting profile definitions

Run `cargo xtask profiles verify` from the repository root with the Rust/Cargo toolchain and workspace dependencies available. The expected result is that the composed catalogs parse and satisfy module/profile validation; extra arguments, parse errors, invalid inheritance, missing requirements, conflicts, or provider-slot collisions return nonzero. See [Generator CLI](generator-cli.md) for the rest of the executable command surface. No profile-generation or verification command was run for this documentation pass.
