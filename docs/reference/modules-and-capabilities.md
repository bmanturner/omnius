---
title: Modules and capabilities
description: Module catalog fields, complete module identifiers, provider slots, and the boundary between selection and public capability metadata.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - platform-developer
  - service-developer
topics:
  - modules
  - capabilities
  - composition
capabilities: []
source:
  - specs/machine/module-catalog.yaml
  - specs/machine/extensions/web-application-suite/module-catalog.yaml
  - specs/machine/extensions/llm-mcp-suite/module-catalog.yaml
  - crates/service-kit/src/catalog.rs
evidence:
  - contracts/capabilities.json
last_verified: 2026-09-03
---

# Modules and capabilities

Canonical [module semantics](../concepts/modules-profiles-and-composition.md#module) and [capability semantics](../concepts/capability-and-consumer-contracts.md#canonical-terms) belong to their concept owners. This reference inventories module catalog descriptors and the current generated capability artifact; those evidence types are not interchangeable, and neither module selection nor an artifact alone proves compiled, runtime, or public exposure.

## Module descriptor

The generator's module descriptor supports these fields:

| Field group | Fields and semantics |
|---|---|
| Identity | `id`, `title`, `version`, `owner`, `spec`, and `kind` identify the catalog entry. The catalogs do not define a generic `status` or `capability` field. |
| Selection | `requires`, `conflicts_with`, and optional `provider_slot` constrain valid selections. |
| Composition | Exact crate dependencies, optional generated registrar, and closed typed `application_requirements` define the compile-time boundary. |
| Runtime metadata | `criticality`, `runtime_toggle`, closed runtime dependency IDs, routes, tasks, health checks, and metrics describe intended integration points; they are not assembly evidence. |
| Configuration | A closed field schema records dotted paths, TOML types, required status, safe reference defaults, and exact hierarchical environment bindings. Secret fields cannot have reference defaults. |
| Operational metadata | Acceptance, persistence, fixtures, generator ownership, and removal behavior guide generation and maintenance. |

Profile resolution validates the final inherited runtime selection. Every selected module's direct requirements must already be present; conflicts and duplicate provider slots are rejected. Entries with `kind: tooling` are rejected by runtime lifecycle commands and never enter schema-2 module state or service-kit runtime features. Recursive dependency collection exists for module add, not for ordinary profile resolution.

## Typed application and runtime dependency contracts

`application_requirements` contains canonical `ApplicationRequirement` enum values, not arbitrary strings. The root service-kit catalog owns that closed enum and every canonical `SelectedModuleContract`; generated consumers provide only profile ID, ordered runtime module IDs, providers, and runtime-disabled IDs. A router, task, health check, or declared route/task ID is an output of a validated runtime and never evidence that the required policy, handler, registry, or provider port exists. Missing and incomplete contracts fail closed during composition; runtime-disabled modules skip only their dormant contracts.

`runtime_dependencies` likewise uses a closed ID registry. `compose` descriptors are repository-owned, digest-pinned, health-checked development services with stable volume/configuration contracts. `external` descriptors declare exact endpoint and credential environment bindings and generate no substitute container. The generated `docs/module-catalog.md` records the resolved distinction for the selected project.

## Base module IDs

The base catalog defines the following runtime identifiers plus tooling-only
`test-support`. The latter is enabled only by a generated dev-dependency and is
never runtime profile/state:

`core`, `config`, `telemetry`, `runtime`, `http`, `health`, `postgres`, `migrations`, `validation`, `openapi`, `idempotency`, `outbound-http`, `redis-core`, `cache-local`, `cache-redis`, `rate-limit-local`, `rate-limit-redis`, `auth-core`, `auth-password`, `auth-session-postgres`, `auth-session-redis`, `auth-jwt`, `auth-oidc`, `auth-oauth-server`, `auth-api-key`, `auth-webauthn`, `auth-totp`, `authz-basic`, `authz-cedar`, `tenancy`, `audit`, `admin`, `jobs-core`, `jobs-apalis-redis`, `jobs-pgmq`, `outbox`, `inbox`, `scheduler`, `events-nats`, `events-redis-ephemeral`, `realtime-core`, `sse`, `websockets`, `object-storage`, `email`, `notifications`, `webhooks-svix`, `webhooks-inbound`, `feature-flags`, `search-meilisearch`, `billing`, `graphql`, `grpc`.

## Web extension module IDs

The runtime IDs are `consumer-contracts`, `asyncapi-contracts`, `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-realtime`, `web-uploads`, `web-feature-flags`, `web-tenancy`, `web-static`, `web-forms`, and `web-local-state`. `web-testing` is tooling-only.

## LLM and MCP extension module IDs

The authoritative AI/MCP extension catalog contains 37 IDs: 33 runtime modules and four tooling modules.

### LLM and shared agent registry

`agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-provider-bedrock`, `llm-provider-vertex`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, and `web-llm` are runtime IDs. `llm-evals` is tooling-only.

### MCP

The runtime IDs are `mcp-server-core`, `mcp-transport-http`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-subscriptions-local`, `mcp-subscriptions-redis`, `mcp-subscriptions-nats`, `mcp-tasks`, `mcp-elicitation`, `mcp-apps`, and `mcp-skills`. `mcp-server-card-preview`, `mcp-progressive-discovery-preview`, and `mcp-conformance` are tooling-only.

No catalog entry or implementation exists for MCP completion or a dedicated MCP progress protocol. Their exact status is recorded in [MCP protocol support](mcp-protocol-support.md).

## Provider slots

A provider slot permits at most one selected implementation. The base catalog uses these non-null slots:

| Slot | Modules |
|---|---|
| `primary-database` | `postgres` |
| `redis-client` | `redis-core` |
| `cache-provider` | `cache-local`, `cache-redis` |
| `rate-limit-provider` | `rate-limit-local`, `rate-limit-redis` |
| `session-store` | `auth-session-postgres`, `auth-session-redis` |
| `authorization-policy` | `authz-basic`, `authz-cedar` |
| `jobs-provider` | `jobs-apalis-redis`, `jobs-pgmq` |
| `events-provider` | `events-nats`, `events-redis-ephemeral` |
| `object-store` | `object-storage` |
| `email-provider` | `email` |
| `webhook-provider` | `webhooks-svix` |
| `feature-flag-provider` | `feature-flags` |
| `search-provider` | `search-meilisearch` |
| `mcp-subscription-backplane` | `mcp-subscriptions-local`, `mcp-subscriptions-redis`, `mcp-subscriptions-nats` |

A slot expresses catalog exclusivity; it does not assert that the chosen provider is configured, reachable, durable, or assembled.

## Current public capability artifact

The checked-in `contracts/capabilities.json` is generated for profile `oauth-provider`. It contains exactly two capability entries:

| Capability ID | Compiled | Runtime available | Authentication modes | Roles |
|---|---:|---:|---|---|
| `auth-oauth-server` | `true` | `true` | `bearer`, `session` | `oauth-authorization-server`, `oauth-resource-server`, `openid-provider` |
| `web-auth` | `false` | `false` | none | none |

The same artifact declares only the `api` transport at `/api`. This is current generated contract evidence, not a universal profile rule and not proof of every route's runtime mounting. The current permissions artifact is separately and intentionally empty; see [Permissions](permissions.md).

For maturity, implementation, profile selection, and concrete exposure, use the independent classifications in [Availability and exposure](availability-and-exposure-matrix.md).
