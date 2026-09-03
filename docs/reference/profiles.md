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
last_verified: 2026-09-03
---

# Profiles

The canonical profile meaning and its selection-versus-assembly boundaries are
defined in [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md#profile).
In this exact-value selection reference, `extends` contributes the ancestor's
resolved modules before the profile's own declaration. The tables below list
**direct runtime modules** exactly as declared; they do not flatten
inheritance. Profile resolution requires the final selection to contain every
declared dependency and rejects conflicts, duplicates, provider-slot
collisions, and any module whose catalog kind is `tooling`. It does not
silently add missing dependencies.

The three catalogs are the sole profile-selection authority. Tooling such as
`generator`, `test-support`, consumer-contract generation, frontend test
harnesses, LLM evaluation harnesses, and MCP preview/conformance tools is not a
runtime selection and is absent from profile state and service-kit feature
contracts. Generated Rust tests enable `service-kit/test-support` only through
the dev-dependency. Extension catalogs may separately associate create-once
application templates with a runtime module; those files become
application-owned and are not runtime module IDs.

This page neither classifies implementation nor records runtime evidence;
[Availability and exposure](availability-and-exposure-matrix.md#authoritative-profile-implementation-map)
is the exhaustive implementation map and binds profile-level claims to its
matrix report.

The evidence report classifies these 23 selections as 10 `base`, 5 `web`, 4
`ai`, 2 `mcp`, and 2 `ai_mcp` rows. Family is derived from resolved `llm-*` and
`mcp-*` modules, not a profile-name allowlist. An untouched generated root with
typed application requirements remains application-required;
`llm-embeddings` is additionally specified-only. Required process/protocol
skips and runtime-contract mismatches prevent assembly.

Generated topology is independent of profile family. `minimal` renders an
application-only Compose topology. Profiles selecting PostgreSQL render a
local PostgreSQL and one-shot migration topology. Other selected runtime
dependencies remain external unless their closed descriptor supplies a
digest-pinned, health-checked local Compose service. Typed application
requirements, provider credentials, and external endpoints are startup
prerequisites rather than runnable defaults.

## Generated application HTTP and schema

Generated services retain the
`application::contributions(ApplicationContributions) -> ApplicationContributions`
entry point and start with an empty application extension. The application may
install its one-shot extension factory through the contributions hook after
selected runtime construction. The factory receives `ApplicationRuntime`; its
`postgres_pool()` and `idempotency_store()` accessors clone selected handles
without opening another connection or performing I/O. Fresh non-SPA output
therefore returns `404 Not Found` for both `/example` and `/reference-records`
unless application-owned contributions deliberately add those routes. A
`web-static` profile may instead serve its generic SPA fallback at unknown
browser paths; it still registers no application API operation for either
path.

The feature-gated `service_kit::postgres`, `service_kit::idempotency`, and
`service_kit::migrations` façades expose selected provider APIs without
competing Omnius dependencies. `service_kit::test_support` is a dev-only
facade, not a runtime profile module. Requesting an unavailable resource fails
with a typed missing-resource error.

`ApplicationExtension::new(router, routes, openapi_document, operations)` is
the single source of application routes and their optional OpenAPI metadata.
The type and factory are available whenever `http` is selected, regardless of
whether `openapi` is selected. HTTP finalization consumes and mounts the
application router exactly once; a local rate limiter may transform it in
place but never mounts it. Omnius provides no `/reference-records` API
fallback.

OpenAPI and idempotency are independent runtime modules. OpenAPI requires HTTP
and validation, not idempotency. Idempotency contributes its selected store;
it does not install pagination, reference routes, or OpenAPI state and has no
pagination signing-secret configuration. The checked-in reference
application remains free to own pagination and reference-record behavior
outside the thin generated-service boundary.

Profiles selecting migrations prepare the framework migrator together with
the application's optional embedded migrator before connecting. With no
application SQL, the prepared set borrows the framework migrator. Application
SQL must use versions in
`9000000000000000000..=9099999999999999999` and, when present, requires:

```toml
schema_version = 1
minimum = "9000000000000000000"
maximum = "9000000000000000000"
```

The quoted positive bounds must be ordered, inside the reserved range, and
contain the application head. Startup compatibility, `migrate`,
`migration-status`, tests, and build metadata use the same prepared combined
set and one `_sqlx_migrations` history. Only `migrate` acquires SQLx's advisory
lock; status and compatibility remain read-only. Framework SQL remains
embedded in Omnius and is never copied into a generated service.

The generated Compose PostgreSQL and single one-shot migration service are
local-development infrastructure. A production deployment uses
operator-provided compatible PostgreSQL and production configuration;
selecting a PostgreSQL profile does not make the local Compose database a
production owner.

## Base profiles

The base catalog has schema version `1`, bundle version `0.3.0`, and ten
authoritative base profiles.

| Profile | Extends | Direct runtime modules |
|---|---|---|
| `minimal` | — | `core`, `config`, `telemetry`, `runtime`, `http`, `health`, `rate-limit-local` |
| `api` | `minimal` | `postgres`, `migrations`, `validation`, `openapi`, `idempotency`, `outbound-http` |
| `authenticated-api` | `api` | `auth-core`, `auth-password`, `auth-session-postgres`, `auth-jwt`, `auth-api-key`, `authz-basic`, `audit`, `email`, `jobs-core` |
| `oauth-provider` | `authenticated-api` | `auth-oauth-server`, `tenancy` |
| `saas` | `authenticated-api` | `redis-core`, `cache-redis`, `tenancy`, `admin`, `jobs-apalis-redis`, `outbox`, `inbox`, `scheduler`, `object-storage`, `notifications`, `webhooks-svix`, `webhooks-inbound`, `feature-flags` |
| `saas-pgmq` | `authenticated-api` | `cache-local`, `tenancy`, `admin`, `jobs-pgmq`, `outbox`, `inbox`, `scheduler`, `object-storage`, `notifications`, `webhooks-svix`, `webhooks-inbound`, `feature-flags` |
| `realtime` | `authenticated-api` | `redis-core`, `cache-redis`, `events-redis-ephemeral`, `realtime-core`, `sse`, `websockets` |
| `realtime-durable` | `authenticated-api` | `cache-local`, `events-nats`, `realtime-core`, `sse`, `websockets`, `outbox`, `inbox` |
| `worker` | — | `core`, `config`, `telemetry`, `runtime`, `http`, `health`, `postgres`, `migrations`, `redis-core`, `jobs-core`, `jobs-apalis-redis`, `outbox`, `inbox`, `scheduler`, `outbound-http` |
| `full-reference` | `saas` | `auth-oidc`, `auth-webauthn`, `auth-totp`, `events-nats`, `realtime-core`, `sse`, `websockets`, `search-meilisearch`, `billing`, `graphql`, `grpc`, `localization`, `data-lifecycle`, `consent`, `moderation` |

The checked-in `apps/server` and `apps/api-server` remain concrete application
evidence, not selection authorities for these generated profiles.

## Web extension profiles

The web extension declares schema version `1.0.0`, extension version `0.3.0`,
and base bundle version `0.3.0`.

Fresh web-family output starts with a readiness-only browser shell and an empty
application OpenAPI/client namespace. Selected auth, realtime, upload, tenancy,
and form modules contribute reusable runtime or SDK primitives; they do not
invent product routes or browser journeys. The application owns those
integrations and regenerates its client after adding its own contract.

| Profile | Extends | Direct runtime modules |
|---|---|---|
| `web-sdk-only` | `api` | `web-sdk-core` |
| `web` | `authenticated-api` | `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-forms`, `web-static` |
| `realtime-web` | `realtime` | `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-realtime`, `web-forms`, `web-static` |
| `saas-web` | `saas` | `events-redis-ephemeral`, `realtime-core`, `sse`, `websockets`, `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-realtime`, `web-uploads`, `web-feature-flags`, `web-tenancy`, `web-forms`, `web-static` |
| `full-reference-web` | `full-reference` | `web-sdk-core`, `web-react`, `web-auth`, `web-authorization`, `web-realtime`, `web-uploads`, `web-feature-flags`, `web-tenancy`, `web-forms`, `web-local-state`, `web-static` |

## LLM and MCP extension profiles

The LLM/MCP extension declares schema version `1.0.0`, extension version
`0.3.0`, base bundle version `0.3.0`, and web extension version `0.3.0`.

| Profile | Extends | Direct runtime modules |
|---|---|---|
| `llm-runtime` | `api` | `auth-core`, `authz-basic`, `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-embeddings`, `llm-prompt-catalog`, `llm-usage-ledger`, `llm-safety-policy` |
| `llm-api` | `authenticated-api` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api` |
| `llm-agent` | `saas` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-provider-bedrock`, `llm-provider-vertex`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api` |
| `ai-worker` | `worker` | `validation`, `rate-limit-local`, `idempotency`, `object-storage`, `auth-core`, `authz-basic`, `audit`, `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy` |
| `mcp-http` | `authenticated-api` | `tenancy`, `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-subscriptions-local` |
| `mcp-enterprise` | `saas` | `events-nats`, `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-nats`, `mcp-apps` |
| `ai-platform` | `saas-web` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, `web-llm`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-redis`, `mcp-apps` |
| `full-reference-ai` | `full-reference-web` | `agent-capability-registry`, `llm-core`, `llm-provider-rig`, `llm-provider-bedrock`, `llm-provider-vertex`, `llm-routing`, `llm-streaming`, `llm-structured-output`, `llm-tool-runtime`, `llm-media`, `llm-embeddings`, `llm-prompt-catalog`, `llm-conversations`, `llm-usage-ledger`, `llm-budgeting`, `llm-safety-policy`, `llm-http-api`, `web-llm`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-nats`, `mcp-apps`, `mcp-skills` |

## Inspecting profile definitions

Run `cargo xtask profiles verify` from the repository root. The checked-in
alias expands to `cargo run --locked --package xtask --`, so dependency
consumption remains locked. The expected result is that composed catalogs
parse and satisfy module/profile validation; invalid inheritance, missing
requirements, conflicts, tooling selections, or provider-slot collisions
return nonzero. See [Generator CLI](generator-cli.md) for the installed
generated-service lifecycle. Runtime evidence comes only from the
schema-version-5 report produced by
`cargo xtask profiles generate-verify --jobs 1`.
