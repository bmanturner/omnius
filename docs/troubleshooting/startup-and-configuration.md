---
title: Startup and configuration troubleshooting
description: Diagnose Omnius startup, configuration, metadata, telemetry, health, listener, static-delivery, and shutdown failures from discriminating evidence.
status: experimental
implementation: implemented
profile_availability:
  - minimal
  - api
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - worker
  - full-reference
public_exposure: assembled
audience:
  - operator
  - developer
topics:
  - troubleshooting
  - startup
  - configuration
capabilities: []
source:
  - crates/config/src/lib.rs
  - apps/server/src/main.rs
  - apps/api-server/src/main.rs
  - config/minimal.toml
  - config/reference.toml
  - crates/generator/src/cargo_service.rs
  - crates/generator/src/provenance.rs
evidence:
  - apps/server/tests/minimal_service.rs
  - apps/api-server/tests/api_profile.rs
last_verified: 2026-09-03
---

# Startup and configuration troubleshooting

Begin with the symptom and the application's emitted startup phase. The checked-in and generated services report phased bootstrap and typed safe error categories. Never dump the effective configuration, environment, or secret wrapper to get more detail.

Configuration layer order and secret semantics are canonical in [configuration and secrets](../guides/backend/configuration-and-secrets.md). Lifecycle meanings belong to [runtime lifecycle](../concepts/runtime-lifecycle.md).

## The process exits before listening

**Discriminating evidence:** last bootstrap phase; typed startup code; selected environment; paths/names of requested configuration files without contents; revision/profile identity.

| Last phase or evidence | Likely cause | Safe diagnostic | Resolution |
|---|---|---|---|
| Configuration | Required base file missing, malformed/unknown field, invalid typed value, or rejected production local file | Compare file presence and keys with the application config type; inspect redacted environment key names only | Correct the protected input; do not bypass deserialization or enable a production local file |
| Metadata | Invalid or inconsistent build metadata | Compare artifact/revision and compiled metadata provenance | Rebuild/promote one revision-bound artifact |
| Telemetry | Invalid telemetry config, identity mismatch, or exporter initialization failure | Compare configured service/version/environment with the concrete binary; inspect exporter availability without secrets | Correct identity/destination or restore the approved exporter; do not disable redaction |
| Health | Duplicate/invalid health composition | Inspect concrete health registration in the composition root | Correct the composition; do not remove an authoritative dependency to force readiness |
| HTTP/static delivery | Invalid listener, HTTP policy, web policy, manifest/build/base-path contract, or occupied address | Inspect typed error and static contract evidence; verify another process/platform binding is not using the address | Repair configuration/build atomicity or listener ownership |
| PostgreSQL/migrations/identity/email | Required provider bootstrap or migration compatibility failure | Route to dependency-specific evidence and typed error | Resolve provider/config/migration issue before admission |

**Prerequisites:** access to redacted startup output and artifact/configuration provenance; no secret values.

**Expected result:** one phase and typed failure identify the configuration/composition boundary.

**Failure path:** if the phase is missing or output is truncated, preserve process exit status and platform events, then reproduce only in an approved non-production environment with identical non-secret configuration shape. Do not increase logging to include secrets.

No startup reproduction was run while writing this page.

## `${NAME}` appears literally or authentication fails with placeholder-like values

**Discriminating evidence:** the loaded TOML contains `${...}` text. The loader has no interpolation mechanism, and generated reference overlays never emit these placeholders.

**Likely cause:** literal placeholder text was put in a TOML layer or a checked-in application example was mistaken for an executable secret binding.

**Safe diagnostic:** identify the field and source layer without revealing its
value. A generated persisted service requires
`OMNIUS__POSTGRES__URL`. Idempotency has no pagination cursor configuration or
cursor-signing secret.

**Resolution:** supply the exact hierarchical environment key or a fully
resolved protected higher-precedence file. Never commit the value, put it in
support output, or copy it into a command line. `${NAME:?message}` in generated
Compose YAML is a separate required-variable check and must remain outside
TOML.

**Escalation data:** field path, source layer, redacted present/missing status,
environment, revision, and typed provider error.

## An environment value has no effect

**Discriminating evidence:** exact variable **name** (not value), nesting, selected environment/local file, and explicit overrides.

**Likely causes:** wrong `OMNIUS__` prefix or nested double-underscore path, wrong application field, later explicit override, or the target module is not assembled.

**Safe diagnostic:** trace the documented layer order and compare the field with the concrete application's configuration type. No supported `inspect-config` runtime command is assembled; do not invent one.

**Resolution:** correct the key/source or compose the intended module. A profile/catalog declaration cannot make an application read a field it does not own.

## A fresh non-SPA service returns 404 for an application route

**Discriminating evidence:** `/live` and `/version` work, while `/example` or
`/reference-records` returns `404 Not Found`. A `web-static` service may serve
the generic SPA shell at an unknown browser path instead; inspect registered
API operations rather than using that fallback status as route evidence.

**Likely cause:** no application-owned route was installed. Fresh generation
deliberately starts with an empty application extension and has no framework
reference API fallback.

**Safe diagnostic:** inspect the generated application's
`application::contributions` hook and its `ApplicationExtension` route
metadata. Do not add a parallel router or a framework fallback.

**Resolution:** install the intended application-owned router, route IDs, and
optional OpenAPI document through `with_application_extension`. HTTP
finalization mounts that router exactly once; OpenAPI selection is independent
of idempotency.

## `cargo service` refuses a lifecycle mutation

**Discriminating evidence:** the stable diagnostic reports an unbound/dirty
release, release mismatch, source override, lock mismatch, or stale plan.

**Likely cause:** the installed CLI lacks a clean immutable release identity;
schema-2 state, managed manifest, or lock disagree; or an effective Cargo
config introduces source replacement, `paths`, patch, or replace behavior.

**Safe diagnostic:** run `cargo service doctor --project <PATH>` and
`cargo service diff --project <PATH>`. These commands are read-only even for an
unbound/dirty CLI. Inspect every applicable `.cargo/config{,.toml}` and the
effective `CARGO_HOME` without exposing credentials.

**Resolution:** use the CLI installed from the project's recorded full
revision for same-release changes, or `cargo service update` for the identity
transition. Remove source overrides before mutation. A build prepared with
`cargo vendor --locked` may use `cargo build --locked --offline`, but its
source-replacement config intentionally keeps lifecycle provenance non-clean.

## Startup completes but `/ready` never becomes ready

**Discriminating evidence:** `/startup`, `/live`, `/ready`, health component name/status/staleness, PostgreSQL pool state, and static build state when enabled.

**Likely cause:** the process is healthy enough to run but an authoritative dependency or static contract is unavailable/stale.

**Safe diagnostic:** compare actual health registrations with the composition. Do not assume LLM, MCP, worker, realtime, cache, or catalog providers contribute health.

**Resolution:** restore the registered dependency/refresh path or correct the build contract. Keep the instance out of admission.

**Escalation data:** revision, lifecycle states, component, last-refresh age, dependency class, and recent typed errors.

## The service listens on an unexpected interface or port

**Discriminating evidence:** protected configuration provenance and the bound address emitted at startup.

**Likely cause:** environment/explicit override or platform binding differs from the expected topology.

**Safe diagnostic:** compare the bound address with deployment inventory and ingress configuration; do not publish internal topology unnecessarily.

**Resolution:** correct the configuration/platform contract and review exposure. The checked-in reference loopback address is not a universal default or production recommendation.

## Shutdown hangs or exits forcibly

**Discriminating evidence:** readiness transition, listener drain, supervised task events, PostgreSQL/email close, telemetry flush, termination signal count, and platform grace period.

**Likely causes:** platform budget shorter than application bounds, stuck task/provider, repeated signal, or client work exceeding drain.

**Safe diagnostic:** identify the component that did not complete before its bound. Repeated termination can deliberately force exit.

**Resolution:** align platform/application budgets and fix cancellation/closure. Before retrying interrupted work, apply [reliability and idempotency](../concepts/reliability-and-idempotency.md).

See [health, readiness, and shutdown](../operations/health-readiness-and-shutdown.md) and [incident response](../operations/incident-response.md).