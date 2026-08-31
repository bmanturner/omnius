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
evidence:
  - apps/server/tests/minimal_service.rs
  - apps/api-server/tests/api_profile.rs
last_verified: 2026-08-30
---

# Startup and configuration troubleshooting

Begin with the symptom and the application's emitted startup phase. The minimal and OAuth-provider servers report phased bootstrap and typed safe error categories. Never dump the effective configuration, environment, or secret wrapper to get more detail.

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

**Discriminating evidence:** the reference file contains `${...}` placeholders and the loader has no interpolation mechanism.

**Likely cause:** a placeholder was mistaken for a default or expected to expand automatically.

**Safe diagnostic:** inspect whether the supported environment layer or protected rendered file replaced the specific field, revealing only source/provenance and redacted presence.

**Resolution:** supply the secret through the approved configuration layer. Never commit the value, put it in support output, or copy it into a command line.

**Escalation data:** field path, source layer, redacted present/missing status, environment, revision, and typed provider error.

## An environment value has no effect

**Discriminating evidence:** exact variable **name** (not value), nesting, selected environment/local file, and explicit overrides.

**Likely causes:** wrong `OMNIUS__` prefix or nested double-underscore path, wrong application field, later explicit override, or the target module is not assembled.

**Safe diagnostic:** trace the documented layer order and compare the field with the concrete application's configuration type. No supported `inspect-config` runtime command is assembled; do not invent one.

**Resolution:** correct the key/source or compose the intended module. A profile/catalog declaration cannot make an application read a field it does not own.

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