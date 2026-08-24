---
spec_id: RSK-026
title: Consumer Contract Generation
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Consumer Contract Generation

## 1. Purpose

The Rust service MUST expose complete, deterministic, machine-readable contracts before any generated frontend integration is considered stable. These contracts are the seam between backend capabilities and every consumer: browser applications, mobile clients, CLIs, test harnesses, documentation, and future framework adapters.

## 2. Required contract artifacts

A web-capable service MUST generate:

```text
contracts/
  openapi.json
  asyncapi.json
  permissions.json
  capabilities.json
  contract-manifest.json
```

`asyncapi.json` MAY be absent only when no asynchronous browser-facing channel is enabled. Its absence MUST be represented in the manifest rather than inferred from a missing build step.

### 2.1 OpenAPI

The OpenAPI document MUST include:

- Stable and unique `operationId` values.
- All request path, query, header, and cookie parameters.
- Request-body schemas.
- Successful and expected error response schemas.
- RFC 9457 problem details.
- Authentication schemes and operation-level requirements.
- pagination and idempotency metadata.
- deprecation metadata.
- examples for security-sensitive and structurally complex operations.
- route tags mapped to capability ownership.

The OpenAPI artifact MUST be generated from the same Rust types and route registrations used by the running service. A route exposed to the selected profile without a contract is a build failure unless explicitly classified as an operator-only route.

### 2.2 AsyncAPI

The AsyncAPI document MUST describe browser-facing WebSocket, SSE, and domain-event contracts using AsyncAPI 3.1 and JSON Schema-compatible payloads. It MUST define:

- channels and addresses.
- send/receive operations.
- protocol bindings.
- authentication requirements.
- message names and versions.
- event-envelope metadata.
- payload schemas.
- correlation and causation identifiers.
- replay/resume semantics where supported.

### 2.3 Permissions

`permissions.json` MUST contain a stable vocabulary, human-readable descriptions, resource/action metadata, deprecation state, and an optional grouping structure for UI use. Permission identifiers MUST originate from the backend authorization registry.

The file MUST NOT disclose policy internals, confidential relationship data, or permissions unavailable in the assembled profile.

### 2.4 Capabilities

`capabilities.json` MUST describe compiled browser-facing capabilities and their public contract surfaces. It MUST distinguish:

- compiled capability availability.
- runtime availability.
- authentication modes.
- route/channel locations.
- optional frontend exports.
- minimum compatible SDK version.
- feature-flag versus structural capability semantics.

A product feature flag MUST NOT be confused with a compiled capability.

### 2.5 Contract manifest

`contract-manifest.json` MUST include:

- manifest schema version.
- service-kit version.
- application version.
- build revision.
- generation timestamp or reproducible-build sentinel.
- SHA-256 for each contract.
- aggregate contract hash.
- enabled profile and modules.
- minimum and maximum supported client contract versions.
- generator versions.

The aggregate hash MUST be calculated from canonical bytes in a deterministic order.

## 3. Determinism

Contract generation MUST be reproducible. The generator MUST:

- sort maps, paths, operations, permissions, capabilities, and schemas deterministically.
- omit wall-clock timestamps in reproducible mode.
- normalize line endings.
- use stable schema naming.
- avoid nondeterministic hash-map iteration.
- produce byte-identical output for unchanged source and configuration.

The command surface MUST include:

```bash
cargo xtask contracts generate
cargo xtask contracts check
cargo xtask contracts diff --against <revision-or-artifact>
```

`check` MUST generate into a temporary directory and fail when committed output is stale.

## 4. Compatibility policy

Contract changes MUST be classified as:

- additive and backward compatible.
- behaviorally significant but schema compatible.
- deprecated.
- breaking.

CI MUST perform a semantic OpenAPI comparison and explicit checks for permission and event compatibility. A breaking change MUST require:

- an ADR or approved breaking-change record.
- a version increment.
- migration notes.
- a compatibility-window decision.
- updated contract fixtures and consumer tests.

Operation IDs, permission IDs, event names, event versions, and schema names are public identifiers. Renaming them is breaking unless an alias/deprecation path exists.

## 5. Generated TypeScript boundary

The TypeScript generator MUST consume only canonical artifacts under `contracts/`. It MUST NOT scrape a live server or infer APIs from frontend code.

Generated code MUST be isolated and marked as derived. Product code MUST NOT edit generated output. Generation MUST fail on:

- duplicate operation IDs.
- unsupported schemas.
- unknown authentication modes.
- invalid discriminated unions.
- unresolved references.
- missing expected error contracts.
- contract input outside the trusted repository path.

## 6. Runtime compatibility

The Rust service MUST expose a minimally sensitive metadata endpoint, normally `GET /api/_meta`, that reports:

- application and API versions.
- aggregate contract hash.
- public capability IDs.
- public transport locations.
- build revision.

The production frontend MUST embed the aggregate hash used at build time. A mismatch MUST be observable. The behavior MAY be warning, degraded mode, forced reload, or hard failure according to deployment policy, but silent mismatch is prohibited.

The endpoint MUST NOT disclose secrets, dependency versions that create unnecessary reconnaissance value, internal module configuration, or non-public authorization policy.

## 7. Contract ownership

Backend modules own the contract fragments they expose. The composition root owns final assembly and collision detection. Removing a module MUST remove its public contract only through an explicit compatibility-aware generator change.

## 8. Testing

Required tests include:

- byte-for-byte deterministic regeneration.
- JSON Schema validation of every artifact.
- generated TypeScript compilation.
- contract hash verification.
- route-to-OpenAPI coverage.
- event-to-AsyncAPI coverage.
- permission registry coverage.
- stale generated-output failure.
- additive and breaking diff fixtures.
- runtime metadata/frontend embedded-hash comparison.

## 9. Acceptance linkage

This specification is satisfied by `AC-WEB-011` through `AC-WEB-020`.
