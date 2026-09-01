---
title: Contracts and code generation
description: Assembled OpenAPI catalog routes, generated contract leaves, aggregate hashing, regeneration, drift checks, and compatibility inputs.
status: experimental
implementation: implemented
profile_availability:
  - api
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - full-reference
public_exposure: assembled
audience:
  - service-developer
  - client-developer
  - release-engineer
topics:
  - contracts
  - code-generation
  - compatibility
capabilities:
  - openapi-contracts
  - openapi
  - contracts.openapi
source:
  - xtask/src/contracts.rs
  - xtask/src/contract_diff.rs
  - crates/reference-api/src/contracts.rs
  - apps/api-server/src/main.rs
  - crates/openapi/src/lib.rs
  - config/reference.toml
  - contracts/contract-manifest.json
evidence:
  - apps/api-server/tests/metadata_contract.rs
  - contracts/openapi.json
  - contracts/permissions.json
  - contracts/capabilities.json
last_verified: 2026-08-30
---

# Contracts and code generation

This page combines two exposure boundaries. The reference API constructs the OpenAPI catalog, merges its router into the HTTP application, and enables the document and docs routes in `config/reference.toml`; that route-bearing `openapi` capability is assembled. The checked-in contract set for profile `oauth-provider` is deterministic generated evidence, so `openapi-contracts` and `contracts.openapi` remain generated-only. Neither boundary proves that every operation declared in the document is mounted, that another catalog profile is assembled, or that a release gate passed.

For backend HTTP API implementation and consumption, use [HTTP APIs](../guides/backend/http-apis.md). For generated Web contracts and SDK behavior, use [Generated contracts and web SDK](../guides/web/generated-contracts-and-sdk.md). For the contributor generation workflow, use [Contract and SDK generation](../development/contract-and-sdk-generation.md).

## Exposure boundary

| Capability | Exposure | Evidence boundary |
|---|---|---|
| `openapi` | Assembled | The API composition merges `catalog.router()`; the checked-in reference configuration enables `GET /openapi.json` and the embedded Swagger UI under `/docs`. |
| `openapi-contracts`; `contracts.openapi` | Generated only | The committed OpenAPI, permissions, capabilities, and manifest leaves are deterministic artifacts, not route-mount evidence by themselves. |

The page-level `assembled` value follows the route-bearing capability. Consumers must retain the generated-only classification for the standalone artifacts.

## Current manifest

| Field | Current value |
|---|---|
| `schema_version` | `1.0.0` |
| `service_kit_version` | `0.1.0` |
| `application_version` | `0.1.0` |
| `build_revision` | `reproducible` |
| `generated_at` | `reproducible` |
| `profile` | `oauth-provider` |
| `minimum_sdk_version` | `0.1.0` |
| `maximum_sdk_version` | `null` |
| `generators.contracts` | `omnius-xtask/0.1.0` |
| `generators.openapi` | `omnius-api-server/0.1.0` |
| aggregate SHA-256 | `9dcd7a6acb299d7abf999cd0d5bcae7b1c08a323033930999de5dccb7c0ac249` |

The manifest records the exact 26-module `PUBLIC_PROFILE_MODULES` inventory from the reference application and individual leaf hashes.

## Required leaves

| Artifact | Source | Current meaning |
|---|---|---|
| `contracts/openapi.json` | `omnius_api_server::openapi_json()` | Canonical OpenAPI document generated from application source. Generated-only, not route-mount evidence by itself. |
| `contracts/permissions.json` | `permissions_contract_json()` | Schema `1.0.0` with an empty current permission array. See [Permissions](permissions.md). |
| `contracts/capabilities.json` | `capabilities_contract_json(aggregate)` | Profile, API transport metadata, aggregate hash, and two public capability entries. |
| `contracts/contract-manifest.json` | xtask manifest builder | Versions, generator identities, profile/modules, leaf hashes, SDK window, and aggregate hash. |

The current set has no `asyncapi.json` leaf or AsyncAPI generator entry. Generation includes a pre-existing AsyncAPI artifact only when the compiled module inventory contains `realtime-core`; otherwise it removes that leaf from the generated set.

## Current capability metadata

The generated capability artifact contains two entries:

| ID | Compiled | Runtime available | Minimum SDK | Auth modes | Roles |
|---|---:|---:|---|---|---|
| `auth-oauth-server` | true | true | `0.1.0` | `bearer`, `session` | `oauth-authorization-server`, `oauth-resource-server`, `openid-provider` |
| `web-auth` | false | false | `0.1.0` | none | none |

It declares API transport base `/api`. The focused metadata test asserts these exact entries, but generated metadata remains narrower than general profile and crate availability.

## Deterministic generation algorithm

1. Generate canonical OpenAPI bytes.
2. Generate canonical permissions bytes.
3. Compute SHA-256 over the exact OpenAPI bytes followed immediately by the exact permissions bytes.
4. Generate capabilities using that aggregate hash.
5. Generate the manifest and per-leaf hashes.
6. Validate JSON, canonical JSON, machine schemas, and hash consistency before writing.

Capabilities are deliberately excluded from the aggregate because the capability document contains that aggregate. The manifest is also not part of it.

## Commands

Run from the repository root. These commands were not run for this documentation pass.

### Regenerate the committed set

```sh
cargo xtask contracts generate
```

- **Prerequisites:** Rust/Cargo toolchain; repository dependencies available; writable `contracts/`; application contract source compiles.
- **Expected result:** rewrites canonical OpenAPI, permissions, capabilities, and manifest artifacts; conditionally handles AsyncAPI as described above.
- **Failure path:** nonzero exit on compilation, serialization, schema, hash, or write failure. Inspect the emitted diagnostic; do not hand-edit generated JSON to bypass it.

### Check deterministic drift

```sh
cargo xtask contracts check
```

- **Prerequisites:** same build prerequisites; committed contract artifacts present.
- **Expected result:** validates committed artifacts, regenerates in memory/on the command's temporary path, and byte-compares the four required leaves plus conditional AsyncAPI handling.
- **Failure path:** nonzero exit identifies invalid or stale artifacts. Regenerate from authoritative source, review the diff, and rerun the check rather than updating hashes manually.

### Compare compatibility

```sh
cargo xtask contracts diff --against PATH
```

- **Prerequisites:** current contracts valid; `PATH` is an allowed baseline described below.
- **Expected result:** reports additive, behavioral/schema-compatible, deprecated, and breaking changes across OpenAPI, optional AsyncAPI, permissions, capabilities, and the manifest.
- **Failure path:** exits nonzero only when at least one breaking finding exists; invalid or unsafe baseline resolution also fails. Review [Compatibility and deprecations](compatibility-and-deprecations.md).

`PATH` may identify an existing workspace-relative path, an existing absolute path, or a constrained Git revision. Accepted filesystem shapes are a contracts directory, an artifact directory containing `contracts/`, or `contract-manifest.json`. Resolved artifacts on both sides must remain under the canonical workspace root.

## Consumer rule

Generated contracts are the client contract authority for their represented profile, but runtime exposure still requires an independently inspected application composition and exercised route. Generated SDKs, fixtures, tests, catalog profiles, and manifest entries do not raise an unassembled surface to assembled.
