---
title: Compatibility and deprecations
description: Contract-diff classifications and enforcement, SDK metadata, MCP protocol compatibility, and deprecated MCP features.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - service-developer
  - client-developer
  - release-engineer
topics:
  - compatibility
  - deprecations
  - contract-diff
capabilities: []
source:
  - xtask/src/contract_diff.rs
  - xtask/src/main.rs
  - specs/machine/extensions/llm-mcp-suite/protocol-compatibility.yaml
  - specs/machine/extensions/llm-mcp-suite/mcp-extension-registry.yaml
evidence:
  - contracts/contract-manifest.json
last_verified: 2026-08-30
---

# Compatibility and deprecations

Compatibility policy is implemented tooling and machine-readable protocol policy. A command definition, workflow, fixture, or runbook is not evidence that a compatibility gate passed. No command on this page was run for this documentation pass.

## Current generated contract metadata

| Field | Current value |
|---|---|
| manifest schema | `1.0.0` |
| service-kit version | `0.1.0` |
| application version | `0.1.0` |
| minimum SDK | `0.1.0` |
| maximum SDK | `null` |
| generated profile | `oauth-provider` |

The prior `0.0.0` generator fixture is a generated `full-reference-web` test baseline, not proof of a released runtime version.

## Contract diff command

From the repository root:

```sh
cargo xtask contracts diff --against PATH
```

- **Prerequisites:** Rust/Cargo toolchain; current required contract set is valid; baseline resolves to an accepted local artifact shape or allowed Git revision.
- **Expected result:** compares OpenAPI, optional AsyncAPI, permissions, capabilities, and manifest; emits every classified finding.
- **Failure path:** exits nonzero when a breaking finding exists or baseline resolution/validation fails. Additive, behavioral-schema-compatible, and deprecated findings remain visible but do not fail enforcement.

`PATH` accepts:

1. an existing workspace-relative path;
2. an existing absolute path;
3. otherwise, a nonempty restricted Git revision no longer than 128 characters.

A filesystem baseline may be a contracts directory, an artifact directory containing `contracts/`, or `contract-manifest.json`. Resolved current and baseline artifacts must stay under the canonical workspace root. The required leaves are OpenAPI, permissions, capabilities, and manifest; AsyncAPI is optional.

## Change classes

| Class | Severity | Fails compatibility? | Meaning |
|---|---|---:|---|
| `additive` | info | no | A public surface was added or a schema was safely relaxed. |
| `behavioral-schema-compatible` | warning | no | Metadata or behavior changed without a classified wire break. Consumer review is still required. |
| `deprecated` | warning | no | A public surface is marked for future removal or replacement. |
| `breaking` | error | yes | A required public surface was removed, moved, narrowed, or made incompatible. |

### Encoded breaking changes

| Contract area | Breaking examples |
|---|---|
| OpenAPI | Public operation or component removal/move; incompatible request/response schema narrowing. |
| AsyncAPI | Document, message, schema, channel, or route removal; incompatible schema narrowing. |
| Permissions | Permission schema-version change; identifier removal; resource/action removal or change. |
| Capabilities | Capability removal or no longer compiled; auth mode or role removal; transport removal or change. |
| Manifest | Module removal. |

### Encoded nonbreaking classes

Additive findings include new identifiers, components, routes, modules, auth modes, roles, transports, and schema relaxations. Deprecation findings are emitted for OpenAPI operations/schemas, AsyncAPI messages, and permissions.

Capability `runtime_available`, minimum-SDK, and service-version changes and manifest compatibility-metadata changes are currently behavioral-schema-compatible warnings, not breaking findings. That classification does not guarantee an application-level behavior change is harmless; it defines only this tool's enforcement.

## MCP protocol compatibility

| Policy field | Current value |
|---|---|
| baseline/current revision | `2026-07-28` |
| lifecycle | stateless |
| discovery | `server_discover_required: true` |
| capabilities | per request |
| result type | required |
| cacheable lists/subscriptions | true |
| `mcp_session_id` | false |
| initialization required | false |
| SSE resume | false |

Compatibility paths are explicit opt-ins:

| Revision range | Mechanism | Default |
|---|---|---:|
| `2025-11-25` | `explicit-rmcp-compatibility` | false |
| earlier versions supported by RMCP | `explicit-probe-and-policy` | false |

Both paths require compatibility tests and policy. Legacy initialization is permitted only through explicit official-SDK compatibility behavior and is never required internally. Earlier results lacking `resultType` may be interpreted only within that compatibility behavior and are treated as complete.

Public MCP names use a stable namespace and are never generated from Rust paths. A breaking semantic or schema change requires a new public version/name or a documented compatibility window.

## MCP extension lifecycle

Current stable extensions are:

- `io.modelcontextprotocol/tasks`;
- `io.modelcontextprotocol/ui`;
- `io.modelcontextprotocol/oauth-client-credentials`;
- `io.modelcontextprotocol/enterprise-managed-authorization`.

Current experimental entries are:

- `io.modelcontextprotocol/skills`;
- `server-card-preview`;
- `progressive-discovery-preview`.

All are default-disabled and capability-negotiated. Preview entries must not invent proprietary public RPC methods or stable wire schemas.

These are protocol-extension lifecycle labels, not the documentation capability maturity. Every capability group in the current coverage matrix remains `experimental`.

## Deprecated MCP features

| Deprecated feature | Default | Negotiation | Replacement |
|---|---:|---|---|
| `roots` | false | prohibited | Resource URIs and explicit tool parameters. |
| `sampling` | false | prohibited | Direct LLM provider APIs. |
| `logging` | false | prohibited | Standard error and OpenTelemetry. |
| `http-sse` | false | prohibited | Streamable HTTP. |

Deprecated registry rows have `module: null`. Dynamic client registration is also disabled in current protocol compatibility policy. None of these deprecated entries may be enabled merely because an older SDK recognizes it.

## Profile/release matrix policy

The exact command surface is:

```sh
cargo xtask profiles generate-verify [--jobs 1] [--report PATH] [--automated-evidence-only] [--matrix-only]
```

- **Prerequisites:** Rust/Cargo toolchain and all generation prerequisites for the selected catalog matrix.
- **Expected result:** schema-version-5 report with generation, sequential cache-cleanup, and selected release-policy decisions for every profile.
- **Failure path:** default enforcement fails when any required profile/release decision fails. `--automated-evidence-only` permits the tool's `automated_ready` evidence class. `--matrix-only` is local diagnostics only and is rejected under CI. The two policy flags are mutually exclusive.

`--jobs` accepts only `1`; profiles build sequentially. After recording a profile's evidence, the task removes its Cargo cache and retains only the generated binary and report artifacts. The default report path is `target/profile-matrix/report.json` under the workspace.

A generated report schema, workflow definition, or runbook does not prove a profile matrix or release gate passed. Retained successful evidence is required separately.
