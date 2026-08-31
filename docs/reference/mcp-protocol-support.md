---
title: MCP protocol support
description: Exact protocol revision, lifecycle, primitives, transports, authentication extensions, unavailable methods, and exposure ceiling.
status: experimental
implementation: unavailable
profile_availability: []
public_exposure: unassembled
audience:
  - mcp-developer
  - service-developer
  - operator
topics:
  - mcp
  - protocol
  - transports
capabilities:
  - mcp-completion
  - mcp-progress
source:
  - crates/mcp-server-core/src/kernel.rs
  - crates/mcp-server-core/src/sdk.rs
  - crates/mcp-transport-http/src/lib.rs
  - crates/mcp-transport-stdio/src/lib.rs
  - migrations/2026082807_create_mcp_mrtr_state.sql
  - migrations/2026082808_create_mcp_tasks.sql
  - crates/migrations/src/lib.rs
evidence:
  - apps/api-server/tests/api_service.rs
  - crates/mcp-server-core/tests/discovery_contracts.rs
  - crates/mcp-transport-http/tests/http_transport.rs
  - crates/mcp-transport-stdio/tests/stdio_contract.rs
last_verified: 2026-08-30
---

# MCP protocol support

> **Availability ceiling:** this page owns `mcp-completion` and `mcp-progress`; both are unavailable, selected by no verified profile, and unassembled. Other MCP libraries described here are implemented or source-only as labeled, but no first-party application mounts an MCP endpoint.

The reference API explicitly tests that `/mcp` and `/.well-known/oauth-protected-resource/mcp` are absent. OpenAPI tests also require those paths to be absent. Profile, module, schema, and generated artifacts do not alter that concrete exposure result.

## Protocol and lifecycle

| Item | Current contract |
|---|---|
| Protocol revision | `2026-07-28` |
| Supported RMCP version set | only `2026-07-28` |
| Lifecycle | stateless, per request |
| Initialization | legacy `initialize` is method-not-found in the strict handler |
| Discovery | `server/discover` |
| Required request context | protocol version, client information, client capabilities, and client identity |
| Primitive enum | `Tool`, `Resource`, `Prompt` |

The kernel uses immutable registries and retains no client, initialization, transport, or session state.

## RMCP handler surfaces

The core `ServerHandler` implements:

- `server/discover`;
- `prompts/list`;
- `resources/list`;
- `resources/templates/list`;
- `tools/list`.

`server/discover` resolves complete request context and returns static `ServerInfo`; its `get_info` path serializes every configured extension and does not invoke `McpExposureFilter`. Applications must preapprove configured extension metadata and explicitly compose that standalone filter for authorized primitive projections. The core list methods are default-empty until an application connects populated projections.

The list methods prepare request context and currently return default empty results. Library projections separately implement:

| Projection | Operations |
|---|---|
| tools | `list_tools`, `call` |
| resources | `list_authorized`, `read`, `execute` |

No checked-in composition connects the standalone authorized projections to a populated RMCP primitive handler or registry. Empty core list results are not proof that a profile intentionally exposes an empty production catalog.

## Unsupported methods

| Capability | Implementation | Profiles | Exposure | Evidence boundary |
|---|---|---|---|---|
| completion | unavailable | none | unassembled | No completion source, module-catalog entry, or handler was found. |
| progress | unavailable | none | unassembled | Subscription code mentions progress correlation, but no dedicated progress protocol or mounted handler exists. |

Do not advertise completion or progress from indirect types, planned specifications, transport metadata, or extension negotiation.

## Streamable HTTP library

| Property | Exact value |
|---|---|
| Library path constant | `/mcp` |
| Accepted method | POST only |
| Session manager | RMCP `NeverSessionManager` |
| Legacy session mode | disabled |
| Request metadata | stateless protocol metadata required |
| Response framing | JSON or bounded SSE response events |
| GET event stream | disabled |
| SSE retry/resume | disabled |

This describes `mcp-transport-http` as a library. No reference router mounts `/mcp`, and there is no first-party MCP HTTP server binary.

## Stdio library

The stdio transport profile is revision `2026-07-28`, newline-delimited JSON, and stateless. Its explicit compatibility adapter maps legacy `initialize` to `server/discover` and relocates metadata. It does not enable an old protocol revision or session state. No checked-in command or binary composes the stdio transport.

## Authentication libraries

| Capability | Contract | Exposure boundary |
|---|---|---|
| OAuth protected resource | Catalog declares `GET /.well-known/oauth-protected-resource`; the library builds metadata but mounts no route. | Implemented, unassembled; the reference API proves MCP-specific metadata absent. |
| OAuth client credentials | Extension `io.modelcontextprotocol/oauth-client-credentials`, revision `2026-07-28`. | Implemented opt-in policy library; unassembled. |
| Enterprise managed authorization | Extension `io.modelcontextprotocol/enterprise-managed-authorization`, revision `2026-07-28`. | Implemented opt-in policy library; unassembled. |

Signing, bearer validation, persistence, identity linking, tenancy, and authorization remain explicit composition ports. A declared extension never supplies those controls automatically.

## Extension registry

All listed extensions are per-request-capability negotiated and default disabled.

| Extension | ID | Maturity | Revision |
|---|---|---|---|
| Tasks | `io.modelcontextprotocol/tasks` | stable | `2026-07-28` |
| Apps/UI | `io.modelcontextprotocol/ui` | stable | `2026-01-26` |
| Skills | `io.modelcontextprotocol/skills` | experimental | `2026-08-22` |
| OAuth client credentials | `io.modelcontextprotocol/oauth-client-credentials` | stable | `2026-07-28` |
| Enterprise managed authorization | `io.modelcontextprotocol/enterprise-managed-authorization` | stable | `2026-07-28` |

Server-card and progressive-discovery previews are experimental, default-disabled, source-only, and not wire-visible. The registry forbids inventing a stable schema or proprietary RPC for them.

Roots, sampling, logging, HTTP-SSE, and dynamic client registration are disabled or deprecated by the current protocol compatibility policy. See [Compatibility and deprecations](compatibility-and-deprecations.md) for replacements and version policy.

## Persistence and backplane limits

Checked-in migrations define plural `public.mcp_mrtr_states`, `public.mcp_mrtr_audit_events`, `public.mcp_tasks`, and protected input-round storage including `public.mcp_task_input_rounds`; the common migrator embeds both files. No first-party MCP application composes those repositories and workers or proves applied runtime state. Enterprise identity-link and skill-artifact persistence remain unverified. Local subscriptions are process-scoped and nondurable; Redis is explicitly ephemeral. NATS adapter source does not prove JetStream durability or application assembly.

The subscription implementations share one provider slot and conflict so a profile selects at most one backplane. Selection remains generated profile evidence. See [MCP capability matrix](mcp-capability-matrix.md).
