---
title: MCP discovery, versioning, and transport
description: Exact discovery, revision, and authenticated stateless Streamable HTTP behavior of the dedicated MCP application.
status: experimental
implementation: implemented
profile_availability:
  - mcp-http
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
public_exposure: assembled
audience:
  - mcp-developer
  - operator
  - security-privacy-reviewer
topics:
  - mcp
  - discovery
  - versioning
  - http
capabilities:
  - mcp-discovery-versioning
  - mcp-transport-http
source:
  - apps/mcp-server/src/lib.rs
  - apps/mcp-server/src/main.rs
  - crates/mcp-server-core/src/sdk.rs
  - crates/mcp-server-core/src/versioning.rs
  - crates/mcp-transport-http/src/lib.rs
  - specs/43-mcp-versioning-discovery-caching-and-transports.md
evidence:
  - apps/mcp-server/tests/authenticated_mcp.rs
  - apps/mcp-server/tests/process_lifecycle.rs
  - crates/mcp-server-core/tests/protocol_contracts.rs
  - crates/mcp-transport-http/tests/http_transport.rs
last_verified: 2026-09-02
---

# MCP discovery, versioning, and transport

The dedicated `apps/mcp-server` application mounts authenticated Streamable HTTP at `POST /mcp`. Streamable HTTP is the only MCP transport in the workspace. The API application remains separate and returns no MCP routes.

Omnius uses fixed protocol revision `2026-07-28`. Every request is self-contained and carries protocol version, client information, client capabilities, and fresh bearer-derived identity/policy evidence. There is no retained initialization, client, or session state and no silent revision downgrade.

## Discovery and reference exposure

`server/discover` reports only the core server contract and configured extensions. The reference application configures an empty extension catalog. Its authorized tools projection exposes exactly `reference_records.list.v1`.

Primitive support is capability-selective:

| Primitive | Reference application behavior |
|---|---|
| Tools | `tools/list` and `tools/call` for `reference_records.list.v1` |
| Resources and resource templates | not advertised; method-not-found |
| Prompts | not advertised; method-not-found |
| Elicitation, subscriptions, tasks, Apps, and Skills | not advertised; method-not-found |
| Completion and progress | unavailable; method-not-found |

The registry and `McpExposureFilter` remain the authorization authority. Discovery never grants invocation permission; every tool call is reauthorized against current principal, global tenant policy, availability, schema, budget, deadline, and cancellation state.

## Streamable HTTP contract

| Policy | Implemented behavior |
|---|---|
| Path and method | `POST /mcp` only |
| Authentication | exactly one Authorization-header bearer credential before MCP dispatch |
| Media negotiation | JSON request content; JSON or bounded event-stream response representation |
| Versioning | exact `2026-07-28` header/body metadata; no downgrade |
| Sessions and replay | `Mcp-Session-Id` and replay headers rejected; no GET event stream or SSE resume |
| Admission | host, origin, content type, accept, method/name metadata, body, and framing checks before dispatch |
| Bounds | configured request, JSON response, response-frame, handler-timeout, and drain limits |
| Drain | new work rejected while draining; admitted work awaited until bounded completion or forced cancellation |

The development overlay allows only `localhost`, `127.0.0.1`, and `::1` authorities and listens on `127.0.0.1:8090`. Production deployments must supply their own approved authority/origin and HTTPS edge policy.

## OAuth resource discovery

`GET /.well-known/oauth-protected-resource/mcp` is mounted by the MCP application outside the bearer-protected router. Its immutable metadata names:

- resource and audience: the configured issuer with `/mcp` appended;
- authorization server: the configured issuer;
- scope: `reference-records:read`;
- bearer method: `header`;
- signing algorithm: `RS256`.

The API application hosts authorization-server discovery and token routes but not this protected-resource route. This route separation prevents the API root resource and MCP resource from being treated as interchangeable audiences.

## Failure boundary

Requests are rejected before dispatch for wrong method/path, invalid media negotiation, disallowed authority/origin, prohibited session or replay state, malformed framing, size limits, unsupported revision, or bearer failure. MCP protocol failures remain bounded and redacted. Missing/unselected primitive methods return JSON-RPC method-not-found rather than an empty success response.

The transport preserves Axum request extensions into RMCP `RequestContext`, so the canonical resolver receives only the identity verified for that request. No global identity cache or transport-owned OAuth policy exists.

## Related guidance

- [Authenticated MCP server quickstart](../../getting-started/mcp-server-quickstart.md)
- [Server architecture](server-architecture.md)
- [Tools, resources, and prompts](tools-resources-and-prompts.md)
- [Authentication, authorization, and tenancy](authentication-authorization-and-tenancy.md)
- [Runtime lifecycle](../../concepts/runtime-lifecycle.md)
- [MCP protocol support](../../reference/mcp-protocol-support.md)
