---
title: MCP protocol support
description: Exact revision, Streamable HTTP route, OAuth boundary, assembled reference tool, and unsupported primitive behavior.
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
  - service-developer
  - operator
topics:
  - mcp
  - protocol
  - transport
capabilities:
  - mcp-completion
  - mcp-progress
source:
  - apps/mcp-server/src/lib.rs
  - apps/mcp-server/src/main.rs
  - crates/mcp-server-core/src/sdk.rs
  - crates/mcp-transport-http/src/lib.rs
  - crates/mcp-auth-oauth/src/resource.rs
evidence:
  - apps/mcp-server/tests/authenticated_mcp.rs
  - apps/mcp-server/tests/process_lifecycle.rs
  - crates/mcp-server-core/tests/protocol_contracts.rs
  - crates/mcp-transport-http/tests/http_transport.rs
last_verified: 2026-09-02
---

# MCP protocol support

This page separates the checked-in reference application from reusable but unassembled profile modules. `apps/mcp-server` is an assembled tools-only MCP process. Broader catalog selection does not expand its wire surface.

## Protocol and lifecycle

| Item | Exact reference contract |
|---|---|
| Protocol revision | `2026-07-28` only |
| Lifecycle | stateless and self-contained per request |
| Initialization | legacy `initialize` is method-not-found |
| Discovery | `server/discover` |
| Required context | version, client information, client capabilities, and fresh bearer-derived identity/policy evidence |
| Transport | authenticated Streamable HTTP only |
| Path/method | `POST /mcp` |
| Session manager | RMCP `NeverSessionManager` |
| GET event stream or resume | unavailable |

The server retains no initialization, client, transport, or session state between requests. `Mcp-Session-Id`, replay/resume state, and silent revision downgrade are rejected.

## Protected resource

| Item | Exact reference value |
|---|---|
| Metadata path | `/.well-known/oauth-protected-resource/mcp` |
| Resource/audience | configured issuer plus `/mcp` |
| Scope | `reference-records:read` |
| Bearer presentation | Authorization header only |
| Signing algorithm | `RS256` |

The metadata route and `/mcp` belong to `apps/mcp-server`. Authorization-server discovery/token routes and the issuer-root API resource belong to `apps/api-server`, which mounts neither MCP route.

## Assembled primitive surface

| Primitive/method | Reference application behavior |
|---|---|
| `tools/list` | exactly `reference_records.list.v1` |
| `tools/call` | bounded list over the PostgreSQL reference-record service |
| resources and resource templates | not contributed; method-not-found |
| prompts | not contributed; method-not-found |
| elicitation | not contributed; method-not-found |
| subscriptions | not contributed; method-not-found |
| tasks | not contributed; method-not-found |
| Apps and Skills | not contributed; method-not-found |
| completion | unavailable; method-not-found |
| progress | unavailable; method-not-found |

Unsupported primitive requests return JSON-RPC `-32601` with HTTP 404. They are not advertised and do not return empty success responses.

`reference_records.list.v1` is a globally scoped, read-only query requiring exactly `reference-records:read`. It accepts optional `limit` (1–100), `cursor`, and `name` and returns `items` plus `next_cursor`. Tenant-bearing identity is rejected.

## Bearer failure contract

| Failure | HTTP status | Challenge error |
|---|---:|---|
| missing credential | 401 | omitted |
| duplicate/malformed header or query token | 400 | `invalid_request` |
| invalid signature, issuer, audience/resource, lifetime, revocation, or live state | 401 | `invalid_token` |
| insufficient scope | 403 | `insufficient_scope` |

Challenges name the exact metadata URL and `reference-records:read`, use `Cache-Control: no-store`, and do not disclose the internal invalid-token cause.

## HTTP admission and response behavior

Requests must pass host/origin, content type, accept, protocol revision, `Mcp-Method`, optional `Mcp-Name`, body/framing, and configured size checks before dispatch. Responses use JSON or bounded event-stream frames according to negotiation. New work is rejected during drain; admitted work is bounded by handler, MCP drain, and listener shutdown deadlines.

## Reusable but unassembled modules

The catalogs also select resource, prompt, elicitation, subscription, task, client-credentials, enterprise authorization, Apps, Skills, server-card preview, and progressive-discovery modules in some profiles. Those contracts remain application-owned and are not reference-app support. Their providers, product authorization, persistence, workers, replay semantics, audit, and lifecycle must be concretely supplied before another application advertises them.

The only MCP profiles are `mcp-http` and `mcp-enterprise`; `ai-platform` and `full-reference-ai` are combined AI/MCP profiles. Streamable HTTP remains the only transport across all four.

## Related reference

- [Authenticated MCP server quickstart](../getting-started/mcp-server-quickstart.md)
- [MCP capability matrix](mcp-capability-matrix.md)
- [Discovery, versioning, and transport](../guides/mcp/discovery-versioning-and-transports.md)
- [MCP security](../security/mcp-security.md)
