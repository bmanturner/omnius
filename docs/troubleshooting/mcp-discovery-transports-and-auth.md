---
title: MCP discovery, transport, and auth troubleshooting
description: Diagnose the dedicated authenticated MCP process, exact OAuth resource, reference tool, and fail-closed unsupported primitives.
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
  - security-analyst
topics:
  - troubleshooting
  - mcp
  - transports
capabilities: []
source:
  - apps/mcp-server/src/lib.rs
  - apps/mcp-server/src/main.rs
  - crates/mcp-transport-http/src/lib.rs
  - crates/mcp-auth-oauth/src/bearer.rs
evidence:
  - apps/mcp-server/tests/authenticated_mcp.rs
  - apps/mcp-server/tests/process_lifecycle.rs
  - apps/api-server/tests/api_service.rs
last_verified: 2026-09-02
---

# MCP discovery, transport, and auth troubleshooting

Start by identifying the process. `apps/mcp-server` serves MCP and MCP protected-resource metadata; `apps/api-server` serves the authorization server and REST API and intentionally returns no MCP routes. The development MCP listener is `127.0.0.1:8090` unless overridden.

Never include a bearer token, authorization code, client secret, signing key, raw personal data, or full private response in escalation material.

## The client receives 404

**Discriminating evidence:** process identity, method, path, authority, and JSON-RPC error body.

**Likely causes:** the client reached `apps/api-server`; used GET instead of POST; called an unsupported primitive; or addressed the wrong listener.

**Resolution:** send MCP requests to `POST /mcp` on `apps/mcp-server`. Fetch metadata with GET at `/.well-known/oauth-protected-resource/mcp`. An unsupported primitive intentionally returns HTTP 404 with JSON-RPC method-not-found (`-32601`); do not replace that with an empty adapter.

## Metadata is missing or names the wrong resource

**Discriminating evidence:** metadata response, configured issuer, and configured resource list without secrets.

**Likely causes:** wrong process; MCP resource absent/duplicated; resource is not the exact issuer-plus-`/mcp`; query or fragment is present; or scope differs from `reference-records:read`.

**Resolution:** configure exactly one query/fragment-free MCP resource and exactly one `reference-records:read` scope. The API root resource remains separate.

## Bearer authentication fails

| Observation | Likely category | Resolution |
|---|---|---|
| 401 challenge without `error` | missing Authorization header | send exactly one header bearer credential |
| 400 `invalid_request` | duplicate/malformed header or `access_token` query parameter | remove query presentation and correct the sole header |
| 401 `invalid_token` | signature, expiry, revocation/live-state, issuer, or audience/resource failure | mint a current token from the configured issuer for the exact `/mcp` resource; do not weaken checks |
| 403 `insufficient_scope` | verified token lacks `reference-records:read` | obtain consent/grant for the exact resource scope |

The challenge must point to `<issuer>/.well-known/oauth-protected-resource/mcp`, name `reference-records:read`, and include `Cache-Control: no-store`. The public boundary intentionally does not reveal the exact invalid-token cause.

A tenant-bearing identity is invalid for this reference capability. Use a non-tenant grant; do not discard or override tenant evidence.

## Revision or request metadata is rejected

**Discriminating evidence:** `Mcp-Protocol-Version`, `Mcp-Method`, optional `Mcp-Name`, JSON-RPC method/params, and request `_meta`.

**Likely causes:** revision differs from `2026-07-28`; header/body method mismatch; missing client information/capabilities; retained initialization/session state; or malformed media headers.

**Resolution:** send complete stateless metadata on every request. Do not add `initialize`, `Mcp-Session-Id`, GET event streams, replay headers, or a trusted-local bypass.

## `tools/list` does not show the expected tool

The checked-in reference app should expose exactly `reference_records.list.v1`.

**Discriminating evidence:** authenticated identity category, resource/scope, process build/profile info, and bounded `tools/list` response.

**Likely causes:** wrong process/build; context resolution rejected identity; registry/policy assembly failed before readiness; or the client interpreted a method-not-found response as an empty list.

**Resolution:** verify the dedicated process reached readiness with profile `mcp-http`, then repeat `tools/list` using a live non-tenant `/mcp` token. Do not inject catalog examples such as `acme.records.search` into the runtime.

## `tools/call` is denied or invalid

**Discriminating evidence:** tool name, safe argument shape, response category, and request ID.

**Likely causes:** name is not `reference_records.list.v1`; `limit` is outside 1–100; `cursor`/`name` violates bounds; token state changed after listing; PostgreSQL is unavailable; or output could not satisfy bounds/schema.

**Resolution:** call the exact tool with optional bounded `limit`, `cursor`, and `name`. Treat listing as stale and preserve invocation-time authorization. Fix repository/configuration health rather than bypassing registry checks.

## Resources, prompts, tasks, or other primitives fail

This is expected for the reference app. Resources, resource templates, prompts, elicitation, subscriptions, tasks, Apps, Skills, completion, and progress are not contributed and return method-not-found.

A catalog profile may select libraries for those primitives, but running them requires a product application with concrete handlers, policy, providers, persistence, workers, and lifecycle ownership. Do not interpret profile selection as a runnable default.

## Requests fail during shutdown

New MCP work is rejected after drain begins. Admitted work is awaited within the configured MCP drain and listener deadlines; forced drain produces a forced process outcome.

**Resolution:** stop sending new work after readiness changes, allow the configured grace period, and investigate handlers that ignore cancellation or exceed bounds. Do not extend shutdown indefinitely.

## Related guidance

- [Authenticated MCP server quickstart](../getting-started/mcp-server-quickstart.md)
- [MCP security](../security/mcp-security.md)
- [MCP server architecture](../guides/mcp/server-architecture.md)
- [Incident response](../operations/incident-response.md)
