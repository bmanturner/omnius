---
spec_id: OMNIUS-ADR-0020
title: Require Authenticated Stateless Streamable HTTP for MCP
version: 0.1.0
status: accepted
last_verified: 2026-09-01
---

# Require Authenticated Stateless Streamable HTTP for MCP

## Context

Protocol-level sessions and initialization no longer fit horizontally scalable servers. MCP transport must also have one explicit authentication boundary rather than a trusted-local bypass.

## Decision

Use authenticated stateless Streamable HTTP POST around transport-neutral dispatch. The checked-in `apps/mcp-server` mounts only bearer-protected `POST /mcp` plus RFC 9728 metadata at `/.well-known/oauth-protected-resource/mcp`; `apps/api-server` mounts neither. Every request carries fresh bearer-authenticated identity and policy evidence. No `Mcp-Session-Id`, initialization dependency, GET event endpoint, SSE resume logic, unauthenticated local path, or alternate MCP transport is introduced.

## Consequences

MCP requests scale like ordinary HTTP work, cross-call state uses explicit handles, and every capability invocation passes through the same request-scoped authentication and authorization boundary. The reference composition exposes only `reference_records.list.v1` for the issuer-plus-`/mcp` resource and `reference-records:read`; unsupported primitives remain unadvertised and method-not-found.

## Rejected alternatives

- Implicit in-memory client sessions.
- Custom WebSocket MCP transport.
- An unauthenticated trusted-local transport.
