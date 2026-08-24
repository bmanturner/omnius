---
spec_id: RSK-ADR-0020
title: Make MCP Stateless over Streamable HTTP and Stdio
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Make MCP Stateless over Streamable HTTP and Stdio

## Context

Protocol-level sessions and initialization no longer fit horizontally scalable servers. The roadmap is moving toward HTTP-native transport unification.

## Decision

Use stateless Streamable HTTP POST and stdio adapters around transport-neutral dispatch. No Mcp-Session-Id, initialization dependency, GET event endpoint, or SSE resume logic is introduced.

## Consequences

Remote servers scale like ordinary HTTP workloads, and local transport shares semantics. Cross-call state must use explicit handles.

## Rejected alternatives

- Implicit in-memory client sessions.
- Custom WebSocket MCP transport.
- Treat stdio as a separate protocol.
