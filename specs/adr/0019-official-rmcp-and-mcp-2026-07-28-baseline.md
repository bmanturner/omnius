---
spec_id: RSK-ADR-0019
title: Use Official RMCP and MCP 2026-07-28 as the Baseline
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Use Official RMCP and MCP 2026-07-28 as the Baseline

## Context

MCP changed substantially in July 2026: stateless requests, discovery, per-request negotiation, cacheable lists, subscriptions/listen, MRTR, and Tasks as an extension.

## Decision

Pin official `rmcp` 3.1.4 and implement MCP `2026-07-28` as the default. Compatibility is explicit and tested. Deprecated features do not enter new profiles.

## Consequences

The implementation follows the authoritative SDK and current protocol rather than older tutorials. SDK upgrades remain protocol-sensitive work.

## Rejected alternatives

- Unofficial protocol structs.
- Base the design on 2025 Streamable HTTP sessions.
- Implement deprecated HTTP+SSE.
