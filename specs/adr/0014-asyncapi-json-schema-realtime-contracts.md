---
spec_id: OMNIUS-ADR-0014
title: Use AsyncAPI 3.1 and JSON Schema for Browser-Facing Realtime Contracts
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Use AsyncAPI 3.1 and JSON Schema for Browser-Facing Realtime Contracts

## Context

OpenAPI does not adequately describe asynchronous channels, protocol bindings, subscriptions, event direction, resume semantics, or versioned messages. The base kit already defines event envelopes and WebSocket/SSE transports.

## Decision

Browser-facing asynchronous contracts use AsyncAPI 3.1 with JSON Schema-compatible message payload definitions.

- OpenAPI remains authoritative for HTTP.
- AsyncAPI describes channels, operations, protocol bindings, security, event names/versions, and payloads.
- Shared schema generation MUST avoid divergent HTTP/event representations.
- TypeScript event unions derive from these artifacts.
- Runtime validation is applied at the browser trust boundary when needed.
- Event-to-query effects are separate machine metadata tied to stable event and operation IDs.

## Consequences

- Event names and versions become public compatibility identifiers.
- AsyncAPI validation and deterministic generation become CI gates.
- The contract does not promise ordering or replay unless the transport/module explicitly provides it.
- Realtime can be consumed by non-React clients.

## Rejected alternatives

- Encoding realtime behavior only in prose.
- Pretending OpenAPI callbacks fully describe interactive browser channels.
- Hand-maintained TypeScript event unions.
- Treating WebSocket payloads as untyped JSON.
