---
spec_id: RSK-011
title: "Realtime: WebSockets and Server-Sent Events"
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Realtime: WebSockets and Server-Sent Events


## Selection

Use SSE for server-to-client streaming. Use WebSockets for bidirectional low-latency commands. Domain events remain transport-independent.

## Upgrade

Before WebSocket upgrade:

- Authenticate through an allowed session or bearer mechanism.
- Validate browser `Origin`.
- Resolve tenant/principal.
- Enforce per-IP/principal/tenant connection limits.
- Negotiate an allowlisted subprotocol.
- Propagate request/trace context.
- Reject oversized/malformed headers.

Upgrade authentication does not authorize later messages.

## Protocol

Versioned envelope:

```json
{
  "v": 1,
  "id": "019...",
  "type": "subscription.create",
  "correlation_id": "019...",
  "payload": {}
}
```

Every command is bounded, parsed, validated, mapped to a named application action, authorized against its resource, rate-limited where needed, and receives a structured reply.

## Lifecycle

Require heartbeats, idle timeout, maximum lifetime or reauthentication, session/token revocation handling, bounded inbound/outbound queues, slow-consumer policy, meaningful close codes, graceful drain, and bounded metrics.

A full outbound queue never grows. Coalesce/drop only explicitly coalescible updates, require resync, or disconnect.

## Subscriptions

Server-side subscriptions are scoped to principal/tenant. Topic names are not authorization. Membership changes revoke affected subscriptions. Resume cursors are opaque and available only with replay storage. Presence is ephemeral.

## Fan-out

Use Redis Pub/Sub only when loss is acceptable, NATS for wider fan-out, and durable streams for replay. Realtime adapters consume application events; domain services never call connection registries.

## SSE

Include auth/authz, heartbeat comments, bounded buffers, proxy buffering guidance, drain/reconnect, and `Last-Event-ID` only with real replay semantics.

## Tests

Invalid origin, expired/revoked session after connection, cross-tenant subscription, oversized frame, malformed command, slow consumer, reconnect/resume, multi-instance fan-out, drain, and load/backpressure.
