---
title: Realtime delivery
description: Authorization, backpressure, transport behavior, and composition boundaries for server-sent events and WebSockets.
status: experimental
implementation: implemented
profile_availability:
  - realtime
  - realtime-durable
  - full-reference
public_exposure: unassembled
audience:
  - rust-application-developer
  - web-application-developer
  - operator
  - security-reviewer
topics:
  - realtime
  - server-sent-events
  - websockets
  - authorization
  - backpressure
capabilities:
  - realtime-delivery
  - realtime-core
  - sse
  - websockets
source:
  - crates/realtime-core/src/lib.rs
  - crates/realtime-sse/src/lib.rs
  - crates/realtime-websocket/src/lib.rs
  - specs/11-realtime-websockets-and-sse.md
evidence:
  - specs/machine/profiles.yaml
  - specs/machine/module-catalog.yaml
  - crates/events-redis-ephemeral/src/lib.rs
  - crates/events-nats/src/lib.rs
  - apps/api-server/src/main.rs
last_verified: 2026-08-30
---

# Realtime delivery

Omnius implements authorization-aware realtime core, server-sent events (SSE), and WebSocket libraries. The [`realtime`, `realtime-durable`, and `full-reference` profile selections](../../concepts/modules-profiles-and-composition.md) include these modules, but the reference application does not mount their routers. There is currently no proven public realtime endpoint.

This guide covers backend transport behavior. Use the [web realtime and upload guide](../web/realtime-and-uploads.md) for browser integration, [authorization and tenancy](authorization-and-tenancy.md) for the canonical access model, and both the canonical [modules, profiles, and composition model](../../concepts/modules-profiles-and-composition.md) and the [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md) before presenting a profile as runnable.

## Profile and module selections

| Profile | Selected event provider | Realtime libraries | Current exposure |
|---|---|---|---|
| [`realtime`](../../concepts/modules-profiles-and-composition.md) | [Ephemeral Redis Pub/Sub](../../concepts/modules-profiles-and-composition.md) | Core, SSE, WebSocket | Unassembled |
| [`realtime-durable`](../../concepts/modules-profiles-and-composition.md) | [Durable NATS event modules](../../concepts/modules-profiles-and-composition.md) | Core, SSE, WebSocket | Unassembled |
| [`full-reference`](../../concepts/modules-profiles-and-composition.md) | [Both event-provider modules](../../concepts/modules-profiles-and-composition.md) are present in profile/module catalog data | Core, SSE, WebSocket | Unassembled |

“Durable” describes the [selected event-provider module](../../concepts/modules-profiles-and-composition.md), not an end-to-end guarantee for a client connection. A concrete application must provision and construct the provider, connect it to realtime delivery, register supervised tasks, and mount a router. Review the provider guarantees in [jobs, events, and scheduling](jobs-events-and-scheduling.md).

## No canonical public route is proven

Source-local router factories and the machine catalog currently disagree about one path:

- the SSE router factory defines a local `/events` path;
- the module catalog describes `/realtime/events`;
- the WebSocket router factory defines a local `/realtime/ws` path and negotiates `omnius.realtime.v1`.

Neither router is mounted by `apps/api-server`. Consequently none of these strings is a supported public reference-app route, and this page does not resolve the SSE ambiguity. A composing application must choose and document its mount prefix, update the contract/catalog, and verify the effective path rather than concatenating paths by assumption.

## Shared delivery boundary

`realtime-core` centralizes behavior that transports must not bypass:

- authenticate the connection and derive canonical principal and tenant context;
- authorize every subscription rather than trusting a client-supplied topic;
- bind events to an authorized tenant/principal scope;
- keep connection, subscription, queue, payload, lifetime, and shutdown work bounded;
- revalidate authorization during long-lived sessions;
- redact tokens, payloads, tenant data, and provider details from public errors and diagnostics;
- expose stable lifecycle and telemetry seams for an application supervisor.

A successful initial connection does not authorize every later subscription forever. Revocation, tenant changes, and session expiry need explicit revalidation behavior in the composed host.

## Server-sent events

SSE is a one-way server-to-client stream over HTTP. The library provides bounded connection and delivery behavior plus browser-compatible framing. It does not implement client-to-server application messages.

A reconnect establishes a new connection. The current SSE layer does not itself provide replay or resume semantics, even if the upstream provider is durable. If the product requires resume, the application must define a stable cursor, authorize its use, retain events, bound replay, and prove the mapping to provider state.

Expected failure behavior:

- an unauthenticated or unauthorized request is rejected before a subscription is established;
- a slow client cannot grow an unbounded per-connection queue;
- overflow, upstream closure, lifetime expiry, or shutdown ends the stream rather than silently accumulating work;
- reconnect can miss ephemeral events and can also miss durable events unless application-owned cursor/replay logic exists;
- proxy buffering, idle timeouts, and disconnect detection remain deployment concerns and require environment evidence.

## WebSockets

The WebSocket library supports bidirectional delivery with a bounded protocol, heartbeat/pong handling, authorization revalidation, and connection lifetime controls. The router-local endpoint requires the `omnius.realtime.v1` subprotocol. This is still a library contract, not proof that a listener accepts upgrades.

A composing host must preserve the security boundary around the HTTP upgrade:

1. Authenticate before accepting application traffic.
2. Validate trusted origin policy for browser clients; do not treat WebSocket upgrade as a CSRF exemption.
3. Apply IP, principal, and tenant connection limits.
4. Authorize each requested subscription and revalidate it over time.
5. Reject unknown, malformed, oversized, or out-of-order protocol messages within bounded work.
6. Drain or close connections within the host's shutdown deadline.

Expected failure behavior:

- missing or wrong subprotocol fails negotiation;
- heartbeat timeout, lifetime expiry, revoked authorization, or shutdown closes the connection;
- a slow consumer is disconnected or has delivery rejected according to bounded queue policy;
- provider disconnect degrades or closes delivery rather than claiming continuity;
- a reconnect is a new authorization decision and does not imply replay.

## Backpressure and durability

There are two independent queues to reason about: the provider-to-host boundary and each host-to-client connection. Bounding one does not bound the other.

| Boundary | Required decision | Failure implication |
|---|---|---|
| Event provider | Redis ephemeral or NATS durable, provisioned and registered | Determines broker replay/acknowledgement behavior, not client resume |
| Realtime ingress | Bounded payload and ingress queue | Overflow must be observable and cannot become unbounded memory |
| Subscription fan-out | Tenant- and principal-scoped authorization | An incorrect scope risks cross-tenant disclosure |
| Client queue | Per-connection capacity and slow-consumer policy | A slow client loses delivery or is closed; it must not block all clients |
| Reconnect | New authentication plus optional application cursor | Without an owned cursor protocol, reconnect means best-effort continuation only |

Redis Pub/Sub can lose messages before readiness, across disconnect/restart, on local overflow or oversize, and during shutdown. NATS JetStream can support durable acknowledgement and redelivery only after stream/consumer provisioning and composition. Neither option turns SSE or WebSockets into exactly-once client delivery.

## Assembly and operational readiness

Before declaring realtime available, preserve evidence of:

- the effective mounted path and listener;
- provider construction, provisioning, and health;
- connection and subscription authorization, including wrong-tenant denial;
- trusted-origin and credential behavior for browser upgrades;
- bounded ingress and per-client queues under a slow consumer;
- provider disconnect, reconnect, replay, and loss behavior matching the [selected provider module](../../concepts/modules-profiles-and-composition.md);
- graceful drain under the deployment's shutdown bound;
- browser behavior through the actual proxy/CDN topology.

The operational owner should also follow [scaling jobs, realtime, and MCP](../../operations/scaling-jobs-realtime-and-mcp.md). Verification for this page remains **not run**; source tests, catalogs, and [profile selections](../../concepts/modules-profiles-and-composition.md) do not promote these routers to runtime exposure.