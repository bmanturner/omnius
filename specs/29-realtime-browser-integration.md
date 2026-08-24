---
spec_id: RSK-029
title: Realtime Browser Integration
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Realtime Browser Integration

## 1. Purpose

The realtime browser capability provides a typed, resilient consumer of the base WebSocket, SSE, and event-envelope modules. HTTP remains the source for reconstructing authoritative resource state unless an event contract explicitly guarantees otherwise.

## 2. Framework-neutral client

The SDK MUST expose a transport-neutral lifecycle:

```text
connect
disconnect
subscribe
unsubscribe
sendCommand          optional
connectionState
lastEventId
diagnostics
```

React hooks wrap this lifecycle but do not own transport correctness.

## 3. Typed messages

Message types MUST derive from AsyncAPI and shared JSON Schemas. The generated union MUST discriminate by stable event name and version. Unknown event types or versions MUST:

- not crash the connection loop.
- be observable.
- be ignored or routed to a compatibility handler according to policy.
- never be coerced into a known payload.

Runtime validation MUST be applied at the trust boundary when the selected generator/types do not inherently validate data.

## 4. Connection lifecycle

The client MUST implement:

- explicit states: idle, connecting, open, degraded, reconnecting, closed, unauthorized.
- exponential backoff with jitter and an upper bound.
- online/offline and visibility awareness without relying on them as perfect signals.
- cancellation and clean disposal.
- stable subscription identity.
- resubscription after reconnect.
- heartbeat/idle timeout behavior compatible with the server.
- authentication failure handling that does not create reconnect storms.
- observability hooks.

Backoff MUST reset only after a stable connection interval.

## 5. SSE

SSE support MUST address:

- `Last-Event-ID` or an equivalent resume cursor.
- named events.
- heartbeat comments.
- proxy buffering guidance.
- authentication constraints.
- browser-native versus fetch-stream implementation tradeoffs.
- cancellation.
- duplicate delivery.

If cookie authentication is sufficient, native `EventSource` MAY be used. If custom headers are required, the SDK MUST use an approved fetch-stream implementation and document browser support.

## 6. WebSockets

WebSocket support MUST address:

- URL derivation and approved protocols.
- origin checks on the server.
- upgrade-time authentication.
- post-upgrade session revalidation.
- maximum message size.
- command authorization.
- request/response correlation where commands are enabled.
- bounded client queues.
- slow or disconnected consumer behavior.
- graceful server drain/reconnect hints.

The browser MUST never assume a successful socket connection authorizes every subscription or command.

## 7. Query synchronization

Modules MAY declare event-to-query effects:

```yaml
event: organization.updated.v1
effects:
  - invalidate:
      operation_id: getOrganization
      parameters:
        id: "$message.data.organization_id"
  - invalidate:
      operation_id: listOrganizations
```

Supported effect types SHOULD include:

- invalidate.
- refetch.
- set/patch from a validated complete representation.
- remove.
- revalidate session.
- revalidate capabilities.

Invalidation is the default. Direct cache patching requires an event payload with a complete, version-compatible representation and conflict policy.

Effects MUST use generated query-key factories. They MUST include tenant and principal scope where applicable.

## 8. Ordering, replay, and duplicates

The client MUST tolerate at-least-once delivery and reconnect duplicates. When the event contract supplies sequence, revision, cursor, or occurred-at values, the SDK MAY use them to reject stale updates. It MUST NOT invent global ordering.

Missed-event recovery MUST be explicit:

- resumable stream.
- HTTP revalidation.
- full subscription snapshot.
- declared non-recoverable ephemeral semantics.

## 9. Multi-tab behavior

An optional cross-tab coordinator MAY avoid redundant connections. If implemented, it MUST:

- preserve correctness when leader election fails.
- carry no credentials.
- validate cross-tab messages.
- fall back to per-tab connections.
- shut down promptly.
- not be required for baseline correctness.

## 10. React integration

The React adapter SHOULD expose:

```text
RealtimeProvider
useRealtime
useConnectionState
useEvent
useSubscription
useRealtimeQuerySync
```

Hooks MUST unsubscribe on cleanup and avoid stale closure bugs. Handler exceptions MUST not terminate the connection manager.

## 11. Testing

Required tests include:

- typed message decoding.
- unknown-version behavior.
- reconnect with jitter under a fake clock.
- resubscription.
- unauthorized terminal state.
- session revocation.
- duplicate delivery.
- SSE resume.
- WebSocket command denial.
- query invalidation and safe patching.
- tenant switch.
- server drain.
- browser E2E across an actual Axum transport.

## 12. Acceptance linkage

This specification is satisfied by `AC-WEB-041` through `AC-WEB-050`.
