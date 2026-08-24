---
spec_id: RSK-046
title: MCP MRTR, Elicitation, Tasks, Subscriptions, and Progress
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP MRTR, Elicitation, Tasks, Subscriptions, and Progress

## 1. Multi Round-Trip Requests

Server-initiated requests are modeled with the current Multi Round-Trip Requests pattern. When additional input is required, the server returns `InputRequiredResult` with stable `requestState` and typed `inputRequests`. The client retries the original request with `inputResponses`; the server validates that state, principal, tenant, capability revision, and prior arguments still match.

State is an explicit signed/encrypted or server-minted bounded handle, never an implicit protocol session. It has expiry, replay policy, maximum rounds, and audit history.

## 2. Elicitation

Elicitation schemas are narrowly scoped to required data. Sensitive fields are identified and MAY require out-of-band URL mode or stronger confirmation. The server MUST NOT ask for provider API keys, passwords, or broad credentials through an ordinary free-text field. User decline and cancellation are normal outcomes.

## 3. Tasks extension

Long-running MCP operations use the official `io.modelcontextprotocol/tasks` extension only after negotiated support. A `CreateTaskResult` is returned only after the task is durably created and immediately resolvable by `tasks/get`. Its flattened task state includes `taskId`, `status`, `createdAt`, `lastUpdatedAt`, and `ttlMs`, with optional `statusMessage` and `pollIntervalMs`. Task IDs map to the existing job abstraction and retain principal, tenant, capability revision, idempotency, budget, and expiration.

`tasks/get` returns `resultType: "complete"` plus the current detailed task, including `inputRequests`, a final result, or a JSON-RPC error as required by status. `tasks/update` and `tasks/cancel` return empty `resultType: "complete"` acknowledgements; their observable effects are eventually consistent. There is no invented `tasks/list` or `tasks/result`. Task results use the same canonical capability result as synchronous execution. Streamable HTTP requests for `tasks/get`, `tasks/update`, and `tasks/cancel` set `Mcp-Name` to `taskId` and `Mcp-Method` to the JSON-RPC method.

## 4. Subscriptions and progress

`subscriptions/listen` maps to the existing event providers through one selected backplane module. Its JSON-RPC request ID is the subscription ID; acknowledgment is the first message for that ID and every delivered notification carries the same subscription metadata. Subscription filters are explicit, authorized, bounded, and tenant-scoped.

Progress for an ordinary synchronous request remains on that request's response stream. Task progress is represented by `Task.status` and `statusMessage`, observed through `tasks/get` and optionally complete `notifications/tasks` snapshots requested through the Tasks extension's `taskIds` subscription filter. `notifications/progress` and `notifications/message` are not supported for Tasks and MUST NOT be sent on a task subscription stream. No path promises exactly-once delivery.

Redis pub/sub is ephemeral; NATS JetStream is durable only where the selected event contract provides durability. Local subscriptions are single-instance development/reference behavior.

## 5. Failure behavior

Broken in-flight HTTP streams are not resumed. A client retries with a new request ID and any explicit idempotency/task handle. Cancellation is best-effort at external providers but authoritative state records whether work was stopped, completed before cancellation, or became indeterminate.

## 6. Acceptance linkage

This specification is verified by `AC-AI-089` through `AC-AI-096`.
