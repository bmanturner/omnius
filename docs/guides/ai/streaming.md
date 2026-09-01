---
title: LLM streaming
description: Ordered stream contracts, part assembly, terminal outcomes, bounded delivery, backpressure, cancellation, and disconnect semantics.
status: experimental
implementation: implemented
profile_availability:
  - llm-runtime
  - llm-api
  - llm-agent
  - ai-worker
  - ai-platform
  - full-reference-ai
public_exposure: unassembled
audience:
  - ai-application-developer
  - web-developer
  - operator
topics:
  - llm
  - streaming
  - cancellation
  - backpressure
capabilities:
  - llm-streaming
source:
  - crates/llm-streaming/src/event.rs
  - crates/llm-streaming/src/delivery.rs
  - crates/llm-streaming/src/coalesce.rs
  - crates/llm-http-api/src/lib.rs
evidence:
  - crates/llm-streaming/tests/contracts.rs
  - crates/llm-http-api/tests/http.rs
last_verified: 2026-08-30
---

# LLM streaming

`llm-streaming` is implemented and selected by all six LLM extension profiles, but its exposure is **unassembled**. The repository contains stream contracts and an SSE route factory; it does not contain non-test composition that mounts the router or connects it to a provider executor.

## Event invariants

A stream is one ordered response. The consumer validates:

- strictly valid sequence progression;
- part identifiers and part-local transitions;
- which event variants are legal before and after part completion;
- a configured cumulative byte bound;
- exactly one response-level terminal outcome;
- no event after the terminal.

A redacted event shape is:

```json
{
  "response_id": "opaque-response-id",
  "sequence": 7,
  "part_id": "opaque-part-id",
  "kind": "content-delta",
  "content": "<redacted text>"
}
```

This illustrates fields, not a live endpoint transcript. Logs should retain only safe identifiers, sequence counters, bounded sizes, event classes, and terminal state—not content deltas.

## Termination is mandatory

A stream succeeds only after the validator observes its single valid success terminal. A failure terminal is a completed failure, not partial success. Transport EOF, consumer disconnect, provider silence, decoder failure, invalid ordering, byte overflow, or deadline expiry without a valid success terminal must not be reported as a completed response.

Once a terminal is observed:

- reject duplicate terminals;
- reject later content or metadata events;
- close downstream delivery;
- reconcile usage and cost conservatively;
- finalize telemetry without raw content.

Consumers must not infer success from accumulated text.

## Bounded delivery and backpressure

Delivery uses finite capacity. Coalescing may reduce delivery pressure only where event semantics allow it; it must not reorder events, combine unrelated parts, hide a terminal, or exceed content bounds.

When a downstream consumer cannot keep up, the host applies its explicit backpressure policy. It must not allocate an unbounded queue. If delivery cannot continue safely, cancel the interactive owner, close the producer path, and surface a non-success terminal or transport failure according to the assembled protocol.

The provider boundary receives an `LlmRequest` whose limits include `deadline_ms`; it does not receive a cancellation token. The assembled host owns cancellation across provider dispatch, decoding, validation, coalescing, and delivery, and must stop or discard downstream work when cancellation becomes effective while asking an adapter to stop upstream work where supported.

## Interactive and durable ownership

Disconnect semantics depend on who owns the work:

- **Interactive stream:** in a live assembled stream, the connected consumer owns the request. The host must detect disconnect and propagate cancellation upstream; the checked-in buffered HTTP factory does not implement that live cancellation path.
- **Durable job:** the job record owns execution. Disconnecting an observer does not cancel the job. Cancellation requires the durable job's cancellation operation and state transition.

Confusing these models either wastes provider work after an interactive disconnect or destroys durable work merely because a browser changed pages.

Provider cancellation is best effort. A canceled attempt may already have consumed tokens or become billable, so usage reconciliation remains conservative.

## Tool and structured-output streams

Tool-call and content parts retain their typed boundaries. Do not execute a tool from an incomplete argument fragment. Assemble within bounds, validate the completed schema, then apply authorization and approval as described in [tools and approvals](tools-and-approvals.md).

Likewise, JSON fragments are not structured-output success. Wait for a valid stream terminal, assemble within bounds, and run local schema validation as described in [structured output](structured-output.md).

## HTTP and browser boundary

The LLM HTTP source describes an SSE contract, and the Web SDK contains a strict parser. These are implementation evidence for an integration surface, not proof that the reference API publishes it. A selected `llm-api` or `ai-platform` profile still does not mount routes.

Before exposing a stream, an application must compose authentication, tenant binding, capability-aware routing, provider execution, usage reservation, safety enforcement, disconnect ownership, bounded SSE delivery, and readiness. See [HTTP and Web integration](http-and-web-integration.md) and the [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md).

## Diagnostic checklist

For an incomplete stream, inspect safe counters and state: last accepted sequence, open part count, byte total, terminal observed, cancellation owner, remaining deadline, delivery saturation, and usage reconciliation state. Do not print accumulated content or provider wire payloads while troubleshooting.
