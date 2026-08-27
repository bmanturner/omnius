---
spec_id: OMNIUS-038
title: Structured Output, Tool Execution, and Streaming
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Structured Output, Tool Execution, and Streaming

## 1. Structured output

The canonical schema dialect is JSON Schema Draft 2020-12. Rust-owned output types SHOULD derive schemas with Schemars; arbitrary approved schemas MAY be supplied as JSON. Schemas MUST be locally compiled and validated with bounded reference resolution before being sent to a provider.

Output strategies, in preference order, are:

1. provider-native strict structured output;
2. provider-native strict tool/function output;
3. explicitly configured constrained fallback;
4. prompt-only JSON only when a route knowingly permits weaker guarantees.

A response is successful only after local validation. Repair retries are bounded, separately metered, preserve the original invalid output for controlled diagnostics, and MUST NOT execute tools while repairing data.

## 2. Tool runtime

Tool definitions derive from the shared capability registry. The runtime validates arguments, authenticates the principal, authorizes the exact capability/resource/action, applies tenant scope, enforces confirmation policy, derives or verifies idempotency keys, imposes deadlines and output limits, and records an audit event.

Tool annotations and model-supplied arguments are untrusted. Side-effecting tools MUST require explicit policy approval; high-impact tools SHOULD support a human-confirmation state. The runtime MUST prevent recursive or duplicate invocation from bypassing controls.

Agent loops have explicit budgets for model turns, tool calls, wall-clock time, tokens, cost, and concurrent work. A zero or exhausted budget terminates deterministically.

## 3. Streaming model

`LlmStreamEvent` is an ordered, sequence-numbered event algebra. It includes response start, part start, text delta, structured-data delta or buffered completion, tool-call delta, safe reasoning-summary delta, media reference/delta, citation, usage update, warning, part completion, response completion, cancellation, and failure.

Partial tool arguments or structured JSON MUST NOT be exposed as complete data. Consumers either use a provider-specific incremental parser behind the adapter or wait for a validated complete value.

## 4. Backpressure and cancellation

Streaming uses bounded channels. Slow consumers trigger configured coalescing, backpressure, cancellation, or disconnect behavior; memory growth is never unbounded. Client cancellation propagates through the service, provider request, tool loop, jobs, and media upload. Disconnect is not automatically treated as cancellation when a durable job owns the request.

## 5. Error semantics

Protocol/transport failure, provider refusal, safety refusal, invalid structured data, tool execution error, budget exhaustion, cancellation, and partial-stream interruption are distinct terminal states. A provider stream that fails after content has been delivered MUST retain partial output and an incomplete status.

## 6. Acceptance linkage

This specification is verified by `AC-AI-025` through `AC-AI-032`.
