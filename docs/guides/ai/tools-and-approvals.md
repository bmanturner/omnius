---
title: Tools and approvals
description: Deny-by-default tool exposure, caller authorization, approval, idempotency, audit, and finite agent-loop budgets.
status: experimental
implementation: implemented
profile_availability:
  - llm-api
  - llm-agent
  - ai-worker
  - ai-platform
  - full-reference-ai
public_exposure: library-only
audience:
  - ai-application-developer
  - security-reviewer
topics:
  - llm
  - tools
  - authorization
  - approvals
capabilities:
  - llm-tool-runtime
source:
  - crates/llm-tool-runtime/src/catalog.rs
  - crates/llm-tool-runtime/src/call.rs
  - crates/llm-tool-runtime/src/budget.rs
  - crates/llm-tool-runtime/src/runtime.rs
evidence:
  - crates/llm-tool-runtime/tests/contracts.rs
last_verified: 2026-08-30
---

# Tools and approvals

`llm-tool-runtime` is an implemented **library-only** capability selected by `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, and `full-reference-ai`. No checked-in application assembles its registry, handlers, authorization port, approval store, worker, provider loop, or route.

A model never receives ambient authority. It may propose a typed tool call; the host decides whether that call is visible, authorized, approved, affordable, safe, and executable.

## Exposure is explicit

Only catalog entries explicitly marked for LLM exposure enter the model-facing registry. Application services, internal commands, and general module APIs are not tools merely because they can be called in Rust.

A tool definition should have:

- a stable name and revision;
- bounded input and output schemas;
- a risk and approval policy;
- required caller, tenant, permission, and data scopes;
- idempotency behavior;
- timeout, concurrency, and cost expectations;
- content-safe audit fields.

Schema descriptions are instructions to a model, not an authorization policy.

## Runtime order and audit boundary

The checked-in runtime processes a call in this order:

1. resolve the tool from the LLM-exposed catalog;
2. bind the principal, tenant, request, confirmation, and idempotency evidence supplied by the host;
3. validate bounded arguments, tenant mode, confirmation requirements, and idempotency;
4. reserve one tool-call unit and one concurrency slot, and check the loop wall-clock deadline;
5. authorize the exact capability, identity, arguments, permissions, side effect, and evidence, then validate the grant;
6. construct the invocation context and invoke the handler within the remaining wall-clock bound;
7. validate and bound the result;
8. derive the terminal outcome and synchronously record its redacted audit record before returning.

The tool-call and concurrency reservation happens before the authorization port runs, so an authorization denial consumes the tool-call counter for that loop. `ToolRuntime::execute` does not call the available model-turn or token/cost charging APIs; an assembled host owns those budgets and their accounting.

Audit is a terminal-outcome boundary, not a pre-handler guard. If the audit write fails, `execute` returns `AuditUnavailable`, but `execute_inner` may already have invoked the handler. The audit error alone therefore cannot prove that no effect occurred: preserve the stable call/effect identity and resolve the outcome idempotently before any retry.

Missing identity, tenant, policy, approval, budget, or idempotency protection fails closed at the applicable guard. Prompt-injection scoring can tighten a decision, but cannot grant permission.

## Approval boundary

Approval is scoped to the exact actor, tenant, tool, revision, admitted arguments or argument digest, and validity window required by policy. A broad statement such as “allow this agent” is not an adequate substitute.

A safe decision record can contain opaque identifiers and policy results:

```json
{
  "call_id": "opaque-call-id",
  "principal_id": "opaque-principal-id",
  "tenant_id": "opaque-tenant-id",
  "tool": "records.lookup",
  "tool_revision": "revision-id",
  "decision": "denied",
  "reason": "approval-required"
}
```

It must not contain a bearer token, provider credential, raw prompt, unrestricted arguments, tool result, personal data, or private reasoning.

The library defines approval checks, but durable approval persistence and an expiry worker are not verified in repository evidence. An application must provide and operate those components before claiming durable approvals. Restart behavior must remain fail-closed until that evidence exists.

## Idempotency and ambiguous outcomes

A side-effecting tool must use a stable idempotency identity for the logical call. Retrying with a fresh identity can duplicate an action. Reusing an identity for different admitted arguments is also invalid.

If a timeout or transport error leaves the handler outcome ambiguous, do not let the model assume failure and issue a new side effect. Resolve the original operation by idempotency identity or surface an ambiguous terminal outcome for human or application handling.

## Finite agent loops

`LoopBudget` defines finite model-turn, tool-call, token, cost, wall-clock, and concurrency dimensions. The tool runtime itself reserves a tool call and concurrency, enforces its wall-clock deadline, and leaves model-turn and token/cost charging to the host.

Provider retries, structured-output repair, and tool execution are not assembled under one shared budget or cancellation owner by these libraries. A host composition must establish that shared deadline, cancellation, and accounting boundary, charge every attempt from returned metering, and stop admitting work when any applicable bound is exhausted.

A tool result is untrusted content on its return path. Bound its size and schema, retain its provenance, and prevent its text from becoming privileged instruction. A successful handler response does not authorize a follow-up tool.

## Failure behavior

Reject without invoking the handler when:

- the tool is absent from the LLM exposure catalog;
- caller or tenant context is absent or mismatched;
- permission, capability, approval, schema, safety, idempotency, or budget checks fail;
- cancellation or the deadline is already effective;
- concurrency limits cannot admit the work.

An audit-write failure is different from these proven pre-handler rejections. It can occur after handler invocation, so return a failure while preserving the idempotency identity and treat the effect as ambiguous until reconciled.

Redact all diagnostics. Authorization denial and approval expiry are terminal policy outcomes, not provider-retry signals.

See [identity, authorization, and tenancy](../../concepts/identity-authorization-and-tenancy.md), [LLM safety and data governance](../../security/llm-safety-and-data-governance.md), [usage budgets and cost control](usage-budgets-and-cost-control.md), and [structured output](structured-output.md).
