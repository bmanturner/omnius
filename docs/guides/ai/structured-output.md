---
title: Structured output
description: Local JSON Schema validation, native and repair strategies, bounded parsing, and failure semantics for model-generated data.
status: experimental
implementation: implemented
profile_availability:
  - llm-runtime
  - llm-api
  - llm-agent
  - ai-worker
  - ai-platform
  - full-reference-ai
public_exposure: library-only
audience:
  - ai-application-developer
  - api-developer
topics:
  - llm
  - json-schema
  - validation
  - repair
capabilities:
  - llm-structured-output
source:
  - crates/llm-structured-output/src/schema.rs
  - crates/llm-structured-output/src/plan.rs
  - crates/llm-structured-output/src/bounded_json.rs
  - crates/llm-structured-output/src/repair.rs
evidence:
  - crates/llm-structured-output/tests/contracts.rs
last_verified: 2026-08-30
---

# Structured output

`llm-structured-output` converts completed model output into locally validated JSON under explicit bounds. It is an implemented library selected by `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, and `full-reference-ai`; its public exposure is **library-only**.

The library is not assembled into the reference application and does not prove that any provider supports native schemas.

## Start with a local schema

Schemas use the JSON Schema Draft 2020-12 contract and are compiled before dispatch. Remote references are rejected: validation must not fetch an attacker-selected URL or depend on mutable network content.

A bounded illustration is:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "category": { "type": "string", "enum": ["accepted", "rejected"] },
    "reference": { "type": "string", "maxLength": 64 }
  },
  "required": ["category", "reference"],
  "additionalProperties": false
}
```

The URL identifies the schema dialect; it is not a runtime reference to fetch. Production schemas should additionally bound every application-controlled string, array, object, numeric range, and nesting shape needed by the use case.

## Plan the generation strategy

The plan chooses between:

- **native structured output**, only when routing proves that the selected model/provider supports the required schema behavior; or
- **validated generation with repair**, when policy permits a bounded repair attempt.

A route that cannot satisfy the required strategy is a capability mismatch. It must be rejected or sent to an explicitly equivalent fallback; it must not silently switch to unvalidated free text.

Provider-advertised schema support does not replace local validation. Provider output is still untrusted input.

## Accept only a completed value

Parsing and validation occur only after a complete response is available. A streaming fragment that happens to be valid JSON at one instant is not a completed result. Wait for a valid stream terminal, assemble within size bounds, then parse and validate once the result is complete.

The bounded JSON layer constrains admitted shape and work before data reaches application logic. Local validation checks the compiled schema. Application authorization and business invariants remain separate checks.

## Repair is another model attempt

Repair receives a bounded diagnostic rather than unrestricted application context. The library enforces a finite repair-attempt count and returns per-attempt metering, but `validate_and_repair` accepts no cancellation token, deadline, or usage-budget port. The assembled host must keep repair under the original deadline and cancellation owner, reserve or charge its usage and cost, reconcile the returned metering, and attribute it separately from primary generation.

Repair must not:

- weaken or replace the schema;
- invent missing authorization or tenant context;
- fetch a remote reference;
- continue after cancellation or deadline expiry;
- expose the original prompt or invalid output in telemetry;
- be repeated without accounting for every provider attempt.

After repair, the completed value is parsed and validated from the beginning. A repaired value that still fails is a terminal structured-output failure.

## Failure semantics

Keep these outcomes distinct:

| Outcome | Meaning | Host action |
| --- | --- | --- |
| schema compilation failure | the local contract is unsupported or invalid | reject before dispatch |
| capability mismatch | no admissible target provides required behavior | reject or use an equivalent explicit fallback |
| generation failure | provider attempt did not produce a completed candidate | apply bounded provider retry policy if eligible |
| parse/shape failure | candidate is not admissible bounded JSON | repair only if planned and budgeted |
| schema failure | parsed value violates the compiled schema | repair only if planned and budgeted |
| authorization/business failure | valid JSON requests a forbidden action or state | reject; do not ask the model to override policy |
| cancellation/deadline | the owner stopped or time expired | terminate and reconcile usage conservatively |

Do not return partial data as success. At an HTTP boundary, map a safe, content-free failure through the canonical [error model](../../reference/error-model.md); do not include raw model output in Problem Details.

## Structured tool arguments

Tool argument schemas use the same fail-closed principle, but successful schema validation never authorizes a tool. The host must still identify the caller, check tenant and policy scope, require approval when configured, enforce idempotency and budgets, and audit the decision. Continue with [tools and approvals](tools-and-approvals.md).
