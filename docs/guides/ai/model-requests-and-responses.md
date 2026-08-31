---
title: Model requests and responses
description: Provider-neutral LLM request, response, content, usage, provenance, and retention contracts.
status: experimental
implementation: partial
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
  - platform-engineer
topics:
  - llm
  - requests
  - responses
  - content
capabilities:
  - llm-core
  - llm-embeddings
source:
  - crates/llm-core/src/request.rs
  - crates/llm-core/src/response.rs
  - crates/llm-core/src/extended_content.rs
  - crates/llm-core/src/provider.rs
evidence:
  - crates/llm-core/tests/contracts.rs
  - crates/llm-core/tests/extended_content.rs
  - crates/llm-core/tests/model_response.rs
last_verified: 2026-08-30
---

# Model requests and responses

`llm-core` defines the provider-neutral contract used by the rest of the LLM libraries. It is not a provider client and it is not assembled into the reference application.

## Availability

| Capability | Status | Implementation | Selected by profiles | Public exposure |
| --- | --- | --- | --- | --- |
| `llm-core` | experimental | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-embeddings` | experimental | specified-only | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | unassembled |

The page-level frontmatter is conservative because these capabilities have different implementation and exposure classifications. In particular, canonical embedding types do not prove an embedding operation, provider adapter, or public endpoint.

## Canonical request boundary

A request carries application intent rather than a provider wire payload. The contract includes:

- canonical messages with explicit roles and typed content parts;
- model selection requirements and provider-neutral generation controls;
- response format and required-capability declarations;
- tool definitions as schemas, not executable authority;
- cancellation and deadline context supplied by the host;
- tenant-safe provenance and policy metadata.

Supported content variants are intentionally bounded. Text, image, audio, document, citations, refusals, tool calls, tool results, and provider extensions have explicit representations. Unknown variants remain distinguishable so a caller can reject or quarantine them instead of silently treating them as text.

A safe diagnostic representation looks like this:

```json
{
  "role": "user",
  "content": [{ "type": "text", "text": "<redacted text>" }],
  "required_capabilities": ["structured-output"],
  "request_id": "opaque-test-id"
}
```

This is a shape illustration, not a provider request and not an invocation of a live service.

## Canonical response boundary

A model response separates:

1. typed content and refusal state;
2. normalized stop reason;
3. usage and model provenance;
4. provider extension metadata;
5. raw provider material under an explicit retention policy.

Provider-only finish reasons and fields must be normalized without discarding the fact that an unknown value was returned. Consumers should branch on the canonical result and reject unsupported variants. They should not deserialize one provider's response throughout application code.

The provider trait currently proves completion and streaming contracts. Specialized response types in the core crate do **not** prove executable embedding, image, audio, or document operations. Treat a capability as available only when the chosen provider adapter and assembled host both implement it.

## Raw data and private reasoning

Raw provider request and response material is discarded by default. A redacted policy may retain only bounded shape and size metadata. Full retention requires an explicit host policy and still must comply with tenant, privacy, retention, and provider terms.

Private reasoning is not application content. The contract withholds it from normal output, logs, traces, and evaluation artifacts. Store a public refusal, citation, answer, usage record, or provider-sanctioned opaque state when the workflow requires those fields; do not substitute hidden reasoning.

For the system-wide rules, see [LLM safety and data governance](../../security/llm-safety-and-data-governance.md) and [data and privacy boundaries](../../concepts/data-and-privacy-boundaries.md).

## Failure handling

Reject or stop when:

- no provider/model satisfies every required capability;
- content exceeds the host's admitted type or size policy;
- a provider returns an unknown or malformed content variant that the caller cannot safely preserve;
- structured output is incomplete or locally invalid;
- a stream has invalid ordering or no valid terminal;
- usage cannot be normalized conservatively;
- a specialized operation exists only as a canonical type.

Do not recover by silently removing a required capability or converting a refusal, error, or partial stream into a successful assistant answer.

## Integration checklist

Before dispatch, the host must define model requirements, data classification, residency/semantic constraints, deadline, retry eligibility, usage reservation, raw-data policy, and allowed content types. After dispatch, it must validate the result, reconcile usage, redact telemetry, and preserve one unambiguous terminal outcome.

Continue with [providers and routing](providers-and-routing.md), [structured output](structured-output.md), and the [LLM contracts reference](../../reference/llm-contracts.md).
