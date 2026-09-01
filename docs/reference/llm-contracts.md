---
title: LLM contracts
description: Provider-neutral request, response, content, usage, limits, errors, and streaming wire contracts.
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
  - ai-developer
  - service-developer
topics:
  - llm
  - contracts
  - streaming
capabilities: []
source:
  - crates/llm-core/src/request.rs
  - crates/llm-core/src/response.rs
  - crates/llm-core/src/provider.rs
  - crates/llm-streaming/src/event.rs
evidence:
  - crates/llm-core/tests/contracts.rs
  - crates/llm-streaming/tests/contracts.rs
last_verified: 2026-08-30
---

# LLM contracts

The Rust crates implement provider-neutral contracts. Core request/response contracts are library-only. A generated AI root is assembled only after its actual process passes startup/readiness, representative and negative workflows, bounded streaming/shutdown, dependency-outage, and runtime-contract parity checks. Deterministic providers and synthetic application contributions are useful test evidence but classification-ineligible.

## Common rules

Current `schema_version` is `1.0.0`. Envelope structures reject unknown fields. Catalog selections, JSON schemas, provider documentation, and generated clients do not prove credentials, routing, or HTTP assembly. `llm-embeddings` remains specified-only because the repository has neither an authoritative embedding operation request schema nor an owning provider port; every selecting profile remains unassembled even if neighboring LLM tests pass.

## Request

`LlmRequest` requires `schema_version`, `request_id`, `route`, `messages`, `output`, and `limits`. Optional fields are `generation`, `tools`, `tool_policy`, `metadata`, `data_policy`, `principal_context`, and `tenant_context`.

### Route and messages

| Structure | Exact contract |
|---|---|
| `route` | `{id, revision?, required_capabilities, preferred_capabilities}`. Revision is an unsigned integer and cannot be zero. Each capability-name list must be unique. Names are strings; this route field is not the typed model-capability enum. |
| message roles | `system`, `developer`, `user`, `assistant`, `tool` |
| message | `{id?, role, name?, content, metadata?}` where `content` is an array of input parts. |

### Input parts

| `kind` | Fields |
|---|---|
| `text` | `text` |
| `structured` | JSON `value` |
| `image`, `audio`, `video` | `mime_type`, `source` |
| `file` | `mime_type`, `source`, optional `filename` |
| `resource` | `uri`, optional `mime_type` |
| `tool_result` | `call_id`, status `success`/`error`/`cancelled`, JSON `content[]` |

A binary `source` is tagged by `type`: `inline` with `data_base64`, `url` with `url`, or `object` with `object_key`.

### Generation

| Field | Constraint |
|---|---|
| `temperature` | optional floating-point value |
| `top_p` | optional, inclusive range 0–1 |
| `max_output_tokens` | optional positive unsigned integer |
| `candidate_count` | optional positive unsigned integer |
| `stop` | string array |
| `seed` | optional signed integer |

No generation defaults are defined by the provider-neutral request contract.

### Output request and tools

Output modes are exactly `auto`, `text`, `structured`, `tools`, and `media`. An output request is `{mode, schema_id?, schema?, strict?, mime_types}`. `schema` is an untagged JSON object or boolean.

A tool definition is `{name, description?, capability_id?, input_schema, output_schema?}`. Both schemas use the same object-or-boolean schema definition.

### Limits

| Field | Required | Constraint |
|---|---:|---|
| `deadline_ms` | yes | positive unsigned integer |
| `max_model_turns` | yes | positive unsigned integer |
| `max_tool_calls` | yes | unsigned integer; zero is allowed |
| `max_input_bytes` | no | positive when present |
| `max_output_bytes` | no | positive when present |
| `max_cost_microunits` | no | unsigned integer; zero is allowed |

## Response

`LlmResponse` requires `schema_version`, `request_id`, `response_id`, `provider`, `model`, `status`, `output`, `usage`, and `created_at`. Optional fields are `provider_response_id`, `provider_request_id`, `stop_reason`, `selected_candidate_index`, `candidates`, `warnings`, and `provider_metadata`.

Completion status is `completed`, `partial`, `refused`, `cancelled`, or `failed`. A candidate is `{id?, index, status, stop_reason?, output, provider_metadata?}`.

### Output parts

`LlmOutputPart` is a non-exhaustive `kind`-tagged union. Current kinds are:

`text`, `structured`, `tool_call`, `tool_result`, `citation`, `refusal`, `image`, `audio`, `video`, `file`, `resource`, `annotation`, `execution_step`, `safety`, `reasoning`, `unknown`.

Core shapes include:

| `kind` | Core fields |
|---|---|
| `text` | `id`, `text`, optional format `plain`/`markdown`/`html-fragment`, annotations, provider metadata |
| `structured` | `id`, JSON `value`, optional `schema_id`, validation `valid`/`invalid`/`not-requested`, `repair_attempts`, annotations, provider metadata |
| `tool_call` | `id`, `call_id`, `name`, JSON `arguments`, optional `capability_id`, annotations, provider metadata |
| `tool_result` | `id`, `call_id`, status `success`/`error`/`cancelled`, recursive output-part `content`, annotations, provider metadata |

### Usage

`input_tokens` and `output_tokens` are required but nullable. Optional counters are:

`cached_input_tokens`, `cache_read_tokens`, `cache_write_tokens`, `reasoning_tokens`, `audio_input_tokens`, `audio_output_tokens`, `image_input_units`, `image_output_units`, `video_input_units`, `video_output_units`, `tool_execution_units`, `estimated_cost_microunits`, `actual_cost_microunits`, and `provider_units`.

## Streaming wire contract

The implemented stream envelope is:

```text
{ schema_version, request_id, sequence, payload }
```

Sequence starts at zero. `payload` is tagged as either `{event: "event", data: …}` or `{event: "terminal", data: …}`.

Nonterminal event variants are:

`response_start`, `part_start`, `text_delta`, `structured_complete`, `tool_call_delta`, `tool_call_complete`, `tool_result_complete`, `safe_reasoning`, `media`, `citation`, `usage`, `warning`, `part_complete`.

Part kinds are `text`, `structured`, `tool_call`, `tool_result`, `safe_reasoning`, `media`, and `citation`. Tool-call deltas contain only tagged `name` or `arguments_fragment` string fields and cannot become executable; only `tool_call_complete` carries a complete tool-call output. `structured_complete` accepts only `valid` structured validation.

Terminal states are:

- `completed`;
- `provider_refused`;
- `safety_refused`;
- `invalid_structured_data`;
- `tool_execution_failed`;
- `budget_exhausted` with dimension `model_turns`, `tool_calls`, `wall_clock`, `tokens`, `cost`, or `concurrency`;
- `cancelled`;
- `failed` with kind `protocol`, `transport`, or `internal`;
- `partial_interrupted` with interruption `transport`, `protocol`, `consumer_disconnected`, or `deadline`.

Stream warning values are `provider_extension_omitted`, `private_reasoning_omitted`, `text_coalesced`, and `estimated_usage`.

### Known machine-schema mismatch

`specs/machine/extensions/llm-mcp-suite/schemas/llm-stream-event.schema.json` describes a different flat envelope with `event`, `timestamp`, and `data`, and advertises additional events such as `candidate_start`, `structured_delta`, and `heartbeat`. It does not describe the current Rust `{payload}` wire shape and requires a timestamp that the Rust type does not contain. Treat the implemented Rust event type as the current library contract; do not use that machine schema as runtime wire evidence until they are reconciled.

## Adapter error vocabulary

Provider error kinds are `unsupported`, `provider`, `transport`, `timeout`, `throttling`, `safety`, and `schema`. Retry classes are `never`, `safe`, and `after_retry_after`.

Unsupported-feature variants cover message identity/name/metadata and message roles, media/file/resource/tool-result input, generation controls, tool policy/output schema, structured validation, ordering, output MIME modes, request metadata/context/policy, cost limit, and streaming. These enums are in-process source contracts and do not themselves derive a standalone wire serialization guarantee.

Raw-retention policy/state is `Discard`/`Redacted`/`Full` and `Discarded`/`Redacted`/`Full`. Redaction retains only the top-level JSON kind and serialized byte count, not the original raw payload.
