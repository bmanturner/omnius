---
spec_id: RSK-036
title: LLM Domain Contracts and Complete Content Model
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# LLM Domain Contracts and Complete Content Model

## 1. Canonical request

`LlmRequest` MUST be provider-neutral and versioned. It includes a stable request ID, route/model requirements, ordered messages, generation controls, desired output mode, tool declarations, response schema reference, metadata, deadline, cancellation, tenant/principal context, and data-handling policy.

Messages MUST support system, developer, user, assistant, and tool roles. Input parts MUST support text, images, audio, files, resource references, structured values, and prior tool results. Large binary payloads SHOULD use the object-storage abstraction rather than duplicated base64 values.

## 2. Canonical response

`LlmResponse` MUST retain stable response identity, provider/model identity, ordered output parts, stop/termination information, usage, latency, warnings, provider request IDs, and policy-controlled provider metadata. Output parts are discriminated and non-exhaustive at the serialization boundary.

Required normalized variants are:

| Variant | Required semantics |
|---|---|
| `text` | Ordered plaintext or markdown fragments with optional annotations |
| `structured` | Any JSON value, schema identity, validation result, and repair history |
| `tool_call` | Stable call ID, capability/tool name, complete JSON arguments, provenance |
| `tool_result` | Stable call ID, success/error classification, ordered result content |
| `citation` | Source identity, location/offset metadata, and association to output |
| `refusal` | Provider or policy refusal with safe category and message |
| `image` | MIME type plus bytes, URL, or object reference and dimensions when known |
| `audio` | MIME/codec plus bytes, URL, or object reference and timing when known |
| `video` | MIME/codec plus bytes, URL, object reference, duration, and dimensions when known |
| `file` | Filename, MIME type, bytes/URL/object reference, checksum when available |
| `resource` | Provider- or application-hosted resource identity, URI/object reference, media type, and lifecycle metadata |
| `annotation` | Typed grounding, citation, safety, token-score/log-probability, URL/file-path, or provider annotation associated with a part |
| `execution_step` | Provider-executed search, code, computer-use, shell, file-search, image-generation, MCP, or future built-in operation with inputs, outputs, status, and provenance |
| `safety` | Provider or application safety/guardrail classification, blocked category, scores, and disposition |
| `reasoning` | Provider-sanctioned summary, signature, or opaque encrypted state only |
| `unknown` | Namespaced provider kind and losslessly retained policy-approved payload |

A response MAY contain several different part types and more than one candidate/choice. The selected `output` remains convenient for common callers, while every provider-returned alternative MUST be retained in ordered `candidates` when available. Text MUST NOT be assumed to be the only final answer.

## 3. Specialized model-operation responses

Completion/chat generation is not the only provider operation. The public model boundary MUST also define normalized, versioned responses for:

| Operation | Required retained output |
|---|---|
| `embeddings` | One result per input with stable input identity/index; dense, sparse, binary/quantized, or multi-vector representation; dimensions; usage; and provider metadata |
| `rerank` | Original document identity/index, deterministic rank, relevance score, optional returned document/explanation metadata, usage, and provider metadata |
| `transcription` | Full text, detected language, duration, timestamped segments and words, channels/speakers where supplied, confidence, and provider metadata |
| `speech` | Generated audio reference/bytes, MIME and codec, voice, duration/sample rate/channels, timing marks or visemes, subtitles/transcript where supplied, and provider metadata |
| `media_generation` | Every generated image/audio/video/file/resource candidate, generation and asset IDs, revised prompt, seed, parameters, provenance, safety outcomes, and usage |
| `classification` | Per-input labels/categories, scores, dispositions, explanation metadata when available, and provider metadata; moderation is represented as a policy-specialized classification |

Specialized responses MUST preserve provider request/response IDs, warnings, status, usage, cost, and unknown namespaced metadata under the same governance rules as `LlmResponse`. Batch and durable forms wrap these contracts in the existing job/task abstractions rather than inventing incompatible result types.

`model-response.schema.json` is the machine-readable union of completion and specialized response families. Adapters MUST NOT coerce embeddings, rerank results, transcripts, generated audio/media, or moderation/classification results into plaintext merely to fit a chat-completion abstraction.

## 4. Reasoning privacy

The kit MUST NOT request, synthesize, expose, or persist hidden private chain-of-thought. It MAY retain provider-supported reasoning summaries, signatures, and encrypted continuation blocks where required to preserve a provider conversation. These values MUST be separately classified, redacted from ordinary logs, and never presented as verified factual explanations.

## 5. Usage and identities

Usage MUST distinguish input, output, cache reads, cache writes, reasoning, audio, image, video, tool/execution, and provider-specific billable units when supplied. Unknown counters remain namespaced metadata. Native response IDs and transport request IDs MUST be retained because retries, provider support, audits, and cost reconciliation require both.

## 6. Serialization compatibility

Canonical contracts MUST use explicit schema versions and stable discriminators. Readers MUST ignore unknown optional fields and preserve unknown output variants where policy permits. Writers MUST produce deterministic ordering for stable fields and parts.

## 7. Validation and size limits

Every content part has explicit byte, item-count, and nesting limits. URLs and object references pass centralized outbound and storage policy. MIME types are validated independently of filenames. Unknown provider payloads are bounded before parsing or persistence.

## 8. Acceptance linkage

This specification is verified by `AC-AI-009` through `AC-AI-016`.
