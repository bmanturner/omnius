---
spec_id: RSK-041
title: LLM HTTP, Jobs, Web SDK, and Observability
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# LLM HTTP, Jobs, Web SDK, and Observability

## 1. HTTP surface

The `llm-http-api` module contributes OpenAPI-described endpoints for model-route discovery, synchronous and streaming generation responses, embeddings, reranking, transcription, speech synthesis, media generation, classification/moderation, durable operation jobs, job status/cancellation, and approved conversation operations. Endpoint names are product-neutral and versioned. Provider keys, raw payloads, and unrestricted model IDs are never accepted as ordinary public parameters.

Synchronous, streaming, and durable generation modes consume the same canonical request and produce the same canonical output algebra. Dedicated model operations return the corresponding member of `model-response.schema.json`. Transport-specific wrappers MUST NOT create incompatible response types, and asynchronous wrappers MUST retain the original operation response unchanged as the completed job result.

## 2. Durable execution

Long-running or disconnect-resilient generation uses the existing jobs, outbox, inbox, idempotency, and object-storage modules. Job payloads reference versioned prompt/route/schema/tool definitions. Retries preserve idempotency and budget reservations. Partial outputs are marked incomplete and never presented as completed structured results.

## 3. Browser integration

The optional `web-llm` module extends the generated web SDK with typed utilities and React integrations for response creation, streaming, cancellation, durable jobs, embeddings, reranking, transcription, speech/media generation, classification results, conversation state, structured data, tool-approval states, citations, media, and usage visibility. TanStack Query owns server state; streaming updates are reconciled into canonical query keys.

The web layer MUST render unknown output parts safely, distinguish refusal/error/cancellation, and avoid interpreting model HTML or markdown as trusted code. It MUST expose request IDs for support without exposing secrets or provider credentials.

## 4. Media handling

Large image, audio, and file inputs/outputs use object-storage references with authorization, expiration, checksum, MIME validation, quarantine/scanning hooks, and lifecycle cleanup. Inline content has strict limits. Generated media is not assumed safe merely because it came from a provider.

## 5. Observability

Telemetry follows OpenTelemetry generative-AI semantic conventions where stable and uses service-kit namespaced attributes for gaps. It records route, provider, model, operation, latency phases, usage, cost, finish state, retry/fallback, tool names, task IDs, and error classification. High-cardinality IDs are restricted to traces/logs and not metric labels.

Prompts, responses, tool arguments, files, authorization headers, and opaque reasoning state are excluded by default. Audit and usage ledgers are separate from debug logs.

## 6. Acceptance linkage

This specification is verified by `AC-AI-049` through `AC-AI-056`.
