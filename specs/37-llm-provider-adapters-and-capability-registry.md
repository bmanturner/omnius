---
spec_id: RSK-037
title: LLM Provider Adapters and Model Capability Registry
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# LLM Provider Adapters and Model Capability Registry

## 1. Default provider framework

The default provider abstraction is Rig, pinned and audited as specified in the extension dependency baseline. Rig is an implementation detail behind `LlmProvider`, `EmbeddingProvider`, and media-provider ports. Service-kit callers MUST NOT import Rig response, message, agent, or streaming types outside adapter crates.

The initial built-in provider family includes Rig-supported direct APIs and OpenAI-compatible endpoints. AWS Bedrock and Google Vertex AI are optional companion adapters because their credentials, endpoints, model catalogs, and dependency graphs differ materially.

## 2. Provider contract

Every provider adapter MUST implement:

- request conversion and unsupported-feature detection;
- non-streaming and streaming execution where supported;
- normalized identities, stop reasons, usage, warnings, and content parts;
- typed provider, transport, timeout, throttling, safety, and schema errors;
- explicit retry classification and retry-after extraction;
- capability discovery or configured capability declarations;
- redacted diagnostics and health evidence;
- deterministic cassette fixtures from representative provider responses.

Adapters MUST retain policy-approved raw terminal responses and unmodeled stream items so new provider behavior is detectable rather than discarded.

Completion, embeddings, reranking, transcription, speech generation, image/media generation, and classification/moderation adapters MAY share provider clients, transport policy, and telemetry, but each operation MUST implement its operation-specific request/response port and compatibility fixtures. A generic completion method MUST NOT be used as a lossy substitute for a provider's dedicated operation API.

## 3. Capability registry

Capabilities are associated with provider/model revisions, not inferred from marketing names. The registry distinguishes at least:

- text, image, audio, video, file, and resource input;
- text, structured, image, audio, video, file, resource, annotation, and execution-step output;
- strict JSON Schema support;
- tools and parallel tool calls;
- streaming and resumable provider conversations;
- citations, grounding annotations, token scores/log probabilities, safety metadata, search results, and provider-executed steps;
- reasoning summaries or opaque state;
- embeddings, reranking, transcription, speech, image generation, and video generation;
- prompt caching and cache controls;
- context/output limits and regional availability.

A route MUST state required and preferred capabilities. Selection MUST fail with an actionable error when requirements cannot be satisfied.

## 4. No silent downgrade

The system MUST NOT silently replace strict structured output with prompt-only JSON, drop media, remove citations, disable tools, weaken data residency, or route to a different provider. Any allowed fallback is an explicit route policy with compatibility tests and observable reason codes.

## 5. Credentials and endpoints

Provider secrets use the existing secret-wrapper and configuration system. Endpoint overrides are allowlisted and pass the outbound HTTP/SSRF policy. Tenant-supplied credentials require separate encryption, access control, rotation, audit, and deletion policies; they are not enabled merely by accepting arbitrary configuration strings.

## 6. Upgrade policy

Provider SDK upgrades are treated as contract work. CI MUST diff normalized cassettes, feature support, dependency advisories, raw response handling, and request conversion. Model IDs are runtime configuration or provider discovery data, not hard-coded global enums.

## 7. Acceptance linkage

This specification is verified by `AC-AI-017` through `AC-AI-024`.
