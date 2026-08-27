---
spec_id: OMNIUS-AI-RESEARCH-PROVIDER-OUTPUTS
title: External LLM Provider Output Findings
version: 0.1.0
status: research
last_verified: 2026-08-24
---

# External LLM Provider Output Findings

## Common output families

First-party provider APIs now expose typed items beyond plaintext: structured JSON, function/tool calls, refusals and safety decisions, citations/grounding and token annotations, provider-executed search/code/computer/file/MCP steps, images, audio, video, files/resources, reasoning summaries or signed/encrypted continuation state, multiple candidates, usage/cache counters, request/response IDs, and provider-specific events. Streaming APIs split these into start/delta/complete events with provider-specific chunking.

No single provider-neutral library type should be assumed to cover every future item. The kit therefore uses a versioned ordered content algebra plus `unknown` and policy-controlled raw metadata. See `SRC-AI-039` through `SRC-AI-054`.

Dedicated provider operations also return shapes that should not be flattened into chat messages: dense/sparse/binary or multi-vector embeddings; ranked document identities and relevance scores; transcripts with language, segments, words, speakers and timing; generated speech with timing marks or visemes; multiple generated media assets with revised prompts, seeds, provenance and safety outcomes; and moderation/classification label-score sets. The suite therefore defines an explicit model-response union in addition to the heterogeneous generation content algebra.

## Structured output

Provider-native strict output materially improves adherence but does not remove the need for local validation, schema limits, explicit refusal/error handling, or compatibility checks. Citation and strict structured-output features may conflict on some providers, reinforcing the need for route capabilities rather than feature assumptions.

## Reasoning state

Some providers return safe summaries; some require signed or encrypted blocks to continue a tool conversation. These are not treated as hidden chain-of-thought suitable for display or logging. The kit preserves only provider-sanctioned summaries or opaque continuation state under separate policy.

## Streaming

Chunk boundaries are not semantic boundaries. Tool arguments and JSON can be partial; usage may arrive only at the end; a stream can fail after visible output. The canonical event model records sequence, part identity, partial status, terminal state, and cancellation while refusing to label incomplete values as complete.
