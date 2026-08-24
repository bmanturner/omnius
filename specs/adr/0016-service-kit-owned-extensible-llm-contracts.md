---
spec_id: RSK-ADR-0016
title: Own an Extensible Lossless LLM Content Contract
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Own an Extensible Lossless LLM Content Contract

## Context

Provider APIs return more than strings and evolve faster than any one abstraction. Existing libraries commonly model a useful subset but may omit citations, refusals, files, audio, provider-only items, or future modalities.

## Decision

Define non-exhaustive, versioned service-kit request, response, output-part, stream-event, usage, and metadata contracts. Include an `unknown` provider part and policy-controlled raw terminal payload.

## Consequences

Callers can consume stable semantics and future provider output is detected rather than silently dropped. Adapter work is required for every provider change.

## Rejected alternatives

- Return only plaintext.
- Expose provider JSON directly.
- Use an untyped `serde_json::Value` for the entire response.
