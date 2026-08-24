---
spec_id: RSK-AI-RESEARCH-CRATE-EVALUATION
title: Rust LLM and MCP Crate Evaluation
version: 0.1.0
status: research
last_verified: 2026-08-24
---

# Rust LLM and MCP Crate Evaluation

## Selected foundation

### Rig

Rig 0.42.0 is selected as the default LLM provider implementation because its current workspace provides a portable provider layer, broad direct-provider coverage, tools, structured output, streaming, embeddings, transcription/audio/image capabilities, provider response identifiers, unknown/raw streaming data, and GenAI telemetry integration. Recent releases include extensive provider cassette fixes and explicit preservation of provider-only response data. See `SRC-AI-030` through `SRC-AI-038`.

Rig is not the public contract. The kit owns its content algebra, route/capability registry, errors, budgets, tools, and stream events. This makes replacing or supplementing an adapter possible without rewriting application code.

### RMCP

RMCP 3.1.4 is selected because it is the official Rust MCP SDK, targets `2026-07-28`, supports discovery lifecycle, current tools/resources/prompts, cache hints, MRTR, subscriptions, Tasks, standard headers, and compatibility modes, and participates in the official conformance program. See `SRC-AI-024` through `SRC-AI-028`.

### Schemars and jsonschema

Schemars 1.2.2 and jsonschema 0.51.0 establish a Rust-native JSON Schema 2020-12 generation and validation path used by LLM structured output, tools, MCP, prompts, and machine contracts. Remote-reference fetching is disabled by default and composition/resource limits are mandatory. See `SRC-AI-055` through `SRC-AI-057`.

## Not selected as the default

- Hand-written provider clients: retained only for a proven missing capability because they recreate authentication, streaming, error mapping, usage, and provider evolution work.
- Provider SDK types as domain types: rejected because they create lock-in and output loss at cross-provider boundaries.
- Multiple generic LLM frameworks: rejected because simultaneous abstractions multiply conversions and ambiguity. A second implementation must satisfy the same provider port and compatibility suite.
- Unofficial MCP frameworks: rejected for the baseline because the official SDK tracks the authoritative schema and conformance work.
- A homegrown JSON Schema subset: rejected because both providers and MCP now require full 2020-12 semantics, including non-object roots.

## Upgrade gates

Crate popularity alone is not an upgrade signal. Rig upgrades require normalized cassette and raw-output review. RMCP upgrades require official changelog and conformance review. Schema upgrades require conformance and adversarial limits. Cloud companion crates require a resolved Cargo graph and workload-identity review.
