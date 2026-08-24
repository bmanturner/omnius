---
spec_id: RSK-AI-SUITE-README
title: LLM and MCP Feature Suite
version: 0.1.0
status: guide
last_verified: 2026-08-24
---

# LLM and MCP Feature Suite

## Purpose

This append-only extension adds a provider-neutral external LLM runtime and a current MCP server to the Rust Service Kit. It is designed for direct extraction into an existing `./specs` tree that already contains base bundle `0.1.0` and Web Application suite `0.1.0`.

## Baselines

- MCP protocol: `2026-07-28`, discovery-first and stateless.
- MCP Rust SDK: official RMCP `3.1.4`.
- LLM provider implementation: Rig `0.42.0` behind service-kit-owned contracts.
- Structured data: JSON Schema Draft 2020-12 with Schemars `1.2.2` and jsonschema `0.51.0`.
- Deprecated MCP Roots, Sampling, Logging, HTTP+SSE, sessions, and initialization are excluded from new profiles.

## Included

- 15 numbered specifications (`35`–`49`).
- 10 ADRs (`0015`–`0024`).
- 38 opt-in modules and 9 coherent profiles.
- 120 acceptance criteria and 30 dependency-ordered tasks (`T150`–`T179`).
- Complete generation output modeling for text, structured JSON, tools, citations, annotations, refusals/safety, image, audio, video, files/resources, provider execution steps, safe reasoning representations, alternative candidates, usage, and unknown provider items.
- Dedicated normalized response contracts for embeddings, reranking, transcription, speech synthesis, media generation, and classification/moderation.
- MCP tools, resources, prompts, current discovery/transports/auth, MRTR/elicitation, Tasks, subscriptions, Apps, experimental Skills, conformance, and roadmap-facing seams.
- Provider, capability, extension, exposure, compatibility, schema, example, risk, research, and traceability catalogs.

## Extraction

```bash
unzip -n rust-service-kit-llm-mcp-feature-suite-v0.1.0.zip -d ./specs
python ./specs/tools/validate_llm_mcp_feature_suite.py ./specs
```

The archive has no enclosing directory. `-n` prevents accidental overwrite in addition to the suite's collision validation.

## First implementation milestone

Begin with `T150` and `T151`: merge/validate catalogs and establish the shared agent capability registry. LLM and MCP adapters are not allowed to bypass this registry. Existing unblocked base/web tasks continue according to their current dependencies.

## Key entry points

- `LLM_MCP_FEATURE_SUITE_AGENT_HANDOFF.md`
- `LLM_MCP_FEATURE_SUITE_INTEGRATION.md`
- `LLM_MCP_FEATURE_SUITE_INDEX.md`
- `LLM_MCP_FEATURE_SUITE_COMPLETE_SPEC.md`
- `machine/extensions/llm-mcp-suite/spec-extension-manifest.json`
- `machine/extensions/llm-mcp-suite/merge-plan.yaml`
