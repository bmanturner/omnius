---
spec_id: OMNIUS-AI-SUITE-README
title: LLM and MCP Feature Suite
version: 0.1.0
status: guide
last_verified: 2026-09-01
---

# LLM and MCP Feature Suite

## Purpose

This append-only extension adds a provider-neutral external LLM runtime and a current MCP server to Omnius. It is designed for direct extraction into an existing `./specs` tree that already contains base bundle `0.1.0` and Web Application suite `0.1.0`.

## Baselines

- MCP protocol: `2026-07-28`, discovery-first and stateless over authenticated Streamable HTTP only.
- MCP Rust SDK: official RMCP `3.1.4`.
- LLM provider implementation: Rig `0.42.0` behind service-kit-owned contracts.
- Structured data: JSON Schema Draft 2020-12 with Schemars `1.2.2` and jsonschema `0.51.0`.
- Deprecated MCP Roots, Sampling, Logging, HTTP+SSE, sessions, and initialization are excluded from new profiles.

## Included

- 15 numbered specifications (`35`–`49`).
- 10 ADRs (`0015`–`0024`).
- 37 opt-in modules and 8 coherent profiles.
- 118 acceptance criteria and 29 dependency-ordered tasks (`T150`–`T179`).
- Complete generation output modeling for text, structured JSON, tools, citations, annotations, refusals/safety, image, audio, video, files/resources, provider execution steps, safe reasoning representations, alternative candidates, usage, and unknown provider items.
- Dedicated normalized response contracts for embeddings, reranking, transcription, speech synthesis, media generation, and classification/moderation.
- A checked-in dedicated `apps/mcp-server` reference process with exact `/mcp` resource OAuth, one read-only `reference_records.list.v1` tool, and method-not-found for unassembled primitives; broader resource, prompt, MRTR, Task, subscription, Apps, Skills, and enterprise contracts remain application-owned.
- Provider, capability, extension, exposure, compatibility, schema, example, risk, research, and traceability catalogs.

The extension catalogs contain 37 modules and 8 profiles. Across base, web, and AI/MCP catalogs there are 23 bundled profiles; the MCP profiles are exactly `mcp-http` and `mcp-enterprise`.

## Extraction

```bash
unzip -n omnius-llm-mcp-feature-suite-v0.1.0.zip -d ./specs
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
