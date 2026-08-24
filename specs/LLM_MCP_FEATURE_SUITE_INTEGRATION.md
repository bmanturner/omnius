---
spec_id: RSK-AI-SUITE-INTEGRATION
title: LLM/MCP Suite Integration Instructions
version: 0.1.0
status: guide
last_verified: 2026-08-24
---

# LLM/MCP Suite Integration Instructions

## Preconditions

The target `./specs` tree contains the validated Rust Service Kit base bundle `0.1.0` and Web Application feature suite `0.1.0`. This extension intentionally uses the next numbered specification, ADR, task, and acceptance ranges and provides frontend exposure declarations for its modules.

## Apply

```bash
unzip -n rust-service-kit-llm-mcp-feature-suite-v0.1.0.zip -d ./specs
python ./specs/tools/validate_llm_mcp_feature_suite.py ./specs
```

The ZIP does not overwrite canonical machine catalogs. New catalog entries live under `machine/extensions/llm-mcp-suite/`. Consumers may read overlays directly or apply `merge-plan.yaml` deterministically with stable unique keys.

## Implementation ordering

1. Complete currently unblocked prerequisite work.
2. Run `T150` to make validators and generator overlay-aware.
3. Run `T151` to resolve the pinned Rust graph and verify protocol/provider compatibility.
4. Implement the shared capability registry before LLM tools or MCP projections.
5. Implement canonical LLM contracts before provider adapters.
6. Implement current MCP core/discovery before transports and primitive projections.
7. Add extensions only after core conformance.
8. Generate/rehearse profiles and release evidence last.

## Amendments

Do not edit or renumber existing requirements because a new suite exposes an issue. Create an amendment ADR and a narrowly scoped prerequisite task. Preserve completed work unless a verified defect requires a change.

## Compatibility

The core LLM/MCP modules do not require a browser application. The `web-llm` module and combined `ai-platform` profiles depend on the web suite. The validator requires the web extension because the user's merged spec tree already includes it and frontend exposure coverage must remain complete.

## Removal

Removing specification files is not the same as removing implemented modules. Generator removal preserves released migrations and stored prompts, conversations, usage, media, audit, tasks, and application-owned source. It produces an explicit cleanup plan.
