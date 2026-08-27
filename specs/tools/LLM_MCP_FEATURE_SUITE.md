---
spec_id: OMNIUS-AI-SUITE-TOOLS
title: LLM and MCP Feature Suite Validation Tool
version: 0.1.0
status: informative
last_verified: 2026-08-24
---

# LLM and MCP Feature Suite Validation Tool

Run against the merged specification tree after extracting this archive:

```bash
python ./specs/tools/validate_llm_mcp_feature_suite.py ./specs
```

The validator parses all structured artifacts, verifies the base and extension manifests, resolves the combined module/profile/task graphs, validates examples against JSON Schema 2020-12, checks frontend exposure coverage, enforces the MCP `2026-07-28` invariants and deprecated-feature policy, and verifies recommendation and research traceability.
