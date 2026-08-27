---
spec_id: OMNIUS-AI-SUITE-VALIDATOR-GUIDE
title: LLM and MCP Feature-Suite Validator Guide
version: 0.1.0
status: guide
last_verified: 2026-08-24
---

# LLM and MCP Feature-Suite Validator Guide

Run the validator against the merged specification root:

```bash
python ./specs/tools/validate_llm_mcp_feature_suite.py ./specs
```

The validator is read-only. It checks archive collisions and hashes, Markdown metadata, structured-file parsing, merged module/profile/task composition, acceptance and recommendation coverage, frontend exposure declarations, LLM schemas and examples, provider/capability references, current MCP discovery/MRTR/Tasks shapes, deprecation guards, dependency pins, research references, and unresolved placeholders.

A release rehearsal runs all three validators:

```bash
python ./specs/tools/validate_bundle.py ./specs
python ./specs/tools/validate_web_feature_suite.py ./specs
python ./specs/tools/validate_llm_mcp_feature_suite.py ./specs
```
