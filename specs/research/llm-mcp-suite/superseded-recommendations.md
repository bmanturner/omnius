---
spec_id: OMNIUS-AI-RESEARCH-SUPERSEDED
title: Superseded LLM and MCP Recommendations
version: 0.1.0
status: research
last_verified: 2026-08-24
---

# Superseded LLM and MCP Recommendations

The following recommendations are intentionally rejected for new profiles:

- Build MCP around `initialize`, protocol sessions, or `Mcp-Session-Id`.
- Expose a GET SSE endpoint or implement Last-Event-ID request resumption.
- Add MCP Sampling as the service's LLM gateway.
- Add Roots or protocol Logging to a new server.
- Prefer Dynamic Client Registration over Client ID Metadata Documents.
- Store client credentials without issuer binding.
- Build a custom task queue or subscription system inside MCP.
- Return only text from an LLM or flatten all output to a string.
- Treat structured output as object-only or trust provider validation without local validation.
- Expose provider or Rig types as application contracts.
- Infer model capabilities from names and silently drop unsupported features.
- Log prompts and responses by default.
- Execute model-selected tools before application authorization and confirmation.
- Implement roadmap proposals as proprietary stable RPCs.

Each replacement is specified in `OMNIUS-035` through `OMNIUS-049` and traced in the acceptance catalog.
