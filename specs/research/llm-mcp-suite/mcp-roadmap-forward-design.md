---
spec_id: OMNIUS-AI-RESEARCH-MCP-ROADMAP
title: MCP Roadmap-Forward Design
version: 0.1.0
status: research
last_verified: 2026-08-24
---

# MCP Roadmap-Forward Design

## Settling direction

The August 22, 2026 roadmap prioritizes agentic messaging primitives, HTTP-native transport unification, agent identity and enterprise security, improved tool/result and discovery primitives, and SDK conformance/developer experience. See `SRC-AI-001` and `SRC-AI-002`.

## Prepared seams

- Tasks, subscriptions, progress, and MRTR use independent ports so future server-initiated events or channels can compose without changing domain services.
- Protocol dispatch is independent of framing while authenticated Streamable HTTP remains the only selected transport.
- Identity evidence is separate from the canonical Principal so workload identity, DPoP, ID-JAG, and token exchange can evolve.
- Tool execution produces one canonical result before MCP rendering so a future tools/call result contract can replace the adapter.
- The capability registry supports partitions, tags, compact metadata, deterministic hashes, and authorization-filtered views for progressive discovery.
- Resources are abstracted from storage and anticipate ranges, hierarchy, checksums, and object references.
- Extensions are isolated and status-tagged so experimental work cannot silently become core.

## Deliberate restraint

The suite does not invent a server-card schema, progressive-discovery RPC, agent-identity token, or future tool-result wire object. Preview modules prepare internal data and tests only. Accepted standards replace previews through an ADR and compatibility transition.
