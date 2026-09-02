---
spec_id: OMNIUS-047
title: MCP Extensions, Apps, Skills, and Roadmap Readiness
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP Extensions, Apps, Skills, and Roadmap Readiness

## 1. Extension lifecycle

Extensions are isolated modules with stable IDs, capability declarations, version/status metadata, negotiation tests, and removal behavior. Stable, draft, and experimental extensions are not conflated. Unsupported extensions are ignored or rejected according to the specification; they never activate from untrusted metadata alone.

## 2. MCP Apps

The optional Apps module negotiates the official `io.modelcontextprotocol/ui` extension and serves `ui://` resources and tool metadata according to the MCP Apps specification. UI assets are immutable/versioned, content-security-policy constrained, permission-minimized, origin isolated, and safe for sandboxed iframe execution. PostMessage traffic is schema-validated and correlated to the owning tool/resource. Apps do not bypass ordinary tool authorization.

## 3. Skills

Skills over MCP remain an experimental Working Group extension rather than a production-stable MCP extension. The `mcp-skills` module is therefore opt-in, excluded from baseline and production-oriented profiles, and included only in the full reference profile or by explicit selection until an accepted SEP, SDK support, and conformance gates pass. Skill artifacts are versioned, signed or provenance-bearing where possible, size-limited, and treated as untrusted instructions. A skill cannot grant tools or data permissions beyond the principal and server policy.

## 4. Server metadata preview

The roadmap references `.well-known` server-card work that is not yet a settled wire contract. The preview module MAY generate internal/public metadata behind an experimental flag, but it MUST NOT claim conformance, publish an invented stable schema, or be enabled in production profiles without a new ADR tied to an accepted standard.

## 5. Progressive discovery preparation

The registry supports catalog partitions, tags, search metadata, compact entry capabilities, and deterministic hashes so future progressive discovery can be adopted. The current server still uses standardized discovery and list methods; it MUST NOT invent proprietary progressive-discovery RPCs.

## 6. Future-facing seams

The architecture deliberately isolates:

- the canonical tool result from MCP's current result representation;
- protocol dispatch from authenticated HTTP framing;
- identity evidence from the canonical principal;
- task/subscription behavior from transport;
- resources from storage/range/hierarchy implementation;
- extension declarations from core capabilities.

These seams align with roadmap work on agentic messaging, HTTP-native transport unification, agent identity, improved results, progressive discovery, and generated/conformant SDKs.

## 7. Acceptance linkage

This specification is verified by `AC-AI-097` through `AC-AI-101` and `AC-AI-103` through `AC-AI-104`.
