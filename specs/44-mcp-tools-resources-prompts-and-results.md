---
spec_id: OMNIUS-044
title: MCP Tools, Resources, Prompts, and Result Contracts
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP Tools, Resources, Prompts, and Result Contracts

## 1. Tools

MCP tool schemas use JSON Schema Draft 2020-12 and may describe any JSON type. Tool names are stable public identifiers and results are deterministic with respect to an explicit capability revision. Input is validated before authorization-sensitive execution; authorization is checked again against the resolved resource and tenant.

A canonical tool result is produced internally and then adapted to the current MCP representation. This seam is mandatory because the roadmap identifies tool-result ambiguity as a target for redesign. A tool MUST NOT independently emit conflicting textual and structured versions of the same output without an explicit compatibility policy.

`structuredContent` may contain any JSON value. Ordered content blocks may include text, image, audio, and embedded resources. Tool-level failures are distinguished from protocol routing/validation failures.

## 2. Resources

Resources expose authorized context through stable URIs and resource templates. Reads support text or binary content, MIME type, provenance, cache metadata, and bounds. URI parsing and resolution are centralized; path traversal, scheme confusion, SSRF, cross-tenant access, and oversized content are rejected.

The internal resource port anticipates byte ranges, hierarchical listing, checksums, and object-storage references, but the server exposes only standardized behavior available in the negotiated protocol revision.

## 3. Prompts

MCP prompts are projections of published prompt-catalog revisions. Arguments are typed, validated, authorized, and size-limited. Prompt lists and prompt results are deterministic and cacheable. Untrusted user data is kept separate from privileged instructions in returned messages.

## 4. Naming and versioning

Public names use a stable namespace and are never generated from Rust function paths. Breaking schema or semantic changes require a new version/name or a documented compatibility window. Descriptions and annotations are treated as public API and reviewed for accuracy and safety.

## 5. Results and MRTR

All current-protocol results include `resultType`. Ordinary results are `complete`; additional-input flows use `input_required`. Earlier-protocol results that omit the discriminator are accepted only within compatibility behavior and interpreted as complete as required by the protocol.

## 6. Acceptance linkage

This specification is verified by `AC-AI-073` through `AC-AI-080`.
