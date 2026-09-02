---
spec_id: OMNIUS-049
title: AI/MCP Profiles, Generator, Roadmap, and Suite Acceptance
version: 0.1.0
status: normative
last_verified: 2026-09-01
---

# AI/MCP Profiles, Generator, Roadmap, and Suite Acceptance

## 1. Profiles

The extension defines eight coherent profiles: four LLM profiles, exactly two MCP profiles (`mcp-http` and `mcp-enterprise`), and two combined AI/MCP profiles. Profiles select authenticated Streamable HTTP and compatible contracts. Safe framework-owned local infrastructure may be rendered by Compose; external endpoints, credentials, authorization policy, product handlers, and advanced provider/application requirements remain explicit and fail closed until supplied.

## 2. Generator behavior

The generator supports adding and removing LLM/MCP modules in existing projects through the checked-in manager:

```text
cargo xtask service add MODULE [--project PATH]
cargo xtask service remove MODULE [--project PATH]
cargo xtask service upgrade --to VERSION [--project PATH]
cargo xtask service doctor [--project PATH]
cargo xtask service diff [--project PATH]
```

Operations are idempotent, use managed regions, preserve released migrations and application-owned source, and regenerate owned configuration/Compose artifacts. Removing a provider does not delete conversations, audit, usage, media, task, or prompt data automatically. MCP conformance and LLM evaluation remain separate explicit tools; the service manager does not claim commands it does not expose.

## 3. Append-only adoption

This archive has no enclosing directory and is intended for direct extraction into `./specs`. It MUST introduce no path collisions with the validated base and web bundles. Existing IDs are unchanged. New tasks begin at `T150`, new ADRs at `0015`, and new numbered specifications at `35`.

Current unblocked implementation work continues. The autonomous agent begins a new task only after its declared prerequisites are satisfied. No existing task is restarted solely because this suite was added.

## 4. Upgrade and protocol watch

The suite pins the current MCP revision and crate baseline but treats protocol evolution as expected. A scheduled review compares the official changelog, roadmap, extension status, Rust SDK conformance, provider SDK releases, JSON Schema libraries, and OpenTelemetry GenAI conventions. Changes are adopted through ADR amendments and compatibility fixtures.

Preview modules never become default merely because a roadmap item exists. Conversely, settled standard behavior should replace preview scaffolding rather than coexist indefinitely.

## 5. Release evidence

A release includes resolved Cargo graph, advisory/license report, profile builds, contract schemas/examples, provider cassette report, MCP conformance report, security matrix, load/failure evidence, eval report, operational runbooks, recommendation traceability, manifest hashes, and extraction rehearsal.

## 6. Suite-wide definition of done

All 118 acceptance criteria are independently verifiable and mapped to implementation tasks. Every recommendation has an acceptance criterion. Every module has an explicit frontend exposure declaration and appears in at least one profile. The base and web bundle validators and this extension validator all pass on the merged tree.

## 7. Acceptance linkage

This specification is verified by `AC-AI-113` through `AC-AI-120`.
