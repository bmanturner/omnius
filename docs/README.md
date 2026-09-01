---
title: Omnius documentation
description: Evidence-qualified entry paths for backend, web, LLM, and MCP users.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - evaluator
  - rust-application-developer
  - application developers
  - ai-application-developer
  - mcp-developer
  - operator
topics:
  - getting-started
  - navigation
  - evidence
capabilities: []
source:
  - docs/navigation.md
  - docs/evidence-inventory.md
  - docs/coverage-matrix.md
evidence:
  - apps/server/src/main.rs
  - web/src/app.tsx
  - crates/llm-http-api/src/lib.rs
  - crates/mcp-server-core/src/kernel.rs
last_verified: 2026-08-30
---

# Omnius documentation

Start with the [overview](getting-started/overview.md) for the product boundary. Omnius includes one checked-in minimal backend process plus broader backend, web, LLM, and MCP libraries, generators, contracts, and tests. A profile or generated artifact does not by itself prove that a capability is assembled or publicly reachable; check the [availability and exposure matrix](reference/availability-and-exposure-matrix.md) before following a broader path.

## Choose a journey

| Journey | Start here | What the current path establishes | Continue with |
|---|---|---|---|
| Backend | [Minimal-service quickstart](getting-started/quickstart.md) | A runnable checked-in process with a small assembled HTTP and lifecycle surface; it does not establish the broader generated profile as assembled. | [Choose a profile](getting-started/choose-a-profile.md), [configuration and secrets](guides/backend/configuration-and-secrets.md), and [HTTP APIs](guides/backend/http-apis.md) |
| Web | [Web integration quickstart](getting-started/web-quickstart.md) | Checked-in React and SDK integration evidence, not a browser application assembled into the active backend runtime. | [Application architecture](guides/web/application-architecture.md), [generated contracts and SDK](guides/web/generated-contracts-and-sdk.md), and [browser security](security/browser-security.md) |
| LLM | [LLM integration quickstart](getting-started/llm-quickstart.md) | A deterministic library and contract evaluation path, not a mounted LLM HTTP surface. | [Model requests and responses](guides/ai/model-requests-and-responses.md), [providers and routing](guides/ai/providers-and-routing.md), and [HTTP and web integration](guides/ai/http-and-web-integration.md) |
| MCP | [MCP server library quickstart](getting-started/mcp-server-quickstart.md) | Implemented MCP library contracts and test tooling, not an MCP listener, stdio executable, or composed client. | [Server architecture](guides/mcp/server-architecture.md), [protocol support](reference/mcp-protocol-support.md), and the [MCP capability matrix](reference/mcp-capability-matrix.md) |

## Evidence and reference

- [Availability and exposure matrix](reference/availability-and-exposure-matrix.md) — compact implementation, profile, and exposure classifications.
- [Coverage matrix](coverage-matrix.md) — capability owners, evidence, verification gaps, and contradiction notes.
- [Evidence inventory](evidence-inventory.md) — source hierarchy, stable capability registry, and inspected evidence.
- [Modules, profiles, and composition](concepts/modules-profiles-and-composition.md) — canonical semantics for selection, generation, assembly, and exposure; [profiles](reference/profiles.md) and [modules and capabilities](reference/modules-and-capabilities.md) provide the exact machine-catalog selections and identifiers.
- [Glossary](glossary.md) — direct links from terms to their sole canonical concept owners.
- [Documentation navigation and ownership](navigation.md) — complete page inventory, ownership, and review ring.
