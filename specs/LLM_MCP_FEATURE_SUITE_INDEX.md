---
spec_id: RSK-AI-SUITE-INDEX
title: LLM and MCP Feature Suite Index
version: 0.1.0
status: guide
last_verified: 2026-08-24
---

# LLM and MCP Feature Suite Index

## Numbered specifications

- `35-llm-mcp-feature-suite-architecture.md` — `RSK-035` — LLM and MCP Feature-Suite Architecture
- `36-llm-domain-contracts-and-content-model.md` — `RSK-036` — LLM Domain Contracts and Complete Content Model
- `37-llm-provider-adapters-and-capability-registry.md` — `RSK-037` — LLM Provider Adapters and Model Capability Registry
- `38-llm-structured-output-tools-and-streaming.md` — `RSK-038` — Structured Output, Tool Execution, and Streaming
- `39-llm-routing-reliability-cost-and-quotas.md` — `RSK-039` — LLM Routing, Reliability, Cost, and Quotas
- `40-llm-prompts-context-caching-and-data-governance.md` — `RSK-040` — Prompts, Context, Caching, and Data Governance
- `41-llm-http-jobs-web-and-observability.md` — `RSK-041` — LLM HTTP, Jobs, Web SDK, and Observability
- `42-mcp-server-architecture-and-capability-exposure.md` — `RSK-042` — MCP Server Architecture and Capability Exposure
- `43-mcp-versioning-discovery-caching-and-transports.md` — `RSK-043` — MCP Versioning, Discovery, Caching, and Transports
- `44-mcp-tools-resources-prompts-and-results.md` — `RSK-044` — MCP Tools, Resources, Prompts, and Result Contracts
- `45-mcp-authentication-authorization-tenancy-and-security.md` — `RSK-045` — MCP Authentication, Authorization, Tenancy, and Security
- `46-mcp-mrtr-elicitation-tasks-subscriptions-and-progress.md` — `RSK-046` — MCP MRTR, Elicitation, Tasks, Subscriptions, and Progress
- `47-mcp-extensions-apps-skills-and-roadmap-readiness.md` — `RSK-047` — MCP Extensions, Apps, Skills, and Roadmap Readiness
- `48-ai-mcp-testing-conformance-evals-and-operations.md` — `RSK-048` — AI and MCP Testing, Conformance, Evaluations, and Operations
- `49-ai-mcp-profiles-generator-roadmap-and-acceptance.md` — `RSK-049` — AI/MCP Profiles, Generator, Roadmap, and Suite Acceptance

## Architecture decisions

- `adr/0015-rig-default-llm-provider-abstraction.md` — `RSK-ADR-0015` — Use Rig as the Default LLM Provider Abstraction
- `adr/0016-service-kit-owned-extensible-llm-contracts.md` — `RSK-ADR-0016` — Own an Extensible Lossless LLM Content Contract
- `adr/0017-json-schema-2020-12-structured-output-boundary.md` — `RSK-ADR-0017` — Use JSON Schema 2020-12 as the Structured Output Boundary
- `adr/0018-explicit-model-capabilities-and-no-silent-downgrade.md` — `RSK-ADR-0018` — Require Explicit Model Capabilities and Forbid Silent Downgrades
- `adr/0019-official-rmcp-and-mcp-2026-07-28-baseline.md` — `RSK-ADR-0019` — Use Official RMCP and MCP 2026-07-28 as the Baseline
- `adr/0020-stateless-streamable-http-and-stdio.md` — `RSK-ADR-0020` — Make MCP Stateless over Streamable HTTP and Stdio
- `adr/0021-shared-agent-capability-registry.md` — `RSK-ADR-0021` — Use One Agent Capability Registry Across HTTP, Jobs, LLM Tools, and MCP
- `adr/0022-mcp-identity-maps-to-canonical-principal.md` — `RSK-ADR-0022` — Map MCP Identity to the Canonical Principal and Authorization System
- `adr/0023-mcp-tasks-jobs-and-subscriptions-events.md` — `RSK-ADR-0023` — Map MCP Tasks to Jobs and Subscriptions to Event Providers
- `adr/0024-mcp-extension-isolation-and-roadmap-seams.md` — `RSK-ADR-0024` — Isolate Extensions and Preserve Roadmap-Facing Seams

## Machine catalogs

- `machine/extensions/llm-mcp-suite/module-catalog.yaml`
- `machine/extensions/llm-mcp-suite/profiles.yaml`
- `machine/extensions/llm-mcp-suite/acceptance-criteria.yaml`
- `machine/extensions/llm-mcp-suite/tasks.yaml`
- `machine/extensions/llm-mcp-suite/provider-catalog.yaml`
- `machine/extensions/llm-mcp-suite/llm-capabilities.yaml`
- `machine/extensions/llm-mcp-suite/mcp-exposure-catalog.yaml`
- `machine/extensions/llm-mcp-suite/mcp-extension-registry.yaml`
- `machine/extensions/llm-mcp-suite/protocol-compatibility.yaml`
- `machine/extensions/llm-mcp-suite/risk-register.yaml`
- `machine/extensions/llm-mcp-suite/recommendation-traceability.csv`

## Validation and research

- `tools/validate_llm_mcp_feature_suite.py`
- `research/llm-mcp-suite/`
