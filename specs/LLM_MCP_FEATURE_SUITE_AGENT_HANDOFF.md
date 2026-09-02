---
spec_id: OMNIUS-AI-SUITE-AGENT-HANDOFF
title: "Autonomous Agent Handoff: LLM and MCP Suite"
version: 0.1.0
status: guide
last_verified: 2026-09-01
---

# Autonomous Agent Handoff: LLM and MCP Suite

## Mission

Implement the append-only LLM and MCP suite without destabilizing work already completed from the base and web bundles. Treat the numbered specifications and accepted ADRs as normative; machine catalogs are execution inputs and validation evidence.

## Non-negotiable constraints

1. Business capabilities are defined once in `agent-capability-registry` and projected into HTTP, jobs, LLM tools, MCP, and browser adapters.
2. Service-kit-owned types form the public boundary. Rig and RMCP types remain inside adapter crates.
3. LLM responses are not strings: preserve every normalized output kind, specialized model-operation result, and unknown future provider part.
4. Structured output is JSON Schema 2020-12 and locally validated.
5. Model features and fallbacks are explicit; no silent downgrade.
6. Tool calls are untrusted and pass validation, authorization, tenancy, confirmation, idempotency, deadline, budget, and audit controls.
7. MCP uses only `2026-07-28`, `server/discover`, authenticated stateless Streamable HTTP `POST /mcp`, per-request negotiation, and explicit extension isolation.
8. Do not implement deprecated MCP Roots, Sampling, Logging, HTTP+SSE, sessions, initialization, SSE request resumption, or an unauthenticated local path.
9. Do not implement roadmap proposals as proprietary stable RPCs.
10. Treat Skills over MCP as experimental and exclude it from production-oriented profiles until an accepted SEP, SDK support, and conformance gates pass.
11. Prompts, responses, tool arguments, media, credentials, and reasoning state are absent from default telemetry.
12. Preserve the checked-in reference boundary: `apps/mcp-server` serves exact RFC 9728 metadata and only `reference_records.list.v1`; `apps/api-server` serves authorization-server/API routes and no MCP route.
13. Treat external services, credentials, product policy/handlers, enterprise authorization, and advanced primitives as application-owned typed requirements that fail closed; never report them as runnable profile defaults.

## Work selection

Select only a task whose dependencies are complete. Do not restart an existing task because this suite was added. When an existing implementation lacks a required seam, create the smallest amendment and prerequisite task that satisfies the new acceptance criteria.

## Verification loop

For each task:

- identify every acceptance criterion it owns;
- implement source, configuration, lifecycle, health, telemetry, tests, docs, and generator wiring;
- run the resolved profile build and focused tests;
- update machine evidence without changing stable IDs;
- preserve raw provider/MCP compatibility fixtures needed to prove behavior;
- run all three validators on the merged tree.

## Required release gates

Cargo graph and advisory review, provider cassettes, schema/property/fuzz tests, MCP official conformance, Inspector smoke tests, authorization matrix, load/failure tests, eval report, profile matrix, extraction rehearsal, traceability, and manifest hashes must pass.
