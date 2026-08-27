---
spec_id: OMNIUS-035
title: LLM and MCP Feature-Suite Architecture
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# LLM and MCP Feature-Suite Architecture

## 1. Purpose

This specification adds external large-language-model execution and a standards-conformant MCP server to Omnius as append-only capabilities. The suite MUST compose with the existing runtime, HTTP, identity, authorization, tenancy, audit, jobs, events, storage, observability, web SDK, generator, and testing contracts. It MUST NOT create a parallel application architecture.

## 2. Architectural boundary

The suite introduces a framework-owned `agent-capability-registry`. A capability is an application operation or read model with stable identity, schemas, authorization metadata, side-effect classification, idempotency requirements, tenancy rules, and adapters. The same capability MAY be exposed through:

- ordinary Rust application services;
- HTTP endpoints;
- durable jobs;
- LLM tool execution;
- MCP tools, resources, or prompts;
- browser SDK utilities.

Business logic MUST remain behind the registry adapter. MCP handlers and LLM-provider handlers MUST NOT directly query product tables or reproduce authorization rules.

## 3. Composition model

The suite is source-composed through workspace crates and generated module manifests. Runtime toggles MAY disable already-compiled providers or exposures, but runtime toggles MUST NOT be used as a substitute for compile-time module selection. Every module participates in typed configuration, startup, health, telemetry, shutdown, testing, documentation, and removal behavior.

Provider SDK types, MCP SDK types, and provider wire objects MUST terminate at adapter boundaries. Public application contracts use service-kit-owned, versioned types.

## 4. Trust boundaries

The following inputs are untrusted:

- prompts, documents, images, audio, and files supplied by users;
- model output, including tool arguments and structured output;
- MCP client metadata, capabilities, tool parameters, and extension declarations;
- tool descriptions or annotations received from outside the service;
- provider error bodies and provider-specific metadata;
- resource URIs, webhook-like URLs, and remote references.

Every operation MUST retain the canonical request context: request ID, trace context, principal, tenant, authorization decision, data-classification policy, budget, deadline, and cancellation token.

## 5. Standards baseline

MCP implementation targets protocol revision `2026-07-28` and uses the official Rust SDK. New profiles MUST be stateless, discovery-first, and extension-aware. They MUST NOT adopt deprecated Roots, Sampling, Logging, HTTP+SSE, protocol sessions, or initialization semantics. Direct LLM provider APIs replace deprecated MCP Sampling.

Compatibility with older clients MAY be enabled through the official SDK's explicit compatibility modes, but compatibility MUST be tested, observable, and disabled from shaping the new internal architecture.

## 6. LLM output completeness

The LLM boundary MUST represent ordered plaintext, structured JSON, tool calls, tool results, citations, annotations, refusals and safety outcomes, images, audio, video, files, provider resources, provider-executed steps, safe reasoning summaries or opaque reasoning state, alternative candidates, token/log-probability metadata, usage, finish information, provider identifiers, and unknown future content without silent loss. Raw provider payload retention is policy-controlled and never the only source of normalized behavior.

## 7. Explicit non-goals

The suite does not define a general autonomous-agent product, a vector database, a RAG opinion, a model marketplace, a hidden-chain-of-thought store, an MCP client, or a replacement identity provider. Those require separate suites or product decisions.

## 8. Implementation invariant

Adding this suite MUST NOT restart completed base or web work. New tasks depend on existing prerequisites. A deficiency in an accepted subsystem requires a narrowly scoped amendment ADR and task; it does not authorize silent redesign.

## 9. Acceptance linkage

This specification is verified by `AC-AI-001` through `AC-AI-008`.
