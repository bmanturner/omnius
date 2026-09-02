---
spec_id: OMNIUS-042
title: MCP Server Architecture and Capability Exposure
version: 0.1.0
status: normative
last_verified: 2026-09-01
---

# MCP Server Architecture and Capability Exposure

## 1. Protocol adapter

The MCP server is a transport and protocol adapter over the shared agent-capability registry. It MUST NOT become a second domain/service layer. MCP tools, resources, and prompts are explicit projections of registered capabilities and retain their schemas, side-effect classification, authorization, tenant scope, idempotency, audit, and lifecycle behavior.

## 2. Current baseline

The baseline is MCP revision `2026-07-28` implemented with the official Rust SDK (`rmcp`). Requests are stateless and self-contained. Capability/version metadata and identity are evaluated per request. The server implements mandatory discovery and supports optional extensions only after explicit negotiation.

The checked-in reference composition is the dedicated `apps/mcp-server` process. It mounts authenticated `POST /mcp` and `GET /.well-known/oauth-protected-resource/mcp`, contributes only `reference_records.list.v1`, and returns method-not-found for resources, prompts, elicitation, subscriptions, tasks, Apps, Skills, completion, and progress. `apps/api-server` owns authorization-server and ordinary API routes and MUST NOT mount either MCP route.

## 3. Exposure declarations

Every MCP-facing capability has a machine-readable declaration containing:

- stable MCP name and kind;
- internal capability ID and version;
- description and annotations;
- input/output or resource schemas;
- required permissions, tenant modes, and principal types;
- side-effect and confirmation policy;
- cache scope/TTL and list-change behavior;
- transport availability;
- required MCP/client extensions;
- deprecation and compatibility state.

Capabilities are deny-by-default. Merely compiling or selecting a module MUST NOT expose it over MCP. Optional profile requirements are application-owned typed contracts, not runnable defaults or generic router/task contributions.

## 4. Request context

Each request constructs a canonical principal and request context from the transport/auth layer. The MCP client identity, workload identity, user delegation, tenant, scopes, protocol version, client capabilities, extension set, request ID, trace context, deadline, and log-level request are retained. Client-supplied metadata is untrusted until validated.

## 5. Deprecated features

New profiles MUST NOT implement deprecated MCP Roots, Sampling, Logging, or HTTP+SSE. The LLM suite calls providers directly rather than through Sampling. Files and directories are passed as tool parameters, resource URIs, or typed server configuration. Services emit diagnostics through structured telemetry rather than protocol responses.

## 6. Error boundary

Application errors are mapped deliberately to protocol errors, tool-level errors, structured results, or input-required results. Internal error details and authorization distinctions are not leaked. Unknown MCP methods and unsupported versions follow specification error codes.

## 7. Acceptance linkage

This specification is verified by `AC-AI-057` through `AC-AI-064`.
