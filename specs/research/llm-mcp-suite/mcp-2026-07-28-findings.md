---
spec_id: OMNIUS-AI-RESEARCH-MCP-CURRENT
title: MCP 2026-07-28 Findings
version: 0.1.0
status: research
last_verified: 2026-08-24
---

# MCP 2026-07-28 Findings

## Required architectural corrections from earlier MCP designs

The current protocol is stateless. Protocol sessions, `Mcp-Session-Id`, `initialize`, and `notifications/initialized` are not part of the preferred lifecycle. `server/discover` is mandatory. Version and client capabilities travel per request; server identity travels in results. This supports horizontal scaling and eliminates hidden per-client server state.

`subscriptions/listen` replaces the old HTTP GET event endpoint and resource subscribe/unsubscribe methods. Request progress remains on the request response stream. Broken response streams are not resumable through SSE IDs; clients re-issue with a new request ID.

All results carry `resultType`. MRTR replaces server-initiated requests with `input_required` results and retries of the original request. Tasks are an official extension with get/update/cancel and no list method.

List/read results are cacheable through TTL and public/private scope. Tools should be deterministically ordered. Schemas use JSON Schema 2020-12 and structured content may be any JSON value.

Roots, Sampling, Logging, and HTTP+SSE are deprecated for new implementations. Direct LLM provider calls replace Sampling, resource URIs/configuration replace Roots, and stderr/OpenTelemetry replace protocol logging.

## Consequences for this kit

The MCP server is a stateless adapter over the capability registry. Cross-call workflows use explicit task or MRTR handles. Auth and tenancy are evaluated on every request and catalog operation. Compatibility with older clients stays in RMCP modes and never drives core state design. See `SRC-AI-003` through `SRC-AI-016`.
