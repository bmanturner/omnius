---
spec_id: OMNIUS-043
title: MCP Versioning, Discovery, Caching, and Transports
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP Versioning, Discovery, Caching, and Transports

## 1. Discovery-first lifecycle

The server MUST implement `server/discover` and advertise supported protocol versions, server identity, core capabilities, and supported extensions. The preferred lifecycle is discovery-first. The legacy initialization lifecycle MAY be accepted only through an explicit compatibility policy in the official SDK and MUST NOT be required by internal state.

Every request validates `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`. Clients SHOULD identify themselves per request; server results include server identity metadata. Unsupported versions and header/body mismatches produce the specified errors.

## 2. Deterministic and cacheable discovery

Tool, resource, template, and prompt lists are deterministically ordered. Cacheable results provide `ttlMs` and `cacheScope`; private results are never shared across principals or tenants. Catalog hashes and list-change events are derived from the same registry revision.

## 3. Streamable HTTP

Remote MCP uses stateless Streamable HTTP POST handling integrated with Axum/Tower. It enforces standard `Mcp-Method` and `Mcp-Name` headers, body/header limits, content types, origin policy, authentication, request deadlines, bounded response streams, graceful drain, and trace propagation.

There is no `Mcp-Session-Id`, HTTP GET event endpoint, or resumable SSE event ID. If an in-flight response stream breaks, the client must issue a new request with a new JSON-RPC request ID; server idempotency is supplied by explicit operation handles or arguments.

## 4. Stdio

Local transport uses stdin/stdout strictly for protocol framing and stderr for diagnostics. It honors cancellation and process shutdown, bounds message sizes, closes cleanly on EOF, and never emits logs or banners on stdout. Credentials are delivered through process environment or platform credential mechanisms rather than the HTTP OAuth flow.

## 5. Subscriptions

`subscriptions/listen` is a long-lived POST-response stream distinct from request-scoped progress/message notifications. The JSON-RPC request ID of `subscriptions/listen` is the subscription ID. The first server message carrying that ID MUST be `notifications/subscriptions/acknowledged`; every later notification and graceful-close response MUST carry the same value in `_meta["io.modelcontextprotocol/subscriptionId"]`. The server authorizes requested event classes, acknowledges only the supported subset, bounds queues, and tears subscriptions down on cancellation or disconnect.

## 6. Transport abstraction

Protocol dispatch is independent of HTTP and stdio framing. This prepares the kit for the roadmap direction of Streamable HTTP over stdio/HTTP2 without inventing a non-standard transport today.

## 7. Acceptance linkage

This specification is verified by `AC-AI-065` through `AC-AI-072`.
