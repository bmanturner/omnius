---
spec_id: OMNIUS-043
title: MCP Versioning, Discovery, Caching, and Streamable HTTP Transport
version: 0.1.0
status: normative
last_verified: 2026-09-01
---

# MCP Versioning, Discovery, Caching, and Streamable HTTP Transport

## 1. Discovery-first lifecycle

The server MUST implement `server/discover` and advertise the exact supported protocol version, server identity, contributed core capabilities, and contributed extensions. The checked-in application accepts only revision `2026-07-28`; `initialize` is method-not-found.

Every request validates `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`. Clients identify themselves per request; server results include server identity metadata. Unsupported versions and header/body mismatches produce the specified errors without downgrade.

## 2. Deterministic and cacheable discovery

Tool, resource, template, and prompt lists are deterministically ordered. Cacheable results provide `ttlMs` and `cacheScope`; private results are never shared across principals or tenants. Catalog hashes and list-change events are derived from the same registry revision.

## 3. Authenticated Streamable HTTP

MCP uses only authenticated stateless Streamable HTTP POST handling integrated with Axum/Tower. It enforces standard `Mcp-Method` and `Mcp-Name` headers, body/header limits, content types, authority and origin policy, bearer authentication, request deadlines, bounded response streams, graceful drain, and trace propagation.

There is no trusted-local authentication bypass, `Mcp-Session-Id`, HTTP GET event endpoint, or resumable SSE event ID. If an in-flight response stream breaks, the client must issue a new request with a new JSON-RPC request ID; server idempotency is supplied by explicit operation handles or arguments.

The checked-in route is authenticated `POST /mcp` in `apps/mcp-server`. RFC 9728 metadata is served at `/.well-known/oauth-protected-resource/mcp`; `apps/api-server` has neither route.

## 4. Subscriptions

`subscriptions/listen` is an optional application-owned long-lived POST-response contract distinct from request-scoped progress/message notifications. An application that contributes it uses the JSON-RPC request ID as the subscription ID, sends `notifications/subscriptions/acknowledged` first, binds later notifications and graceful-close responses in `_meta["io.modelcontextprotocol/subscriptionId"]`, authorizes event classes, bounds queues, and tears down on cancellation or disconnect. The reference application contributes no subscription adapter, does not advertise the method, and returns method-not-found.

## 5. Transport boundary

Protocol dispatch remains isolated from HTTP framing, but authenticated Streamable HTTP is the only MCP transport. The adapter must provide fresh bearer-derived identity and policy evidence for every request.

## 6. Acceptance linkage

This specification is verified by `AC-AI-065` through `AC-AI-068` and `AC-AI-070` through `AC-AI-072`.
