---
title: MCP discovery, versioning, and transports
description: Discovery filtering, revision negotiation, Streamable HTTP policy, stdio framing, and the unassembled transport boundary.
status: experimental
implementation: implemented
profile_availability:
  - mcp-local
  - mcp-http
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
public_exposure: unassembled
audience:
  - mcp-developer
  - operator
  - security-privacy-reviewer
topics:
  - mcp
  - discovery
  - versioning
  - http
  - stdio
capabilities:
  - mcp-discovery-versioning
  - mcp-transport-http
  - mcp-transport-stdio
source:
  - crates/mcp-server-core/src/discovery.rs
  - crates/mcp-server-core/src/sdk.rs
  - crates/mcp-server-core/src/versioning.rs
  - crates/mcp-transport-http/src/lib.rs
  - crates/mcp-transport-stdio/src/lib.rs
  - specs/43-mcp-versioning-discovery-caching-and-transports.md
evidence:
  - crates/mcp-server-core/tests/discovery_contracts.rs
  - crates/mcp-server-core/tests/protocol_contracts.rs
  - crates/mcp-transport-http/tests/http_transport.rs
  - crates/mcp-transport-stdio/tests/stdio_contract.rs
  - apps/api-server/tests/api_service.rs
last_verified: 2026-08-30
---

# MCP discovery, versioning, and transports

> **Assembly status:** Discovery, Streamable HTTP, and stdio are implemented libraries. `StatelessHandlerAdapter` is a first-party RMCP `ServerHandler` facade that serves `server/discover` and empty primitive list methods. No first-party application hosts that adapter, connects it to populated primitive projections, mounts `/mcp`, or starts an MCP stdio executable. The selected profiles identify library availability only.

Omnius MCP uses the fixed protocol revision `2026-07-28`. The kernel is stateless: neither transport establishes retained initialization, client, or session state. Start with [server architecture](server-architecture.md) for the registry projection and see the [MCP capability matrix](../../reference/mcp-capability-matrix.md) for profile-specific availability.

## Discovery and revision boundaries

`McpExposureFilter::authorized` is the library's deterministic borrowed projection over the canonical capability registry. When an embedder explicitly composes and invokes it, the projection filters for availability, exposure, tenant compatibility, canonical authorization, and capability-specific authorization.

That filter is not integrated into `StatelessHandlerAdapter::discover`. The adapter resolves request context and returns static `ServerInfo`; `get_info` serializes every configured extension without invoking `McpExposureFilter`. An application must therefore treat configured extension metadata as already approved for disclosure and deliberately connect authorized tool, resource, and prompt projections. Bare `server/discover` does not prove registry filtering.

A caller and server must agree on revision `2026-07-28`; the transport does not silently downgrade. The kernel retains no initialization exchange or negotiated client state. A stdio legacy adapter can translate `initialize` to `server/discover` and relocate metadata, but it does not enable an older protocol revision or create a session.

Safe discovery planning therefore requires:

- deliberate composition of `McpExposureFilter` for registry projections rather than assuming `server/discover` applies it;
- a fresh authenticated and tenant-bound context for every request;
- deterministic filtering before primitive metadata leaves the server;
- bounded, disclosure-approved extension metadata;
- invocation-time reauthorization after discovery;
- no inference that a discovery schema or profile selection proves a live endpoint.

## Streamable HTTP library

`McpHttpServer` implements one stateless, one-shot Streamable HTTP request path:

| Policy | Implemented behavior |
|---|---|
| Path and method | `/mcp`, `POST` only, when an application deliberately mounts the handler |
| Media negotiation | JSON request content; response negotiation accepts JSON and event-stream representations |
| Versioning | Exact supported revision and method metadata are required; no downgrade |
| Sessions and replay | Session and replay headers are rejected; there is no retained session, GET event stream, replay, or SSE resume |
| Request admission | Host, origin, content/header/body size, and framing checks occur before dispatch |
| Bounds | Defaults include 2 MiB JSON and response-frame limits |
| Drain | New work is rejected while draining; remaining work has a default 10-second drain window and can be force-cancelled |

The default authority policy is localhost-only. A production composition must explicitly define trusted authorities and origins; it must not reflect arbitrary browser origins. Transport acceptance does not replace bearer authentication, tenant resolution, registry authorization, schema validation, or confirmation.

The reference API does not mount this handler and its focused tests require `/mcp` to be absent. No MCP-specific health route, telemetry sink, authentication adapter, or secret configuration is proven by the transport library.

## Stdio library

The stdio transport uses newline-delimited JSON-RPC. Protocol frames go to stdout; diagnostics must use the separate diagnostic channel, normally stderr, so logging cannot corrupt framing.

Its default operating bounds are:

- 1 MiB per input frame;
- at most 64 ordinary requests and 16 subscription requests in flight;
- a 30-second ordinary request deadline;
- a 7-second shutdown window;
- a 5-second output-write deadline;
- no configured request deadline above 24 hours.

Subscription requests remain long-lived until response, cancellation, or EOF and are not governed by the ordinary request deadline. This distinction does not make them durable; restart and replay behavior belongs to the selected subscription backplane.

Stdio is process-local and receives credentials from the process composition. It does not perform an OAuth flow. The repository provides no first-party stdio command, executable, process manifest, secret source, or lifecycle composition.

## Choosing a transport

Use HTTP only when an application owner can supply a mounted route, HTTPS deployment, strict authority/origin policy, bearer authentication, tenant resolution, request bounds, cancellation, draining, and lifecycle signals. Use stdio only when a process owner can supply an executable, clean stdout framing, a separate diagnostic sink, process-scoped credentials, bounded concurrency, EOF/cancellation behavior, and shutdown ownership.

**Expected result:** every request is admitted by one explicit transport policy, carries a fresh identity and tenant context, uses revision `2026-07-28`, and either completes within its bounds or reaches registry cancellation.

**Failure path:** reject before dispatch on wrong path or method, unsupported revision, disallowed authority or origin, invalid media negotiation, prohibited session/replay state, oversized input, malformed framing, exceeded concurrency, output backpressure, drain, EOF, or cancellation. Diagnostics must remain bounded and secret-safe.

No repository command can demonstrate this end to end until an application assembles a server. After assembly, external-client evidence belongs in [client interoperability and conformance](client-interoperability-and-conformance.md), not in profile or generator output.

## Related guidance

- [Tools, resources, and prompts](tools-resources-and-prompts.md)
- [Authentication, authorization, and tenancy](authentication-authorization-and-tenancy.md)
- [Runtime lifecycle](../../concepts/runtime-lifecycle.md)
- [Health, readiness, and shutdown](../../operations/health-readiness-and-shutdown.md)
- [MCP protocol support](../../reference/mcp-protocol-support.md)
