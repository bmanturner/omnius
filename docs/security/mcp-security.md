---
title: MCP security
description: Security boundaries for the dedicated OAuth-authenticated MCP application and its unassembled optional primitives.
status: experimental
implementation: implemented
profile_availability:
  - mcp-http
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
public_exposure: assembled
audience:
  - security-analyst
  - mcp-developer
  - operator
topics:
  - security
  - mcp
  - authorization
capabilities: []
source:
  - apps/mcp-server/src/lib.rs
  - apps/mcp-server/src/main.rs
  - crates/mcp-transport-http/src/lib.rs
  - crates/mcp-auth-oauth/src/bearer.rs
  - crates/mcp-auth-oauth/src/challenge.rs
  - crates/reference-api/src/oauth_provider.rs
evidence:
  - apps/mcp-server/tests/authenticated_mcp.rs
  - apps/mcp-server/tests/process_lifecycle.rs
  - apps/api-server/tests/api_service.rs
last_verified: 2026-09-02
---

# MCP security

The checked-in MCP boundary is the dedicated `apps/mcp-server` process. It exposes authenticated `POST /mcp`, public RFC 9728 metadata, and one read-only globally scoped tool. `apps/api-server` remains the authorization server and REST application and deliberately exposes neither MCP route. No trusted-local, anonymous, session, or API-key fallback exists.

Apply the shared [security model](security-model.md) and [identity, authorization, and tenancy](../concepts/identity-authorization-and-tenancy.md). Protocol support details belong in the [MCP protocol support reference](../reference/mcp-protocol-support.md).

## Trust boundaries

- **Client to HTTP transport:** enforce method/path, host/origin, media/framing, version, size, timeout, and drain limits before protocol dispatch.
- **Transport to identity:** authenticate exactly one header bearer credential against exact issuer, `/mcp` audience/resource, scope, signature, lifetime, and current PostgreSQL-backed token state.
- **Identity to request context:** preserve only typed verified identity in request extensions; construct fresh canonical authorization, budget, deadline, trace, and cancellation evidence per request.
- **Context to registry projection:** filter availability, declared exposure, global tenant mode, canonical authorization, and capability-specific policy.
- **Registry to handler:** reauthorize invocation and validate bounded schemas before calling the shared reference-record service.
- **Handler to data:** use the real PostgreSQL repository/paginator and reject tenant-bearing identity rather than ignoring it.

## Authenticated transport controls

The only MCP transport is stateless Streamable HTTP at `POST /mcp`. The development configuration allows loopback authorities only. The transport rejects retained sessions, GET event streams, replay/resume headers, unsupported revisions, malformed method/name metadata, invalid media negotiation, oversized input/output, and new work during drain.

Axum request extensions are explicitly preserved into RMCP `RequestContext`; there is no global identity cache. Shutdown begins HTTP listener and MCP drain together and bounds admitted work.

## OAuth controls

The authorization-server configuration must contain the issuer-root API resource and exactly one query/fragment-free issuer-plus-`/mcp` resource. Only the latter owns `reference-records:read`. A root-API token is not interchangeable with an MCP token.

Bearer failure projection is deterministic and redacted:

- missing credential: 401;
- malformed, duplicated, or query credential: 400 `invalid_request`;
- bad signature, expiry, revocation/live-state, issuer, or audience/resource: 401 `invalid_token`;
- missing required scope: 403 `insufficient_scope`.

Every challenge points to `<issuer>/.well-known/oauth-protected-resource/mcp`, names `reference-records:read`, and is returned with `Cache-Control: no-store`. Never log credentials or distinguish cryptographic, expiry, revocation, or live-state failure at the public boundary.

## Capability and data controls

The reference application exposes only `reference_records.list.v1`. It is side-effect free, requires no confirmation, accepts bounded `limit`, `cursor`, and `name` arguments, and returns a bounded page. The registry remains authoritative for schema, authorization, availability, global tenant mode, budget, deadline, and cancellation.

Resources, prompts, elicitation, subscriptions, tasks, Apps, Skills, completion, and progress are absent and return method-not-found. Do not add empty adapters, sample handlers, or allow-all policy to make those methods appear supported.

## Optional profile risks

The reusable catalog includes advanced application contracts, but they are not reference-app defaults:

- client credentials and enterprise authorization require real key, replay, identity-link, entitlement, consent, audit, persistence, and lifecycle owners;
- elicitation and tasks require composed repositories, payload protection, workers, expiry, reconciliation, and retention;
- subscriptions require the selected backplane's real durability/replay semantics;
- Apps and Skills require origin, integrity, storage, authorization, audit, and execution isolation.

Missing providers or product policy must fail before startup. A generated profile, extension identifier, migration, port, or catalog row does not satisfy an application-owned control.

## Security review procedure

1. Confirm traffic reaches `apps/mcp-server`, not `apps/api-server`, and only the documented route set is mounted.
2. Verify metadata resource, issuer, scope, bearer method, and algorithm against the actual token issuer.
3. Exercise missing, malformed, query, expired, revoked, wrong-audience, insufficient-scope, and tenant-bearing credentials without retaining secrets.
4. Confirm `tools/list` exposes only `reference_records.list.v1` and unsupported primitives return method-not-found.
5. Trace one list call through request extension, canonical context, registry policy, service, PostgreSQL repository, and bounded result.
6. Exercise host/origin, media, revision, framing, size, cancellation, readiness, and bounded shutdown behavior.
7. Reject any deployment that broadens the primitive set without concrete application policy and negative evidence.

## Related guidance

- [Authenticated MCP server quickstart](../getting-started/mcp-server-quickstart.md)
- [MCP troubleshooting](../troubleshooting/mcp-discovery-transports-and-auth.md)
- [Scaling jobs, realtime, and MCP](../operations/scaling-jobs-realtime-and-mcp.md)
