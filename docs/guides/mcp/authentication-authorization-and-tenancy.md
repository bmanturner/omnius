---
title: MCP authentication, authorization, and tenancy
description: OAuth protected-resource, client-credentials, enterprise authorization, tenant isolation, and redaction boundaries for an assembled MCP server.
status: experimental
implementation: implemented
profile_availability:
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
  - authentication
  - authorization
  - tenancy
  - oauth
capabilities:
  - mcp-auth-oauth
  - mcp-auth-client-credentials
  - mcp-auth-enterprise
source:
  - crates/mcp-server-core/src/discovery.rs
  - crates/mcp-server-core/src/sdk.rs
  - crates/mcp-auth-oauth/src/resource.rs
  - crates/mcp-auth-oauth/src/bearer.rs
  - crates/mcp-auth-client-credentials/src/lib.rs
  - crates/mcp-auth-enterprise/src/lib.rs
  - specs/45-mcp-authentication-authorization-tenancy-and-security.md
evidence:
  - crates/mcp-auth-oauth/tests/security_contracts.rs
  - crates/mcp-auth-client-credentials/tests/grant.rs
  - crates/mcp-auth-enterprise/tests/enterprise.rs
  - apps/api-server/tests/oauth_provider.rs
last_verified: 2026-08-30
---

# MCP authentication, authorization, and tenancy

> **Assembly status:** OAuth, client-credentials, and enterprise authorization contracts are implemented libraries for the listed profiles. They mount no route, authenticate no live request, persist no identity state, and assemble no MCP endpoint. The reference API proves that MCP protected-resource metadata is absent.

MCP reuses the canonical principal, tenant, membership, and authorization model; it does not define a parallel identity system. Read [identity, authorization, and tenancy](../../concepts/identity-authorization-and-tenancy.md) before applying the surface-specific rules below, and use [MCP security](../../security/mcp-security.md) for threat and hardening guidance.

## Protected-resource and bearer boundary

The OAuth library models RFC 9728 protected-resource metadata and RFC 8707 exact resource binding. For a production resource or issuer, HTTPS is required, and a protected resource identifier cannot contain a query. The metadata model does not mount `/.well-known/oauth-protected-resource/mcp` or act as an authorization server.

Bearer credentials are accepted only from the authorization header. Credentials in a query are rejected. Validation must establish:

- the exact trusted issuer;
- audience and protected-resource binding;
- signature and bounded lifetime;
- current issuer and principal state through application-owned ports;
- the tenant and operation constraints required by policy.

A session, API key, model identity, tool claim, or caller-supplied tenant cannot substitute for that validation. The raw bearer value must not be retained in request context, logs, audit records, error material, or outbound metadata.

The transport-safe MCP header allowlist excludes authorization, host, cookies, hop-by-hop and framing headers, forwarding and proxy headers, and correlation or tracing headers. A deployment must create trusted correlation and network context itself instead of forwarding caller-controlled values.

## Authorization and resource isolation

Authentication establishes a principal; it does not authorize discovery or execution. Each request must resolve active tenant membership and canonical authorization, then every capability must pass its own authorizer. Resolved tool targets, resource URIs, prompt retrieval, tasks, subscriptions, and extension state require resource-specific reauthorization.

Use indistinguishable outcomes where existence is sensitive. In particular, owner-scoped task access by the wrong principal or tenant appears as not found. Capability absence and authorization denial likewise share a redacted rejection category. Detailed schema or resource validation must not run first when it would become an oracle.

Tenant context is request-scoped and must be bound to authenticated state. It cannot be inherited from an MCP session because the kernel retains no session state. An explicitly composed `McpExposureFilter` enforces a capability's tenant mode for primitive projection, and invocation must enforce it again; bare `server/discover` does not invoke that filter.

## Confidential client credentials

The extension `io.modelcontextprotocol/oauth-client-credentials@2026-07-28` defines a trusted confidential-client contract. Application-owned ports resolve the resource-authoritative issuer and scopes, current client and grant state, service account, tenant, and scope ceiling. Issued claim material has a maximum 15-minute lifetime.

The library emits canonical unsigned claims. Key custody, signing, token endpoint behavior, bearer validation, client-secret handling, durable grant state, revocation, and audit persistence remain external composition responsibilities. The stable extension identifier proves a contract, not a public runtime.

## Enterprise managed authorization

The extension `io.modelcontextprotocol/enterprise-managed-authorization@2026-07-28` models ID-JAG-style enterprise delegation. A received assertion is evidence to evaluate, not authorization to perform an action. Safe composition requires concrete ports for cryptography, replay protection, durable identity links, tenant entitlements, policy, consent, and audit.

The catalog declares `mcp_enterprise_identity_links`, but the inspected repository does not prove a migration or composed repository adapter. If crypto, replay, link, membership, policy, consent, or audit dependencies are unavailable, authorization must fail closed.

## Composition checklist

An application owner must still supply:

1. a deliberately mounted HTTPS MCP resource and protected-resource metadata route;
2. trusted issuer configuration and exact resource identifiers;
3. secret injection, key custody, signature verification, and live-state adapters;
4. canonical principal and active-tenant resolution;
5. capability and resource-level authorization with redacted denial behavior;
6. confirmation or approval decisions from trusted policy, never from untrusted MCP content;
7. replay protection, persistence, migrations, retention, and reconciliation where required;
8. bounded, secret-safe challenges, diagnostics, telemetry, and audit sinks;
9. deadline and cancellation propagation through authentication, authorization, and execution.

**Expected result:** each admitted request has a live authenticated principal, an active tenant, exact resource binding, and fresh operation/resource authorization; no raw credential or sensitive existence information crosses the response or observability boundary.

**Failure path:** reject on missing or misplaced bearer credentials, issuer/resource/audience/signature/lifetime mismatch, stale principal or grant state, inactive membership, tenant mismatch, insufficient authorization, replay, unavailable enterprise dependencies, or cancellation. Do not fall back to anonymous, session, API-key, or caller-asserted identity.

No executable setup command is available because these libraries are not mounted. Exact protocol availability remains canonical in [MCP protocol support](../../reference/mcp-protocol-support.md).

## Related guidance

- [Server architecture](server-architecture.md)
- [Discovery, versioning, and transports](discovery-versioning-and-transports.md)
- [MCP capability matrix](../../reference/mcp-capability-matrix.md)
- [Configuration and secrets](../backend/configuration-and-secrets.md)
- [Security model](../../security/security-model.md)
