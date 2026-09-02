---
title: MCP authentication, authorization, and tenancy
description: Exact OAuth resource, bearer rejection, canonical authorization, and global tenant policy for the reference MCP application.
status: experimental
implementation: implemented
profile_availability:
  - mcp-http
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
public_exposure: assembled
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
  - apps/mcp-server/src/lib.rs
  - crates/mcp-auth-oauth/src/resource.rs
  - crates/mcp-auth-oauth/src/bearer.rs
  - crates/mcp-auth-oauth/src/challenge.rs
  - crates/reference-api/src/oauth_provider.rs
  - specs/45-mcp-authentication-authorization-tenancy-and-security.md
evidence:
  - apps/mcp-server/tests/authenticated_mcp.rs
  - crates/mcp-auth-oauth/tests/security_contracts.rs
  - apps/api-server/tests/oauth_provider.rs
last_verified: 2026-09-02
---

# MCP authentication, authorization, and tenancy

`apps/mcp-server` is an OAuth protected resource. `apps/api-server` is the separate first-party authorization server. Each process independently constructs verification state from the same validated issuer/resource configuration, signing key material, PostgreSQL-backed live token-state adapter, and clock.

The MCP process has no authorization-server routes. The API process has no MCP routes.

## Exact resource contract

The validated authorization-server configuration must contain the MCP resource exactly once. Its URI is the query- and fragment-free issuer URI with `/mcp` appended, and it owns exactly one scope:

```text
reference-records:read
```

That resource is simultaneously the RFC 8707 resource indicator and exact access-token audience. The API issuer-root resource is separate and a token for it is rejected at the MCP boundary.

The MCP process serves RFC 9728 metadata at:

```text
/.well-known/oauth-protected-resource/mcp
```

The document names the exact MCP resource, sole issuer, `reference-records:read`, header bearer presentation, and `RS256`. In production, issuer and resource must be HTTPS.

## Bearer presentation and validation

Only one well-formed Authorization-header bearer credential is accepted. A duplicate header, malformed scheme/token, or any `access_token` query parameter is an invalid request even if a valid header is also present.

Authentication verifies:

- exact issuer, audience, and resource;
- signing key and signature;
- issued-at, not-before, and expiry bounds;
- client and durable grant evidence;
- current PostgreSQL-backed token/principal live state, including revocation;
- the exact `reference-records:read` scope;
- global tenant policy.

The raw credential is dropped after verification. It is not retained in request context, logs, audit records, errors, or outbound metadata. Only the typed, redacted `McpAuthenticatedIdentity` reaches RMCP request extensions.

## Deterministic bearer failures

| Condition | HTTP status | `WWW-Authenticate` error |
|---|---:|---|
| Missing Authorization header | 401 | omitted |
| Duplicate/malformed header or query token | 400 | `invalid_request` |
| Signature, issuer, audience/resource, lifetime, revocation, or live-state failure | 401 | `invalid_token` |
| Verified token lacks the required scope | 403 | `insufficient_scope` |

Every challenge also carries `resource_metadata="<issuer>/.well-known/oauth-protected-resource/mcp"` and `scope="reference-records:read"`; responses include `Cache-Control: no-store`. Invalid-token failures intentionally collapse cryptographic, issuer, audience, expiry, revocation, and live-state causes into one redacted boundary.

## Canonical authorization and tenant policy

Authentication establishes identity evidence; registry and capability policy authorize discovery and execution. The reference tool is globally scoped. The canonical resolver and policy both reject a tenant-bearing principal rather than ignoring tenant context.

An admitted request must have:

- JWT authentication;
- no principal or invocation tenant;
- exactly `reference-records:read`;
- current canonical authorization `Allow`;
- matching resource and audience.

Every call is reauthorized after listing. Schema validation, budgets, deadlines, cancellation, and the no-side-effect capability contract are enforced by the canonical registry.

## Advanced profile contracts

Client-credentials and enterprise-managed authorization crates remain optional application contracts. They do not alter the checked-in reference app and do not provide runnable defaults. Product applications selecting them must supply concrete signing/verification, replay protection, identity links, tenant entitlements, consent, audit, persistence, and lifecycle ownership; absence fails closed.

## Related guidance

- [Authenticated MCP server quickstart](../../getting-started/mcp-server-quickstart.md)
- [Server architecture](server-architecture.md)
- [Discovery, versioning, and transport](discovery-versioning-and-transports.md)
- [MCP security](../../security/mcp-security.md)
- [MCP protocol support](../../reference/mcp-protocol-support.md)
