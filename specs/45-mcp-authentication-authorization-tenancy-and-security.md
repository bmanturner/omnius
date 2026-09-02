---
spec_id: OMNIUS-045
title: MCP Authentication, Authorization, Tenancy, and Security
version: 0.1.0
status: normative
last_verified: 2026-09-01
---

# MCP Authentication, Authorization, Tenancy, and Security

## 1. Core authorization profile

The checked-in `apps/mcp-server` is an OAuth protected resource and resource server. It serves RFC 9728 metadata at `/.well-known/oauth-protected-resource/mcp`, protects only `POST /mcp`, requires the exact issuer-plus-`/mcp` resource/audience and `reference-records:read`, and validates RS256 signature, lifetime, issuer, audience, revocation, and PostgreSQL-backed live token state.

`apps/api-server` is the separate first-party OAuth authorization server and ordinary API resource. It mints resource-specific tokens but mounts neither MCP route; the MCP process mounts no authorization-server route. The processes independently construct verification state from validated configuration, key material, PostgreSQL, and clock.

Client ID Metadata Documents remain the preferred client-registration path for product compositions. Dynamic Client Registration is compatibility-only. Credentials and registrations are issuer-bound and MUST NOT be reused across authorization servers.

## 2. Principal construction

The bearer middleware inserts only verified `McpAuthenticatedIdentity`; a fresh canonical context is derived per request with no session, API-key, local, or anonymous fallback. The reference tool is globally scoped and rejects tenant-bearing identity rather than ignoring it. The MCP client application is not conflated with the end user.

Every contributed list, read, prompt, and tool call is authorized. Catalog discovery MUST NOT leak tenant-private capabilities. The reference app contributes only `reference_records.list.v1`; optional primitives remain method-not-found.

## 3. Non-interactive and enterprise extensions

OAuth Client Credentials and Enterprise-Managed Authorization are optional modules negotiated as extensions. Client credentials remain issuer-bound and scoped to the MCP resource. Enterprise flow validates ID-JAG issuer, audience, signature, subject, expiry, resource, and delegation claims and maps them through ordinary authorization policies.

The identity layer provides extension points for DPoP, workload identity federation, and RFC 8693 token exchange as the MCP roadmap matures. These mechanisms MUST NOT be simulated with pasted long-lived API keys.

## 4. Transport security

The HTTP module enforces TLS deployment assumptions, origin checks where applicable, CORS denial by default, trusted proxy rules, header allowlists, duplicate-header handling, and centralized SSRF/egress policy. `x-mcp-header` parameters are allowlisted by capability and cannot set authorization, host, hop-by-hop, proxy, or tracing-control headers unless explicitly safe.

Missing credentials return 401; duplicate, malformed, or query credentials return 400 `invalid_request`; invalid signature/lifetime/issuer/audience/resource/revocation/live state returns 401 `invalid_token`; insufficient scope returns 403 `insufficient_scope`. Challenges name the exact metadata URL and scope, include `Cache-Control: no-store`, and redact the internal invalid-token cause.

## 5. Consent and audit

Side-effecting and sensitive tools expose clear descriptions, required permissions, confirmation state, and consequence metadata. User or policy consent is recorded with capability revision and arguments summary. Audit records include client identity, principal, tenant, action, decision, result, request ID, trace ID, and extension use without recording raw secrets or sensitive payloads.

## 6. Acceptance linkage

This specification is verified by `AC-AI-081` through `AC-AI-088`.
