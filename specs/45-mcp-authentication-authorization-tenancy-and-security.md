---
spec_id: OMNIUS-045
title: MCP Authentication, Authorization, Tenancy, and Security
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP Authentication, Authorization, Tenancy, and Security

## 1. Core authorization profile

The future remote HTTP MCP server is an OAuth protected resource and resource server. It uses protected-resource metadata, authorization-server metadata, resource indicators, bearer-token validation, issuer validation, and appropriate OAuth/OIDC discovery; it does not own or implicitly become an authorization server.

Remote hosted-auth profiles may explicitly consume the issuer supplied by `auth-oauth-server`, the sole first-party OAuth Authorization Server and OpenID Provider module. That dependency is declarative until the MCP runtime task `T170`; MCP protocol, transport, route, and protected-resource implementation ownership remains with the existing MCP task graph.

Client ID Metadata Documents are the preferred client-registration path. Dynamic Client Registration is compatibility-only. Credentials and registrations are keyed by issuer and MUST NOT be reused across authorization servers. Every accepted identity and token continues to map through the canonical `Principal`.

## 2. Principal construction

Validated token, workload, client, and delegation claims map into the canonical `Principal`. The context distinguishes interactive user, service account, workload/agent, delegated-on-behalf-of identity, and anonymous local process where explicitly permitted. The MCP client application is not conflated with the end user.

Every list, read, prompt, and tool call is authorized. Catalog discovery MUST NOT leak the existence of tenant-private capabilities. List caching keys include principal/tenant and authorization revision when private.

## 3. Non-interactive and enterprise extensions

OAuth Client Credentials and Enterprise-Managed Authorization are optional modules negotiated as extensions. Client credentials remain issuer-bound and scoped to the MCP resource. Enterprise flow validates ID-JAG issuer, audience, signature, subject, expiry, resource, and delegation claims and maps them through ordinary authorization policies.

The identity layer provides extension points for DPoP, workload identity federation, and RFC 8693 token exchange as the MCP roadmap matures. These mechanisms MUST NOT be simulated with pasted long-lived API keys.

## 4. Transport security

The HTTP module enforces TLS deployment assumptions, origin checks where applicable, CORS denial by default, trusted proxy rules, header allowlists, duplicate-header handling, and centralized SSRF/egress policy. `x-mcp-header` parameters are allowlisted by capability and cannot set authorization, host, hop-by-hop, proxy, or tracing-control headers unless explicitly safe.

## 5. Consent and audit

Side-effecting and sensitive tools expose clear descriptions, required permissions, confirmation state, and consequence metadata. User or policy consent is recorded with capability revision and arguments summary. Audit records include client identity, principal, tenant, action, decision, result, request ID, trace ID, and extension use without recording raw secrets or sensitive payloads.

## 6. Acceptance linkage

This specification is verified by `AC-AI-081` through `AC-AI-088`.
