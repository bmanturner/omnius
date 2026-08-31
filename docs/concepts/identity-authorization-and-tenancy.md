---
title: Identity, authorization, and tenancy
description: The canonical principal, authentication, authorization, tenant-context, and accountability boundaries shared by HTTP, browser, async, LLM, and MCP surfaces.
status: experimental
implementation: implemented
profile_availability:
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - full-reference
public_exposure: library-only
audience:
  - rust-application-developer
  - web-developer
  - mcp-developer
  - security-and-privacy-reviewer
topics:
  - identity
  - authentication
  - authorization
  - tenancy
capabilities:
  - identity-principal
source:
  - specs/08-authentication-and-identity.md
  - specs/09-authorization-tenancy-and-audit.md
  - crates/auth-core/src/lib.rs
evidence:
  - apps/api-server/src/lib.rs
  - crates/authz-basic/src/lib.rs
  - crates/tenancy/src/lib.rs
last_verified: 2026-08-30
---

# Identity, authorization, and tenancy

Identity, authorization, and tenancy are separate decisions. Combining them into a role string, session object, or client-selected organization creates confused-deputy and cross-tenant risks.

## Audience path

Application and protocol authors should use this model before implementing an authenticated operation. Continue to the backend guides for concrete mechanisms and policies, then to the security model for surface and deployment threats.

## Canonical principal

The canonical `Principal` normalizes the identity established by an accepted authentication mechanism. It carries a subject identifier, optional tenant context, principal kind, authentication method, assurance level, and bounded scopes.

A principal answers **who and how**. It does not prove:

- that the subject may perform the requested action;
- that a client-provided tenant is active or authorized;
- that scopes alone satisfy application policy;
- that identity remains valid after revocation-sensitive state changes;
- that the same credential is admissible on every listener or protocol.

The principal contract is an internal, `library-only` capability. Its use inside handlers does not create a public identity endpoint.

## Decision sequence

```text
untrusted request or message
  -> authenticate one supported mechanism
  -> construct canonical principal
  -> resolve authoritative tenant membership when needed
  -> build minimal request/application context
  -> authorize action on resource in that context
  -> execute effect in a tenant-scoped transaction
  -> emit bounded accountability evidence
```

Each stage may reject independently. Authentication success must never skip tenant resolution or action authorization.

## Authentication boundary

Mechanism adapters validate credentials and map them into the canonical principal. Password login, browser sessions, API keys, OAuth/OIDC provider behavior, upstream JWT validation, and external OIDC are different trust paths with different rotation, revocation, audience, and assurance semantics.

The checked-in OAuth-provider reference app assembles local password authentication, PostgreSQL browser sessions, API keys, hosted OAuth/OIDC behavior, basic authorization, and tenancy. Its JWT resource-server configuration is disabled, so selected JWT source is not evidence of a live upstream-bearer path. Redis sessions, external OIDC, TOTP, WebAuthn, and Cedar remain library-only or unassembled according to the coverage matrix.

## Authorization boundary

Authorization decides whether a canonical principal may perform a named action on a resource under current context. It belongs at the application/use-case boundary, after parsing and identity establishment and before a side effect or sensitive read.

Required properties:

- deny by default when policy input or authoritative context is missing;
- use stable backend-owned action identifiers;
- evaluate resource and tenant facts server-side;
- reauthorize long-lived, deferred, or replayed work when relevant facts can change;
- return a safe denial without leaking policy internals or resource existence;
- record security-relevant decisions with bounded reason classes.

The current committed `contracts/permissions.json` is empty. Consumers must not invent a permission vocabulary from UI roles, route names, catalog examples, or source constants.

## Tenant boundary

A tenant hint from a header, path, session, token, browser store, job envelope, or MCP request is untrusted selection input. `TenantContext` becomes authoritative only after the application verifies active membership and any policy conditions for that principal.

After resolution:

- every tenant-owned query and mutation includes the tenant dimension;
- cache keys, idempotency scopes, object keys, search projections, jobs, events, and audit records retain the same boundary;
- switching tenant invalidates stale authorization and tenant-scoped client state;
- a generic database pool does not enforce isolation by itself;
- reference tables without a tenant column are not multi-tenant isolation evidence.

UI route guards and hidden controls improve presentation but are never authorization controls.

## Async and protocol continuity

Jobs and events may carry bounded principal/tenant/correlation facts, but the worker must restore a typed context and decide whether the effect requires current authorization. A model or MCP client never acquires authority merely by proposing a tool call. The host application maps protocol identity to the canonical principal, applies tenant and authorization policy, deduplicates the effect, and records accountability evidence.

## Audit boundary

Audit records support accountability; they do not grant access. Record stable actor, tenant, action, resource class/opaque identifier, decision/outcome, request/correlation identity, and bounded reason metadata. Do not record credentials, session cookies, raw tokens, passwords, provider payloads, or arbitrary content. The audit library is selected and used internally, but no general public audit-query surface is proven.

## Evidence

- [Authentication and identity specification](../../specs/08-authentication-and-identity.md)
- [Authorization, tenancy, and audit specification](../../specs/09-authorization-tenancy-and-audit.md)
- [Canonical principal implementation](../../crates/auth-core/src/lib.rs)
- [Basic policy implementation](../../crates/authz-basic/src/lib.rs)
- [Tenant-context implementation](../../crates/tenancy/src/lib.rs)
- [OAuth-provider route/application assembly](../../apps/api-server/src/lib.rs)
- [OAuth-provider configuration](../../config/reference.toml)

## Next

- [Authentication and sessions](../guides/backend/authentication-and-sessions.md)
- [Authorization and tenancy](../guides/backend/authorization-and-tenancy.md)
- [Security model](../security/security-model.md)
