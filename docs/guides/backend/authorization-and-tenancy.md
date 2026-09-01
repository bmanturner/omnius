---
title: Authorization and tenancy
description: Propagate authoritative tenant context through Omnius and apply assembled basic authorization without overclaiming Cedar or permission exposure.
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
public_exposure: assembled
audience:
  - developer
  - security-reviewer
topics:
  - backend
  - authorization
  - tenancy
capabilities:
  - authorization-policy-basic
  - authorization-policy-cedar
  - organizations-tenancy
source:
  - crates/auth-core/src/lib.rs
  - crates/authz-basic/src/lib.rs
  - crates/authz-cedar/src/lib.rs
  - crates/tenancy/src/lib.rs
  - crates/tenancy/src/store.rs
  - crates/reference-api/src/browser_tenancy.rs
  - apps/api-server/src/lib.rs
  - contracts/permissions.json
evidence:
  - crates/authz-basic/tests/security.rs
  - crates/authz-cedar/tests/provider.rs
  - crates/tenancy/tests/postgres.rs
  - apps/api-server/tests/authenticated_profile.rs
  - apps/api-server/tests/browser_auth.rs
last_verified: 2026-08-30
---

# Authorization and tenancy

Authentication produces a principal; authorization decides whether that principal may perform an action on a resource. Tenant selection narrows context but never grants permission. Omnius assembles the basic authorization provider and organization tenancy in the reference API. The Cedar provider is an implemented library with no selected profile, application mount, policy persistence surface, or policy-management route.

Use [Identity, authorization, and tenancy](../../concepts/identity-authorization-and-tenancy.md) for the canonical principal model and the [permissions reference](../../reference/permissions.md) for generated permission exposure.

## Exposure summary

| Capability | Runtime exposure | Boundary |
| --- | --- | --- |
| Basic authorization | Assembled | Evaluates the concrete principal, resource, action, and basic policy inputs |
| Organization tenancy | Assembled | Persists organizations and memberships; browser routes select an active tenant after membership verification |
| Cedar authorization | Library only | Strict policy evaluator exists, but no reference runtime composition or policy-management surface exists |

`contracts/permissions.json` currently exposes an empty permission artifact. Do not invent permission identifiers or claim a published permission catalog.

## Canonical flow

The security boundary is an ordered pipeline:

```text
credential
  -> authenticate
  -> Principal
  -> resolve authoritative active membership
  -> TenantContext
  -> authorize action and resource
  -> execute a tenant-scoped repository query
  -> shape response
```

Every transition may reduce access; none may silently widen it. Missing credentials, missing or inactive membership, absent tenant context, unknown action, invalid policy input, provider failure, or denied decision must stop the operation before the repository mutation or protected read.

The principal carries tenant context, authentication method, assurance level, and scopes. It is a transport between boundaries, not an authorizer by itself.

## Tenant propagation

The assembled browser tenancy surface exposes tenant listing and switching at `/tenants` and `/tenants/{tenant_id}/switch`. A tenant identifier supplied by a path, body, query, cookie, or header is only a requested selection. The server must load an active membership before creating or updating tenant context.

After selection:

- pass tenant context explicitly through the application and repository layers;
- include the tenant key in every tenant-owned read, write, uniqueness constraint, cache key, idempotency scope, job payload, audit event, and search query;
- derive search tenancy from the principal, then reauthorize authoritative records;
- reject a resource whose stored tenant does not match the active context;
- clear or replace tenant context when membership is revoked or the session changes.

A PostgreSQL pool does not add these predicates. The `reference_records` repository has no tenant dimension and is not evidence of tenant isolation.

## Basic authorization

The basic provider can evaluate policy inputs including role, ownership, membership, scopes, assurance level, and equality conditions. Call it with the smallest complete context immediately before the protected action.

A safe application pattern is:

```rust,no_run
// Illustrative boundary ordering; names are intentionally generic.
let principal = authenticate(request).await?;
let tenant = require_active_membership(&principal, requested_tenant).await?;
authorize(&principal, &tenant, action, resource).await?;
repository.load_for_tenant(tenant.id(), resource.id()).await
```

The example documents ordering only; it is not a copyable public API. A failed membership lookup or authorization decision must return a safe denial and must not fall back to a default tenant, system principal, or unscoped query.

## Cedar distinction

The Cedar library validates schema and policy inputs strictly before activation and evaluates requests fail closed. That implementation is not selected by any profile and is not assembled into the API server.

Consequently, the repository does not provide a supported command, environment variable, policy directory, hot-reload behavior, persistence format, administration route, or public Cedar permission catalog. Do not create any of those contracts from the library API alone.

If Cedar is composed in a future application, the integration must define policy provenance, validation and activation order, entity construction, tenant partitioning, failure behavior, rollback, observability, and the mapping from published permissions to policy actions. Until then, use the assembled basic provider where the reference application already wires it.

## Fail-closed review scenario

Use synthetic users and tenants in a configured `authenticated-api` or `oauth-provider` environment. Do not use production identities.

**Prerequisites**

- start the assembled API server only after PostgreSQL migrations and protected identity settings succeed;
- create two synthetic organizations and memberships through supported administration flows;
- authenticate a synthetic principal with membership in only one organization;
- retain request IDs but no cookies, tokens, or API keys in review notes.

**Expected result:** the principal can select only an organization with active membership; a cross-tenant resource identifier is denied before an unscoped repository result is returned; revoking membership removes subsequent tenant access.

**Failure path:** if cross-tenant data is returned, stop testing against the environment, preserve redacted request IDs and audit evidence, and treat the route as unsafe. Fix membership resolution, tenant propagation, authorization, and the repository predicate together; an HTTP-only denial or cache-key special case is not a complete repair.

This is a documented verification scenario and was not run as part of this documentation work.

## Audit boundary

The internal audit library can record security events, but the reference application does not prove complete authorization-handler coverage or expose a public audit query API. Audit events support investigation; they are not an authorization decision and must not contain credentials or raw secret material.

## Related pages

- [Authentication and sessions](authentication-and-sessions.md)
- [Identity, authorization, and tenancy](../../concepts/identity-authorization-and-tenancy.md)
- [Permissions reference](../../reference/permissions.md)
- [Search authorization](caching-search-and-rate-limits.md#search-projection-and-authorization)
- [Security model](../../security/security-model.md)
- [Identity and permissions troubleshooting](../../troubleshooting/identity-and-permissions.md)
