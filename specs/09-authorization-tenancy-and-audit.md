---
spec_id: OMNIUS-009
title: Authorization, Tenancy, and Audit
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Authorization, Tenancy, and Audit


## Boundary

Authorization is enforced in application services so it applies to HTTP, WebSockets, jobs, CLI, GraphQL, and gRPC.

```text
authorize(principal, action, resource, context) -> allow | deny(reason)
```

Unknown action, missing tenant/resource context, and evaluator error deny by default.

## Built-in policy

Support roles-to-permissions, ownership, tenant membership, administrative capability, API scope restrictions, step-up assurance, and bounded contextual conditions. Route middleware may enforce coarse authentication but not replace service-level checks.

## Cedar

Optional for centrally authored RBAC/ABAC/ReBAC.

- Version schema/policies.
- Validate at build/deploy.
- Centralize entity construction.
- Deny on evaluation failure.
- Avoid high-cardinality decision metrics.
- Support staged/shadow policy rollout.
- Keep database/product invariants outside Cedar.

## Required authorization tests

Anonymous/authenticated; horizontal access; vertical escalation; cross-tenant; list filtering; bulk operations; indirect references; jobs acting for users; stale token roles/scopes; support/impersonation; newly added route without declared action.

Maintain a machine-readable permission matrix.

## Tenancy

When enabled, tenant appears in principal/context, database constraints and every tenant query, cache keys, job/event/webhook envelopes, object paths, quotas, audit, and bounded metrics. A path tenant is never trusted without membership validation.

Default isolation is explicit predicates plus constraints/tests. PostgreSQL RLS is optional defense in depth and requires transaction-local context, pool leakage tests, explicit migration/admin roles, and fail-closed missing context.

## Organization model

Organization, membership, role assignment, invitations, status, ownership transfer, last-owner protection, suspension, deletion. Grants are versioned/audited.

## Audit

Append-only application audit records event/time, actor, effective tenant, action, resource, outcome, request/correlation/causation IDs, safe metadata, reason, and separate impersonator/subject identities. Never store secrets or arbitrary large before/after data.

## Impersonation

Requires dedicated permission, recent high-assurance auth, reason, short lifetime, prominent context, complete audit, and restrictions on credentials/payment/security enrollment.
