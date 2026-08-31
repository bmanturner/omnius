---
title: Web authorization, tenancy, and capabilities
description: Browser presentation rules for runtime capabilities, permission decisions, identity-scoped caches, and tenant transitions.
status: experimental
implementation: source-only
profile_availability:
  - saas-web
  - full-reference-web
public_exposure: unassembled
audience:
  - web developers
  - authorization integrators
  - security reviewers
topics:
  - authorization
  - tenancy
  - capabilities
  - query-scope
capabilities:
  - web-tenant-context-and-authorization-presentation
  - web-feature-flags
source:
  - packages/web-sdk/src/authorization/index.ts
  - packages/web-sdk/src/capabilities/index.ts
  - packages/web-sdk/src/react/query-scope.ts
  - packages/web-sdk/src/react/capabilities.ts
  - packages/web-sdk/src/react/tenant.ts
  - web/src/components/tenant-switcher.tsx
evidence:
  - contracts/capabilities.json
  - contracts/permissions.json
  - specs/machine/extensions/web-application-suite/profiles.yaml
last_verified: 2026-08-30
---

# Web authorization, tenancy, and capabilities

Browser code presents authorization decisions; it does not create authority. Tenant selection, hidden controls, route guards, and cached permission data are defense-in-depth around backend authentication and authorization. The server must enforce every operation independently.

This page covers two separately classified surfaces:

| Surface | Implementation | Profile availability | Exposure |
|---|---|---|---|
| `web-feature-flags` capability module and checked React capability-resolution hooks | implemented | `saas-web`, `full-reference-web` | library-only |
| Tenant and authorization presentation journey | source-only | `saas-web`, `full-reference-web` | unassembled |

The page frontmatter conservatively follows the unassembled tenant journey. Profile selection and reusable hook source do not prove that an application mounts either surface or that a served runtime exposes it.

The current browser tenancy presentation is source-only and unassembled. Its intended profiles are `saas-web` and `full-reference-web`. The checked `tenant-switcher` component is not imported into the application, and the checked permissions artifact is empty. Do not infer a mounted tenant journey or permission catalog from these files.

Use [identity, authorization, and tenancy](../../concepts/identity-authorization-and-tenancy.md) for canonical principal and tenant concepts. Use [backend authorization and tenancy](../backend/authorization-and-tenancy.md) for server enforcement, the [permissions reference](../../reference/permissions.md) for generated permission metadata, and the [availability matrix](../../reference/availability-and-exposure-matrix.md) for current classification.

## Three independent gates

A browser action should be offered only after three separate questions are answered:

1. **Capability:** does the queried runtime report that the feature is compiled and runtime-available?
2. **Authentication and tenant context:** is the expected principal established in the intended tenant or global scope?
3. **Authorization:** does the current permission decision allow this concrete action and resource context?

A package export, source component, generated permission type, selected profile, or successful fixture test cannot answer the first question for a live runtime. A visible control cannot answer the third question for the server.

Keep failure presentation distinct:

| Condition | Browser presentation |
|---|---|
| Capability not compiled or unavailable | Do not offer the runtime action; explain profile/runtime unavailability where useful. |
| Principal absent | Start or require authentication, preserving only a validated local return path. |
| Tenant context missing | Require an explicit valid tenant selection when the operation is tenant-scoped. |
| Permission denied | Present a denied state without revealing protected resource details. |
| Capability/contract document invalid | Fail closed and surface an integration or contract error. |
| Backend denies an apparently allowed operation | Honor the backend denial, refresh relevant decision data, and do not retry as a bypass. |

## Runtime capabilities

The SDK capability parser validates capability and contract/profile metadata. UI logic should consume the parsed runtime document and check both compiled and runtime flags. It must not assume that all exported SDK modules are present on the server.

The implemented React adapter exposes `useCompiledCapability` for structural build composition and `useRuntimeCapability` for subscribed runtime-availability decisions. The runtime hook deliberately resolves only runtime availability: feature flags, entitlements, and permissions remain separate decision inputs. These exports are library-only evidence, not proof of a mounted flag provider, browser control, or served runtime.

The checked capability artifact currently identifies the `oauth-provider` profile. It reports `web-auth` as false at both compiled and runtime layers. That artifact is evidence for the checked contract state; it does not prove what a separately deployed environment reports. Conversely, the checked-in web routes do not override this negative capability evidence.

When the runtime contract hash differs from the generated SDK identity, stop capability-dependent actions. A mismatched capability document is not a safe source for feature gates.

## Permission presentation

The SDK authorization helpers model permission decisions for browser presentation. A generated permission inventory can improve type safety and consistency, but it is not a substitute for the backend policy engine. The current `contracts/permissions.json` is empty, so documentation must not invent named permissions or claim that a specific browser control is backed by a generated permission.

When permissions are supplied by an assembled runtime:

- scope a decision to the principal, tenant, capability, and resource context it describes;
- use denial-safe copy that does not disclose whether a protected resource exists;
- invalidate or refresh decisions after identity, membership, role, tenant, or capability changes;
- never treat hiding a control as enforcement;
- preserve backend `forbidden` or equivalent problem responses instead of rewriting them as not-found or success unless the backend contract explicitly defines that behavior.

## Identity-scoped query keys

The React SDK scopes server-state keys under an Omnius namespace and explicit identity context. `QueryKeyScope` carries a tenant identifier, principal identifier, and optional permission scope. The tenant and principal values may be null where the resource is intentionally global or anonymous, but scoped resources must not omit their actual owner context.

This boundary prevents cache entries for one tenant or principal from being reused under another. A route parameter alone is not enough: the query key must include the validated identity scope that controls the backend request.

After logout, tenant switch, membership change, or permission-scope change, remove or invalidate affected entries before presenting the next identity state. Do not rely only on a component rerender; stale server state can outlive a view.

## Tenant transition protocol

`createTenantTransitionCoordinator` implements an ordered transition:

1. synchronously publish `transitioning`;
2. cancel queries belonging to the previous tenant/principal scope;
3. remove those queries by default, or invalidate them when explicitly configured;
4. reset registered tenant-local state owners;
5. reestablish realtime for the next tenant;
6. replace the tenant route;
7. publish `ready` with the next scope.

The coordinator rejects concurrent transitions. It publishes an `error` state if a phase fails and does not silently publish the next tenant as ready. Callers can supply an abort signal, which is checked between phases.

**Expected result:** while transitioning, no old-tenant data is presented as if it belonged to the new scope. On success, cache, local state, realtime, and route agree on the same next tenant.

**Failure path:** keep a non-ready error state, avoid rendering old data in the new context, and require a deliberate recovery or return to a known scope. Do not continue later phases after an earlier failure.

This is implemented library behavior, but application assembly is not proven. The checked browser authentication manager's realtime identity-reset hook is a no-op, and the tenant switcher is not mounted. An assembled tenant workflow must provide a real realtime port and verify failure recovery before claiming support.

## Tenant switcher presentation

The checked component demonstrates an accessible tenant selector and transition state. Its presence is source evidence only. If an application mounts a tenant selector, it should:

- label the control with the active tenant context;
- disable competing changes while a transition is active;
- avoid listing tenants the backend has not authorized for the principal;
- announce success or failure without exposing internal identifiers unnecessarily;
- keep the prior selection visually distinct from a not-yet-ready target;
- handle lost membership as a backend-driven context change, not merely a selection error.

Do not persist tenant authority in an unsigned browser value. A stored preference may suggest a tenant to request, but the backend establishes whether the principal can use it.

## Membership and authorization changes

Realtime can notify the client that identity, membership, or authorization changed. Such a notification is an invalidation signal, not a new permission grant. The safe reaction is to refresh the authoritative principal, tenant memberships, capabilities, and permission decisions, then clear affected query data.

If realtime is unavailable, browser code still needs refresh boundaries around navigation, sensitive actions, and rejected backend operations. Never retain an allow decision indefinitely because a websocket was expected to revoke it.

## Verification checklist

An independent assembled-runtime review should observe:

- capability parsing and fail-closed behavior;
- separation of unavailable, anonymous, missing-tenant, and denied states;
- backend denial even when a control was visible;
- tenant/principal/permission scope in relevant query keys;
- cancellation and removal of old-scope queries before next-scope rendering;
- local-state reset, realtime reestablishment, and route replacement ordering;
- concurrent and failed tenant-transition handling;
- membership-loss behavior;
- no cross-tenant data in memory-backed views, persistent state, logs, or telemetry.

No tenant transition, authorization request, generation check, or browser scenario was run for this page. Profile specifications, empty permission metadata, SDK source, and an unimported component do not prove a runtime tenant experience.
