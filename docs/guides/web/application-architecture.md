---
title: Web application architecture
description: Composition, routing, base-path, capability, and ownership boundaries for the checked-in React application.
status: experimental
implementation: source-only
profile_availability:
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: unassembled
audience:
  - web developers
  - application architects
topics:
  - web
  - react
  - routing
  - architecture
capabilities:
  - web-application
  - web-app-composition-and-routing
source:
  - web/src/app.tsx
  - web/src/router.tsx
  - web/src/routes/status-route.tsx
  - web/src/components/app-shell.tsx
  - crates/http/web-route-topology.json
evidence:
  - web/e2e/base-path.spec.ts
  - web/e2e/browser.spec.ts
  - contracts/capabilities.json
last_verified: 2026-08-30
---

# Web application architecture

The repository contains an implemented application composition and router source, but no inspected evidence assembles that source into the active `oauth-provider` runtime. The application surface is therefore documented as source-only and publicly unassembled. Consult the [availability matrix](../../reference/availability-and-exposure-matrix.md) before treating any route as deployed.

## Composition root

`web/src/app.tsx` is the browser composition root. It creates and owns:

- a single TanStack Query client;
- a `BrowserSessionAuthManager`;
- a TanStack Router instance;
- a `WebSdkProvider` connecting framework-neutral SDK configuration to React;
- disposal of browser authentication resources when the root unmounts.

The default SDK base URL is `/` and the default request credential mode is `same-origin`. Callers may configure the composition, but should preserve one ownership boundary. Route-local SDK clients, duplicate query clients, or unmanaged authentication managers would split identity and cache state.

The [generated contracts and SDK](generated-contracts-and-sdk.md) guide describes the SDK boundary. The [authentication and account flows](authentication-and-account-flows.md) guide describes session state and protected-route behavior. The [data fetching, forms, and errors](data-fetching-forms-and-errors.md) guide describes query ownership.

## Router topology

`web/src/router.tsx` is the current application-route source of truth. It defines these public/general routes:

| Route | Source behavior |
|---|---|
| `/` | Public `StatusRoute` service overview; requests readiness and runtime metadata when mounted. |
| `/records` | Reference-record list and mutation workflow. |
| `/login` | Anonymous-only login entry. |
| `/register` | Anonymous-only local registration entry. |
| `/verify-email` | Verification workflow with route-local secret handling. |
| `/forgot-password` | Anonymous-only reset request entry. |
| `/reset-password` | Reset completion workflow with route-local secret handling. |

It defines these authenticated routes:

| Route | Source behavior |
|---|---|
| `/authorize` | OAuth authorization decision UI. |
| `/account` | Account overview. |
| `/account/security` | Password and broader security actions. |
| `/account/sessions` | Session listing and revocation. |
| `/account/api-keys` | Service account and API key management. |
| `/account/connected-apps` | Connected OAuth grant management. |

Route components are lazy-loaded. The application shell remains responsible for shared navigation, skip navigation, route focus, build/contract identity presentation, and contract-mismatch alerts.

The root route is not a static landing page. Its readiness and runtime-metadata queries require a compatible backend, so serving the source shell alone does not complete that journey.

The records route validates its URL-owned state before exposing it to a component:

- `limit` accepts 10, 25, 50, or 100 and otherwise resolves to 25;
- `cursor` must be a nonempty string no longer than 256 characters;
- `name` is trimmed and constrained to 1–100 Unicode code points when present.

This validation is browser-state hygiene, not backend authorization or validation.

## Base path and reserved routes

The application base path comes from Vite's public base URL and is normalized before it reaches TanStack Router. A deployment may therefore host the shell below a nested browser path. Backend APIs remain at origin-root paths such as `/api`; the nested browser base path does not move them.

The canonical static-delivery topology is imported from `crates/http/web-route-topology.json`. Development proxy and static fallback behavior must follow that shared topology:

1. recognized API and infrastructure paths belong to the backend;
2. websocket upgrade behavior applies only to declared websocket routes;
3. recognized application routes may receive the browser shell;
4. an unknown route must retain its intended backend or not-found semantics.

A catch-all that returns HTML for an API path is an architectural failure. The expected result for a direct application deep link is the shell; the expected result for a reserved backend path is backend handling, not the shell. The fixture tests exercise this distinction, but fixture behavior does not prove production mounting. See [static delivery and browser security](static-delivery-and-browser-security.md).

## Capability boundary

Application routes and components are not runtime availability evidence. Optional navigation and actions must be gated by the runtime capability document and by authorization decisions. The current checked capability artifact selects `oauth-provider` and marks `web-auth` unavailable at compiled and runtime layers. That active evidence does not assemble the checked-in route source.

Use [capability and consumer contracts](../../concepts/capability-and-consumer-contracts.md) for the canonical evidence layers. In particular:

- profile selection expresses intended composition;
- source proves an implementation exists;
- generation proves an artifact was produced;
- tests prove only their exercised target;
- runtime capability data reports the runtime being queried;
- route mounting and public exposure require separate evidence.

## State ownership

The architecture separates three state categories:

- **Server state:** TanStack Query owns fetched and mutated resources. Query keys include identity scope where required.
- **Authentication state:** the browser authentication manager owns the public principal snapshot and cross-tab synchronization.
- **Route state:** the router owns navigable filters and return paths after validation.

Ephemeral one-time values stay in memory and are removed from the address. Durable browser state is available through an SDK helper but is not proof that this application uses it for a specific workflow. Tenant transitions have a coordinator in the React SDK, while the checked tenant-switcher component is not imported into the application. See [authorization, tenancy, and capabilities](authorization-tenancy-and-capabilities.md).

## Error and failure boundaries

The shell may surface a contract mismatch reported by the transport. A route may surface a structured RFC 9457 problem or a network failure. Authentication guards may redirect to login with a validated same-origin return path. These are distinct failure classes and should not collapse into a generic success, empty state, or permission denial.

When application and API contract identities disagree, stop affected operations and show the mismatch. When a capability is absent, hide or disable the optional workflow rather than attempting an undocumented endpoint. When a route cannot restore a safe return path, use the route's safe local fallback.

## Integration review checklist

Before runtime verification, review that:

- one composition root owns the SDK, query cache, router, and authentication manager;
- application deep links and reserved backend paths follow shared topology;
- all optional routes and controls use runtime capability and authorization data;
- authenticated routes never rely on source presence as a guard;
- nested browser deployment does not rewrite origin-root API paths;
- unmounting closes authentication synchronization resources;
- route focus and skip navigation remain in the shared shell;
- contract mismatches remain visible.

## Evidence status

No build, test, or browser session was run for this page. The cited E2E files are inspected test evidence. Runtime acceptance requires an assembled application whose deep links, reserved routes, capability response, contract identity, focus behavior, and teardown are directly observed.
