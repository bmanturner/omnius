---
title: Web, SDK, auth, and realtime troubleshooting
description: Diagnose Omnius frontend build, SDK, browser authentication, client mounting, CSP, static delivery, events, and realtime symptoms without assuming an assembled web runtime.
status: experimental
implementation: partial
profile_availability:
  - web-sdk-only
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: unassembled
audience:
  - frontend-developer
  - operator
topics:
  - troubleshooting
  - web
  - realtime
capabilities: []
source:
  - web/
  - web/src/main.tsx
  - crates/http/src/static_delivery.rs
  - crates/http/src/web_security.rs
  - templates/base-service/apps/service/src/lib.rs
evidence:
  - templates/base-service/apps/service/tests/http.rs
  - web/e2e/generated-profile.spec.ts
  - specs/machine/extensions/web-application-suite/profiles.yaml
  - docs/coverage-matrix.md
last_verified: 2026-09-03
---

# Web, SDK, auth, and realtime troubleshooting

Omnius includes frontend source, generated web profiles, SDK contracts, and Rust static-delivery/security libraries, but checked-in applications do not assemble a web runtime. The active web capability record reports `web-auth: false`. Fixture tests expect `/events`, `/realtime/ws`, and `/uploads` to return 404. Diagnose composition before debugging a browser symptom.

Use [web application architecture](../guides/web/application-architecture.md) for the canonical contract and [browser security](../security/browser-security.md) for trust boundaries.

## The browser receives 404 or no application shell

**Discriminating evidence:** concrete application revision, mounted routes, static-delivery configuration, manifest/build identity, base path, and requested path.

**Likely causes:** no checked-in app mounted web delivery, stale/missing manifest, build/base-path mismatch, or a non-HTML API/static path correctly not using SPA fallback.

**Safe diagnostic:** prove the composition root owns the static manifest and shell. Compare immutable build identity and base path. Do not infer a mount from templates, profiles, generated artifacts, or library source.

**Resolution:** deploy a concrete application composition with one atomic static build and reviewed HTTP/browser policy. Never add universal HTML fallback to make API or asset failures disappear.

**Escalation data:** URL path without sensitive query, response status/content type, revision, static build identity, base path, manifest lookup result, and safe server error.

No web runtime or browser scenario was run while writing this page.

## Static assets 404 while the shell loads

**Discriminating evidence:** shell build identity, manifest entry, requested fingerprinted asset, base path, cache header class, and rollout overlap.

**Likely causes:** mixed shell/assets revisions, incorrect base path, partial upload, or manifest mismatch.

**Safe diagnostic:** compare the shell and asset manifest from the same release artifact. Do not weaken CSP or serve mutable stale bundles as a workaround.

**Resolution:** publish/switch the static artifact atomically and retain compatible immutable assets for the rollout window. Roll back shell and assets together.

## API calls fail despite a rendered page

**Discriminating evidence:** actual API origin/base URL, browser network status, content type, request correlation, credential mode, CORS/preflight result, and server revision.

**Likely causes:** SDK base-path/schema drift, API route absent, wrong origin, CORS/policy mismatch, authentication not assembled, or proxy returning the shell for an API path.

**Safe diagnostic:** distinguish network, HTTP, parse, authentication, authorization, validation, conflict, and server categories. Compare generated SDK/contracts with the deployed API revision; generation does not prove compatibility.

**Resolution:** align the web/API release and explicit origin/base-path policy. Keep responses typed and do not parse HTML as JSON or relax cross-origin credentials globally.

## Login UI is present but login is unavailable

**Discriminating evidence:** active capability contract and actual mounted backend identity routes.

**Likely cause:** route/UI source or a generated profile was mistaken for runtime assembly. The active capability record has `web-auth: false`; no checked-in web application composition proves the flow.

**Safe diagnostic:** verify backend route availability and cookie/CSRF contract before browser-state debugging.

**Resolution:** remove/disable unsupported UI in that deployment or compose the complete backend/browser contract. Route guards and hidden controls are UX only; backend authorization remains authoritative.

## A request with cookies is rejected as CSRF

**Discriminating evidence:** authentication method, request method/origin, cookie attributes without value, CSRF header/cookie presence without token value, and safe server code.

**Likely causes:** missing/mismatched CSRF material, origin mismatch, insecure cookie deployment, or incorrect SDK credential behavior.

**Safe diagnostic:** inspect attributes and presence in an approved browser. Never record cookie or CSRF values.

**Resolution:** align the SDK with the server's cookie/CSRF policy and trusted origin. Do not disable CSRF, place sessions in browser storage, or broaden origins indiscriminately.

## The client application does not mount or a lazy route fails to load

**Discriminating evidence:** presence of the HTML `#root` container, shell/chunk build identity, requested asset URL/status/content type, route/base path, CSP violation category, and first JavaScript or framework error.

**Likely causes:** a missing root container, mixed shell and chunk revisions, an incorrect base or public asset path, a failed lazy-chunk request, CSP or integrity rejection, or extension/cached-asset interference.

**Safe diagnostic:** use a clean approved browser profile. Verify that `index.html` contains `#root`, the main module is fetched, and matching fingerprinted chunks load; record errors and paths without copying sensitive values.

**Resolution:** deploy a compatible shell and assets atomically, correct the root/base path and CSP or integrity wiring, and fix the first mount/runtime error rather than weakening browser policy. This Vite SPA uses `createRoot`; SSR bootstrap serialization and hydration remedies do not apply.

## Realtime connection fails or updates are missed

**Discriminating evidence:** requested path/transport, HTTP status, mounted route inventory, provider, connection interval, and authoritative resource version.

**Likely causes:** no public realtime route (expected for checked-in fixture), client chose an unsupported transport, transient disconnect, or ephemeral provider delivery.

**Safe diagnostic:** first prove the route is mounted. After any gap, re-read authoritative HTTP state; events are invalidation hints unless a durable replay contract is actually composed.

**Resolution:** compose/document the intended transport and lifecycle or keep realtime disabled. Do not invent `/events` or `/realtime/ws`, and do not promise replay from Redis Pub/Sub or process-local delivery.

## PWA install, caching, or update behavior is absent

**Discriminating evidence:** an actual service-worker registration, deployable worker and manifest artifacts, and an explicitly selected capability/profile module.

**Likely cause:** the capability is not implemented. The checked-in web profile catalog contains no PWA module or selectable PWA profile, and the source shell contains no service-worker registration.

**Resolution:** treat PWA behavior as unavailable. Do not infer it from a generic web profile or static assets; a future implementation would require an explicit module/profile and a reviewed cache, update, and security lifecycle before any runtime claim.

See [web release and static delivery](../operations/web-release-and-static-delivery.md) and [startup troubleshooting](startup-and-configuration.md).