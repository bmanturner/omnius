---
title: Web static delivery and browser security
description: Base-path builds, route-aware static fallback, cache policy, browser headers, and same-origin deployment boundaries.
status: experimental
implementation: implemented
profile_availability:
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: generated-only
audience:
  - web developers
  - platform engineers
  - security reviewers
topics:
  - static-delivery
  - browser-security
  - caching
  - deployment
capabilities:
  - web-static-delivery-and-browser-security
source:
  - web/vite.config.ts
  - crates/http/web-route-topology.json
  - templates/base-service/apps/service/src/lib.rs
  - templates/base-service/ops/Dockerfile
evidence:
  - web/e2e/security.spec.ts
  - web/e2e/base-path.spec.ts
  - web/e2e/release-gates.config.test.mjs
  - release/web-suite-runbook.md
last_verified: 2026-08-30
---

# Web static delivery and browser security

The repository implements generated static-delivery policy for web profiles. Its public exposure is generated-only: templates, Vite configuration, and fixture tests do not prove a production deployment. A concrete generated service must be built, served, and inspected before its headers, fallback behavior, caching, and source-map policy are operational claims.

Use [browser security](../../security/browser-security.md) for the canonical threat boundary and [web release and static delivery](../../operations/web-release-and-static-delivery.md) for release operations.

## Same-origin deployment model

The checked application assumes browser shell and API share an origin. Browser requests default to same-origin credentials. Static delivery must therefore keep three namespaces distinct:

- the browser application's configured base path;
- origin-root backend/API paths;
- immutable generated asset paths.

A nested application base path changes where browser routes and assets live. It does not move the API below that base. Cross-origin deployment requires a separately reviewed credential, CORS, CSRF, and content-security design; it is not implied by the checked source.

## Build-time inputs

`web/vite.config.ts` validates build inputs for:

- a canonical public base path;
- build time;
- source revision;
- development proxy origin;
- route topology imported from `crates/http/web-route-topology.json`.

It injects generated contract identity into the application. Build manifest generation is enabled, the output targets ES2024, and asset/chunk names are content-hashed. Source maps are disabled by default, with hidden maps for private handling and public maps only under explicit public selection.

These inputs must be non-secret. Build-time values become observable in generated files or metadata. Never put cookies, bearer values, one-time authentication material, API keys, presigned destinations, private service credentials, or production-only secrets into Vite-exposed configuration.

**Expected result:** the shell identifies the intended build and contract, and its asset URLs resolve below the normalized base path.

**Failure path:** reject malformed base paths or incomplete build identity rather than emitting a bundle with ambiguous routing or compatibility.

## Route-aware fallback

The static server and development proxy share a route-topology source. A safe request decision is:

1. serve a known generated asset when it exists;
2. preserve declared API, health, metrics, websocket, and other reserved backend routes;
3. return the shell only for recognized browser application routes;
4. retain a not-found response for unknown paths.

The fixture evidence expects a browser deep link to return HTML while API paths are not swallowed by the shell. It also expects an unknown application path to remain not found. This avoids the common failure where an API typo returns HTML with a success status.

Websocket proxying is restricted to topology-declared websocket routes. Do not enable websocket upgrade on every proxied request.

## Cache policy

The intended delivery policy separates mutable shell/navigation responses from immutable content-addressed assets:

| Resource | Intended behavior |
|---|---|
| Application shell and deep-link HTML | Revalidated/no-cache semantics so a new release can replace contract and asset references. |
| Hashed static assets | Long-lived immutable caching; ETag support remains useful for validation and intermediaries. |
| API responses | Backend-owned cache semantics; never inherit static-asset policy. |
| Source maps | Absent publicly unless explicitly selected and reviewed. |

A release must publish API compatibility and the shell/asset set coherently. Rolling back only HTML while retaining incompatible API behavior, or rolling back API behavior without compatible generated web assets, can create contract mismatch and broken routes.

## Browser security headers

The fixture security source checks for a policy equivalent in intent to:

- a Content Security Policy without inline-script or eval allowances;
- denial of framing;
- MIME sniffing disabled;
- a no-referrer policy;
- a restrictive permissions policy.

The exact production CSP must be generated from the assembled asset and connection needs. It should narrowly identify self-hosted scripts/styles, API connections, and explicitly selected realtime endpoints. Do not add broad wildcards, inline allowances, or eval allowances to fix a build defect. If a required resource violates policy, correct asset ownership or declare the exact trusted source after security review.

The frame policy should have one unambiguous outcome across CSP and legacy headers. MIME protection requires assets to carry correct content types. Permissions policy should disable browser features the application does not use.

The checked fixture expectations are not observed production headers. Reverse proxies and CDNs can remove, duplicate, or weaken them, so verification must inspect the public response path.

## Cross-origin mutation defense

The fixture security evidence contains a negative cross-origin mutation scenario. Same-origin cookies require a complete server-side CSRF design; client-side same-origin fetch configuration alone is insufficient.

An assembled application must ensure:

- mutating requests are accepted only under the backend's origin/CSRF policy;
- cookies have appropriate Secure, HttpOnly, SameSite, path, and lifetime attributes at issuance;
- redirects do not bypass mutation checks;
- CORS does not reflect arbitrary origins with credentials;
- API and upload destinations do not receive unrelated authorization headers;
- error responses remain security-header compliant.

Do not publish cookie values or CSRF material in troubleshooting examples.

## Source maps and artifact hygiene

The default build does not expose source maps. A private hidden-source-map workflow still requires controlled storage, access, retention, and deletion. “Hidden” means not referenced by the browser bundle; it does not make an uploaded map non-sensitive.

Release inspection should also reject fixture-only content, local origins, private paths, test credentials, one-time-token shapes, or accidental environment material in HTML and assets. String scanning is one control, not proof that application state and telemetry are secret-safe.

## Development proxy boundary

The Vite proxy is a development convenience governed by the same route topology. It is not a production gateway design. Its origin configuration is validated, and websocket behavior is route-specific.

**Expected result:** local browser routes load through Vite, while declared backend routes reach the intended development backend with their original root paths.

**Failure path:** if a browser route or backend path is ambiguous, update the shared topology and both consumers together. Do not add an unreviewed proxy exception that production static delivery cannot reproduce.

## Deployment verification checklist

For a concrete generated service, independently observe:

- root and nested-base shell loading;
- direct browser deep links;
- API/reserved paths retaining backend responses;
- unknown paths retaining not-found semantics;
- asset content type, immutable caching, and ETag behavior;
- HTML revalidation behavior;
- CSP and other security headers on success and error responses;
- public source-map absence under the selected policy;
- cross-origin mutation denial;
- absence of fixture/private/secret material from built assets;
- contract identity agreement between browser and API;
- coordinated API/static rollback.

No generation, build, server, browser, header inspection, or test was run for this page. Template and fixture evidence is generated-only policy evidence, not a production security result.
