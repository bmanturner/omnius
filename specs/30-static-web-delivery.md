---
spec_id: RSK-030
title: Static Web Delivery
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Static Web Delivery

## 1. Purpose

The `web-static` module allows the Rust service to serve the production browser application without a separate JavaScript server. It uses the existing Axum/Tower runtime and `tower-http` filesystem service rather than implementing file serving, range requests, or content metadata from scratch.

## 2. Route ownership

The composition root MUST reserve backend namespaces before installing the SPA fallback. At minimum:

```text
/api/*
/ws
/events
/_health/*
/_metrics
```

The exact list is generated from enabled modules.

The SPA fallback MUST:

- apply only to `GET` and `HEAD`.
- apply only after backend routes fail to match.
- never convert an API or transport 404 into `index.html`.
- reject path traversal and malformed paths.
- return the configured application shell.
- preserve a real 404 mode for deployments that do not use client routing.

## 3. Production artifacts

The production web build MUST emit:

- content-hashed JavaScript and CSS assets.
- an application shell.
- an asset manifest.
- embedded build revision.
- embedded aggregate contract hash.
- optional precompressed Brotli, gzip, or Zstandard variants supported by the selected server/browser policy.
- license notices required by dependencies.

The Rust build MAY embed the assets or copy them into the runtime image. The default SHOULD copy a directory into the final image to avoid recompiling Rust for every frontend-only change, unless single-binary distribution is an explicit profile goal.

Missing required production assets MUST fail startup or readiness; a production web profile MUST NOT silently expose only the API.

## 4. Cache policy

Default response policy:

```text
fingerprinted assets:
  Cache-Control: public, max-age=31536000, immutable

index.html and manifest-like bootstrap files:
  Cache-Control: no-cache

public runtime metadata:
  Cache-Control: no-store or short-lived according to deployment policy
```

ETags or equivalent validators SHOULD be enabled where supported. `index.html` MUST NOT be cached immutably because it selects the current asset graph.

## 5. Security headers

The module MUST integrate with the base HTTP security policy and define:

- Content-Security-Policy.
- `X-Content-Type-Options: nosniff`.
- frame-ancestor/clickjacking policy.
- referrer policy.
- permissions policy.
- HSTS at the appropriate TLS boundary.
- cross-origin opener/resource/embedder policies when application requirements permit.

CSP MUST avoid `unsafe-eval` in production. Inline scripts/styles require an explicit nonce/hash strategy or must be removed. Development CSP MAY be less strict for HMR but MUST be separate from production policy.

## 6. MIME, compression, and ranges

The implementation MUST use battle-tested serving middleware. It MUST:

- emit correct content types.
- negotiate only available precompressed variants.
- set `Vary` correctly.
- avoid double compression.
- support range requests where the underlying service safely supports them.
- avoid serving source files, environment files, contracts intended only for build use, or package metadata unintentionally.

## 7. Source maps

Source-map policy MUST be explicit:

- disabled.
- private and uploaded to an error-monitoring service.
- publicly served.

Production profiles SHOULD NOT publicly serve source maps by default. If maps are uploaded, the release identifier MUST match build metadata.

## 8. Development integration

Development MUST use Vite's development server with proxy rules for API and realtime paths. The generator MUST produce a single source of route-path configuration used by:

- Vite proxy configuration.
- SDK runtime configuration.
- Rust route assembly.
- browser E2E configuration.

HMR MUST remain a Vite concern. Axum MUST NOT attempt to implement HMR.

The development proxy MUST support:

- HTTP API requests.
- WebSocket upgrades.
- SSE streaming without buffering.
- secure-cookie development policy.
- configurable Rust target.
- IPv4/IPv6 host consistency.

## 9. Base path and reverse proxies

The module MUST support deployment at `/` and an explicitly configured public base path. Asset URLs, router base, API URLs, WebSocket URLs, and metadata endpoints MUST agree.

Trusted proxy configuration remains governed by the base HTTP specification. Static delivery MUST not broaden trust of forwarded headers.

## 10. Container build

The reference container SHOULD use:

1. A pinned Node/pnpm stage to install and build the web workspace.
2. A pinned Rust stage to compile the server.
3. A minimal non-root runtime image containing the server and web artifacts.

Build caches MUST not make lockfile changes invisible. Production dependency installation MUST be frozen. Secrets MUST use build-secret mechanisms and MUST not be copied into layers or client bundles.

## 11. Observability

Expose metrics for:

- static requests by status and asset class.
- bytes served.
- cache-control class.
- fallback count.
- missing-asset failures.
- contract mismatch reports.

Asset path labels MUST be normalized to avoid high cardinality.

## 12. Testing

Required tests include:

- asset serving.
- immutable cache headers.
- non-immutable shell.
- deep-link fallback.
- API 404 preservation.
- path traversal rejection.
- content type.
- precompressed negotiation.
- missing production build behavior.
- base-path deployment.
- CSP/security headers.
- Vite HTTP/WebSocket/SSE proxy.
- production container smoke test.

## 13. Acceptance linkage

This specification is satisfied by `AC-WEB-051` through `AC-WEB-060`.
