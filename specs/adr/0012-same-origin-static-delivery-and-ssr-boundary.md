---
spec_id: RSK-ADR-0012
title: Default to Same-Origin Static Delivery and Keep SSR Out of the Baseline
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Default to Same-Origin Static Delivery and Keep SSR Out of the Baseline

## Context

A browser application can be deployed as static assets served by Axum, from a CDN, or behind a JavaScript SSR runtime. The default should minimize operational components while supporting secure first-party sessions.

## Decision

The default `web` profile:

- builds a Vite SPA.
- serves production assets from Axum using `tower-http`.
- uses same-origin API, session, WebSocket, and SSE paths.
- uses the Vite dev server with proxying in development.
- does not include SSR, React Server Components, or a Node production server.

Static CDN and separate-origin deployments are supported configuration variants. SSR requires a new adapter/profile and ADR.

## Consequences

- Cookie/CORS complexity is minimized in the default.
- SEO/content requirements that truly need server rendering are not solved by the baseline.
- The static service must implement correct fallback, cache, CSP, and asset behavior.
- A future Leptos or JavaScript SSR adapter can reuse contracts and client core.

## Rejected alternatives

- Always separate frontend and API origins: needless default CORS/cookie complexity.
- Mandatory SSR: adds runtime and deployment coupling many applications do not need.
- Custom Rust file server: duplicates hardened `tower-http` behavior.
