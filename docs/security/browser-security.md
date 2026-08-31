---
title: Browser security
description: Protect Omnius browser sessions, navigation, contracts, static assets, realtime, and release evidence without treating frontend state as authority.
status: experimental
implementation: implemented
profile_availability:
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: generated-only
audience:
  - security-analyst
  - web-developer
  - operator
topics:
  - security
  - browser
  - web
capabilities: []
source:
  - web/src
  - packages/web-sdk/src
  - crates/http/src/web_security.rs
  - crates/http/src/static_delivery.rs
evidence:
  - web/e2e
  - docs/coverage-matrix.md
  - release/web-suite-runbook.md
last_verified: 2026-08-30
---

# Browser security

Browser security source and generated web profiles are implemented, and static delivery can be conditionally assembled by the reference API. The active checked-in `oauth-provider` capability artifact reports `web-auth: false`; no checked-in web application is proven active. Treat browser profile selection, generated SDKs, and E2E fixtures as generated evidence, not runtime exposure.

This page applies the [security model](security-model.md) to browsers. Use [identity, authorization, and tenancy](../concepts/identity-authorization-and-tenancy.md) for the authoritative backend model.

## Trust boundary

The browser is an untrusted client. It may:

- render permission and capability state for usability;
- hold same-origin session state according to the server contract;
- generate request IDs and idempotency keys within the client contract;
- reconnect and re-read authoritative state.

It must not:

- enforce authorization or tenant membership;
- store server secrets, API keys, signing material, or provider credentials;
- treat capability metadata as permission or route exposure;
- trust model/MCP output as HTML, navigation, consent, or approval;
- treat realtime messages, local storage, query cache, or BroadcastChannel traffic as authoritative.

## Implemented controls and limits

| Control | Evidence-qualified behavior |
|---|---|
| Session requests | SDK uses same-origin credential behavior; backend session/auth remains authoritative |
| Cross-tab coordination | BroadcastChannel messages are credential-free |
| URL fragments | Sensitive fragments are removed after processing |
| API keys | One-time display state is designed not to become durable browser storage |
| Route guards | Presentation/UX only; backend permission checks are required |
| Static assets | Vite manifest/fingerprints and conditional static delivery validate asset contracts |
| Cache policy | Fingerprinted assets are immutable; shell responses are revalidated/no-cache in tested policy |
| CSP/headers | Strict fixture policy avoids unsafe inline/eval and adds security headers |
| Source maps | Absent under the tested release policy |
| Optional routes | Current fixture expects `/events`, `/realtime/ws`, and `/uploads` not found; this is not a universal contract |

No evidence supports persisting browser secrets. Do not add local/session storage fallbacks for tokens or credentials.

## Threats and controls

### Cross-site request forgery and origin confusion

Use the assembled HTTP CSRF/CORS/session controls and an explicit trusted-origin policy. WebSocket upgrades require origin and authentication checks plus connection/message limits and ongoing authorization. Do not disable CSRF to repair an SDK mismatch; machine callback routes use a deliberately different contract and must not be reused for browser actions.

### Cross-site scripting and content injection

Keep a restrictive CSP, encode untrusted content, reject unsafe active content in static delivery, and do not render prompts, model output, MCP content, filenames, or provider errors as trusted markup. Avoid inline script/style exceptions that cannot be bound to an approved policy.

### Token and navigation leakage

Keep credentials in protected same-origin mechanisms. Remove sensitive URL fragments promptly, avoid referrer/log/history leakage, validate return targets, and never put tokens into query strings, telemetry, screenshots, BroadcastChannel, or support bundles.

### Contract and asset skew

Release API, capability/permission contracts, SDK, and browser assets from one revision. A generated client operation does not mean the server mounted it. Atomically retain and roll back the API/web artifact; do not mix old shells with new contracts.

### Realtime trust

Authenticate the connection, verify origin, bind tenant/principal, re-authorize subscriptions and effects, bound messages/connections, and reconnect by reading authoritative HTTP state. Redis Pub/Sub/local transports are ephemeral and do not prove replay.

## Security review procedure

**Prerequisites**

- concrete deployed application and capability artifact;
- candidate browser build, manifest, contracts, and CSP/header policy from one revision;
- approved non-production browser identities and tenant data;
- named accessibility, security, and release reviewers.

1. Confirm whether the application actually enables web/static/auth/realtime/upload capabilities.
2. Review credential storage and transport; reject browser persistence of secrets.
3. Exercise session expiry, cross-tab logout, fragment cleanup, denied permission, tenant switch, CSRF rejection, and safe error rendering.
4. Review CSP/security headers, source-map policy, manifest/fingerprints, cache classes, and symlink/active-content controls.
5. Verify navigation and UI guards never replace backend authorization.
6. Confirm optional routes fail safely when absent and the client does not loop/retry indefinitely.
7. Bind results to the release artifact and required manual accessibility evidence.

**Expected result:** the browser exposes only the candidate's concrete capabilities, retains no secrets, renders untrusted data safely, and fails closed without weakening backend controls.

**Failure path:** block release for token persistence/leakage, unsafe markup/CSP, missing origin/CSRF enforcement, contract skew, frontend-only authorization, or undeclared optional routes. Correct the client/server contract rather than adding a permissive fallback.

No browser or release verification was run while writing this page. See [web release and static delivery](../operations/web-release-and-static-delivery.md) and [web troubleshooting](../troubleshooting/web-sdk-auth-and-realtime.md).