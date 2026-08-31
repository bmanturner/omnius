---
title: Web realtime and uploads
description: Source-backed realtime and upload libraries, their lifecycle invariants, and the current contract and assembly gaps.
status: experimental
implementation: source-only
profile_availability:
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: unassembled
audience:
  - web developers
  - realtime integrators
  - file-workflow integrators
topics:
  - realtime
  - uploads
  - contracts
  - lifecycle
capabilities:
  - web-realtime
  - web-uploads
source:
  - packages/web-sdk/src/realtime/
  - packages/web-sdk/src/uploads/
  - packages/web-sdk/src/react/realtime.ts
  - packages/web-sdk/src/react/uploads.ts
  - packages/web-sdk/scripts/generate-realtime.mjs
evidence:
  - packages/web-sdk/src/internal/generated/realtime.ts
  - contracts/contract-manifest.json
  - web/e2e/browser.spec.ts
  - specs/26-consumer-contract-generation.md
last_verified: 2026-08-30
---

# Web realtime and uploads

The web SDK contains substantial realtime and upload implementations, but the browser-facing surfaces are not assembled. Their classifications differ:

| Surface | Implementation | Intended profiles | Exposure |
|---|---|---|---|
| Realtime | source-only because contract drift is unresolved | `realtime-web`, `saas-web`, `full-reference-web` | unassembled |
| Uploads | implemented library | `saas-web`, `full-reference-web` | unassembled |

A selected profile, package export, checked-in generated module, source component, or fixture test does not prove backend routes. The current browser fixture expects `/events`, `/realtime/ws`, and `/uploads` to be absent, and the current OpenAPI artifact has no `initiateBrowserUpload` operation.

Use [backend realtime](../backend/realtime.md) and [files, notifications, and webhooks](../backend/files-notifications-and-webhooks.md) for service-side semantics. Use the [availability matrix](../../reference/availability-and-exposure-matrix.md) for current status.

## Realtime contract drift gap

The current realtime generation path has a specific unresolved gap:

1. `packages/web-sdk/scripts/generate-realtime.mjs` reads `contracts/contract-manifest.json`.
2. If the manifest does not select `contracts/asyncapi.json`, the script reports that realtime generation is not selected.
3. It then exits successfully before inspecting or comparing existing generated realtime output.
4. The repository nevertheless contains `packages/web-sdk/src/internal/generated/realtime.ts`.
5. The package nevertheless exports `./realtime`.

The current contract tree has no selected AsyncAPI artifact. Therefore, a successful current generator check cannot establish that the checked-in generated realtime module matches a canonical contract, or that it should remain exported. This contradicts treating absence of input as a complete drift decision. The specification requires no-AsyncAPI selection to be represented by the contract manifest rather than inferred from a missing file, but manifest non-selection still leaves the existing generated output unchecked.

Until generator behavior, manifest selection, checked output, and export lifecycle agree, realtime drift is **not verified**. Do not use the generated module as proof of current wire compatibility.

## Realtime library boundary

The framework-neutral realtime SDK contains SSE and websocket transports, a connection/subscription manager, query effects, and typed public state. Its source models subscription creation and deletion, cursor-aware delivery, reconnect behavior, command correlation, authorization-driven revocation, and controlled teardown.

The React layer binds realtime state and effects to React Query. Integration must preserve identity and tenant scope: an event can invalidate or update only data whose resource, tenant, principal, and permission context match the event's authoritative scope.

A safe assembled lifecycle would require:

1. runtime capability and contract identity agreement;
2. a selected and validated AsyncAPI contract;
3. generated output proven current against that contract;
4. an actually mounted SSE and/or websocket endpoint;
5. authenticated connection establishment under the backend's selected mode;
6. explicit subscription acknowledgement before treating a stream as active;
7. cursor/reconnect behavior compatible with server retention semantics;
8. identity, membership, permission, and tenant changes that revoke or rebuild affected subscriptions;
9. teardown on logout, tenant transition, component ownership loss, and application disposal.

**Expected result:** the UI exposes connected/subscribed/reconnecting/revoked/failure states without presenting stale data as current.

**Failure path:** when contract, capability, route, or identity evidence is missing, keep realtime unavailable and retain polling/manual refresh behavior where the product contract supports it. Do not repeatedly reconnect to an undocumented route.

## Identity and tenant transitions

Realtime connections and subscriptions must not outlive the identity context that authorized them. A tenant transition should cancel or remove old-scope queries, reset local state, reestablish realtime under the next scope, then replace the route and publish ready.

The generic tenant coordinator has a realtime port for that phase. However, the checked browser authentication manager's realtime reset for an identity transition is an explicit no-op. That is an integration gap, not a valid default for an application claiming identity-scoped realtime.

Authorization or membership change events are invalidation signals. Refresh authoritative capabilities, principal, memberships, and permissions; do not grant authority from event payload alone.

## Upload coordinator

The upload SDK models a multi-phase workflow:

1. calculate a SHA-256 digest;
2. initiate and authorize the upload;
3. transfer one or more parts through a direct or proxied plan;
4. finalize with part receipts;
5. poll while the remote object is quarantined/scanning;
6. reach available, rejected, cancelled, failed, abandoned, or disposed state;
7. clean up when ownership ends.

An upload identity has two stable values:

- a business workflow key that must never be reused for different bytes;
- an idempotency key reused by retries, including finalize retries.

The initiation port must durably bind those identities to file size and digest before returning an authorized destination. Finalize must independently authorize completion and be idempotent under the workflow identity. These are client-port requirements; a real backend implementation remains necessary.

### Authorized destinations

A browser transfer target may specify an HTTP method, headers, raw or form body, and credential behavior. It is an opaque authorized destination. Treat it as sensitive even when it is time-limited:

- never put it in docs, logs, analytics, crash reports, durable browser state, or clipboard-oriented diagnostics;
- do not send unrelated default authorization headers to a cross-origin storage destination;
- follow only the method, fields, and headers returned for that part;
- do not reuse a destination for different bytes or a different workflow;
- clear targets and receipts when the coordinator is disposed.

### Availability and scanning

Transferred or finalized does not mean downloadable. The state machine exposes an object as available only after the backend reports `available`. A quarantined object remains unavailable while scanning. A rejected or deleted object must not retain an active download affordance.

**Expected result:** progress reflects transferred bytes, retries preserve workflow identity, and the UI offers the object only after remote availability.

**Failure path:** authorization, validation, identity conflict, checksum, transfer, finalize, scan, cancellation, retry exhaustion, remote rejection, and illegal state remain distinct rejection classes. Do not convert scan timeout or cleanup failure into success.

## React presentation

The React SDK contains upload integration helpers, and the web source contains an upload panel. The panel is not imported into the current application. Its presence does not prove a route, navigation entry, capability gate, or backend operation.

If assembled, the view should:

- label file selection and progress;
- allow cancellation where the coordinator can cancel safely;
- distinguish retryable from terminal rejection;
- announce phase and failure changes;
- remove sensitive destination details from user-visible errors;
- make quarantine/scanning explicit;
- abandon or dispose incomplete work when the owning view ends according to product policy.

## Troubleshooting boundaries

| Symptom | Evidence boundary | Response |
|---|---|---|
| Realtime drift check succeeds without AsyncAPI | Generator gap | Do not claim drift verification; reconcile manifest, output, and export. |
| `/events` or `/realtime/ws` is absent | Runtime assembly | Check selected capability and backend mounting; source is insufficient. |
| Events arrive after logout or tenant switch | Identity lifecycle | Close/revoke old subscriptions and clear affected query state. |
| Upload helper exists but initiation operation does not | Contract/runtime assembly | Keep upload unavailable; do not invent an endpoint. |
| Transfer completes but object remains quarantined | Scan lifecycle | Continue bounded status handling; do not expose as available. |
| Retried upload conflicts on identity | Workflow identity | Confirm the same bytes and same intended effect; never reuse the key for different content. |

## Verification checklist

An independent verifier must separately observe canonical AsyncAPI selection, generated-output comparison, endpoint mounting, connection authentication, subscription acknowledgement, reconnect/cursor behavior, logout and tenant teardown, upload initiation authorization, digest and part handling, idempotent finalize, quarantine-to-available transition, cancellation, cleanup, and secret-safe diagnostics.

No generator, realtime connection, upload, browser scenario, or test was run for this page. The current source and fixture evidence explicitly leave realtime drift and runtime assembly unresolved.
