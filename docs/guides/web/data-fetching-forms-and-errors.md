---
title: Web data fetching, forms, and errors
description: React Query ownership, identity-scoped keys, safe RFC 9457 form mapping, and reference-record mutation semantics.
status: experimental
implementation: implemented
profile_availability:
  - full-reference-web
public_exposure: unassembled
audience:
  - web developers
  - API integrators
topics:
  - data-fetching
  - forms
  - errors
  - concurrency
capabilities:
  - web-react-state
  - web-data-forms-errors-and-reference-records
  - web-local-state
source:
  - packages/web-sdk/src/react/core.ts
  - packages/web-sdk/src/react/forms.ts
  - packages/web-sdk/src/react/query-scope.ts
  - packages/web-sdk/src/react/local-state.ts
  - web/src/routes/reference-records-route.tsx
evidence:
  - web/e2e/browser.spec.ts
  - packages/web-sdk/src/client/etag.ts
  - packages/web-sdk/src/client/idempotency.ts
  - contracts/openapi.json
  - specs/machine/extensions/web-application-suite/profiles.yaml
last_verified: 2026-08-30
---

# Web data fetching, forms, and errors

This page combines two evidence scopes without merging their availability:

| Surface | Implementation | Profile availability | Exposure |
|---|---|---|---|
| React state helpers (`web-react-state`) | implemented | `web`, `realtime-web`, `saas-web`, `full-reference-web` | library-only |
| Local-state ownership and restoration (`web-local-state`) | implemented | `full-reference-web` | library-only |
| Reference records/forms workflow | implemented | no distinct profile ID | unassembled |

Because frontmatter cannot express per-capability exposure, it records the `full-reference-web` selection contributed by `web-local-state` while conservatively retaining the unassembled route exposure. Do not apply that profile or exposure to every table row. React and local-state SDK source is reusable library evidence, not proof that a route or local store is generated, mounted, or served. See the [availability matrix](../../reference/availability-and-exposure-matrix.md) for the separate rows. Backend HTTP semantics belong to [HTTP APIs](../backend/http-apis.md), canonical problem fields belong to the [error model](../../reference/error-model.md), and the route-level source inventory belongs to [reference application workflows](reference-application-workflows.md).

## React SDK provider

`WebSdkProvider` binds one service client and one TanStack Query client to a React tree. It rejects conflicting authentication configuration so application code cannot accidentally apply an auth adapter on top of its designated authentication owner.

The checked query defaults are:

- 30 seconds stale time;
- 5 minutes garbage-collection time;
- refetch on window focus;
- refetch on reconnect;
- query retry up to two times under the configured predicate;
- mutation retry disabled.

These are library defaults, not universal service guarantees. An operation still needs a selected capability, mounted backend, and explicit retry safety. Do not enable generic mutation retries to mask network uncertainty.

## Query-key ownership

Query keys are scoped with explicit tenant, principal, and optional permission context. This prevents server state from one identity context being reused by another. Use one key factory per resource family and derive invalidation from that factory rather than from ad hoc string prefixes.

A safe query lifecycle is:

1. validate route and identity inputs;
2. construct the scoped key;
3. call the generated operation through the application client;
4. expose pending, success, empty, structured failure, and contract-mismatch states distinctly;
5. invalidate only the affected scoped resource family after a confirmed mutation;
6. clear affected scoped queries during logout or tenant transition.

The server remains responsible for access control and filtering. A scoped key protects browser cache boundaries; it does not authorize the request.

## URL-owned list state

The reference records route owns list state in the URL so navigation and reload reproduce the view. Its current parameters are:

| Parameter | Browser validation |
|---|---|
| `limit` | 10, 25, 50, or 100; otherwise 25. |
| `cursor` | Nonempty string, at most 256 characters. |
| `name` | Trimmed value of 1–100 Unicode code points when present. |

The list operation sends these values to `GET /reference-records`. The UI offers next-page navigation and a return-to-first-page action. It does not document arbitrary cursor traversal or a total-count guarantee.

**Expected result:** a valid URL reproduces the same list request and state.

**Failure path:** invalid URL state is normalized by router validation. Backend validation still applies and may return a structured problem.

## Create workflow

Creating a reference record sends JSON to `POST /reference-records` with an `Idempotency-Key`. The key identifies one intended effect and must not be reused for a different payload.

**Expected result:** a confirmed creation invalidates the scoped record list and presents the created state once.

**Failure path:** if the result is unknown after a network interruption, retry only under the operation's idempotency contract with the same key and same intended payload. Do not generate a fresh key for the same uncertain effect. Canonical replay semantics are described in [reliability and idempotency](../../concepts/reliability-and-idempotency.md).

## Update and conflict workflow

Updating a record sends JSON to its resource path with `If-Match: "v<version>"`, derived from the version last read by the client. The route recognizes conflict/precondition statuses 409, 412, and 428.

The user can reload the current server value or choose a retry path. The retry path first fetches the latest representation, then performs a new update using that latest ETag. It does not silently overwrite with a stale version.

**Expected result:** a matching version updates the record and invalidates the scoped list.

**Failure path:** a conflict remains visible with explicit reload/retry choices. If the latest read or retry fails, preserve that failure and do not claim the original edit was saved.

The current route has no delete workflow. Do not document or infer one from generic SDK capability.

## RFC 9457 problem mapping

The transport distinguishes structured problem details from network, abort, invalid-response, configuration, and contract-mismatch failures. The form helper can map RFC 9457 validation entries to fields while preserving a summary and request identifier.

Safe mapping rules include:

- accept only bounded, valid pointer paths;
- reject prototype-related segments and unsafe traversal;
- map only to registered form fields;
- keep unmapped or global errors in the form summary;
- render text as text, never as trusted markup;
- preserve the request identifier for support without exposing sensitive request content;
- bound the number and size of messages shown.

A problem response is not automatically a field error. Authentication, authorization, not-found, conflict, rate-limit, and service failures usually remain summary or workflow-level states unless the API contract supplies a valid field mapping.

## Form submission state

A mutation form should prevent accidental duplicate submission while one effect is active, but it must remain keyboard-operable and expose progress. On completion:

- success clears or advances state only after server confirmation;
- validation failures retain safe user input and focus/announce the summary;
- conflicts retain the attempted edit for an explicit recovery decision;
- contract mismatches stop the operation;
- unknown network outcomes preserve idempotency context where the operation supports it;
- aborted requests do not appear as success.

The React form helpers are library-only. Their presence does not prove that every checked-in route uses every helper or that an active backend returns compatible problems.

## Local state

`web-local-state` is implemented reusable library behavior and is selected only by `full-reference-web`. `assertLocalStateOwnership` permits explicitly client-local ephemeral or durable categories and rejects remote/server truth, authenticated principals, authentication secrets, and permission caches. Durable descriptors require a positive schema version. `restoreLocalState` validates and decodes the current envelope, can migrate an older version, and safely discards malformed, future-version, invalid, or unmigratable state.

These helpers remain library-only: their source and profile selection do not prove that an application has created a store or exposed browser behavior. Use ephemeral memory for one-time values and transient UI state. Durable state requires an explicit non-sensitive use case, versioning, and identity/tenant reset policy.

Never store session cookies, bearer values, verification/reset/invitation material, API key values, presigned upload URLs, or raw authorization decisions through the durable helper. Browser persistence is a data boundary, not a convenience default.

## Troubleshooting boundaries

| Symptom | Likely boundary | Correct response |
|---|---|---|
| Generated operation returns not found | Runtime assembly/exposure | Check capability and route mounting; generation alone is insufficient. |
| Data from a previous tenant appears | Query scope/transition | Remove old-scope queries and audit every key. |
| Mutation appears twice | Idempotency/submission ownership | Reuse the same effect identity only under the API contract; prevent competing submitters. |
| Field errors appear on unrelated inputs | Pointer mapping | Reject unsafe or unknown paths and preserve them in the summary. |
| Update repeatedly conflicts | Concurrency | Reload authoritative state and require a deliberate new edit/retry. |
| Contract mismatch appears | Release compatibility | Stop affected operations and align API and web artifacts. |

## Verification checklist

An independent assembled-runtime scenario should observe URL restoration, scoped query keys, list paging, create idempotency, update preconditions, conflict recovery, safe problem mapping, focus/announcement of failures, abort behavior, and query clearing across identity changes. It should record the runtime capability and contract identity used.

No browser workflow, HTTP request, package test, or generated profile was run for this page. The fixture E2E, checked SDK source, and profile selection do not establish an assembled local-state consumer or active reference-record route.
