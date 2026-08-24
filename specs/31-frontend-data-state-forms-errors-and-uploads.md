---
spec_id: RSK-031
title: Frontend Data, State, Forms, Errors, and Uploads
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Frontend Data, State, Forms, Errors, and Uploads

## 1. State ownership

The generated application MUST use the following ownership model:

| State | Owner |
|---|---|
| Remote resources, lists, mutations, cache | TanStack Query |
| Route parameters, filters, pagination links, shareable UI state | TanStack Router/search parameters |
| Form drafts and validation state | React Hook Form or component-local form state |
| Authenticated principal/session resource | TanStack Query plus auth lifecycle helpers |
| Realtime connection manager | Framework-neutral SDK lifecycle |
| Ephemeral client-only state | Component state or optional Zustand |
| Durable server truth | Rust application and persistence modules |

Data fetched from the API MUST NOT be copied into Zustand as a routine pattern.

## 2. Query defaults

The SDK MUST define documented defaults for:

- retry classifications.
- mutation retry behavior.
- stale time.
- garbage collection.
- focus and reconnect refetch.
- offline behavior.
- cancellation.
- problem-details error handling.

Defaults MAY be overridden by operation metadata or product code. Authentication, validation, authorization, conflict, and not-found errors MUST not receive generic retry loops.

## 3. Pagination and collection utilities

The SDK MUST expose standard primitives for the backend's cursor-pagination convention:

- typed cursor parameters.
- finite queries.
- infinite-query options.
- next/previous cursor extraction.
- filter/sort normalization.
- reset-on-filter-change behavior.
- URL serialization.
- duplicate-item reconciliation policy.

Cursors MUST remain opaque to product code. Pagination utilities MUST preserve tenant and permission scope in query keys.

## 4. Idempotent mutations and concurrency

For operations marked idempotent-key capable, the SDK MUST support:

- cryptographically strong idempotency-key generation.
- caller-supplied keys for workflow recovery.
- stable reuse across one controlled retry sequence.
- no reuse across unrelated business actions.
- visibility in diagnostics without treating the key as a credential.

Optimistic-concurrency contracts such as ETags or version fields MUST have standard client helpers. Conflict responses MUST become typed problems suitable for refresh, merge, or user-directed resolution.

## 5. RFC 9457 problem handling

The application MUST have one normalized error pipeline. It MUST preserve:

- status.
- problem `type`.
- title.
- presentation-safe detail.
- stable application error code.
- field violations.
- request ID.
- retry-after metadata.
- conflict/current-version metadata where defined.
- underlying cause category.

The UI MUST be able to present the request ID for support without exposing stack traces or internal SQL/provider details.

Network errors, aborted requests, invalid responses, and contract mismatches MUST remain distinguishable from application problems.

## 6. Forms

React Hook Form is the default for nontrivial forms. Zod MAY provide client-side validation and transformation, but:

- Rust remains authoritative.
- Client schemas MUST derive from or be tested against contract schemas when they represent the same request.
- Client validation MUST not reject valid server inputs through drift.
- Server field violations MUST map back to controls.
- Global form errors MUST remain visible.
- submission MUST be cancellable or protected against double submission.
- accessibility semantics MUST be preserved.
- destructive actions SHOULD require deliberate confirmation proportional to risk.

Simple forms MAY use native/component-local state when a form library adds no value.

## 7. Local state

Zustand is optional. A new durable store requires a documented reason and ownership statement. Appropriate uses include:

- editor/workbench state not yet persisted.
- transient multi-step UI workflows.
- panel layout.
- local selection sets.
- safe local preferences.

Inappropriate uses include:

- lists fetched from the backend.
- the canonical user or organization record.
- a second permission cache.
- secrets or bearer tokens by default.
- data whose invalidation is already handled by TanStack Query.

Persisted local state MUST be versioned and migrated or discarded safely.

## 8. Uploads

The upload adapter MUST support the base object-storage and quarantine workflow. It MUST provide:

- metadata/initiation request.
- direct or proxied upload according to backend contract.
- streaming/progress where browser APIs permit.
- cancellation.
- multipart/resumable behavior when enabled.
- checksum support.
- completion/finalization.
- scan/quarantine status polling or realtime updates.
- retry semantics that do not duplicate objects.
- cleanup of abandoned uploads.
- typed rejection reasons.

A signed upload URL is a capability, not an authorization bypass. The backend MUST authorize initiation and completion. Object availability MUST remain false until required validation/scanning completes.

## 9. Feature flags and capabilities

The SDK MUST distinguish:

- structural compiled capabilities from `capabilities.json`.
- runtime provider availability.
- product feature flags.
- entitlements/permissions.

A capability check answers whether an integration exists. A feature flag answers whether behavior is enabled for a context. A permission answers whether the current principal may act. Product code MUST not conflate them.

## 10. Tenant-sensitive state

On tenant change:

- cancel in-flight tenant-scoped work where possible.
- invalidate or remove tenant-scoped queries.
- reset tenant-local form/store state.
- reconnect realtime subscriptions.
- update route state.
- prevent stale tenant content from flashing.

## 11. Testing

Required tests include:

- query retry classifications.
- cancellation.
- cursor pagination and URL round-trip.
- idempotency-key reuse boundaries.
- optimistic-concurrency conflict.
- RFC 9457 field mapping.
- form server-error mapping.
- Zustand absence from server-state paths.
- upload cancel/resume/finalize/quarantine.
- feature/capability/permission distinction.
- tenant switch isolation.

## 12. Acceptance linkage

This specification is satisfied by `AC-WEB-061` through `AC-WEB-068`.
