---
spec_id: RSK-ADR-0011
title: Separate Server, URL, Form, Realtime, and Client-Local State
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Separate Server, URL, Form, Realtime, and Client-Local State

## Context

Frontend boilerplates often introduce a global store that duplicates backend resources already cached by a server-state library. This creates conflicting sources of truth and difficult invalidation.

## Decision

- TanStack Query owns remote/server state.
- TanStack Router owns route and shareable URL state.
- React Hook Form or component state owns form state.
- The framework-neutral realtime client owns connection lifecycle.
- Component state or optional Zustand owns genuinely client-local state.
- Rust remains authoritative for durable state.

Zustand is optional and MUST NOT be used as a routine mirror of API resources, permissions, session records, or tenant resources.

## Consequences

- Query keys and invalidation are public SDK concepts.
- Tenant and principal changes require explicit cache isolation.
- Local persisted stores require versioning and ownership documentation.
- Semantic hooks may compose these systems but may not collapse them into one global store.

## Rejected alternatives

- Zustand/Redux for all data: duplicates Query behavior and invites drift.
- No server-state cache: loses mature concurrency, cancellation, retries, and invalidation.
- URL state in a global store: breaks shareability, navigation, and browser semantics.
