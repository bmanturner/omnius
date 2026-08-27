---
spec_id: OMNIUS-ADR-0010
title: Derive Frontend Integrations From Backend Consumer Contracts
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Derive Frontend Integrations From Backend Consumer Contracts

## Context

Without a formal boundary, frontend projects routinely duplicate DTOs, hand-code fetch wrappers, invent incompatible error handling, and integrate backend modules inconsistently.

## Decision

The Rust composition root generates deterministic OpenAPI, AsyncAPI, permission, capability, and contract-manifest artifacts. TypeScript HTTP/event types and baseline client bindings derive from those artifacts.

Every browser-facing module declares its frontend exposure. Generated operation access is universal; hand-written hooks/utilities are added only when they provide semantic behavior.

## Consequences

- Stable operation, permission, event, and capability identifiers are public API.
- Contract generation and semantic diffing become CI gates.
- Generated code is kit-owned.
- The same client core can serve React, Expo, CLI, or other consumers.
- Backend route/event coverage must be verifiable.

## Rejected alternatives

- Manual SDKs as the default: high drift and repetitive maintenance.
- Inferring contracts from TypeScript: makes the backend depend on a consumer representation.
- Generating complete product UI: contracts do not contain enough product/design meaning.
