---
spec_id: ADR-0008
title: Use RFC 9457 Problem Details and Code-First OpenAPI
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Use RFC 9457 Problem Details and Code-First OpenAPI


## Context

A reusable service kit needs stable error and API-description conventions. Ad hoc JSON errors and manually maintained OpenAPI documents drift from handlers and make generated clients unreliable.

## Decision

- Public HTTP errors use an RFC 9457-compatible Problem Details shape with an additional stable `code`, request ID, and field-error extension.
- `utoipa` generates OpenAPI 3.1 from code and shared schemas.
- `garde` performs boundary validation where derive-based validation fits.
- Domain invariants and database constraints remain separate.
- CI generates, validates, and diffs the OpenAPI document.

The service kit defines the small Problem Details value type directly rather than depending on a niche wrapper crate; the protocol itself is standardized and the type is part of the service's public contract.

## Consequences

- Error codes become versioned API surface.
- Internal causes never cross the transport boundary.
- Breaking API changes are identified in CI.
- GraphQL and gRPC adapters map from the same canonical application errors but use transport-native representations.

## Validation

Every public route declares responses and authentication. Golden tests cover serialization, validation pointers, redaction, and unexpected errors. OpenAPI diffs are release artifacts.
