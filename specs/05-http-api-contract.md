---
spec_id: RSK-005
title: HTTP API Contract
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# HTTP API Contract


## Handler responsibility

Axum handlers parse/validate transport input, obtain request/principal/tenant context, call an application service, and map the result to the stable HTTP contract. They do not contain SQL, password hashing, provider retry loops, or substantive authorization rules.

## Middleware order

The effective order is documented and integration-tested. Outer to inner:

1. Panic boundary.
2. Request ID.
3. Sensitive-header marking.
4. Trusted-proxy/client metadata.
5. Trace span.
6. Concurrency controls.
7. Header/request deadlines.
8. Body limit.
9. CORS.
10. CSRF/cross-origin protection for cookie-authenticated mutation.
11. Authentication.
12. Request/tenant context.
13. Route-specific rate limit.
14. Handler.
15. Security headers, compression, and metrics.

Rejections still carry request ID and observability.

## Request IDs

Generate UUIDv7. Accept an inbound value only from a trusted proxy after syntax/length validation. Return it to the client and propagate it to logs, traces, errors, jobs, and event causation metadata.

## Problem Details

Errors use RFC 9457-compatible `application/problem+json` with stable `type`, `title`, HTTP `status`, application `code`, `request_id`, optional safe `detail`, and optional field errors using JSON Pointer paths.

Internal causes, SQL, traces, secrets, and raw provider responses are never returned. Authentication and recovery responses resist enumeration.

## Validation

Use `garde` at transport boundaries; keep business invariants in domain/application code and database constraints.

Reject unknown fields for security-sensitive commands, unsupported content types, invalid text encodings, oversized/nested collections, and malformed pagination/filter expressions.

## Pagination

Default to opaque cursor pagination with bounded `limit`, stable sort plus unique tiebreaker, allowlisted filters/sorts, and `next_cursor`. Offset pagination is limited to bounded administrative data.

## Idempotency

Retryable state-changing operations support `Idempotency-Key`.

Persist principal/tenant scope, operation, request hash, in-progress/completed status, safe response, and expiry. Reusing a key with a different request conflicts. Coordinate business effect and idempotency record transactionally where possible.

## Conditional requests

Mutable resources should expose version/ETag and use `If-Match`. Cacheable reads may use `If-None-Match`. Auth and recovery responses are `no-store`; user-specific responses use correct private policy.

## CORS and CSRF

CORS is deny-by-default. Credentials never use wildcard origin. Cookie-authenticated mutation uses tower-http 0.7 CSRF/cross-origin protection plus origin policy; SameSite is defense in depth.

## Trusted proxies

Honor forwarded headers only when the immediate peer is trusted. Bound hop count; reject malformed chains. Direct clients cannot choose effective IP, scheme, or host.

## Initial defaults

- JSON body: 2 MiB.
- Auth body: 64 KiB.
- Header read: 5 seconds.
- General handler/total body deadline: 30 seconds.
- Max page size: 100.
- Accepted request ID: at most 128 bytes.

Upload/stream routes override explicitly.

## OpenAPI

Use `utoipa` and OpenAPI 3.1. CI deterministically generates and validates the document, diffs breaking changes, and requires operation ID, auth scheme, responses, and Problem Details for every public route. Admin APIs use a separate document/listener.

## Outbound HTTP

Reuse configured `reqwest::Client` instances per policy class. Use rustls, connect/total timeouts, controlled redirects, response size limits, explicit proxy behavior, user agent, retry only for safe/idempotent operations, tracing, and metrics.
