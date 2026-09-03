---
title: HTTP APIs
description: Build and consume Omnius HTTP APIs with bounded request handling, RFC 9457 errors, validation, pagination, and conditional updates.
status: experimental
implementation: implemented
profile_availability:
  - minimal
  - api
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - worker
  - full-reference
public_exposure: assembled
audience:
  - developer
  - integrator
topics:
  - backend
  - http
  - api-contracts
capabilities:
  - http
  - http-request-semantics
  - validation
  - rfc9457-problems
  - conditional-etag
  - pagination
source:
  - crates/http/src/lib.rs
  - crates/http/src/conditional.rs
  - crates/validation/src/lib.rs
  - crates/pagination/src/lib.rs
  - apps/server/src/main.rs
  - apps/api-server/src/lib.rs
evidence:
  - crates/validation/tests/contracts.rs
  - apps/server/tests/minimal_service.rs
  - apps/api-server/tests/api_service.rs
last_verified: 2026-08-30
---

# HTTP APIs

Omnius provides an assembled HTTP shell with request bounds, validation, RFC 9457 problem responses, signed cursors, and revision-based conditional updates. The API server concretely exposes the OAuth provider reference surface; selecting another HTTP-capable profile does not by itself prove that a domain route exists.

Use the [contract and code-generation reference](../../reference/contracts-and-code-generation.md) for generated contract boundaries and the [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md) before relying on any route.

## Request boundary

The HTTP shell applies defensive limits before application handlers. Its source defaults include a 2 MiB body limit, 64 KiB total header limit, 100-header count limit, 1,024 in-flight request limit, 5-second header timeout, and 30-second handler timeout. A deployment may configure stricter supported values; do not assume a route can accept a larger request.

The shell also:

- unconditionally removes `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-Proto`, and `X-Real-IP` before handlers;
- accepts a caller-supplied request ID only when a composing host has inserted the internal `TrustedProxy` marker;
- limits accepted request-ID syntax and length, and otherwise generates a server request ID;
- applies CORS and CSRF controls with deny-by-default behavior;
- maps header overflow, body overflow, timeout, overload, and unexpected failures to bounded responses;
- normalizes ordinary 4xx and 5xx responses into RFC 9457 problems unless a trusted protocol adapter owns that response format.

The checked-in reference composition has no trusted-proxy allowlist and no production path that inserts the internal trust marker. It therefore strips those six forwarding headers regardless of sender and ignores an external request ID. Do not configure ingress on the assumption that any of those values becomes application authority.

## Validation and RFC 9457

Request DTOs reject unknown fields where the concrete type opts into strict deserialization. Syntactic validation runs before domain validation; domain invariants still belong in the application layer.

Problem responses use `application/problem+json` and contain:

- `type`, derived from the non-resolving base `https://errors.omnius.invalid/` plus the lowercase problem code;
- `title` and HTTP `status`;
- stable machine-readable `code`;
- `request_id` for correlation;
- optional safe `detail`;
- optional field-level `errors`.

Each field error has a JSON Pointer `pointer`, a machine `code`, and a safe `message`. The response is capped at 100 field errors. Internal errors, SQL text, secrets, tokens, and configuration values must not be copied into `detail` or `message`.

A shape-only example is safe to log or document:

```json
{
  "type": "https://errors.omnius.invalid/validation_failed",
  "title": "Unprocessable Entity",
  "status": 422,
  "code": "VALIDATION_FAILED",
  "request_id": "<redacted request id>",
  "errors": [
    {
      "pointer": "/display_name",
      "code": "INVALID_VALUE",
      "message": "The value is invalid."
    }
  ]
}
```

The values are illustrative, not evidence of a particular route or permission.

## Conditional updates

Revisioned resources use strong ETags in canonical form:

```http
ETag: "v42"
```

For mutations, `If-Match` accepts either `*` or one exact strong revision tag. Weak tags, lists of tags, and noncanonical encodings are rejected. A missing or stale precondition must fail rather than silently overwriting a concurrent change.

The concrete resource must store and atomically compare the revision. Formatting an ETag alone does not provide optimistic concurrency.

## Pagination

Cursor pagination uses signed, expiring cursors with bounded page sizes and key rotation support. Treat a cursor as opaque. Clients must not decode, alter, or synthesize it, and servers must not put sensitive record contents in its payload.

Cursor verification failure, expiry, unsupported version, or out-of-range page size produces a client error; it must not fall back to an unsigned offset. The pagination library is implemented, but a profile or generated contract does not prove that a particular endpoint uses it.

## Idempotency boundary

Mutation idempotency is a canonical reliability concept; see [Reliability and idempotency](../../concepts/reliability-and-idempotency.md). The HTTP layer supplies the header and error semantics, while durable behavior depends on the store and scope selected by the concrete route.

The reference handler currently uses an unscoped idempotency path even though the normative model scopes records to tenant and principal. Do not use that handler as proof of tenant-safe replay isolation.

## Minimal shell recipe

This checks only the assembled minimal HTTP shell, not the OAuth provider or any unassembled module.

**Prerequisites**

- run both commands from the repository root;
- install the repository Rust toolchain and `curl`;
- keep `127.0.0.1:8080` free.

Start the server:

```bash
cargo run --locked -p omnius-minimal-server -- server --config config/minimal.toml
```

Then, in another terminal:

```bash
curl --fail-with-body --include http://127.0.0.1:8080/example
```

**Expected result:** the example route returns HTTP 200 through the bounded shell.

**Failure path:** if startup fails, correct configuration or listener availability before retrying. If the request fails, retain the response request ID and inspect redacted server diagnostics; do not weaken request limits or expose internal errors.

This is a documented verification recipe and was not run as part of this documentation work.

## OpenAPI distinction

The API server mounts its generated OpenAPI document and documentation router for the concrete reference API. The generated document is a build artifact, not independent proof that an optional provider is assembled or reachable. Confirm both the runtime composition and the selected profile before publishing a route.

## Related pages

- [Error model](../../reference/error-model.md)
- [Contracts and code generation](../../reference/contracts-and-code-generation.md)
- [Authentication and sessions](authentication-and-sessions.md)
- [Authorization and tenancy](authorization-and-tenancy.md)
- [Startup and configuration troubleshooting](../../troubleshooting/startup-and-configuration.md)
