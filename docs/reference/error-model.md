---
title: Error model
description: Stable service error codes, RFC 9457 problem details, field violations, and protocol-specific error families.
status: experimental
implementation: implemented
profile_availability:
  - api
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - full-reference
public_exposure: assembled
audience:
  - service-developer
  - client-developer
topics:
  - errors
  - http
  - problem-details
capabilities: []
source:
  - crates/core/src/error.rs
  - crates/http/src/lib.rs
  - apps/api-server/src/lib.rs
  - crates/reference-api/src/oauth_provider.rs
evidence:
  - apps/api-server/tests/api_service.rs
last_verified: 2026-08-30
---

# Error model

Omnius has a safe internal service error and an HTTP Problem Details representation. OAuth protocol errors and the source-level LLM router use distinct wire families; clients must not parse them as the generic problem shape without checking the endpoint contract.

## Stable service error

`ErrorCode` accepts 1–64 ASCII uppercase letters, digits, and underscores. The first character must be uppercase. `ServiceError` contains:

- a stable `ErrorCode`;
- a client-safe message;
- an optional retained source error.

`Display` omits the retained source. Focused source tests establish this behavior for `ServiceError`; they do not prove that every downstream log or error reporter redacts arbitrary secrets.

## RFC 9457 problem shape

The HTTP library emits `application/problem+json` and `Cache-Control: no-store` with this public structure:

| Field | Required | Contract |
|---|---:|---|
| `type` | yes | `https://errors.omnius.invalid/` followed by the lowercase stable code. |
| `title` | yes | Client-safe summary. |
| `status` | yes | An HTTP 4xx or 5xx status. Other values fail problem construction. |
| `code` | yes | Stable uppercase error code. |
| `request_id` | yes | Request correlation identifier. |
| `detail` | no | Client-safe detail. |
| `errors` | no | Field-error array. |

A field error has a JSON Pointer, a lower-snake-case code, and a nonempty message. The empty pointer is allowed for a whole-document failure. At most 100 field errors are accepted.

## Generic status mapping

| HTTP status | Stable code |
|---:|---|
| 400 | `BAD_REQUEST` |
| 401 | `UNAUTHORIZED` |
| 403 | `FORBIDDEN` |
| 404 | `NOT_FOUND` |
| 405 | `METHOD_NOT_ALLOWED` |
| 408 | `REQUEST_TIMEOUT` |
| 409 | `CONFLICT` |
| 413 | `PAYLOAD_TOO_LARGE` |
| 415 | `UNSUPPORTED_MEDIA_TYPE` |
| 422 | `VALIDATION_FAILED` |
| 429 | `RATE_LIMITED` |
| 431 | `REQUEST_HEADERS_TOO_LARGE` |
| 503 | `SERVICE_UNAVAILABLE` |
| other 5xx | `INTERNAL_ERROR` |
| other 4xx | `REQUEST_FAILED` |

Route-specific mappings override this generic fallback.

## Reference API codes

These tables describe source mappings in the checked-in `oauth-provider` reference application. They are not promises for unassembled profiles.

### Request, reference-record, and idempotency paths

| Status | Codes |
|---:|---|
| 400 | `INVALID_JSON`, `INVALID_PAGINATION`, `INVALID_IDEMPOTENCY_KEY`, `INVALID_REFERENCE_RECORD_ID`, `INVALID_CURSOR`, `INVALID_FILTER`, `INVALID_IF_MATCH` |
| 404 | `REFERENCE_RECORD_NOT_FOUND` |
| 409 | `REFERENCE_RECORD_CONFLICT`, `IDEMPOTENCY_CONFLICT`, `IDEMPOTENCY_CLAIM_LOST`, `IDEMPOTENCY_IN_PROGRESS` |
| 412 | `PRECONDITION_FAILED` |
| 413 | `PAYLOAD_TOO_LARGE` |
| 415 | `UNSUPPORTED_MEDIA_TYPE` |
| 422 | `VALIDATION_FAILED` |
| 428 | `PRECONDITION_REQUIRED` |
| 500 | `INTERNAL_ERROR` |
| 503 | `DATABASE_UNAVAILABLE` |

### Account and browser authentication paths

| Status | Codes |
|---:|---|
| 400 | `INVALID_ACCOUNT_REQUEST`, `INVALID_PATH_PARAMETER`, `ACCOUNT_TOKEN_REJECTED` |
| 401 | `CURRENT_PASSWORD_REJECTED`, `AUTHENTICATION_REQUIRED`, `LOGIN_REJECTED`, `SESSION_REVOKED_OR_EXPIRED` |
| 403 | `PERMISSION_DENIED`, `CSRF_ORIGIN_DENIED` |
| 404 | `SESSION_NOT_FOUND`, `INVITATION_NOT_FOUND` |
| 409 | `ACCOUNT_CONFLICT` |
| 422 | `PASSWORD_POLICY_REJECTED` |
| 500 | `INTERNAL_ERROR` |
| 503 | `EMAIL_DELIVERY_UNAVAILABLE`, `ACCOUNT_SERVICE_UNAVAILABLE`, `AUTHENTICATION_UNAVAILABLE` |

### API-key and service-account paths

| Status | Codes |
|---:|---|
| 400 | `INVALID_API_KEY_REQUEST`, `INVALID_PATH_PARAMETER` |
| 401 | `AUTHENTICATION_REQUIRED` |
| 403 | `CSRF_ORIGIN_DENIED`, `PERMISSION_DENIED`, `API_KEY_SCOPE_ESCALATION` |
| 404 | `SERVICE_ACCOUNT_NOT_FOUND`, `API_KEY_NOT_FOUND` |
| 409 | `API_KEY_CREATOR_INACTIVE`, `SERVICE_ACCOUNT_DISABLED`, `API_KEY_INACTIVE`, `API_KEY_STATE_CONFLICT` |
| 500 | `INTERNAL_ERROR` |
| 503 | `AUTHENTICATION_UNAVAILABLE`, `API_KEY_PERSISTENCE_UNAVAILABLE` |

## OAuth error family

OAuth errors serialize their code in snake case. The exact code set is:

`invalid_request`, `invalid_client`, `unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`, `invalid_target`, `invalid_grant`, `invalid_token`, `login_required`, `consent_required`, `unsupported_token_type`, `server_error`.

Endpoint responses use status 401 only for `invalid_client`, 503 for `server_error`, and 400 otherwise. An `invalid_client` response includes `WWW-Authenticate: Basic realm="oauth-token"`. Redirectable errors use status 303 with `error`, optional `state`, and `iss`. OAuth error responses are no-store.

## LLM HTTP source error family

The LLM router source emits a smaller `AiProblem` shape rather than the generic `ProblemDetails` structure:

| Status | Code |
|---:|---|
| 400 | `INVALID_REQUEST` |
| 401 | `AUTHENTICATION_REQUIRED` |
| 403 | `TENANT_CONTEXT_REQUIRED` |
| 404 | `NOT_FOUND` |
| 409 | `CONFLICT` |
| 429 | `BUDGET_REJECTED` |
| 500 | `INTERNAL` |
| 503 | `SERVICE_UNAVAILABLE` |

No non-test reference composition mounts the LLM router. This table is a source contract, not current public exposure; see [LLM contracts](llm-contracts.md).
