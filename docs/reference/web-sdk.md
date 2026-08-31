---
title: Web SDK reference
description: Public package subpaths, transport contracts, errors, retries, pagination, ETags, idempotency, capabilities, realtime, uploads, and LLM entry points.
status: experimental
implementation: implemented
profile_availability:
  - web-sdk-only
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: library-only
audience:
  - client-developer
  - web-developer
topics:
  - web-sdk
  - transport
  - public-api
capabilities: []
source:
  - packages/web-sdk/package.json
  - packages/web-sdk/src/client/index.ts
  - packages/web-sdk/src/internal/generated/contract-metadata.ts
  - packages/web-sdk/orval.config.ts
evidence:
  - packages/web-sdk/test/transport.test.ts
  - packages/web-sdk/test/http-utilities.test.ts
  - packages/web-sdk/test/generated-http.test.ts
last_verified: 2026-08-30
---

# Web SDK reference

The private ESM package exposes nine deliberate subpaths. It has no public `@omnius/web-sdk` root export. Package exports are implemented library surfaces; generated operations, URLs, profile declarations, and tests do not prove matching backend routes are assembled.

## Package metadata

| Field | Exact value |
|---|---|
| package/version | `@omnius/web-sdk` / `0.1.0` |
| publication | `private: true` |
| module format | ESM (`type: module`) |
| side effects | `false` |
| Node engine | `24.19.0` |
| license | `MIT OR Apache-2.0` |
| packaged files | `dist` |
| `engines.pnpm` | `11.23.0` |
| browser floors | Chrome 151, Firefox 153, Safari 26.5 |

## Public subpaths

| Import | Public surface |
|---|---|
| `@omnius/web-sdk/client` | `createServiceClient`, client configuration and URL normalization, retry/idempotency/cursor/ETag utilities, contract metadata, errors, and generated HTTP operations under the `serviceHttp` namespace. |
| `@omnius/web-sdk/auth` | Auth managers for `session`, `bearer`, `oidc-redirect`, and explicit `none`; current-principal generated port; route-prerequisite helpers. |
| `@omnius/web-sdk/authorization` | Presentation-only `createPresentationAuthorization`, `can`, `canAny`, `canAll`, `hasPermission`, `satisfiesPermissionRequirement`, and `canSatisfy`. These never replace server authorization. |
| `@omnius/web-sdk/realtime` | Generated `DomainEventV1`, realtime manager/query effects, SSE and WebSocket transports and types. Constructors are `createRealtimeManager`, `createSseTransport`, and `createWebSocketTransport`. |
| `@omnius/web-sdk/uploads` | Browser-support detection, progress calculation, workflow identity, coordinator, checksum port, `UploadCoordinator`, `UploadPortError`, and injected `UploadPorts`. It does **not** export the source-level `createHttpUploadPorts`. |
| `@omnius/web-sdk/llm` | `createLlmClient`, fixed operation IDs, response helpers, event-stream parser, and LLM stream HTTP/protocol errors. |
| `@omnius/web-sdk/capabilities` | Strict capability-manifest parser, availability helpers, registry, and dimension-specific `require*` functions. |
| `@omnius/web-sdk/react` | Optional React/TanStack adapter, provider, query utilities, hooks, forms, auth, realtime, tenant, uploads, LLM, capabilities, and local state. |
| `@omnius/web-sdk/testing` | Value/deferred/auth-signal/identity-transition recorders, manual realtime time, fake WebSocket/EventSource factories, and realtime query-client fixture. |

The React peer versions declared by this package are exactly React `19.2.8` and `@tanstack/react-query` `5.102.2`; both are optional peer dependencies.

## Client contract

`createServiceClient` requires `baseUrl`. Optional configuration includes credentials, static or asynchronous headers, fetch implementation, auth manager, retry policy, `onProblem`, and `onContractMismatch`. Per-request options add `deadlineMs` and a retry policy or `false`. `request<T>()` returns `{data, status, headers}`; `requestOptions()` binds generated calls.

### Errors

| Kind | Exported class |
|---|---|
| `configuration` | `ServiceClientConfigurationError` |
| `problem` | `ServiceProblemError` |
| `network` | `NetworkRequestError` |
| `aborted` | `AbortedRequestError` |
| `invalid-response` | `InvalidResponseError` |
| `contract-mismatch` | `ContractMismatchError` |

`ServiceProblemError` retains status, type, code, title, optional detail, field violations, retry-after information, and response body.

### Contract compatibility headers

| Constant | Value |
|---|---|
| generated aggregate | `sha256:9dcd7a6acb299d7abf999cd0d5bcae7b1c08a323033930999de5dccb7c0ac249` |
| minimum SDK | `0.1.0` |
| maximum SDK | `null` |
| response contract header | `X-Omnius-Contract-Hash` |
| minimum-SDK header | `X-Omnius-Minimum-Sdk-Version` |
| maximum-SDK header | `X-Omnius-Maximum-Sdk-Version` |

See [Contracts and code generation](contracts-and-code-generation.md) for the current manifest and compatibility boundary.

## Retry and idempotency

`IDEMPOTENT_HTTP_METHODS` is exactly `GET`, `HEAD`, `OPTIONS`, `PUT`, and `DELETE`. `RetryPolicy.maxAttempts` includes the first attempt. The documented policy defaults are 100 ms initial delay and 2,000 ms maximum delay.

A request is retried only when the error classification, attempt ceiling, and method policy permit it. Retrying a non-idempotent operation additionally requires a valid idempotency key and `retryNonIdempotentWithKey` opt-in.

`Idempotency-Key` values must contain 1–128 visible ASCII characters. `createIdempotencyKey()` requires `crypto.randomUUID()` and has no insecure fallback. `createIdempotencySequence(recoveredKey?)` maintains one active key and issues new headers without silently replacing a recovered key.

## Pagination and cache concurrency

An opaque cursor is trimmed, nonempty, and no longer than 256 characters. `CursorPagination` has optional `cursor` and `limit`. Scoped query keys begin with:

```text
['omnius', { tenantId, principalId, permissionFingerprint }, …generatedKey]
```

Unscoped tenant and principal dimensions are represented by `null`, not omission.

ETags use headers `ETag` and `If-Match`. Entity tags must be strong quoted tags; `If-Match` additionally permits `*`. `createVersionEntityTag()` accepts a positive safe integer and returns `"v<revision>"`. Status 409, 412, or 428 is classified as contention.

## Authentication and authorization presentation

`AUTH_MODES` is exactly `session`, `bearer`, `oidc-redirect`, and `none`. No auth mode is inferred when configuration is ambiguous. The authorization subpath only controls presentation decisions; a rendered or hidden control is never server-side authorization evidence.

The current generated contract advertises `auth-oauth-server` available with `bearer` and `session`, but advertises `web-auth` as neither compiled nor runtime available. That metadata is current `oauth-provider` generated evidence, not a web-profile runtime claim.

## Realtime

The WebSocket subprotocol is `omnius.realtime.v1`. The concrete library implementation defaults to `/realtime/ws`, but that path is not proof of an assembled route. SSE and WebSocket constructors require an explicit application composition.

## Uploads

`UploadPorts` injects initiate, transfer, finalize, status, and abandon I/O. Workflow identity is stable `{workflowKey, idempotencyKey}`. A workflow key must not be reused for different bytes, and finalize is expected to be idempotent by that identity.

Coordinator states are `idle`, `checksumming`, `initiating`, `transferring`, `finalizing`, `quarantined`, `available`, `rejected`, `cancelled`, `failed`, `abandoned`, and `disposed`. Browser support detection reports AbortController, `Blob.arrayBuffer`, SHA-256, and XMLHttpRequest upload progress; fetch does not expose upload progress through this contract.

Upload coordinator defaults are three transfer attempts, exponential retry delay `min(250 × 2^(attempt−1), 4000)` milliseconds, 120 scan polls, and a 1,000 ms scan-poll interval. Attempt and poll ceilings must be positive safe integers; poll intervals must be finite and nonnegative.

## LLM entry point

`AI_OPERATION_IDS` maps:

| Logical operation | Generated operation ID |
|---|---|
| routes list | `aiRoutesList` |
| response create | `aiResponseCreate` |
| response stream | `aiResponseStream` |
| job submit | `aiJobSubmit` |
| job get | `aiJobGet` |
| job cancel | `aiJobCancel` |
| job result | `aiJobResult` |

The checked-in reference application does not mount the source-level LLM router. These operation bindings are generated/library contracts, not current public endpoint exposure.

## Generation boundary

Orval reads only `contracts/openapi.json` and writes internal fetch and React Query output. The generated HTTP surface is exported only as `client.serviceHttp`. The current manifest names profile `oauth-provider`; the current permissions catalog is empty. See [Permissions](permissions.md). Regenerating types does not assemble server routes or upgrade an unavailable capability.
