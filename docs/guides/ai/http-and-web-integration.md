---
title: LLM HTTP and Web integration
description: Authentication, tenant scoping, sync and streaming responses, durable jobs, conversations, and strict Web SDK boundaries.
status: experimental
implementation: implemented
profile_availability:
  - llm-api
  - llm-agent
  - ai-platform
  - full-reference-ai
public_exposure: unassembled
audience:
  - api-developer
  - web-developer
  - platform-engineer
topics:
  - llm
  - http
  - sse
  - web-sdk
  - durable-jobs
capabilities:
  - llm-http-api
  - web-llm
source:
  - apps/api-server/src/llm_http.rs
  - packages/web-sdk/src/llm/index.ts
  - packages/web-sdk/src/llm/stream.ts
evidence:
  - apps/api-server/tests/llm_http.rs
  - contracts/openapi.json
last_verified: 2026-08-30
---

# LLM HTTP and Web integration

The repository contains an LLM router factory, focused tests, checked-in AI OpenAPI operations, and a Web SDK module. `PUBLIC_HTTP_OPERATIONS` includes the AI operations, but the reference application's composition root does not merge `llm_http_router`. The allowlisted contract entries therefore remain unassembled rather than live routes.

## Availability

| Capability | Status | Implementation | Selected by profiles | Public exposure |
| --- | --- | --- | --- | --- |
| `llm-http-api` | experimental | implemented | `llm-api`, `llm-agent`, `ai-platform`, `full-reference-ai` | unassembled |
| `web-llm` | experimental | implemented | `ai-platform`, `full-reference-ai` | library-only |

The page-level exposure is conservative. Profile selection, checked-in OpenAPI entries, TypeScript source, and focused tests cannot raise it above unassembled.

## Router-factory contract

The factory defines operation families for:

- route/readiness inspection;
- synchronous model responses;
- server-sent event responses;
- durable job submission, inspection, result retrieval, and cancellation;
- conversation, message, and provider-state operations.

These are source-level contracts, not deployment instructions or a live base URL. See the [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md) for the current ceiling.

## Identity and tenant boundary

The HTTP boundary requires an authenticated principal and tenant scope. Missing or inconsistent scope fails closed. A client-supplied tenant value is not authoritative merely because it is syntactically valid; assembled authentication and authorization must bind it to the caller.

Conversation, job, provider-state, usage, and result operations preserve that scope. Opaque identifiers do not replace authorization. Cross-tenant absence should not disclose whether an object exists.

Read [identity, authorization, and tenancy](../../concepts/identity-authorization-and-tenancy.md) and [backend HTTP APIs](../backend/http-apis.md) before composition.

## Synchronous responses

Before provider execution, the router contract performs admission through a budget port. The factory releases only an explicit `PreDispatchFailed` outcome; every `Dispatched` outcome commits actual or missing usage even when execution fails. An execution port that cannot prove non-dispatch must classify the outcome as dispatched so the host can reconcile it conservatively. The executor, budget implementation, provider, router mount, and safety composition are absent from the reference runtime.

HTTP errors use the canonical content-safe error model. They must not return raw prompts, model output, provider payloads, credentials, personal data, or private reasoning.

## Streaming responses

The checked-in SSE factory validates a fully buffered event sequence and settles its reservation before returning an iterator over serialized events. It does not observe a live HTTP disconnect or cancel provider work. An exposing host must wire live disconnect detection to the interactive cancellation owner. Replay is not accepted for the interactive response stream; clients must not assume an event-history service exists.

A durable job is different: disconnecting an observer does not cancel job execution. Cancellation follows the durable job operation and state machine. See [LLM streaming](streaming.md) for termination, backpressure, and ownership rules.

## Web SDK boundary

The Web SDK exposes typed client and stream parsing helpers. It validates strict identifier forms used by the contract, carries idempotency where required, and rejects malformed stream transitions rather than treating them as successful text.

The SDK does not:

- discover or mount a backend;
- prove an authenticated browser session can call LLM operations;
- authorize a tenant, tool, or model;
- supply provider credentials;
- persist durable jobs or conversations;
- make checked-in AI OpenAPI operations public;
- provide a checked-in reference UI for these operations.

Generated types are compatibility aids. Runtime exposure must be established independently by application composition and deployment evidence. See the [Web SDK reference](../../reference/web-sdk.md).

## Composition prerequisites

Before publishing any LLM HTTP or Web path, a host must assemble and verify:

1. authenticated principal and tenant resolution;
2. route-level authorization and request/body limits;
3. provider-neutral request validation and capability-aware routing;
4. provider credential injection and executor lifecycle;
5. usage reservation, commit, release, and reconciliation;
6. safety, media, outbound-egress, and raw-retention policy;
7. tool authorization, approval, audit, and idempotency;
8. stream cancellation, bounded delivery, and one-terminal validation;
9. durable job and conversation persistence with restart behavior;
10. redacted errors, readiness, telemetry, retention, and deletion;
11. contract generation and SDK compatibility checks against the assembled surface.

**Expected result:** only operations actually mounted by the host appear in its runtime contract, and clients reject any request or stream that violates identity, schema, terminal, or idempotency rules.

**Failure path:** if runtime discovery and the checked-in contract or generated client disagree, treat the operation as unavailable. Do not bypass the SDK guard, hard-code an inferred route, or interpret a checked-in contract as proof of deployment.

## Exposure review

The checked-in AI OpenAPI entries describe intended shapes. The current public-operation set does not establish them as public. An application claiming LLM HTTP exposure needs non-test router composition, concrete port implementations, runtime contract evidence, and end-to-end identity/safety/budget verification.

Continue with [generated contracts and SDK](../web/generated-contracts-and-sdk.md), [model requests and responses](model-requests-and-responses.md), and the [error model](../../reference/error-model.md).
