---
title: Reliability and idempotency
description: The canonical model for deadlines, retries, overload control, effect identity, duplicate suppression, and honest failure semantics.
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
  - ai-worker
public_exposure: assembled
audience:
  - rust-application-developer
  - operator
  - web-developer
  - ai-application-developer
  - mcp-developer
topics:
  - reliability
  - idempotency
  - retries
  - overload
capabilities:
  - idempotency
source:
  - specs/05-http-api-contract.md
  - crates/idempotency/src/lib.rs
  - apps/api-server/src/lib.rs
evidence:
  - crates/idempotency/tests/idempotency.rs
  - apps/api-server/tests/api_profile.rs
last_verified: 2026-08-30
---

# Reliability and idempotency

Reliability means producing an honest, bounded outcome under partial failure. It does not mean retrying until a request appears successful, and idempotency does not create exactly-once execution.

## Audience path

Application authors should apply this model to every side effect regardless of whether it begins over HTTP, a job, realtime delivery, an LLM tool call, or MCP. Operators and consumer authors should continue to the surface-specific guide for exact status, header, and recovery behavior.

## One effect identity

A logical side effect needs an identity stable across attempts. At minimum it binds:

```text
principal or service identity
+ authoritative tenant
+ operation
+ client idempotency key or source message identity
+ canonical request fingerprint
```

The same effect identity must cross transport boundaries. An HTTP handler that enqueues work passes it into the job envelope; a worker uses it for its durable effect; an outbox-derived event keeps the causation relationship. Each independently retryable effect may derive a child identity while retaining correlation and causation.

## Idempotency state machine

For an operation that supports idempotency:

1. parse and validate the key before executing the effect;
2. compute a canonical fingerprint from the operation and relevant request input;
3. claim the tenant/principal-scoped effect identity in durable state;
4. when the claim is new, execute the effect and commit the result atomically where possible;
5. when a completed matching claim exists, replay the stored safe response;
6. when a matching claim is in progress, return the documented in-progress outcome;
7. when the key exists with a different fingerprint, reject the conflict;
8. expire records only under a declared retention policy compatible with client retry windows.

The reusable idempotency implementation accepts ASCII keys from 1 through 128 bytes and hashes request fingerprints. Its observable claim outcomes are `Started`, `Replay`, and `InProgress`.

## Retry decision

Retry only when all of these are known:

- the failure class is transient;
- the operation is safe or protected by a durable effect identity;
- the end-to-end deadline has enough remaining budget;
- the retry policy permits another bounded attempt;
- retrying does not bypass admission, authorization, quota, or circuit state.

Use jittered exponential backoff and respect server-provided retry guidance where the surface contract defines it. Never retry validation, authentication, authorization, idempotency-conflict, or other permanent failures. If the outcome of an external side effect is ambiguous and the downstream system has no idempotency/reconciliation contract, report the ambiguity rather than blindly issuing it again.

Retries are an availability tool, not a load-control strategy. Every retry consumes the original deadline and attempt budget.

## Deadlines, cancellation, and overload

A request owns one end-to-end deadline. Derive shorter downstream timeouts from its remaining budget rather than restarting the clock at every layer. Propagate cancellation to work whose result is no longer needed, while protecting commits and other non-cancellable critical sections from partial interruption.

Bound queues and concurrency. On saturation, reject or shed work predictably instead of accumulating unbounded latency. Apply rate limits and quotas to authoritative identity/tenant dimensions rather than untrusted addresses alone. Circuit breakers should cover a named dependency and fail with a safe, observable state; they must not turn a durable failure into silent success.

## Outcome taxonomy

Keep these outcomes distinct:

| Outcome | Meaning | Safe handling |
|---|---|---|
| Validation or policy rejection | The requested effect was not admitted | Correct the request or authority; do not retry unchanged |
| Transient dependency failure | The effect is known not to have committed, or safe idempotency protects it | Retry within the shared budget |
| In progress | Another attempt owns the same matching effect | Follow documented polling/backoff behavior |
| Replay | The matching effect completed and a safe response was retained | Return the retained result without re-executing |
| Conflict | The key was reused for a different fingerprint or incompatible resource state | Use a new logical operation/key after reconciling intent |
| Ambiguous | The system cannot prove whether an external effect happened | Reconcile using provider state; do not assume failure |
| Overloaded | Admission capacity is exhausted | Back off according to the surface contract |

The exact HTTP error representation and wire-level retry signals belong to the backend and error-model references.

## Current assembly boundary

The checked-in OAuth-provider reference application assembles PostgreSQL-backed idempotency for `POST /reference-records`. It requires an idempotency key and can replay the stored `201` response. This is concrete evidence for one reference operation, not a claim that every mutating route is protected.

That handler currently uses `IdempotencyScope::unscoped()`. It therefore demonstrates replay mechanics but is **not tenant-safe reusable semantics**. A tenant-aware application must include the authoritative tenant and actor/service boundary in its scope before exposing an equivalent multi-tenant operation.

The capability is selected by the profiles listed in this page's metadata; profile selection alone does not prove route assembly for those profiles.

## Evidence

- [HTTP API contract specification](../../specs/05-http-api-contract.md)
- [Idempotency implementation](../../crates/idempotency/src/lib.rs)
- [Idempotency contract tests](../../crates/idempotency/tests/idempotency.rs)
- [Reference route assembly](../../apps/api-server/src/lib.rs)
- [Reference API behavior tests](../../apps/api-server/tests/api_profile.rs)

## Next

- [HTTP APIs](../guides/backend/http-apis.md)
- [Asynchronous processing](asynchronous-processing.md)
- [Error model](../reference/error-model.md)
