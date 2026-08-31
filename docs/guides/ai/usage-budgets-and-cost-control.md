---
title: Usage budgets and cost control
description: Conservative reservation, commit, release, and reconciliation of LLM tokens, attempts, tools, and estimated cost.
status: experimental
implementation: partial
profile_availability:
  - llm-runtime
  - llm-api
  - llm-agent
  - ai-worker
  - ai-platform
  - full-reference-ai
public_exposure: unassembled
audience:
  - ai-application-developer
  - operator
  - platform-engineer
topics:
  - llm
  - usage
  - budgets
  - quotas
  - cost
capabilities:
  - llm-usage-ledger
  - llm-budgeting
source:
  - crates/llm-usage-ledger/src/service.rs
  - crates/llm-usage-ledger/src/model.rs
  - crates/llm-usage-ledger/src/postgres.rs
  - migrations/2026082803_create_llm_usage_ledger.sql
  - apps/api-server/src/llm_http.rs
evidence:
  - crates/llm-usage-ledger/tests/postgres_repository.rs
  - crates/llm-usage-ledger/src/tests.rs
  - apps/api-server/tests/llm_http.rs
last_verified: 2026-08-30
---

# Usage budgets and cost control

Usage accounting is implemented as a library and durable ledger. End-to-end budgeting is only partial: the catalog names a standalone `llm-budgeting` capability, but no standalone crate exists, and the API router's budget port has no checked-in runtime composition.

## Availability

| Capability | Status | Implementation | Selected by profiles | Public exposure |
| --- | --- | --- | --- | --- |
| `llm-usage-ledger` | experimental | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-budgeting` | experimental | partial | `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | unassembled |

The page-level classifications are conservative because budgeting is the enforcing boundary and remains partial/unassembled.

## Reserve before dispatch

A host estimates the maximum admitted work and reserves it before provider execution. The estimate covers the primary model attempt and every concurrently possible or policy-permitted component, including:

- input and output token bounds;
- retry and hedge attempts;
- structured-output repair;
- model turns and tool calls;
- tool-specific units or cost;
- media or other provider-priced operations when supported;
- wall-clock and concurrency admission where policy tracks them.

If the required reservation exceeds an applicable quota or cost ceiling, reject before dispatch. Do not send the request and attempt to enforce the budget afterward.

Pricing and tokenizer estimates are policy inputs with a revision and effective scope. Repository code does not establish current provider prices or guarantee that an estimate equals an invoice.

## Reservation lifecycle

| Transition | When it is safe | Result |
| --- | --- | --- |
| reserve | before any potentially billable work | holds a conservative estimate |
| commit | provider dispatch finished, with actual, missing, or ambiguous usage evidence | actual usage moves directly to `Reconciled`; missing or ambiguous evidence moves conservatively to `Committed` |
| release | dispatch is proven not to have occurred and the reservation is still `Reserved` | moves the complete reservation to `Released`; it is not a partial refund |
| reconcile | complete actual usage arrives for a `Committed` missing or ambiguous record | replaces the conservative evidence and moves the record to `Reconciled` |

Transitions are idempotent and concurrency-safe. Repeating a logical request or ledger transition must not multiply credit or erase a committed charge. A stale revision is a conflict to reload and resolve, not permission to overwrite.

## Attribute every attempt

Keep primary generation, provider retry, hedge, structured repair, and tool execution distinguishable under one logical request. This allows operators to explain consumption without recording prompt or output content.

A safe usage record can contain opaque tenant/request identities, provider/model identifiers allowed by policy, attempt class, normalized token/unit counts, estimated cost, pricing revision, reservation state, and timestamps. It must not contain credentials, prompts, outputs, personal data, private reasoning, or raw provider payloads.

## Missing or ambiguous usage

Provider cancellation, timeout, connection loss, and malformed responses can leave usage unknown. In those cases:

- do not assume the attempt was free;
- after dispatch, commit missing or ambiguous usage conservatively and later reconcile exact actual usage;
- preserve the attempt identity for provider reconciliation;
- do not release hedge losers merely because local cancellation was requested;
- surface an accounting state distinct from a confirmed non-dispatch outcome.

The same rule applies to side-effecting tools whose completion is ambiguous.

## Quotas are layered policy

A composition may enforce ceilings by tenant, principal, capability, model/provider, time window, concurrency, or operation class. The checked-in source does not prove which layers a production host enables, what their values are, or how administrative changes propagate.

Quota admission does not authorize data access or tool execution. Authorization does not imply affordability. Both checks must pass, along with routing and safety policy.

## Failure behavior

Fail closed when:

- no finite estimate can cover the admitted work;
- a reservation cannot be created before dispatch;
- quota or cost policy rejects the estimate;
- ledger ownership or tenant scope is inconsistent;
- a compare-and-set transition is stale;
- required usage cannot be normalized and no conservative reconciliation is allowed;
- a mandatory accounting/audit dependency is unavailable.

Do not recover by dropping retry, repair, hedge, or tool attribution after work occurred. Do not weaken authorization or capability requirements to fit a budget unless the caller made an explicit new request under policy.

## Operational boundary

A host still needs pricing/configuration ownership, a composed budget port, retention and deletion policy, reconciliation workers or procedures, metrics, alerts, and provider-invoice review. The LLM HTTP factory exercises reserve/commit/release behavior in focused tests, but it is not mounted and proves no production quota.

See [providers and routing](providers-and-routing.md), [tools and approvals](tools-and-approvals.md), [operations usage budgets and quotas](../../operations/usage-budgets-and-quotas.md), and [LLM provider operations](../../operations/llm-provider-operations.md).
