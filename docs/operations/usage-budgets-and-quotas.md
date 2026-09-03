---
title: Usage budgets and quotas
description: Operate LLM reservations, ledger reconciliation, budgets, provider quotas, and tenant fairness within the current unassembled composition boundary.
status: experimental
implementation: partial
profile_availability:
  - llm-api
  - llm-agent
  - ai-worker
  - ai-platform
  - full-reference-ai
public_exposure: unassembled
audience:
  - operator
  - ai-platform-engineer
  - finance-owner
topics:
  - operations
  - llm
  - quotas
capabilities: []
source:
  - crates/llm-usage-ledger/src/lib.rs
  - migrations/2026082803_create_llm_usage_ledger.sql
  - specs/39-llm-routing-reliability-cost-and-quotas.md
evidence:
  - docs/coverage-matrix.md
  - crates/llm-usage-ledger/tests
last_verified: 2026-09-03
---

# Usage budgets and quotas

The LLM usage ledger is implemented as a library with migration support. Budgeting is partial, and no checked-in application assembles the ledger, provider dispatch, reconciliation worker, public usage API, or operator surface. A migration or profile selection does not make accounting active.

Use [usage, budgets, and cost control](../guides/ai/usage-budgets-and-cost-control.md) for the request contract and [reliability and idempotency](../concepts/reliability-and-idempotency.md) for operation identity. This page covers operator policy.

## Separate the controls

| Control | Purpose | Limitation |
|---|---|---|
| Authorization | Whether the principal may request the capability | Not a spending limit |
| Reservation | Holds estimated usage before provider dispatch | Must be committed, released, or reconciled |
| Budget | Caps approved spend/usage over a policy interval | Partial and unassembled |
| Provider quota | External account/model/region limit | May reject before Omnius budget is exhausted |
| Rate/concurrency limit | Protects capacity and fairness | Does not replace durable accounting |
| Ledger | Records operation-linked accounting state | Library/migration evidence only until composed |

The system is designed to reserve before dispatch. Commit or release behavior is only unambiguous when dispatch state is known. Provider timeouts, disconnects, and partial streams can leave ambiguous usage that requires reconciliation.

## Policy requirements

Before composing provider traffic, define:

- authoritative tenant/principal and operation identity;
- currency/token/request units and estimation rules;
- budget period, reset authority, and effective policy version;
- hard denial versus warning thresholds;
- reservation expiry and reconciliation ownership;
- provider quota mapping and headroom;
- tenant fairness and per-model/provider concurrency;
- who may grant an override, its scope, expiry, and audit evidence;
- retention and privacy classification of usage records.

Do not use browser state, frontend role checks, model output, or MCP capability metadata as budget authority.

## Admission and accounting procedure

**Prerequisites**

- an assembled ledger and provider dispatcher sharing the same operation identity;
- authorized tenant context and policy version;
- monitored reconciliation processing;
- provider account/region/model quota visibility;
- an approved non-sensitive verification workload.

1. Authenticate and authorize the principal and tenant before estimating usage.
2. Resolve applicable budget, provider quota, rate, and concurrency policies.
3. Create an idempotent reservation before dispatch.
4. Dispatch once under the operation identity and record the provider-side correlation where available.
5. Commit actual usage on a confirmed terminal result.
6. Release only when non-dispatch is proven and the reservation remains `Reserved`; dispatched or ambiguous work must be committed conservatively and reconciled.
7. Move ambiguous outcomes to reconciliation without blind replay.
8. Alert on reservation age, reconciliation backlog, repeated denials, provider-account exhaustion, and policy/version mismatch.

**Expected result:** every provider attempt is denied or tied to one durable reservation and a terminal commit, release, or reconcile state.

**Failure path:** fail closed for missing tenant/policy, unavailable authority, exhausted budget, or an unbounded reservation path. Preserve operation identity and bounded metadata; do not duplicate a reservation or estimate away ambiguous provider usage.

No ledger, provider, or reconciliation scenario was run while writing this page.

## Reconciliation

Reconciliation must determine, from authoritative local and provider evidence where available, whether the request dispatched, produced billable usage, and already reached a ledger terminal state. It must be idempotent and safe under restart/redelivery.

Escalate when:

- a reservation exceeds its approved age;
- provider usage cannot be matched to an operation;
- committed usage differs materially from provider reporting;
- a policy reset or override races with an in-flight reservation;
- a reconciliation backlog threatens budget accuracy;
- tenant or provider attribution is missing.

Do not expose prompts, outputs, credentials, or tool arguments to finance or quota diagnostics. Required evidence is operation identity, bounded counts/costs, provider/model identifiers, timestamps, policy version, and outcome state.

## Capacity and alerts

Useful signals for a composed runtime include:

- available/reserved/committed budget by bounded policy key;
- reservation rate and age distribution;
- commit, release, and reconcile outcomes;
- provider quota rejections and retry-after class;
- concurrency saturation and queue delay;
- tenant fairness outliers;
- override count, scope, age, and expiry.

Avoid tenant names, user identifiers, raw model identifiers from arbitrary input, or error messages as metric labels. Dashboards and alerts are deployment-owned; none is proven by the library.

## Overrides

An override is a security- and finance-sensitive state change. Require least privilege, a bounded amount/scope, expiry, reason, incident or business reference, and audit evidence. Never make an override permanent merely to resolve an outage, and never change a shared provider account limit as a substitute for tenant-level policy.

## Related operations

- [LLM provider operations](llm-provider-operations.md)
- [LLM safety and data governance](../security/llm-safety-and-data-governance.md)
- [Incident response](incident-response.md)

The profile list above describes selection availability for budgeting-related modules; it does not prove runtime assembly or public exposure.