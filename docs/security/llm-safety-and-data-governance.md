---
title: LLM safety and data governance
description: Govern Omnius model inputs, outputs, routing, retention, tools, structured data, media, and usage within the current library-only boundary.
status: experimental
implementation: implemented
profile_availability:
  - llm-runtime
  - llm-api
  - llm-agent
  - ai-worker
  - ai-platform
  - full-reference-ai
public_exposure: library-only
audience:
  - security-analyst
  - privacy-owner
  - ai-platform-engineer
topics:
  - security
  - llm
  - data-governance
capabilities: []
source:
  - crates/llm-safety-policy/src/lib.rs
  - crates/llm-routing/src/lib.rs
  - crates/llm-tool-runtime/src/lib.rs
  - crates/llm-structured-output/src/lib.rs
  - crates/llm-media/src/lib.rs
evidence:
  - docs/coverage-matrix.md
  - crates/llm-core/tests
last_verified: 2026-08-30
---

# LLM safety and data governance

Omnius implements safety-policy, routing, prompt, structured-output, media, tool, and usage libraries. No checked-in application composes them into a live LLM runtime or mounts the HTTP factory. The policy library existing is not proof that every model request is evaluated. This page defines controls required before assembly and exposure.

Apply the general [security model](security-model.md) and [data and privacy boundaries](../concepts/data-and-privacy-boundaries.md). Use the LLM guides for exact provider-neutral contracts rather than duplicating them here.

## Data classes and flows

Review separately:

- system/developer/user prompts and prompt-template inputs;
- retrieved context and tenant documents;
- model output, reasoning-like provider fields, citations, and structured values;
- uploaded media, derived/transcoded material, and object references;
- tool names, schemas, arguments, results, approvals, and side effects;
- provider/model/region routing metadata;
- conversations, usage ledger entries, audit events, evaluations, and telemetry;
- provider-side retention/training/abuse-monitoring records.

The provider-adapter retention default discards raw provider material. Full raw retention requires authorization. Local discard does not control a provider's own retention; approve provider/account policy independently.

## Threats and controls

| Threat | Required control |
|---|---|
| Prompt injection or malicious retrieved content | Treat every prompt/context/output as untrusted data; separate instructions from content; constrain capabilities; never grant authority based on model text |
| Sensitive-data disclosure | Classify before dispatch; minimize/redact; enforce provider/region/residency/retention policy; keep content out of telemetry |
| Unsafe provider downgrade | Route only when capabilities, residency, classification, retention, and safety requirements match; fail when no candidate qualifies |
| Tool abuse/confused deputy | Authenticate principal/tenant, authorize tool, validate bounded schema, require approval when policy says so, budget, and sandbox the effect; record the terminal audit outcome after execution but before return, and resolve an audit-write failure as a potentially ambiguous effect by stable idempotency identity |
| Approval spoofing or replay | Bind approval to principal, tenant, exact arguments/policy/revision, scope, and expiry; current persistence/expiry worker composition is unproven |
| Structured-output abuse | Limit schema/size/depth/repair; local references only; remote references are rejected; validate again at the effect boundary |
| Media abuse | Enforce MIME/signature/size/dimension/duration/source policy; isolate processing; authorize object access and retention |
| Denial of wallet/service | Reserve budget before dispatch; rate/concurrency/size limits; timeouts/cancellation; reconcile ambiguous usage |
| Cross-tenant conversation leakage | Authoritative tenant context, row/object ownership checks, bounded retrieval, no shared cache authority |
| Evaluation leakage | Use approved datasets and sinks; eval tooling is implemented, but no run or persistence pipeline is proven |

## Tool execution boundary

Model output is never approval. Before a tool effect:

1. authenticate and normalize the principal and tenant;
2. authorize discovery/use of the tool;
3. evaluate safety/data policy;
4. obtain bound human/system approval when required;
5. validate the exact arguments against bounded schemas;
6. reserve budget and establish operation/effect identity;
7. execute through a least-privilege adapter with destination/tenant controls;
8. record safe audit outcome and reconcile ambiguous effects.

The tool runtime fails closed in library behavior, but approval persistence, expiry enforcement workers, and complete application composition are not proven. Do not bypass an unavailable approval path.

## Provider admission review

**Prerequisites**

- approved use case and data-flow inventory;
- provider legal/privacy/security terms, account policy, regions/models, and retention settings;
- concrete runtime composition and protected credentials;
- safety policy owner, tool approvers, budgets, and incident/reconciliation owners;
- non-sensitive evaluation inputs and explicit acceptance thresholds.

1. Map each data class to allowed providers, regions, models, retention modes, and features.
2. Verify routing capabilities and forbid silent downgrade.
3. Verify secrets, transport security, least-privilege account roles, and destination controls.
4. Bind safety/prompt/tool policies to versioned configuration and audit evidence.
5. Exercise denials, provider errors, invalid structured output, cancellation, tool rejection, and ambiguous usage in an approved non-production assembly.
6. Review redacted telemetry and provider-side data controls.
7. Approve exposure only after the application mounts the runtime and all lifecycle controls.

**Expected result:** every model request and effect is authorized, classified, policy-compatible, bounded, attributable, and recoverable without retaining unnecessary content.

**Failure path:** fail closed for unknown classification, incompatible provider, unavailable policy/approval/budget authority, invalid output, or ambiguous effect. Do not log the content, choose an unapproved fallback, or disable a control.

No model call, evaluation, safety check, or tool execution was run while writing this page.

## Known gaps

- No LLM runtime/bootstrap/provider credentials are assembled.
- The HTTP router factory is unmounted; OpenAPI is not exposure proof.
- Approval persistence/expiry processing is unproven.
- Safety-library policy is not shown in a concrete enforcement composition.
- Budgeting is partial and reconciliation workers are unassembled.
- Evaluation tooling has no inspected run/persistence evidence.
- Embeddings are specified-only with no crate.

See [LLM provider operations](../operations/llm-provider-operations.md), [usage budgets and quotas](../operations/usage-budgets-and-quotas.md), and [LLM troubleshooting](../troubleshooting/llm-providers-streaming-and-tools.md).