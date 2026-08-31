---
title: LLM integration quickstart
description: A deterministic, secret-safe path for evaluating Omnius LLM contracts without implying that an LLM runtime or HTTP API is assembled.
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
  - evaluator
topics:
  - llm
  - quickstart
  - contracts
  - composition
capabilities: []
source:
  - crates/llm-core/src/lib.rs
  - crates/llm-routing/src/lib.rs
  - crates/llm-structured-output/src/lib.rs
  - crates/llm-tool-runtime/src/lib.rs
  - crates/llm-streaming/src/lib.rs
  - crates/llm-safety-policy/src/lib.rs
  - crates/llm-usage-ledger/src/lib.rs
  - crates/llm-evals/src/lib.rs
  - apps/api-server/src/llm_http.rs
evidence:
  - crates/llm-core/tests/contracts.rs
  - crates/llm-structured-output/tests/contracts.rs
  - crates/llm-evals/fixtures/provider-contracts/v1
last_verified: 2026-08-30
---

# LLM integration quickstart

> **Integration boundary:** Omnius has implemented LLM contracts and libraries, but the checked-in reference application does not assemble an LLM provider, executor, stream, durable AI worker, or public AI router. Extension-profile selection, the router factory, focused tests, the Web SDK, and checked-in OpenAPI operations do not make an endpoint live.

This quickstart evaluates the provider-neutral boundary before an application owner supplies credentials or writes composition code. It intentionally contains no provider key, credential value, raw prompt, model output, personal data, media storage identifier, or private reasoning.

## What this path establishes

The deterministic path establishes that:

- canonical requests and responses live in `crates/llm-core` rather than in a provider SDK;
- routing can reject a model that does not meet explicit capability, region, residency, or semantic requirements;
- structured output is accepted only after local schema validation;
- tool calls require application-owned authorization and, where policy requires it, approval;
- stream consumers must observe exactly one terminal outcome;
- raw provider material and private reasoning are not retained by default;
- fixture-based evaluation is possible without live credentials.

It does **not** establish provider reachability, current pricing, runtime readiness, public HTTP exposure, browser integration, durable job processing, production safety enforcement, or release conformance. See the [availability and exposure matrix](../reference/availability-and-exposure-matrix.md) before planning an integration.

## Capability availability

This quickstart spans capabilities with different implementation and exposure classifications. The frontmatter uses the least-promissory aggregate values; the exact rows are:

| Capability | Implementation | Selected profiles | Public exposure |
| --- | --- | --- | --- |
| `llm-core` | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-routing` | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-structured-output` | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-tool-runtime` | implemented | `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-streaming` | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | unassembled |
| `llm-safety-policy` | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-usage-ledger` | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-budgeting` | partial | `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | unassembled |
| `llm-evals` | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | not-applicable |

Profile selection does not prove generated output, application assembly, credentials, provider reachability, or public exposure.

## Prerequisites

Work from the repository root with:

1. a checkout containing the cited source and focused-test files;
2. a synthetic request fixture containing no private or production data;
3. explicit required model capabilities and a bounded deadline;
4. a local JSON Schema when structured output is required;
5. deny-by-default tool policy, finite tool/model step budgets, and an opaque test principal and tenant;
6. provider credentials omitted unless a separate host application has an approved secret-injection path.

A profile name is not a prerequisite for this verification. The listed extension profiles prove selection only; read [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md) before treating generated output as an application.

## Deterministic repository path

1. **Start at the contract.** Inspect `crates/llm-core/src/request.rs`, `response.rs`, `extended_content.rs`, and `provider.rs`. Confirm that application code can remain provider-neutral and that raw retention is an explicit policy choice.
2. **Choose requirements before a model.** Follow `crates/llm-routing/src/selection.rs` and `fallback.rs`. A candidate that lacks a required capability must produce a rejection rather than an implicit downgrade.
3. **Choose one bounded result path.** For JSON, follow `crates/llm-structured-output/src/schema.rs` and `repair.rs`. For streaming, follow `crates/llm-streaming/src/event.rs` and `delivery.rs`. Do not treat a JSON fragment or an unterminated stream as success.
4. **Keep side effects outside model authority.** For tools, inspect `crates/llm-tool-runtime/src/runtime.rs`, `call.rs`, and `budget.rs`. The model proposes a call; the host authorizes, approves, deduplicates, executes, and audits it.
5. **Use offline evidence.** Compare the behavior with `crates/llm-core/tests/contracts.rs`, `crates/llm-structured-output/tests/contracts.rs`, and the versioned fixtures under `crates/llm-evals/fixtures/`. These are deterministic contract evidence, not a report that verification has been run for this documentation revision.

**Expected result:** the host-facing design has explicit request requirements, one validated result path, finite work limits, redacted diagnostics, and no dependency on provider-specific request types.

**Failure path:** stop integration if a required capability has no admissible route, structured output fails local validation, a stream ends without a valid terminal, a tool lacks authorization or approval, usage cannot be bounded, or safety/media admission fails. Do not retry by weakening capability, safety, residency, schema, or authorization requirements.

## Before adding a live provider

A host composition must still supply configuration loading, secret injection, the provider adapter, routing dispatch, cancellation propagation, usage reservation and reconciliation, safety enforcement, telemetry redaction, and lifecycle/readiness integration. A live-provider retry must be bounded by one absolute deadline and must distinguish a safe transient retry from an ambiguous billable attempt.

Continue with:

- [Model requests and responses](../guides/ai/model-requests-and-responses.md)
- [Providers and routing](../guides/ai/providers-and-routing.md)
- [Structured output](../guides/ai/structured-output.md)
- [Tools and approvals](../guides/ai/tools-and-approvals.md)
- [Safety and media](../guides/ai/safety-and-media.md)
- [Evaluations and conformance](../guides/ai/evaluations-and-conformance.md)
