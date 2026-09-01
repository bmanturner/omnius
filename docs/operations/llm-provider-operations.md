---
title: LLM provider operations
description: Operate Omnius LLM provider libraries, routing, streaming, tools, and failure reconciliation without implying an assembled runtime or public route.
status: experimental
implementation: implemented
profile_availability:
  - llm-runtime
  - llm-api
  - llm-agent
  - ai-worker
  - ai-platform
  - full-reference-ai
public_exposure: unassembled
audience:
  - operator
  - ai-platform-engineer
topics:
  - operations
  - llm
  - providers
capabilities: []
source:
  - crates/llm-core/src/lib.rs
  - crates/llm-provider-rig/src/lib.rs
  - crates/llm-routing/src/lib.rs
  - crates/llm-streaming/src/lib.rs
  - crates/llm-http-api/src/lib.rs
evidence:
  - docs/coverage-matrix.md
  - crates/llm-core/tests
  - release/ai-mcp-suite-runbook.md
last_verified: 2026-08-30
---

# LLM provider operations

Omnius implements provider-neutral LLM contracts, adapters, capability-aware routing, structured output, bounded streaming, tools, prompt/safety libraries, and usage accounting. The reusable HTTP surface now lives in `crates/llm-http-api/src/lib.rs` and consumes the provider-neutral runtime from `crates/llm-runtime`; it is not mounted unless a generated application supplies every mandatory budget, conversation, jobs, tool-policy, and media contribution. Checked-in contracts never substitute for that runtime evidence.

Do not provision provider credentials or advertise LLM availability until a concrete application composes bootstrap, configuration, health, telemetry, shutdown, usage, policy, and an authorized transport. See [providers and routing](../guides/ai/providers-and-routing.md) and the [availability matrix](../reference/availability-and-exposure-matrix.md).

## Provider admission

**Prerequisites**

- an approved concrete application composition;
- provider account/region/model identifiers and secret references from protected systems;
- data-classification, residency, retention, and safety decisions;
- per-tenant authorization, budgets, timeouts, concurrency, and rate controls;
- observable provider health and a tested shutdown/cancellation path;
- an incident and ambiguous-usage reconciliation owner.

1. Verify that the adapter supports the required request, streaming, tool, structured-output, media, and retention capabilities.
2. Configure credentials by reference; never place provider keys or cloud credentials in repository files, shell history, logs, screenshots, prompts, or support artifacts.
3. Constrain routing by capability, residency, classification, safety, and tenant policy. The router rejects incompatible candidates and must not silently downgrade requirements.
4. Decide provider raw-data retention explicitly. The library default discards raw provider material; full retention requires authorization.
5. Reserve usage before dispatch and define commit, release, and reconciliation handling.
6. Register health, telemetry, readiness contribution, and drain for the composed provider clients.
7. Exercise bounded non-sensitive requests, cancellation, timeout, provider rejection, stream failure, and ambiguous response handling in an authorized non-production environment.

**Expected result:** only policy-compatible providers are eligible, secrets stay in the protected boundary, usage is reserved before dispatch, and every outcome has a reconciliation/telemetry path.

**Failure path:** fail closed when no provider satisfies required capabilities or policy. Do not silently substitute a provider/model, drop safety/retention/residency requirements, or replay an ambiguous request without its operation identity.

No provider call or LLM verification was run while writing this page.

## Runtime signals

When a runtime is eventually assembled, observe bounded metadata rather than content:

- provider/model capability decision and policy reason;
- tenant/operation correlation identifiers;
- queue and dispatch delay;
- first-token and completion latency;
- outcome class, retryability, and provider-safe error code;
- reservation, commit, release, and reconciliation state;
- cancellation requested/acknowledged;
- tool authorization, approval, and audit outcome;
- safety-policy version and decision without raw prompt/output.

Do not label metrics with prompts, outputs, tool arguments, file contents, model error strings, API keys, tenant payloads, or user identifiers.

## Failure classes

| Failure | Operator action |
|---|---|
| No compatible provider | Inspect declared capability/residency/classification/safety constraints; add an approved provider or change the request contract, never silently downgrade |
| Authentication or quota rejection | Validate secret reference/account status through the provider's protected control plane; rotate only under an authorized plan |
| Timeout before known dispatch | Release reservation only according to proven pre-dispatch state and retry policy |
| Ambiguous dispatch/result | Preserve operation identity, reconcile provider and ledger state, and avoid blind retry |
| Stream terminates early | Expect one terminal protocol outcome; cancel provider work where supported and reconcile usage |
| Structured output invalid | The library may perform bounded repair; remote schema references are rejected and must not be enabled as a workaround |
| Tool denied or approval unavailable | Fail closed; do not bypass authorization/approval or treat model output as consent |
| Provider outage | Use only policy-compatible routing candidates; otherwise return the bounded failure |

## Streaming and shutdown

The streaming library enforces ordering/correlation and one terminal outcome, but the core provider interface carries no cancellation token and no checked-in server mounts the stream factory. An assembled runtime must own and wire cancellation around provider calls, bound stream concurrency and duration, stop new admissions during drain, allow only the approved completion window, and reconcile usage even when the client disconnects.

A client disconnect is not proof the provider stopped billing or processing. Preserve operation identity and reconcile the final provider/ledger state.

## Provider-specific scope

Profile selection differs by adapter. Bedrock and Vertex are selected only in `llm-agent` and `full-reference-ai`; Rig is selected in all six LLM profiles. This is selection evidence only, not configured credentials, enabled regions/models, health, or runtime assembly.

## Related controls

- [LLM safety and data governance](../security/llm-safety-and-data-governance.md)
- [Usage budgets and quotas](usage-budgets-and-quotas.md)
- [LLM troubleshooting](../troubleshooting/llm-providers-streaming-and-tools.md)
- [Incident response](incident-response.md)

The documentation verification result remains `not run`; see the [verification plan](../verification-plan.md).