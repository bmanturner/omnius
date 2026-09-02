---
title: LLM providers, streaming, and tools troubleshooting
description: Diagnose Omnius LLM provider, routing, streaming, structured-output, tool, conversation, media, usage, and quota symptoms within the unassembled runtime boundary.
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
  - ai-developer
  - operator
topics:
  - troubleshooting
  - llm
  - streaming
capabilities: []
source:
  - crates/llm-core/src/lib.rs
  - crates/llm-routing/src/lib.rs
  - crates/llm-streaming/src/lib.rs
  - crates/llm-tool-runtime/src/lib.rs
  - crates/llm-usage-ledger/src/lib.rs
evidence:
  - specs/39-llm-routing-reliability-cost-and-quotas.md
  - docs/coverage-matrix.md
last_verified: 2026-09-02
---

# LLM providers, streaming, and tools troubleshooting

Provider adapters, routing, structured output, the tool runtime, prompt catalog, media, safety policy, and usage ledger are **library-only** in checked-in applications. Streaming, conversations, and budgeting are **unassembled**; `llm-evals` has **not-applicable** exposure because it is an evidence workflow rather than a runtime surface. `PUBLIC_HTTP_OPERATIONS` includes checked-in AI operations and tests exercise an LLM router factory, but the reference application's composition root does not mount that factory. Start by proving a concrete embedding application and route; profile selection and an allowlisted contract entry are not runtime assembly.

Use [model requests and responses](../guides/ai/model-requests-and-responses.md), [provider operations](../operations/llm-provider-operations.md), and [LLM safety and data governance](../security/llm-safety-and-data-governance.md).

## The expected LLM endpoint returns 404

**Discriminating evidence:** concrete application composition, mounted route inventory, revision/profile, and response provenance.

**Likely cause:** the source router factory was never mounted. Provider profiles and specs do not expose HTTP routes.

**Safe diagnostic:** inspect the composition root rather than guessing a path. Do not add ingress to an internal test router.

**Resolution:** compose the full authn/authz/tenancy/policy/usage/provider/streaming/lifecycle boundary in a reviewed application, then document its actual route. Keep public exposure unavailable until that work exists.

**Escalation data:** revision, composition root, selected modules/providers, route inventory, response status, and correlation.

No LLM route, provider call, or streaming scenario was run while writing this page.

## No provider is eligible

**Discriminating evidence:** normalized request requirements and policy-filter reasons per candidate, excluding prompts, credentials, and sensitive metadata.

**Likely causes:** capability/modality/region/residency/policy mismatch, unhealthy or breaker-open candidate, tenant allowlist, budget/rate denial, or missing credential configuration.

**Safe diagnostic:** verify the concrete route's `PolicyConstraints`, registry entries, health/breaker state, tenant policy, and credential presence/provenance. Provider registration alone does not make a candidate eligible.

**Resolution:** correct request/policy/registry/configuration intentionally. Do not silently drop a residency, modality, safety, tool, or structured-output constraint to force selection; routing should fail closed.

**Escalation data:** request identity, tenant/policy version, requested capability/modality/region, filtered candidate IDs/reasons, breaker/health state, and revision.

## Provider requests time out or trip the circuit breaker

**Discriminating evidence:** provider/operation, retry class/count, timeout stage, breaker transition, latency, and whether any output/effect began.

**Likely causes:** provider/network degradation, budget shorter than observed latency, rate limiting, or unsafe retry classification.

**Safe diagnostic:** separate connection, first-byte, stream-idle, and total timeout. Determine whether the call/effect may have committed before retry.

**Resolution:** restore provider/network capacity, tune bounded policy from measurements, or route to an independently eligible fallback. Retry only transient, idempotent operations within the shared deadline/budget.

## A stream ends without a complete terminal result

**Discriminating evidence:** normalized stream event sequence, terminal/error event, usage/finalization state, client disconnect, and provider correlation—without content.

**Likely causes:** provider interruption, idle/total timeout, client cancellation, normalization error, or lost backpressure/connection.

**Safe diagnostic:** confirm exactly one terminal/error transition and whether partial output was exposed. Streaming cannot retroactively retract emitted content.

**Resolution:** mark the attempt partial/failed and commit or reconcile usage under the observed contract. Before retry, prove that dispatch caused no side effect, or reuse the original idempotency identity to resolve the original provider/tool operation; if neither is possible, surface an ambiguous outcome instead of replaying it. Never splice a second provider into a visible stream or present partial output as a complete response.

## Structured output does not validate

**Discriminating evidence:** schema identity/version/hash, validation error path/category, repair attempt count, and provider/model—never sensitive object values.

**Likely cause:** provider output violated the schema or repair policy exhausted.

**Safe diagnostic:** validate the normalized final output and inspect value-free error paths. Do not deserialize into trusted domain/effect types before validation.

**Resolution:** correct prompt/schema/provider capability or bounded repair policy. Fail closed after the approved limit; do not loosen the schema based on one response.

## A tool call waits indefinitely or executes unexpectedly

**Discriminating evidence:** tool/operation identity, registry version, authorization/policy decision, approval state/expiry, invocation idempotency key, effect state, and worker composition.

**Likely causes:** approvals/task workers are not composed, expired approval handling is absent, schema/permission mismatch, or ambiguous external effect.

**Safe diagnostic:** prove the approval/task persistence and worker exist. Re-authorize at execution time and reconcile the effect by stable identity.

**Resolution:** keep execution pending/denied until authorization, bounded validation, approval, worker/lifecycle, and idempotency are complete. Do not bypass approval or resubmit an ambiguous non-idempotent effect.

## A usage reservation blocks requests or totals drift

**Discriminating evidence:** tenant/subject/model/operation scope, reservation/effect identity, `Reserved`/`Committed`/`Reconciled`/`Released` state, provider usage, and policy version.

**Likely causes:** stale reservation, missing finalization after failure/disconnect, delayed provider usage, reconciliation gap, or lower hard budget.

**Safe diagnostic:** trace one reservation through dispatch and finalization. Preserve an auditable trail; do not mutate totals directly.

**Resolution:** release only after proving that provider dispatch did not occur and while the ledger state remains `Reserved`. After dispatched or ambiguous work, commit missing/ambiguous usage conservatively and reconcile exact actual usage by stable identity; never refund or release it. Repair the finalization or reconciliation path, and do not dispatch before a hard-budget reservation.

## Conversation or media data cannot be recovered

**Discriminating evidence:** whether conversations/media/object storage/lifecycle are actually composed and authoritative storage state.

**Likely cause:** source/provider profile was mistaken for durable runtime assembly.

**Resolution:** do not claim durability. Compose storage, authorization, retention, privacy propagation, failure handling, and recovery before enabling the feature.

See [usage budgets and quotas](../operations/usage-budgets-and-quotas.md) and [incident response](../operations/incident-response.md).