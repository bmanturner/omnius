---
title: Providers and routing
description: Provider adapters, capability-aware selection, fallback, retries, deadlines, circuit state, and readiness boundaries.
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
  - ai-application-developer
  - platform-engineer
  - operator
topics:
  - llm
  - providers
  - routing
  - retries
capabilities:
  - llm-provider-rig
  - llm-provider-bedrock
  - llm-provider-vertex
  - llm-routing
source:
  - crates/llm-provider-rig/src/lib.rs
  - crates/llm-provider-bedrock/src/lib.rs
  - crates/llm-provider-vertex/src/lib.rs
  - crates/llm-routing/src/selection.rs
  - crates/llm-routing/src/fallback.rs
  - crates/llm-routing/src/retry.rs
  - crates/llm-routing/src/circuit.rs
  - crates/llm-routing/src/hedge.rs
evidence:
  - crates/llm-provider-rig/tests/public_api.rs
  - crates/llm-provider-bedrock/tests/public_api.rs
  - crates/llm-provider-vertex/tests/public_api.rs
  - crates/llm-routing/src/selection.rs
  - crates/llm-routing/src/retry.rs
last_verified: 2026-08-30
---

# Providers and routing

Provider adapters translate between canonical LLM contracts and provider SDKs. Routing selects an admissible target under application policy. Both are implemented libraries; no checked-in reference runtime instantiates them, injects credentials, dispatches traffic, or publishes readiness.

## Availability

| Capability | Status | Implementation | Selected by profiles | Public exposure |
| --- | --- | --- | --- | --- |
| `llm-provider-rig` | experimental | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-provider-bedrock` | experimental | implemented | `llm-agent`, `full-reference-ai` | library-only |
| `llm-provider-vertex` | experimental | implemented | `llm-agent`, `full-reference-ai` | library-only |
| `llm-routing` | experimental | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |

Profile-selection semantics are owned by [modules, profiles, and composition](../../concepts/modules-profiles-and-composition.md#profile). In this catalog, selection records intent; it does not configure an account, workload identity, region, model, network path, quota, safety policy, or host lifecycle.

The scoped [LLM/MCP module catalog](../../../specs/machine/extensions/llm-mcp-suite/module-catalog.yaml) and [LLM/MCP profiles](../../../specs/machine/extensions/llm-mcp-suite/profiles.yaml) are the authoritative source evidence for selection and dependency declarations.

## Provider adapter boundary

An adapter maps canonical requests, responses, streaming events, errors, usage, model identity, and supported capabilities. The canonical `ProviderErrorKind` values are exactly `Unsupported`, `Provider`, `Transport`, `Timeout`, `Throttling`, `Safety`, and `Schema`; retry eligibility is reported separately. Cancellation, availability, malformed-output, and ambiguous-outcome distinctions require adapter or host evidence and policy rather than a nonexistent canonical error kind.

The application remains responsible for:

- secret injection through an approved runtime channel;
- account, project, region, and residency policy;
- allowed models and capabilities;
- provider-specific retention and training controls;
- egress and identity configuration;
- health signals, telemetry, budgets, and shutdown.

No credential is shown here because repository source confirms adapter boundaries, not an approved deployment-specific credential procedure. See [LLM provider operations](../../operations/llm-provider-operations.md).

## Capability-aware selection

Selection happens after requirements are fixed. A request may require a content modality, structured output, tools, streaming, region, data residency, or semantic boundary. Candidates that cannot prove each hard requirement are rejected before scoring.

A route decision should retain an explanation such as:

| Candidate | Result | Safe reason |
| --- | --- | --- |
| model A | rejected | required capability absent |
| model B | rejected | residency constraint not satisfied |
| model C | admissible | all hard requirements satisfied |

The explanation contains no prompt, output, credential, personal data, or private reasoning. A capability mismatch is a routing failure, not permission to silently downgrade the request.

## Fallback policy

Fallback is explicit and ordered. Each fallback target must independently satisfy the original hard requirements. Changing provider, model, region, response format, tool availability, or safety behavior is allowed only when policy proves that the change preserves the request contract.

Do not use fallback to:

- remove a required capability;
- cross a residency or semantic boundary;
- bypass a refusal or authorization failure;
- escape a budget decision;
- turn invalid structured output into unvalidated text;
- hide an exhausted deadline.

## Retry discipline

Retries share one absolute request deadline and a finite attempt budget. Backoff is bounded and jittered. A retry decision considers whether the operation is safe, whether an attempt may already be billable, whether the provider outcome is ambiguous, and whether enough time remains for another attempt and response validation.

A robust attempt lifecycle is:

1. reserve usage and cost conservatively;
2. select an admissible target;
3. dispatch with the remaining bounded `deadline_ms` encoded in the canonical request while the host retains cancellation ownership;
4. classify the outcome without exposing raw content;
5. retry only an eligible transient failure within remaining bounds;
6. after dispatch, commit actual, missing, or ambiguous usage evidence and reconcile exact actual usage when it becomes available;
7. release only when provider dispatch is proven not to have occurred.

Authentication, authorization, invalid input, capability mismatch, safety rejection, schema rejection, cancellation, and an exhausted deadline are not transient retry signals. An ambiguous provider outcome must not be assumed free or safe to duplicate.

## Circuit state, hedging, and readiness

Circuit state prevents repeatedly selecting a target that is demonstrably unhealthy. Readiness combines configured policy with current admissibility rather than merely confirming that a provider object was constructed.

Hedging can create multiple billable attempts. Policy must reserve for every possible attempt, correlate their usage, accept one winner, and cancel losers when possible. Cancellation does not prove that a provider stopped work or billing, so reconciliation remains conservative.

These libraries define policy and state machines; they do not prove a scheduler, durable circuit backend, health poller, provider bootstrap, or assembled readiness endpoint.

## Troubleshooting boundary

When selection fails, inspect the redacted rejection reasons and original requirements. When retries exhaust, inspect attempt classes, remaining deadline, circuit state, and reservation reconciliation. Do not print prompts, outputs, raw provider payloads, or credentials while diagnosing.

See the [provider capability reference](../../reference/llm-providers-and-model-capabilities.md), [usage budgets and cost control](usage-budgets-and-cost-control.md), and [provider operations](../../operations/llm-provider-operations.md).
