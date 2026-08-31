---
title: Adding an LLM provider
description: Contributor workflow for implementing an LLM provider adapter with explicit capabilities, redacted errors, deterministic fixtures, and security review.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - ai-contributor
  - maintainer
  - security-reviewer
topics:
  - llm
  - providers
  - adapters
  - security
capabilities: []
source:
  - crates/llm-core/src/provider.rs
  - crates/llm-provider-rig/src/lib.rs
  - specs/machine/extensions/llm-mcp-suite/provider-catalog.yaml
evidence:
  - crates/llm-provider-rig/tests/public_api.rs
  - crates/llm-provider-rig/tests/version_surface.rs
  - crates/llm-provider-rig/tests/catalog.rs
last_verified: 2026-08-30
---

# Adding an LLM provider

An LLM provider is an adapter behind the common `LlmProvider` boundary. Provider code remains library composition until an application supplies credentials, routing policy, safety policy, outbound networking, and runtime assembly. Adding a catalog entry or selecting an AI profile does not expose an endpoint.

Consult [LLM providers and model capabilities](../reference/llm-providers-and-model-capabilities.md), [Evaluations and conformance](../guides/ai/evaluations-and-conformance.md), and [LLM safety and data governance](../security/llm-safety-and-data-governance.md) before implementation.

## Core provider contract

`crates/llm-core/src/provider.rs` defines a `Send + Sync` provider with two asynchronous operations:

- `complete(LlmRequest)` returns `ProviderCompletionResult` or `ProviderError`;
- `stream(LlmRequest)` returns `ProviderStream` or `ProviderError`.

The boundary uses typed, redacted errors. Raw provider response retention defaults to discard. Provider SDK types must remain inside the adapter; callers consume core Omnius types.

## Choose the adapter shape

Use the existing Rig adapter when the provider fits Rig's canonical direct-provider contract. The checked-in direct provider set covers OpenAI, Anthropic, Gemini, and OpenRouter. The repository pins the Rig compatibility surface to `0.42.0`.

Use a companion adapter when deployment, credentials, signing, region handling, or protocol behavior differs materially. Bedrock and Vertex are existing examples. Do not force cloud-specific identity and transport into the direct API-key configuration merely to avoid a crate.

A genuinely new crate must follow workspace naming and lint policy and be added to the explicit member list in `Cargo.toml`. Extending an existing adapter does not require a new crate.

## Configuration and transport

The direct Rig configuration requires:

- an exact provider variant;
- a non-empty model ID;
- a non-empty API key held as `SecretString`;
- repository-owned outbound HTTP clients;
- an explicit raw-response retention policy.

A new adapter must preserve these principles even when its credential type differs:

1. Use typed secret-bearing configuration and never format a credential into diagnostics.
2. Use the outbound HTTP abstraction so timeouts, proxying, TLS, and network policy remain centrally governable.
3. Bound response bodies, streams, tool fragments, and retries.
4. Map provider failures into stable typed and redacted errors.
5. Default raw payload retention to discard; any retention change requires data-governance review.
6. Preserve stream ordering and terminal/error semantics at the core boundary.

## Register provider metadata

The machine-readable provider catalog is `specs/machine/extensions/llm-mcp-suite/provider-catalog.yaml`. Its entries bind provider identity to:

- adapter module and protocol family;
- authentication modes;
- models and authoritative capability source;
- capability declarations;
- raw-response and data policies;
- implementation notes.

Capabilities are evidence for an exact provider, model, revision, and region where those dimensions matter. Never infer capabilities from a provider family name or from another model. Update both the catalog and the adapter's enum/mapping surface so they cannot drift silently.

## Implement the adapter

1. Select direct Rig or a companion adapter based on the transport and identity contract.
2. Add workspace membership only for a new crate.
3. Implement `complete` and `stream` against core request/result types.
4. Normalize finish reasons, usage, tool calls, and errors without leaking provider SDK types.
5. Preserve request-deadline and bounded streaming behavior. `LlmProvider` accepts only the canonical request and carries no cancellation token; the assembled host owns cancellation propagation around adapter calls.
6. Define raw-response handling and redaction before adding diagnostics.
7. Add the exact catalog entry and capability evidence.
8. Add deterministic fixtures for success, streaming, tool use, malformed responses, authentication failures, throttling, and provider errors that the adapter supports.
9. Add public API and version-surface tests.
10. Add evaluation cases where response semantics extend beyond adapter normalization.

Do not use live API calls as required test evidence. Fixtures must contain synthetic prompts, synthetic responses, and no credentials or user data.

## Test a direct Rig provider change

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain. The tests use checked-in fixtures and require no live provider key.

```bash
cargo test -p omnius-llm-provider-rig --test public_api
cargo test -p omnius-llm-provider-rig --test version_surface
cargo test -p omnius-llm-provider-rig --test catalog
```

**Expected result:** the common provider surface, pinned Rig compatibility surface, and machine-catalog alignment pass against deterministic fixtures.

**Failure path:** fix the core mapping, adapter version boundary, fixture, or catalog. Do not widen the public API to expose provider SDK types and do not weaken catalog equality.

## Test a companion adapter change

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain. Tests must use synthetic fixtures and local credential representations, not cloud credentials.

```bash
cargo test -p omnius-llm-provider-bedrock --test public_api
cargo test -p omnius-llm-provider-vertex --test public_api
```

**Expected result:** the checked-in Bedrock and Vertex companion adapters preserve their public provider boundary.

**Failure path:** run only the command for the changed companion when isolating a failure. Resolve cloud-specific configuration or normalization inside that adapter rather than changing unrelated providers.

## Verify AI catalogs and profiles

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain and internally consistent AI/MCP machine catalogs. No live provider credentials are required.

```bash
cargo xtask ai verify
cargo xtask profiles verify
```

**Expected result:** AI catalog relationships and profile composition validate against the checked-in schema and provider/module selections.

**Failure path:** fix the provider catalog, capability metadata, module catalog, or profile selection at its source. A successful catalog check still does not establish application assembly.

## Required security and operations review

Every provider addition must review:

- credential source, scope, rotation, and diagnostic redaction;
- allowed outbound hosts, TLS, proxy, and regional routing;
- tenant and request isolation;
- prompt, attachment, tool result, response, and raw-payload data policy;
- request deadlines, cancellation, retry and backoff boundaries;
- rate limits, cost ceilings, usage normalization, and billing attribution;
- model revision and regional capability evidence;
- tool-call validation and downstream authorization;
- safety filters, governance, and incident diagnostics;
- availability and fallback policy without silently changing model semantics.

A provider adapter must fail closed when required identity, policy, routing, or capability evidence is absent. Never downgrade to another provider or model as an undocumented fallback.

## Compatibility expectations

Treat changes to core requests/results, finish reasons, streaming event order, tool-call fragments, error classification, usage accounting, model IDs, and capability metadata as compatibility-sensitive. Pin external adapter versions and add fixtures before accepting changed upstream behavior.

Use [Authoring LLM evaluations](./authoring-llm-evaluations.md) for semantic conformance and [Compatibility and release gates](./compatibility-and-release-gates.md) before changing a public contract.

## Evidence boundary

Provider fixtures, public API tests, and catalog verification demonstrate library behavior and metadata alignment. They do not prove live credentials, provider availability, application routing, runtime exposure, deployment, or release promotion.