---
title: Prompts and conversations
description: Immutable prompt revisions, deterministic rendering, scoped conversation state, provider-state boundaries, and retention responsibilities.
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
  - ai-application-developer
  - data-governance-reviewer
topics:
  - llm
  - prompts
  - conversations
  - provenance
capabilities:
  - llm-prompt-catalog
  - llm-conversations
source:
  - crates/llm-prompt-catalog/src/lib.rs
  - crates/llm-conversations/src/lib.rs
  - migrations/2026082804_create_llm_prompt_catalog.sql
  - migrations/2026082805_create_llm_conversations.sql
evidence:
  - crates/llm-prompt-catalog/tests/lifecycle_render.rs
  - crates/llm-prompt-catalog/tests/context_cache.rs
  - crates/llm-conversations/tests/contracts.rs
last_verified: 2026-08-30
---

# Prompts and conversations

Prompt management and conversation state are separate contracts. A prompt revision controls reproducible rendering; a conversation controls tenant- and principal-scoped history and provider state. Neither grants a model access to data or tools.

## Availability

| Capability | Status | Implementation | Selected by profiles | Public exposure |
| --- | --- | --- | --- | --- |
| `llm-prompt-catalog` | experimental | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-conversations` | experimental | implemented | `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | unassembled |

The prompt catalog has a library and migration. Conversation contracts and a migration also exist, but the reference application has no assembled conversation adapter, public route, or retention worker.

## Immutable prompt revisions

A published prompt revision is immutable. Execution provenance should identify the exact revision, not only a mutable prompt name. Rendering is strict: missing or unexpected variables, invalid types, and work beyond the renderer's bound fail instead of producing a best-effort prompt.

A revision may define:

- declared variables and their accepted types;
- content templates and rendering bounds;
- required model capabilities and response format;
- retrieval/context policies;
- safety, truncation, and cache fences;
- provenance metadata that is safe to audit.

Prompt source and rendered content can contain sensitive instructions or user data. Do not place either in ordinary logs, traces, usage records, approval descriptions, or evaluation summaries. Prefer revision identifiers, hashes, bounded sizes, and redacted policy outcomes.

## Retrieval and context assembly

Retrieved records remain untrusted content. Retrieval authorization happens before content enters the context, and retrieved text never becomes privileged instruction merely because it is concatenated near a system message. Preserve source provenance and tenant scope through truncation and caching.

Context caches must be fenced by every dimension that changes authorization or meaning, including tenant, principal or policy scope, prompt revision, retrieval policy, and model-relevant transformation. A cache hit is not authorization.

When content exceeds the admitted context budget, apply the revision's deterministic truncation or summarization policy. Do not silently omit required policy instructions, citations, or authorization context to fit a model window.

## Conversation scope and concurrency

A conversation is scoped by tenant and principal. Reads, appends, pagination, provider-state updates, archival, and deletion must preserve that scope. Optimistic concurrency protects against lost updates; a stale write is a conflict, not permission to overwrite newer history.

Canonical conversation messages use the same provider-neutral content boundary described in [model requests and responses](model-requests-and-responses.md). A conversation record is not a raw provider transcript and must not expose private reasoning.

## Provider state

Only provider-sanctioned resumable state belongs in the provider-state boundary, such as a public summary, a signature, or an encrypted opaque reference. Treat it as provider- and model-specific. Validate ownership and expiry before reuse, and never interpret it as authorization.

Do not persist raw hidden reasoning, an unrestricted provider payload, or a secret-bearing client object as conversation state. Redaction policy still applies when a provider returns state through an extension field.

## Failure and deletion behavior

Fail closed when:

- a prompt revision cannot be resolved or is no longer admissible;
- variable validation or bounded rendering fails;
- retrieval authorization is absent;
- tenant or principal scope does not match;
- conversation version preconditions are stale;
- provider state is malformed, expired, or belongs to another scope;
- the retention/deletion policy cannot be satisfied.

The schema proves persistent records can exist; it does not prove that an application invokes archival or erasure, that object/media references are cascaded, or that a retention worker runs. Hosts must inventory prompts, messages, provider state, cache entries, evaluations, and usage records for deletion and retention workflows.

## Injection boundary

Prompt-injection detection can restrict tools, retrieval, or egress, but it does not replace authentication, authorization, tenant filtering, schema validation, or human approval. Untrusted instructions must not elevate their own role or expand tool authority.

See [safety and media](safety-and-media.md), [LLM safety and data governance](../../security/llm-safety-and-data-governance.md), and [data and privacy boundaries](../../concepts/data-and-privacy-boundaries.md).
