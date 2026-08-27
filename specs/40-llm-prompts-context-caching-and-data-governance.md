---
spec_id: OMNIUS-040
title: Prompts, Context, Caching, and Data Governance
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Prompts, Context, Caching, and Data Governance

## 1. Prompt catalog

Reusable prompts are versioned artifacts with stable IDs, owners, input schemas, allowed routes, tool sets, data-classification limits, evaluation sets, rollout metadata, and deprecation state. Published prompt revisions are immutable. Draft editing and production publication are separate permissions.

Prompt templates use the established safe template engine rather than ad hoc string replacement. Variables are typed and size-limited. System/developer instructions are stored separately from untrusted user or retrieved content.

## 2. Context assembly

Context assembly is deterministic and records provenance. It applies tenant and authorization filters before retrieval, enforces content and token budgets, and uses explicit ordering and truncation strategies. Documents, tool output, web content, and model output are marked as untrusted data and MUST NOT be concatenated into privileged instruction channels.

The suite intentionally does not select a vector database or RAG framework. Retrieval ports MAY be implemented later, but they must return authorized, provenance-bearing context records.

## 3. Prompt caching

Provider prompt-cache behavior is represented as a capability and route policy. Cache breakpoints, TTLs, and provider-specific controls remain adapter metadata. Cache keys MUST include all security- and semantics-relevant inputs and MUST NOT allow cross-tenant or cross-principal reuse of private content.

Application caches store normalized, policy-approved values and include route, model revision, prompt revision, tool/schema revisions, tenant scope, and data classification. Sensitive responses are not cached merely because a provider supports caching.

## 4. Data governance

Every request has a data-handling policy covering provider allowlist, region, training/retention restrictions, storage, raw payload retention, logging, and deletion. Prompts, responses, tool arguments, citations, files, and opaque reasoning state receive independent classifications.

Default telemetry excludes prompt and response content. Diagnostic capture is time-bounded, access-controlled, sampled, encrypted, audited, and redacted. User deletion and tenant retention operations propagate to conversations, usage metadata where legally permitted, media objects, caches, eval artifacts, and provider-side deletion APIs when available.

## 5. Prompt-injection defenses

Prompt injection is treated as a confused-deputy and data-flow problem, not solved by a single classifier. The design combines least-privilege tools, provenance, instruction/data separation, output encoding, human confirmation, egress policy, authorization at execution time, and adversarial tests.

## 6. Acceptance linkage

This specification is verified by `AC-AI-041` through `AC-AI-048`.
