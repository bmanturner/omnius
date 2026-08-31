---
title: Safety and media
description: Data classification, redaction, egress admission, prompt-injection restrictions, and quarantined media lifecycle contracts.
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
  - security-reviewer
  - data-governance-reviewer
topics:
  - llm
  - safety
  - media
  - privacy
  - ssrf
capabilities:
  - llm-safety-policy
  - llm-media
source:
  - crates/llm-safety-policy/src/boundary.rs
  - crates/llm-safety-policy/src/classification.rs
  - crates/llm-safety-policy/src/diagnostics.rs
  - crates/llm-safety-policy/src/inventory.rs
  - crates/outbound-http/src/lib.rs
  - crates/outbound-http/src/policy.rs
  - crates/llm-media/src/workflow.rs
  - crates/llm-media/src/ports.rs
  - migrations/2026082806_create_llm_media.sql
evidence:
  - crates/llm-safety-policy/tests/contracts.rs
  - crates/llm-media/src/tests.rs
last_verified: 2026-08-30
---

# Safety and media

Safety policy and media lifecycle are implemented libraries. They are not assembled into the reference application, so they do not prove enforcement, storage, scanning, reconciliation, deletion, routing, or a public upload/media API.

## Availability

| Capability | Status | Implementation | Selected by profiles | Public exposure |
| --- | --- | --- | --- | --- |
| `llm-safety-policy` | experimental | implemented | `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |
| `llm-media` | experimental | implemented | `llm-agent`, `ai-worker`, `ai-platform`, `full-reference-ai` | library-only |

## Classify every artifact separately

A single LLM operation can contain prompt, response, retrieval context, media, tool arguments/results, provider state, and raw provider material. Classify each independently. The most permissive classification on one artifact must not lower controls on another.

Classification informs routing, residency, retention, provider eligibility, diagnostics, cache fencing, evaluation admission, and deletion inventory. It does not replace authorization or provider contractual review.

## Redaction and retention

Default diagnostics are content-free. Safe telemetry can include opaque identifiers, policy reason codes, event classes, counts, bounded sizes, hashes or revisions where approved, usage totals, and timing. It must exclude:

- raw or rendered prompts and model output;
- private reasoning;
- retrieved or tool-returned text;
- tool arguments and results unless separately admitted and redacted;
- provider credentials and wire payloads;
- personal or tenant-confidential data;
- media bytes, provider URLs, storage keys, checksums, and scanner messages.

Full provider-payload retention requires explicit, current, in-scope evidence and bounds; missing, denied, expired, oversized, or out-of-sample evidence fails closed. Provider retention/training controls must also satisfy deployment policy. A debug flag is not sufficient authorization.

## Prompt injection and tool safety

Retrieved text, uploaded content, provider output, and tool results are untrusted. Injection indicators may add restrictions to tool use, egress, or side effects. They cannot grant authority, resolve a caller, bypass tenant scoping, approve a tool, or weaken schema validation.

Tools still pass through the registry, authentication, authorization, approval, budget, and audit boundaries in [tools and approvals](tools-and-approvals.md).

## SSRF and outbound egress

A model-supplied URL is untrusted input. Proposed egress must pass through the centralized outbound URL policy and produce an `ApprovedUrl` for the exact destination. Missing authority or a server-policy denial stops the operation. Safety code receives the approved destination as authority; it does not treat URL syntax, a model recommendation, a prompt instruction, or a previous approval as sufficient.

This boundary is what prevents model-controlled egress from becoming an SSRF bypass. The assembled host must preserve redirect, DNS/address, scheme, destination, credential, and response-size controls enforced by the canonical outbound HTTP layer. Do not fetch a URL directly from a prompt, structured output, tool result, or media reference.

## Media admission

A public `MediaReference` contains only a server-generated media identifier. Tenant, principal, object-storage key, checksum, scanner details, provider URL, and credentials remain server-side.

Both registered input and provider-produced media begin quarantined. The workflow requires:

1. authenticated tenant- and principal-scoped registration;
2. exact declared media kind, size, checksum, and normalized MIME contract;
3. a finite expiry;
4. server-internal storage access without returning a provider URL or credential;
5. a full bounded read through EOF with size and checksum verification;
6. scanner processing under a fenced claim;
7. publication only after a clean verdict wins the lifecycle race;
8. independent authorization for resolve, use, and delete;
9. reconciliation for quarantine, rejection, expiry, and deletion.

MIME is metadata, not proof of content. Scanner transport failure, checksum mismatch, size mismatch, malformed encoding, expiry, stale fence, or non-clean verdict fails closed. Inline media is limited separately from stored media and must use canonical bounded decoding.

## Content and resource bounds

Apply explicit limits to string bytes, arbitrary JSON bytes and nodes, collection items, nesting, inline binary bytes, stored media size, stream totals, tool input/output, and provider responses. Validate before allocation or downstream parsing where possible. Exceeding a bound is rejection, not truncation, unless a named deterministic policy explicitly permits truncation without removing required safety or provenance.

Unknown content types and provider extensions remain untrusted. Do not render, execute, fetch, or persist them merely because deserialization succeeded.

## Assembly gaps

The media library has a repository and migration, but no checked-in application composes its storage adapter, scanner, authorization port, reconciliation worker, route, or configuration. The safety library defines policy facts and restrictions, but no reference runtime composes it across requests, tools, providers, caches, evaluations, or retention jobs.

Treat those gaps as blockers for a public media or safety-enforced LLM claim. See [LLM safety and data governance](../../security/llm-safety-and-data-governance.md), [data and privacy boundaries](../../concepts/data-and-privacy-boundaries.md), and [backup, recovery, and data retention](../../operations/backup-recovery-and-data-retention.md).
