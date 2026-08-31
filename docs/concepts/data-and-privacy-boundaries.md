---
title: Data and privacy boundaries
description: The canonical model for data classification, minimization, tenant isolation, derived projections, lifecycle work, consent, moderation, and recovery copies.
status: experimental
implementation: partial
profile_availability:
  - full-reference
public_exposure: unassembled
audience:
  - rust-application-developer
  - operator
  - security-and-privacy-reviewer
  - ai-application-developer
topics:
  - data-governance
  - privacy
  - retention
  - consent
capabilities:
  - data-lifecycle
source:
  - specs/15-security-and-supply-chain.md
  - specs/18-optional-product-modules.md
  - crates/privacy/src/lib.rs
evidence:
  - crates/privacy/tests/contracts.rs
  - crates/privacy/tests/postgres.rs
  - specs/machine/profiles.yaml
last_verified: 2026-08-30
---

# Data and privacy boundaries

Every copy of data inherits purpose, authority, tenant, retention, deletion, export, legal-hold, and incident-response obligations. Encryption at rest does not replace authorization, and moving data into a cache, queue, search index, model context, log, or backup does not weaken those obligations.

## Audience path

Application authors and reviewers should use this page when introducing a field, persistence adapter, provider, projection, or model input. Continue to the security and operations pages for concrete controls, lifecycle procedures, and LLM-specific governance.

## Classify before collection

For every data element, record:

- the application purpose and lawful/policy basis;
- subject, tenant, and authoritative owner;
- sensitivity and whether it is a credential, identifier, content, security evidence, or public contract value;
- which actors and services may read, change, export, or delete it;
- source of truth and all derived copies;
- retention start, cutoff, deletion/anonymization behavior, and legal-hold behavior;
- whether it may enter logs, metrics, traces, analytics, search, prompts, external providers, or backups;
- incident and breach-response ownership.

If a purpose and lifecycle cannot be stated, do not collect the field. Prefer bounded opaque identifiers and digests over raw content where the use case permits it.

## Trust boundaries

| Boundary | Required invariant |
|---|---|
| HTTP, realtime, MCP, and model input | Treat identifiers, tenant hints, URLs, filenames, metadata, and content as untrusted until parsed, bounded, and authorized |
| PostgreSQL | Scope tenant-owned rows and transactions explicitly; a generic pool or application convention is not database-enforced isolation |
| Object storage | Use opaque object identities, tenant-aware ownership checks, safe content handling, and bounded signed access |
| Search | Treat the index as a derived projection; authorize against current source-of-truth state before returning sensitive content |
| Jobs, events, and schedules | Carry the minimum bounded context; protect payloads and lifecycle them with the source data rather than assuming queues are temporary |
| Logs, metrics, and traces | Record bounded operational metadata, never payloads, credentials, raw personal content, or high-cardinality subject/tenant labels |
| Browser and device | Minimize persisted state, never treat client storage as authoritative policy, and clear tenant-sensitive derived state when context changes |
| LLM/provider boundary | Minimize and classify prompts/context, authorize retrieval and tools, apply provider policy, and preserve deletion/retention obligations |
| Backup and recovery copy | Apply access control, encryption, inventory, retention, deletion reconciliation, restore testing, and legal-hold policy |

## Source of truth and projections

PostgreSQL is concretely assembled in the checked-in OAuth-provider reference app. That proves a database-backed composition, not tenant enforcement for every table. A query is tenant-safe only when the authoritative tenant dimension is included and tested end to end; the reference-record table is not tenant-scoped.

Search, analytics, caches, and materialized views are projections. They must be versioned and rebuildable from an authoritative source. A projection result is never standalone authorization evidence. Reauthorize the subject/resource before returning it, and propagate source updates, retention, deletion, anonymization, and legal holds through replayable reconciliation work.

## Lifecycle workflow

Export, delete, anonymize, retention, and legal-hold operations are durable workflows, not synchronous best-effort loops:

1. authenticate and authorize the actor and target;
2. create an immutable request identity and snapshot the required inventory coverage;
3. fence destructive work while a relevant hold is pending or active;
4. reconcile each PostgreSQL, object, search, queue, and provider adapter with leases and retry-safe effect identities;
5. persist redaction-safe per-adapter evidence;
6. retry typed transient failures, then dead-letter visibly under policy;
7. complete only after every required inventory entry reconciles;
8. expose an authorized export manifest or bounded completion state;
9. audit the request, authority, transitions, and outcome without recording raw exported content.

Deletion is not proven when only the primary row disappears. Retained security/accountability evidence and legally held data need explicit policy, minimization, and separate access.

## Consent and moderation

Consent evidence is append-only, tied to document/policy version, jurisdiction/source/transport, actor, time, and permitted withdrawal behavior. It is evidence of a ceremony, not a universal authorization token. The governed legal text remains externally owned.

Moderation records reports, opaque evidence references/digests, actions, appeals, policy versions, actor roles, subjects, retention, and accountability evidence. Every application action requires injected authorization. Raw evidence belongs in an appropriate protected store, not arbitrary database fields or logs.

## Current assembly boundary

The privacy crate implements durable restartable lifecycle contracts and PostgreSQL persistence, stable inventory adapters, legal-hold fencing, immutable consent evidence, moderation workflows, authorization ports, typed failures, and redaction-safe evidence. Its contract and PostgreSQL tests demonstrate those library behaviors.

The checked-in applications do not compose privacy routes, an inventory registry spanning application stores, or a lifecycle worker. The coverage matrix therefore classifies `data-lifecycle` as `partial`, available only in the `full-reference` selection, and `unassembled`. The profile, schema, library, and tests do not prove a runtime privacy service.

Backup and recovery requirements are specified and recovery-rehearsal support exists, but the repository does not assemble a production backup system. Operators must not infer backup coverage or recovery objectives from database migrations or a rehearsal tool.

## Evidence

- [Security and data-protection specification](../../specs/15-security-and-supply-chain.md)
- [Product lifecycle and privacy specification](../../specs/18-optional-product-modules.md)
- [Privacy library boundary](../../crates/privacy/src/lib.rs)
- [Provider-neutral privacy contracts](../../crates/privacy/tests/contracts.rs)
- [PostgreSQL privacy contracts](../../crates/privacy/tests/postgres.rs)
- [Profile selections](../../specs/machine/profiles.yaml)
- [Checked-in API composition](../../apps/api-server/src/main.rs)

## Next

- [Privacy, consent, and moderation](../security/privacy-consent-and-moderation.md)
- [Backup, recovery, and data retention](../operations/backup-recovery-and-data-retention.md)
- [LLM safety and data governance](../security/llm-safety-and-data-governance.md)
