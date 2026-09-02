---
title: Privacy, consent, and moderation
description: Govern privacy requests, consent, retention, moderation, legal holds, exports, and deletion while preserving the partial and unassembled implementation boundary.
status: experimental
implementation: partial
profile_availability: []
public_exposure: unassembled
audience:
  - privacy-owner
  - security-analyst
  - operator
topics:
  - security
  - privacy
  - consent
capabilities:
  - privacy-lifecycle-consent-moderation
source:
  - crates/privacy/src/lib.rs
  - migrations/2026082320_create_privacy_lifecycle.sql
  - specs/18-optional-product-modules.md
evidence:
  - docs/coverage-matrix.md
  - crates/privacy/tests
last_verified: 2026-09-02
---

# Privacy, consent, and moderation

Omnius contains privacy-lifecycle migration/schema support and partial library behavior. No checked-in application exposes a privacy API or composes the workers needed to complete export, deletion, retention, consent, or moderation workflows. Database rows and profiles do not prove that a request reaches every data store or external provider.

Use [data and privacy boundaries](../concepts/data-and-privacy-boundaries.md) for canonical classification and retention semantics and the [security model](security-model.md) for shared trust boundaries.

## Assets and roles

Privacy operations may touch identity records, tenant data, content, object storage, email/provider state, OAuth/session state, audit, telemetry, derived indexes, job/event history, LLM prompts/outputs/media/usage, MCP task/resource state, backups, and legal-hold evidence.

Separate roles for:

- the requesting data subject or authorized tenant representative;
- identity-verification and request-intake staff;
- privacy decision maker;
- data-store/operator owners;
- legal-hold authority;
- moderation reviewer and appeal reviewer;
- security/incident authority;
- audit/evidence custodian.

A tenant administrator is not automatically authorized to export or delete every member's data. A model decision is not consent or a moderation judgment.

## Required controls

### Request identity and authorization

Authenticate the requester at an assurance appropriate to the action. Verify subject/tenant scope and active authority. Prevent account-recovery or privacy workflows from becoming weaker alternate authentication. Use uniform external errors and rate limits without recording token values.

### Consent

Bind consent to subject, tenant where applicable, purpose, scope, policy/version, locale/presentation evidence, time, and withdrawal behavior. Absence of a record is not implied consent. Separate security/transactional processing from optional categories and make withdrawal effects explicit across downstream providers.

### Export

Authorize once and again at retrieval/delivery. Minimize fields, preserve provenance, fence tenant/subject access, use protected temporary storage, expire links/artifacts, and audit access without storing the export in the audit event. Avoid putting exports in email bodies or support systems.

### Deletion and retention

Inventory authoritative and derived stores, provider copies, object references, search indexes, queues, logs, backups, and legal holds. Use restartable, idempotent workflow state with per-store outcomes and reconciliation. Deletion completion requires evidence from every in-scope owner, not only a database status change.

### Moderation

Treat reports/content/model suggestions as untrusted. Require scoped reviewer permission, tenant boundaries, reason categories, evidence minimization, appeal/override controls, and safe notification. Automated model output may prioritize review but must not silently become final policy authority.

### Audit and privacy

Audit accountable transitions, approvals, exceptions, and completion state without reproducing sensitive content or credentials. The audit library is not a mounted query service; define protected storage, access, retention, and legal-hold behavior in the concrete deployment.

## Workflow readiness review

**Prerequisites**

- approved policy, jurisdiction/contract scope, and data inventory;
- concrete application/API/worker/provider composition;
- identity-verification, legal-hold, privacy, and escalation owners;
- protected export storage and delivery channel;
- approved disposable, non-sensitive workflow fixtures.

1. Map request states and every authoritative/derived/provider store.
2. Define authentication, authorization, tenant scope, deadlines, holds, retries, and irreversible transitions.
3. Compose and observe workers with stable operation identities, leases/fencing, idempotent per-store effects, and reconciliation.
4. Exercise denial, duplicate request, partial provider failure, restart, hold, withdrawal, expiry, appeal, and final delivery/deletion.
5. Verify retention/cleanup of temporary artifacts, job state, telemetry, and evidence itself.
6. Expose the workflow only after safe status/query behavior and operator escalation exist.

**Expected result:** each request is attributable, scoped, restartable, reconciled across all in-scope stores, and closed only with authorized evidence.

**Failure path:** keep the request pending/failed and preserve bounded state. Do not mark complete, delete around a legal hold, email raw data, bypass identity verification, or manually edit durable workflow rows.

No privacy workflow, API, or worker was run while writing this page.

## Current gaps

- no assembled privacy request API;
- no assembled export/deletion/retention/moderation worker;
- no proof of provider, object, search, LLM, MCP, or backup propagation;
- no public audit query surface;
- no end-to-end consent enforcement composition;
- no runtime verification result in this documentation pass.

Until those gaps close, treat the library/schema as a design and integration boundary, not an operational promise.

## Related pages

- [Backup, recovery, and data retention](../operations/backup-recovery-and-data-retention.md)
- [Identity and permissions troubleshooting](../troubleshooting/identity-and-permissions.md)
- [LLM safety and data governance](llm-safety-and-data-governance.md)
- [Observability](../operations/observability.md)