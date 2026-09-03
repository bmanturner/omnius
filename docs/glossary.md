---
title: Glossary
subtitle: Canonical terminology index
description: Direct links from documentation terms to their sole canonical concept owners.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - evaluator
  - contributor
  - application developers
topics:
  - terminology
  - architecture
  - navigation
capabilities: []
source:
  - docs/navigation.md
  - docs/concepts/architecture.md
  - docs/concepts/modules-profiles-and-composition.md
  - docs/concepts/capability-and-consumer-contracts.md
evidence:
  - docs/coverage-matrix.md
  - docs/reference/availability-and-exposure-matrix.md
last_verified: 2026-09-03
---

# Glossary

This index does not redefine terms. Each term or term family links directly to its sole canonical concept owner; application guides should link to the same owner rather than introducing another definition.

| Term or term family | Sole canonical owner |
|---|---|
| Architecture boundary; composition root; reference application; system boundary | [Architecture](concepts/architecture.md) |
| Module; profile; selection; generation; assembly; exposure model | [Modules, profiles, and composition](concepts/modules-profiles-and-composition.md) |
| Startup; liveness; readiness; draining; shutdown | [Runtime lifecycle](concepts/runtime-lifecycle.md) |
| Capability; consumer contract; generated contract; public contract; compatibility | [Capability and consumer contracts](concepts/capability-and-consumer-contracts.md) |
| Principal; authentication mechanism; authorization; tenant context; active membership | [Identity, authorization, and tenancy](concepts/identity-authorization-and-tenancy.md) |
| Effect identity; idempotency; replay safety; retry | [Reliability and idempotency](concepts/reliability-and-idempotency.md) |
| Job envelope; event envelope; delivery semantics; lease; durable processing | [Asynchronous processing](concepts/asynchronous-processing.md) |
| Data classification; retention; privacy; consent; privacy trust boundary | [Data and privacy boundaries](concepts/data-and-privacy-boundaries.md) |
| Telemetry; correlation; health signal; audit event; accountable change | [Observability model](concepts/observability-model.md) |
| Error code; RFC 9457 problem; field error; retryability | [Error model](reference/error-model.md) |
| Permission identifier; authorization vocabulary | [Permissions](reference/permissions.md) |
| Availability; implementation; maturity; public exposure classification; `assembled`; `library-only`; `generated-only`; `unassembled` | [Availability and exposure matrix](reference/availability-and-exposure-matrix.md) |
| Security asset; actor; security trust boundary; cross-surface control | [Security model](security/security-model.md) |
