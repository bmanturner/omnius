---
title: Incident response
description: Detect, triage, contain, recover, and preserve evidence for Omnius incidents without unsafe retries, secret disclosure, or unsupported rollback.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - operator
  - security-analyst
  - incident-commander
topics:
  - operations
  - incidents
  - recovery
capabilities: []
source:
  - crates/runtime/src/lib.rs
  - crates/telemetry/src/lib.rs
  - release/web-suite-runbook.md
  - release/ai-mcp-suite-runbook.md
evidence:
  - docs/verification-plan.md
  - docs/evidence-inventory.md
last_verified: 2026-08-30
---

# Incident response

This runbook applies to concrete Omnius deployments. It does not turn unassembled surfaces into incident scope: the checked-in application does not expose an LLM router, MCP server/stdio transport, realtime listener, web application, or worker executable merely because libraries, profiles, contracts, or tests exist.

For signal semantics, use [observability](observability.md). For canonical identity and data boundaries, use [identity, authorization, and tenancy](../concepts/identity-authorization-and-tenancy.md) and [data and privacy boundaries](../concepts/data-and-privacy-boundaries.md).

## Response principles

1. Protect people and authoritative data before availability.
2. Establish the affected concrete application, environment, revision, tenant scope, and time window.
3. Preserve evidence before mutation; never include secrets or unnecessary customer content.
4. Contain through existing platform controls and approved trust boundaries.
5. Treat retries, replay, migration, restore, credential rotation, and rollback as potentially destructive actions requiring authorization.
6. Prefer typed error codes, correlations, bounded metadata, and provider state over raw payloads.
7. Do not claim recovery until the application-specific lifecycle and affected user journey are verified.

## Initial triage

**Prerequisites:** an incident commander, access through approved operator identities, evidence retention authority, and a communication channel that does not collect credentials.

1. Record detection source, start time, impact, environments, revisions, and known affected capabilities.
2. Confirm whether the surface is assembled in the deployed application. A generated route or profile is not proof.
3. Classify the incident: startup/configuration, dependency/data, identity/authorization, browser/static, async/realtime, LLM/provider, MCP, or supply chain.
4. Inspect liveness, startup, readiness, version metadata, supervised-task events, typed errors, and request/operation correlations available in that deployment.
5. Identify authoritative state and the last known safe action before retrying anything.
6. Set containment, evidence-preservation, and customer-communication owners.

**Expected result:** responders share a bounded impact statement, concrete topology, current lifecycle state, evidence set, and next decision owner.

**Failure path:** if environment or target identity is uncertain, stop mutating actions. Escalate access and inventory rather than experimenting on production.

## Containment choices

| Condition | Safe containment direction |
|---|---|
| Bad candidate with compatible prior revision | Stop promotion, remove candidate from admission, assess rollback as one compatible artifact unit |
| Database/migration integrity concern | Stop writers/migration attempts according to the approved plan; preserve status and database evidence |
| Credential exposure | Revoke/rotate through the provider authority, then invalidate dependent sessions/tokens as required; preserve only identifiers and timing |
| Authorization/tenant isolation failure | Disable the affected operation at an existing policy/ingress boundary; do not rely on frontend guards |
| Provider or quota outage | Stop new dispatch or route only to policy-compatible providers; preserve ambiguous usage identities |
| Duplicate/ambiguous asynchronous effects | Stop automated replay; preserve effect/operation identities and provider state for reconciliation |
| Browser artifact mismatch | Restore the atomic API/web artifact and cache policy; do not copy individual assets |
| Suspected supply-chain compromise | Quarantine artifacts and credentials, retain provenance/SBOM/workflow evidence, and rebuild only from a trusted revision/environment |

No containment action should introduce a new unauthenticated route, dump configuration, disable tenant checks, weaken CSP/CSRF, bypass tool approval, or turn ephemeral messaging into authoritative state.

## Recovery decision

Before restore, replay, rollback, migration, or key rotation, require:

- authorization and change record;
- protected backup/evidence and a disposable rehearsal where applicable;
- explicit data-loss, duplicate-effect, and compatibility assessment;
- concrete stop/continue signals;
- a roll-forward alternative;
- an observation and customer-communication window.

Use [backup, recovery, and data retention](backup-recovery-and-data-retention.md), [migrations](migrations.md), and [upgrades and rollbacks](upgrades-and-rollbacks.md). A previous binary may be incompatible with current schema, durable history, audit, usage ledger, or cursors; retaining an image is not enough.

## Verification before closure

Verify only the affected concrete surface:

- lifecycle and admission state;
- dependency integrity and migration compatibility;
- authentication, authorization, and tenant isolation where implicated;
- idempotent/reconciled outcome for interrupted work;
- one bounded user journey without production-secret exposure;
- telemetry continuity and absence of recurring indicators;
- rollback/recovery evidence and remaining risk acceptance.

Document what was observed versus inferred. The repository's documentation verification plan is `not run`; it is not incident evidence.

## Escalation data

Retain:

- incident timeline and decision log;
- service/environment/revision/artifact identities;
- typed error codes, lifecycle states, request/operation/effect correlations;
- affected tenant identifiers only under need-to-know controls;
- redacted dependency/provider status;
- change, revoke, restore, migration, replay, and rollback approvals;
- data-loss/duplicate-effect/contract-compatibility assessment;
- confirmation that secrets and raw sensitive payloads were excluded.

## Symptom routes

- [Startup and configuration](../troubleshooting/startup-and-configuration.md)
- [Database, cache, and jobs](../troubleshooting/database-cache-and-jobs.md)
- [Identity and permissions](../troubleshooting/identity-and-permissions.md)
- [Web, SDK, auth, and realtime](../troubleshooting/web-sdk-auth-and-realtime.md)
- [LLM providers, streaming, and tools](../troubleshooting/llm-providers-streaming-and-tools.md)
- [MCP discovery, transports, and auth](../troubleshooting/mcp-discovery-transports-and-auth.md)

No incident drill or runtime check was run while writing this page.