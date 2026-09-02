---
title: Upgrades and rollbacks
description: Promote or recover Omnius revisions using contract, migration, browser, AI/MCP, and supply-chain evidence rather than workflow definitions alone.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - operator
  - release-manager
topics:
  - operations
  - upgrades
  - rollback
capabilities: []
source:
  - release/web-suite-runbook.md
  - release/ai-mcp-suite-runbook.md
  - .github/workflows/ci.yml
  - scripts/release
evidence:
  - release/web-release-evidence.schema.json
  - release/ai-mcp-release-evidence.schema.json
  - docs/verification-plan.md
last_verified: 2026-09-02
---

# Upgrades and rollbacks

Omnius defines release gates, evidence schemas, and web and AI/MCP runbooks. CI definitions retain useful artifacts, but repository inspection did not establish a passing release, publication, production promotion, signing, or admission decision. A workflow or schema is a process definition, not evidence that the candidate passed.

Upgrade a concrete application, not a profile. Start with [deployment topologies](deployment-topologies.md), [compatibility and deprecations](../reference/compatibility-and-deprecations.md), and the [availability matrix](../reference/availability-and-exposure-matrix.md).

## Release unit

Bind these identities before promotion:

- source revision and immutable application/container artifact;
- compiled profile and concrete composition root;
- migration set and current target database status;
- capability, permission, OpenAPI, realtime, SDK, and MCP/LLM contract artifacts that apply;
- web build and manifest when static delivery is enabled;
- SBOM, provenance, checksums, dependency/security review, and exceptions;
- configuration provenance and secret references without values;
- for generated services, hashes of manager-derived `config/reference.toml`, `ops/compose.yaml`, and `docs/module-catalog.md`;
- candidate evidence, approvals, and retained prior compatible artifact.

Do not promote artifacts assembled from different revisions, even when individual checks pass.

## Upgrade procedure

**Prerequisites**

- authorized change window and stop authority;
- approved candidate/release evidence bound to one revision;
- protected backup and rehearsed recovery for authoritative state;
- reviewed schema and durable-history compatibility;
- concrete health, observability, capacity, and incident owners;
- a rollback **and** roll-forward decision.

1. Inspect the resolved profile, then confirm the actual application assembly and public mounts.
2. For a generated service, apply the lifecycle plan so the strict reference overlay, Compose topology, and selected dependency summary are regenerated together; do not carry forward hand-edited derived files.
3. Review dependency/SBOM/provenance/checksum outputs and every active exception. Workflow success cannot be inferred from YAML.
4. Compare contracts and consumers, including generated browser artifacts, without assuming generated operations are live.
5. Review and explicitly apply production migrations under [migration operations](migrations.md); generated local Compose's one-shot owner is not a production migration policy.
6. Verify startup, liveness, readiness, version metadata, dependency state, tenant/identity boundary, and one affected functional path.
7. For web releases, require manual accessibility evidence and treat API/browser assets as one image.
8. For AI/MCP changes, verify library/runtime composition, policy, durable history, usage/audit state, and absence of newly implied routes.
9. Expand only while stop criteria remain clear and evidence remains within the approved observation window.
10. Retain the final decision and artifacts under the release policy.

**Expected result:** the promoted application, schema, generated consumers, policies, and retained recovery unit are revision-compatible and observed on the concrete surface.

**Failure path:** stop expansion and remove the candidate from admission. Choose rollback only after compatibility review; otherwise roll forward. Preserve evidence before changing schema, durable state, credentials, or traffic.

No release workflow, deployment, or smoke scenario was run while writing this page.

## Rollback decision

A rollback is safe only when the previous binary can interpret:

- current PostgreSQL schema and data invariants;
- current OAuth/session/key state;
- durable job/event envelopes and outbox/inbox history;
- MCP task/elicitation/subscription state, if a future runtime composes it;
- LLM usage, audit, conversations, and media references;
- web contracts and static assets;
- configured secret/key versions and external provider state.

The AI/MCP runbook forbids rolling back released migrations or durable history such as audit, usage, and cursors. If compatibility is uncertain or false, use a reviewed roll-forward. Never edit migration history, erase audit/usage evidence, or discard cursors to make an older binary start.

## Rollback procedure

**Prerequisites:** incident/change authorization, retained prior immutable artifact and contract hash, schema/durable-state compatibility decision, and customer-impact owner.

1. Stop candidate expansion and preserve telemetry, error, migration, and operation evidence.
2. Remove affected candidate instances from admission and allow bounded drain.
3. Confirm the prior artifact matches its retained web/contracts/config expectations.
4. Reintroduce it through the approved platform path without reversing schema or durable history unless a separately authorized recovery plan requires restore.
5. Verify lifecycle, dependency compatibility, identity/tenancy boundaries, and the affected user journey.
6. Reconcile interrupted jobs/provider operations and monitor for delayed compatibility failures.

**Expected result:** the prior revision serves within its known contract without corrupting or discarding state created after its release.

**Failure path:** remove the incompatible prior revision and execute the approved roll-forward or restore plan. Do not keep alternating revisions against authoritative data.

## Stop signals

- startup/configuration or telemetry identity failure;
- migration dirty/checksum/gap/version mismatch;
- sustained unready dependency;
- authentication, authorization, or tenant-isolation regression;
- contract/browser asset mismatch or missing manual approval;
- duplicate or unreconciled durable effects;
- unsafe LLM routing, budget, safety, or tool authorization behavior;
- MCP exposure without explicit listener/auth composition;
- missing or inconsistent supply-chain evidence.

## Evidence status

All verification-plan results were `not run` at the time of this documentation pass. Release artifacts and reports must be produced by an authorized release execution; this page does not claim one exists.