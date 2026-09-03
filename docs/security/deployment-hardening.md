---
title: Deployment hardening
description: Harden a concrete Omnius deployment across ingress, containers, configuration, databases, providers, lifecycle controls, and operator access.
status: experimental
implementation: implemented
profile_availability:
  - oauth-provider
public_exposure: assembled
audience:
  - operator
  - security-analyst
  - platform-engineer
topics:
  - security
  - deployment
  - hardening
capabilities: []
source:
  - apps/api-server/src/main.rs
  - config/reference.toml
  - crates/http/src/lib.rs
  - templates/base-service/ops/Dockerfile
  - templates/base-service/ops/compose.yaml
evidence:
  - apps/api-server/tests/api_profile.rs
  - docs/coverage-matrix.md
last_verified: 2026-09-03
---

# Deployment hardening

Apply these controls to the actual composition and platform. The OAuth-provider API is the broad assembled reference application. The base-template Dockerfile and compose file contain useful local controls but are generated/local evidence, not a production baseline, ingress policy, or orchestrator guarantee.

Read the cross-surface [security model](security-model.md) and [deployment topologies](../operations/deployment-topologies.md) first.

## Minimum production controls

### Network and ingress

- Terminate TLS at an approved boundary. The platform owns any client-address trust chain; the checked-in reference API does not consume forwarded client identity.
- The HTTP shell unconditionally strips its six recognized forwarding headers and has no reference trusted-proxy allowlist or repopulation path. Do not assume that configuring an ingress proxy makes those headers authoritative or visible downstream.
- Expose only concrete mounted routes. Catalog, OpenAPI, reserved-path, LLM factory, MCP source, and fixture routes are not exposure evidence.
- Keep PostgreSQL and every internal provider on least-access networks; do not use local compose loopback settings as a production topology.
- Bound body size, request time, concurrency, connection count, and idle/stream lifetime at compatible ingress and application layers.

### Identity and authorization

- Deliver session, API-key, OAuth, signing, and pepper material from protected systems; reference placeholders are not defaults and are not interpolated automatically.
- Keep service-layer authorization and tenant membership authoritative. Frontend guards and capability artifacts are not enforcement.
- Scope operator and migration identities separately from application identities.
- Protect administrative CLI actions and OAuth client/invite changes with named operator roles and audit evidence.
- Enable only authentication mechanisms configured and exercised in the application. JWT source/profile selection does not mean JWT is enabled in the reference configuration.

### Process and container

- Run as a non-root, dedicated identity with a read-only root filesystem and a bounded writable temporary area when the platform supports it.
- Remove unnecessary Linux capabilities, prevent privilege escalation, and use a platform-appropriate syscall/resource policy.
- Use immutable, digest-identified release artifacts. The local recovery database tag is not digest pinned and must not become a production precedent.
- Keep runtime secrets out of image layers, build arguments, generated artifacts, and support bundles.
- Align platform termination grace with application listener/provider/telemetry drain so the platform does not preempt cleanup.

### Data and providers

- Require verified PostgreSQL TLS in production and least-privilege database roles.
- Keep migrations explicit and single-owner; reference production configuration disables startup execution.
- Treat caches, search, realtime, and model/provider outputs as non-authoritative unless a concrete contract says otherwise.
- Apply outbound destination/SSRF controls, certificate validation, provider allowlists, timeouts, and idempotency/reconciliation for effects.
- Define production backup, off-site retention, encryption/key recovery, restore rehearsal, and RPO/RTO. The local rehearsal does not supply them.

### Telemetry and evidence

- Configure only approved exporters and destinations. The checked-in reference disables Prometheus and does not prove a scrape surface.
- Redact credentials, cookies, database URLs, request bodies, prompts, model output, and tenant content.
- Keep labels bounded and separate audit event production from audit storage/query access.
- Retain revision, contract, SBOM, provenance, migration, recovery, approval, and rollback evidence under access-controlled retention.

## Hardening review procedure

**Prerequisites**

- exact revision, artifact, composition root, and resolved configuration provenance;
- architecture/data-flow and threat model for the real platform;
- protected access to ingress, secret, database, provider, and observability control planes;
- approved non-production environment and stop authority.

1. Enumerate actual listeners, mounted routes, tasks, dependencies, credentials, and egress destinations from the composition.
2. Compare platform exposure with that inventory and remove undeclared access.
3. Inspect effective configuration with secret values redacted; no supported `inspect-config` command is assembled, so use platform and source evidence rather than inventing one.
4. Verify identity/tenant/permission enforcement at service boundaries.
5. Review container/process restrictions and every writable path, capability, volume, and credential mount.
6. Exercise startup failure, dependency unreadiness, normal drain, and forced termination in the approved environment.
7. Review recovery and rollback compatibility before promotion.
8. Record residual risks and owners; do not mark workflow definitions or templates as passed controls.

**Expected result:** every exposed surface, secret, privilege, dependency, egress destination, writable resource, lifecycle action, and release artifact has an explicit owner and least-privilege control.

**Failure path:** block promotion for unknown exposure, credential leakage, missing TLS/tenant enforcement, implicit migrations, unrehearsed recovery, lifecycle mismatch, or unverifiable artifact identity. Correct the topology rather than weakening the control.

No deployment or hardening exercise was run while writing this page.

## Generated template cautions

The template uses a non-root user, read-only filesystem options, `no-new-privileges`, loopback compose binding, and a constrained `/tmp`. Its readiness is unconditional; it does not configure production TLS, orchestration, backups, external dependencies, exporters, or secret delivery. A generated project must be re-reviewed after rendering because selected modules may add privileges, state, network access, and lifecycle requirements.

## Release gate

Before traffic admission, require migration status, application-specific readiness, bounded functional identity/tenant checks, dependency and egress review, recovery evidence, supply-chain evidence, and a compatible prior or roll-forward artifact. See [upgrades and rollbacks](../operations/upgrades-and-rollbacks.md) and [supply chain](supply-chain.md).