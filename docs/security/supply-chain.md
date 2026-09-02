---
title: Supply chain
description: Review Omnius dependency and build material while distinguishing checked-in workflow and evidence producers from a passing, signed, promoted release.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - security-analyst
  - release-manager
  - maintainer
topics:
  - security
  - supply-chain
  - release
capabilities:
  - supply-chain
source:
  - .github/workflows/supply-chain.yml
  - .github/workflows/ci.yml
  - supply-chain/check-material.py
  - supply-chain/check-advisory-exceptions
  - scripts/release
evidence:
  - deny.toml
  - .cargo/audit.toml
  - supply-chain/imports.lock
  - docs/verification-plan.md
last_verified: 2026-09-02
---

# Supply chain

Omnius includes CI and scheduled supply-chain workflow definitions plus scripts that produce a release manifest, SBOM, provenance material, and SHA-256 checksums. Many third-party actions are commit-SHA pinned and workflow permissions are limited. Repository inspection did not establish a passing workflow, artifact publication, cryptographic signing, verified builder identity, production promotion, or admission enforcement.

Workflow YAML and generated evidence formats are controls to execute and inspect, not proof of a trusted release.

## Trust boundaries

1. **Dependency declaration to lock/material:** Rust and Node manifests, feature selection, lockfiles, source imports, and exceptions.
2. **Repository to CI:** branch/review policy, workflow changes, action references, permissions, secrets, and untrusted pull-request input.
3. **CI to artifact:** toolchain/container identity, generated contracts, tests, build inputs, SBOM/provenance/checksum producer, and artifact retention.
4. **Artifact to publication:** immutable identity, signing, transparency/attestation, repository permissions, and promotion approval.
5. **Publication to runtime admission:** signature/provenance/policy verification, environment binding, and rollback retention.

The checked-in workflows cover only parts of these boundaries.

## Current controls and gaps

| Area | Inspected source evidence | Do not infer |
|---|---|---|
| Rust dependency policy | lockfile, `deny.toml`, cargo-audit configuration, advisory exception checks | a current passing audit or complete runtime reachability decision |
| Node dependencies | lockfile and CI/supply-chain workflow steps | a license allow/deny policy; none is implemented for Node |
| Secrets | gitleaks configuration/workflow step | absence of historical or runtime secrets without an executed result |
| Actions | most action references pinned and checked | the behavior of allowed actions or a successful run |
| SBOM/provenance/checksums | producer scripts and workflow definitions | signatures, verified builder identity, publication, or runtime admission |
| Release evidence | schemas/runbooks/artifact retention | approval or production promotion |

Rust advisory/license exception sources differ and must be reconciled during review; do not assume one file represents the complete active exception set. Time-bound exceptions require an owner, rationale, affected reachability, compensating controls, and expiry action.

## Candidate review procedure

**Prerequisites**

- protected release revision and review-approved workflow definitions;
- trusted isolated builder and repository permissions;
- resolved Rust/Node dependency material and source-import inventory;
- authorized security/release reviewers;
- signing/publication/admission policy supplied by the deployment organization.

1. Verify the candidate revision and ensure workflow/action/config changes received independent review.
2. Resolve lockfiles and feature/profile selection; dependency reachability can change when a previously inactive feature becomes active.
3. Inspect secret scanning, vulnerability/advisory, license, action-pin, material/import, and contract/profile results produced for this revision.
4. Reconcile every exception source and reject expired, ownerless, ambiguous, or newly reachable exceptions.
5. Generate and inspect the manifest, SBOM, provenance, and checksums from the same build environment and candidate.
6. Bind immutable artifact identity to that evidence.
7. Apply organization-owned signing, publication, promotion, and admission verification; these are not implemented by the inspected repository workflows.
8. Retain the prior compatible artifact/evidence and record the release decision.

**Expected result:** the deployed artifact is traceable to one reviewed revision and builder, with inspected dependency/material evidence, resolved exceptions, immutable identity, and organization-owned signing/admission proof.

**Failure path:** quarantine the candidate for missing/inconsistent material, secret findings, policy violation, unpinned action, exception drift, provenance mismatch, absent signature/admission, or mixed-revision artifacts. Do not regenerate only the failing evidence or bypass policy.

No workflow, scanner, dependency check, SBOM producer, signing step, or admission check was run while writing this page.

## Incident response

For a suspected compromise:

- stop publication/promotion and quarantine candidate and related credentials;
- preserve repository, workflow, runner, artifact, SBOM, provenance, checksum, signature, and access evidence;
- identify affected revisions, dependencies/features, build environments, consumers, and deployed artifacts;
- revoke/rotate compromised repository, registry, signing, cloud, and provider credentials through their authorities;
- rebuild only from a trusted revision and isolated environment;
- verify admission against new immutable identities;
- communicate scope without publishing secrets or exploit-enabling internal details.

Do not treat a rebuild with the same untrusted inputs/builder as remediation.

## Maintainer rules

- Pin third-party actions to immutable commits and review updates.
- Keep workflow permissions least-privilege and jobs isolated from untrusted code/secrets.
- Treat generated contracts and profile output as release inputs, not runtime proof.
- Add a Node license policy before claiming cross-ecosystem license enforcement.
- Keep dependency exceptions narrow, documented, reachable-state aware, and expiring.
- Add signing, verified publication, and runtime admission before claiming end-to-end provenance enforcement.

See [upgrades and rollbacks](../operations/upgrades-and-rollbacks.md), [deployment hardening](deployment-hardening.md), and the [verification plan](../verification-plan.md).