---
title: Web release and static delivery
description: Release Omnius browser artifacts with contract, browser-security, accessibility, and rollback evidence while distinguishing conditional static assembly from the current web runtime ceiling.
status: experimental
implementation: implemented
profile_availability:
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: assembled
audience:
  - operator
  - web-developer
  - release-manager
topics:
  - operations
  - web
  - release
capabilities:
  - static-delivery
source:
  - crates/http/src/static_delivery.rs
  - web/vite.config.ts
  - release/web-suite-runbook.md
  - release/web-release-evidence.schema.json
  - .github/workflows/ci.yml
evidence:
  - web/e2e
  - docs/coverage-matrix.md
  - release/web-manual-accessibility-evidence.schema.json
last_verified: 2026-09-02
---

# Web release and static delivery

Static delivery is implemented and conditionally assembled by the reference API. It validates the Vite manifest, fingerprinted assets, configured base path, symlink policy, active-content policy, browser security policy, and build availability. That does not make the checked-in web application active: the concrete `oauth-provider` capability artifact reports `web-auth: false`, and browser E2E evidence expects several optional runtime routes to remain absent.

Profile resolution, generated contracts, and E2E fixtures do not prove that a deployed API contains a web build. Check [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md) and [static delivery and browser security](../guides/web/static-delivery-and-browser-security.md).

## Release evidence boundary

The repository defines CI and release-evidence schemas plus a web suite runbook. These are process definitions, not passing evidence. Manual accessibility evidence is a blocking input in the release process. Workflow presence or a generated evidence object does not prove approval, artifact publication, promotion, or production behavior.

## Candidate review

**Prerequisites**

- approved source revision and immutable Rust/web artifact identities;
- generated contract/capability artifacts from the same revision;
- the web release runbook and required evidence schemas;
- authorized browser test targets containing no production secrets;
- a retained prior compatible API/web image;
- named accessibility, security, and release approvers.

1. Confirm the concrete server enables static delivery and points at the candidate Vite output.
2. Verify manifest and fingerprint relationships and reject missing, untracked, mutable, symlinked, or inline active content not allowed by policy.
3. Compare OpenAPI, capability, permission, realtime, and SDK artifacts from the same build. Generated clients are compatibility evidence, not runtime exposure evidence.
4. Verify browser asset policy: hashed assets are immutable; the application shell is revalidated/no-cache; source maps meet the approved exposure policy.
5. Review the effective CSP and security headers. Do not relax them to make an undeclared asset load.
6. Exercise authentication/account journeys only when the backend capability artifact and assembled routes support them. Frontend route guards are presentation controls, not authorization.
7. Complete required browser-support, accessibility, localization, and error/fallback review.
8. Confirm rollback retains API and browser artifacts as one compatibility unit.
9. Sign the release decision with the retained evidence and known gaps.

**Expected result:** the candidate's server, web assets, contracts, browser policy, accessibility approval, and rollback unit resolve to one revision and one explicit capability set.

**Failure path:** block the release for manifest mismatch, missing fingerprinted assets, unsafe CSP change, source-map policy breach, contract drift, absent manual approval, or an optional browser feature whose backend route is not assembled. Fix the artifact/composition; do not add fallback routes or weaken browser controls.

This procedure was not run while writing this page.

## Static delivery failure modes

| Symptom | Discriminating evidence | Safe response |
|---|---|---|
| Service is unready when web delivery is enabled | Static build/manifest availability and contract-mismatch signal | Keep out of admission; restore a complete revision-matched build |
| Shell loads but an asset fails | Manifest key, fingerprint, base path, asset response class, CSP report | Repair build/deploy atomicity; do not make missing assets mutable |
| Client enters a route that backend does not support | Capability artifact plus concrete mounted-route evidence | Disable the client feature at generation/release; do not infer exposure from OpenAPI or catalogs |
| Old shell requests new assets, or vice versa | Cache class and retained artifact identities | Restore atomic API/web unit and correct cache policy |
| Authentication appears absent | Current capability metadata and backend session assembly | Treat `web-auth: false` as authoritative for the checked-in active artifact; do not add browser-stored secrets |
| Realtime/upload browser path returns not found | Concrete composition and fixture expectations | This may be the expected current runtime ceiling; verify before classifying as outage |

The checked-in browser fixture expects `/events`, `/realtime/ws`, and `/uploads` to be absent. That is fixture evidence for the current composition boundary, not a universal route guarantee.

## Rollback

The web runbook treats API and browser artifacts as one image. Retain the prior image and its contract hash. Before rollback, confirm the prior binary can interpret the current schema and any durable state. Restore traffic only after static readiness, security headers, authentication ceiling, and a bounded browser journey agree with the retained revision.

Do not roll back by serving a prior shell against new SDK/contracts or by copying individual asset files across revisions. See [upgrades and rollbacks](upgrades-and-rollbacks.md).

## Evidence to retain

- revision, image, web build, and contract identities;
- static-delivery configuration provenance without filesystem secrets;
- manifest/fingerprint/security-policy results;
- current capability artifact and exposure decision;
- browser-support and accessibility approvals;
- candidate and rollback observations;
- explicit note that workflow and runbook definitions are not execution evidence.

No build, browser test, workflow, or release validation was run for this documentation pass.