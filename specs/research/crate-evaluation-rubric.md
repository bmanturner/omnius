---
spec_id: RSK-RES-002
title: Crate Evaluation Rubric
version: 0.1.0
status: evidence
last_verified: 2026-08-23
---

# Crate Evaluation Rubric


## Scoring model

Each direct dependency candidate is scored from 0 to 5 in each category. Scores guide review; they do not replace judgment.

| Category | Weight | A score of 5 means |
|---|---:|---|
| Ecosystem fit | 15 | Maintained by or naturally integrated with the selected ecosystem |
| Stable adoption | 15 | Broad production use or foundational transitive use |
| Maintenance | 15 | Active stable releases, issue handling, multiple maintainers/organization |
| Documentation | 10 | Complete API docs, examples, migration notes, semantics |
| Security posture | 15 | Transparent advisories, safe defaults, reviewable crypto/protocol boundary |
| Compatibility | 15 | Cleanly resolves with pinned Tokio/Axum/Tower/SQLx/rustls/OTel lines |
| API stability | 5 | Predictable semver and migration path |
| Testing | 5 | Strong test suite, conformance/fuzz/property tests where appropriate |
| License/provenance | 5 | Approved license and registry release from credible source |

Maximum weighted score: 500.

## Admission thresholds

- **Default:** normally at least 375 with no zero in security, compatibility, maintenance, or provenance.
- **Optional:** normally at least 325 with isolation to one module.
- **Experimental:** lower score or prerelease, only in a non-default profile with ADR.
- **Rejected:** incompatible, abandoned, insecure, redundant, unclear license, or no stable release for required behavior.

## Hard gates

A candidate is rejected from default profiles regardless of score when:

- It is yanked.
- It has an unmitigated applicable high/critical advisory.
- It requires an unapproved license/source.
- It introduces a conflicting runtime/framework/database line across public APIs.
- The required release is a prerelease.
- It silently performs network or filesystem behavior outside the module contract.
- It cannot be bounded, timed out, canceled, or observed where those properties are required.
- It has no credible maintenance path.

## Evidence record template

```yaml
crate: example
version: 1.2.3
capability: example
status: default|optional|experimental|rejected
source_ids: []
scores:
  ecosystem_fit: 0
  stable_adoption: 0
  maintenance: 0
  documentation: 0
  security_posture: 0
  compatibility: 0
  api_stability: 0
  testing: 0
  license_provenance: 0
risks: []
alternatives: []
decision: ""
reviewed_on: 2026-08-23
```

## Review cadence

- Every service-kit minor release: changed direct dependencies.
- Every service-kit major release: all direct dependencies.
- Immediately: security advisory, maintainer/archive event, license change, or foundational version upgrade.
- Quarterly: dependencies marked optional/experimental and provider SDKs.
