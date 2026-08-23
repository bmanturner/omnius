---
spec_id: RSK-RES-001
title: Research and Dependency Selection Methodology
version: 0.1.0
status: evidence
last_verified: 2026-08-23
---

# Research and Dependency Selection Methodology


## Verification date

August 23, 2026.

## Research boundary

The review focused on crates and systems that directly affect the proposed service-kit architecture. It did not attempt to rank every Rust web crate. The goal was to identify a coherent, maintainable dependency graph with secure defaults and established ownership.

Primary sources were preferred:

1. Rust, Tokio, Tower, and project documentation.
2. docs.rs documentation and published crate manifests.
3. Official project repositories and release notes.
4. RustSec and official security advisories.
5. Protocol specifications and OWASP guidance.
6. Official provider documentation.

Search-result popularity, blog posts, and social media were not used as the controlling basis for a default dependency.

## Selection process

For each capability:

1. Define the actual capability and failure semantics.
2. Determine whether the standard library or an already selected crate covers it.
3. Identify established candidates.
4. Verify current stable releases.
5. Inspect runtime/framework/database compatibility.
6. Check whether the capability crosses a public type boundary.
7. Review maintenance, documentation, advisories, license, and unsafe-code implications.
8. Prefer a crate maintained by the relevant ecosystem team or standards-focused organization.
9. Reject unnecessary wrappers when the foundational crate already provides the behavior.
10. Record alternatives and an upgrade/removal path.

## Interpretation of “battle-hardened”

No crate is certified safe merely because it is popular. In this bundle, “battle-hardened/community approved” means the candidate has a strong combination of:

- Meaningful production adoption or ecosystem centrality.
- Maintained stable releases.
- Clear documentation and examples.
- Compatibility with the chosen runtime and foundational dependency lines.
- A credible maintainer/project organization.
- Security advisories handled transparently.
- Tests and an established public API.
- Permissive/approved licensing.
- No need to depend on an unreviewed git commit or prerelease for the default profile.

## Compatibility over novelty

The newest release is not automatically the best baseline.

The key example is SQLx. SQLx 0.9.0 is current, but the selected session-store integration still targets 0.8. The baseline therefore pins 0.8.6 and records an upgrade gate. This avoids:

- Duplicate SQLx lines.
- Incompatible pool or transaction types.
- Custom infrastructure written only to bridge versions.
- A default profile based on prerelease adapters.

## Thin adapters

Avoiding reinvention does not mean every ten-line policy needs a dependency. A thin adapter is preferred when it:

- Converts a mature crate into canonical application types.
- Adds config, health, tracing, metrics, or test fakes.
- Enforces domain-specific authorization/tenancy.
- Coordinates a database transaction and outbox.
- Normalizes a vendor/provider behind a narrow interface.

Examples of intentionally application-owned thin code include the canonical `Principal`, Problem Details type, event envelope, module lifecycle metadata, idempotency record, transactional outbox, tenant query conventions, and provider ports.

## Reverification

Before implementation and every baseline upgrade, the agent MUST:

- Resolve the exact dependency graph in a scratch workspace.
- Review duplicate foundational crates.
- Run advisories, license/source policy, and supply-chain checks.
- Compile every named profile.
- Run integration and upgrade tests.
- Update `research/sources.md`, `21-crate-selection-matrix.md`, and ADRs.
