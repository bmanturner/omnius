---
title: Compatibility and release gates
description: Compatibility policy, profile matrices, release evidence, rollback rehearsal, and the boundary between evidence and production approval.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - maintainer
  - release-engineer
  - security-reviewer
topics:
  - compatibility
  - release
  - evidence
  - rollback
capabilities:
  - release-evidence
  - profile-matrix
  - contract-compatibility
  - web-release-evidence
  - ai-mcp-release-evidence
source:
  - xtask/src/profiles.rs
  - xtask/src/contracts.rs
  - xtask/src/contract_diff.rs
  - xtask/src/web_release.rs
  - scripts/release/ai_mcp_evidence.py
evidence:
  - .github/workflows/ci.yml
  - release/web-suite-runbook.md
  - release/ai-mcp-suite-runbook.md
last_verified: 2026-09-03
---

# Compatibility and release gates

Compatibility is evaluated across contracts, generator state, profiles, SDKs, storage, protocols, and operations. Release evidence binds those checks to a candidate revision; it does not publish, sign, deploy, admit, or promote that candidate.

Use [Upgrades and rollbacks](../operations/upgrades-and-rollbacks.md) for operator procedure, [Contracts and code generation](../reference/contracts-and-code-generation.md) for artifact ownership, and [Compatibility and deprecations](../reference/compatibility-and-deprecations.md) for the canonical compatibility model.

## Compatibility surfaces

Review each changed surface independently:

| Surface | Compatibility concerns | Required evidence |
| --- | --- | --- |
| Rust library | public types, features, trait behavior, errors | public API and focused behavior tests |
| HTTP contract | paths, methods, schemas, status and error behavior | generated OpenAPI, semantic diff, SDK checks |
| Realtime contract | channels, payloads, ordering, replay, reconnect | conditional AsyncAPI, semantic diff, realtime tests |
| Permissions/capabilities | identifiers, scope, enforcement, discovery | generated artifacts, authorization and registry tests |
| SDK | exports, manual wrappers, generated types, TS lines | drift, TS6/TS7, tests, boundaries, build |
| Generator | schema-2 release identity, ownership/hashes, managed regions, thin tree, add/remove/profile-set/update, lock/graph scope, recovery | lifecycle tests, doctor/diff, fresh generation, prior-release update |
| Profile | inheritance, dependencies, conflicts, provider slots | catalog verification and profile matrix |
| Persistence | migrations, stored formats, downgrade limits | migration tests and prior-version rehearsal |
| LLM | provider/model revisions, stream events, tool and error semantics | adapter fixtures, evaluations, capability evidence |
| MCP | protocol date, IDs/revisions, negotiation, discovery, transports | core, transport, auth, and conformance tests |
| Operations | config, secrets, external dependencies, rollback | runbook and bound release evidence |

A passing check on one surface cannot waive another.

## Contract compatibility gate

Run from the repository root.

The repository's `cargo xtask` alias expands to
`cargo run --locked --package xtask --`.

**Prerequisites:** set `BASELINE` to the trusted artifact directory or safe Git revision for the supported compatibility line. Install the pinned Rust toolchain. The baseline must contain no secrets.

```bash
cargo xtask contracts check
cargo xtask contracts diff --against "$BASELINE"
```

**Expected result:** checked-in artifacts are deterministic and the semantic comparison covers OpenAPI, optional AsyncAPI, permissions, capabilities, and manifest metadata. Breaking changes fail; additive, behavioral/schema-compatible, and deprecated classifications remain review inputs.

**Failure path:** resolve unintended drift or breaking changes. An intentional break requires a documented migration, deprecation/compatibility decision, consumer update, and release evidence; a warning must not be ignored solely because the command exits successfully.

## Generated-service lifecycle and update gate

A release-affecting lifecycle change must preserve strict schema-2 state,
canonical Git/revision/version agreement, ownership hashes and regions,
application-owned files, create-once templates, semantic dependency-lock
identity, bounded graph diffs, and durable transaction recovery. Rehearse both
a fresh thin service and `update` from every supported prior schema-1 baseline.

Use a disposable Cargo home and a remotely reachable immutable candidate:

```bash
REV=<full-lowercase-40-hex-revision>
export CARGO_HOME="$(mktemp -d)"
export OMNIUS_RELEASE_REVISION="$REV"
cargo install --locked \
  --git https://github.com/bmanturner/omnius.git \
  --rev "$REV" \
  --bin cargo-service \
  omnius-generator
export PATH="$CARGO_HOME/bin:$PATH"

cargo service update --dry-run --project "$PROJECT_PATH"
cargo service doctor --project "$PROJECT_PATH" --json
cargo service diff --project "$PROJECT_PATH"
cargo metadata --format-version 1 --locked --manifest-path "$PROJECT_PATH/Cargo.toml"
```

The target is always the executing CLI's immutable release; there is no
version, source, branch, tag, or revision operand. Add `--offline` to the
mutating lifecycle command only when the canonical dependency is already in
the disposable cache.

**Expected result:** dry-run performs exact staged resolution and reports the
sealed file/lock/package diff without mutating the project. Doctor validates
integrity and provenance, diff is deterministic, metadata accepts the
committed lock without rewriting it, and the lock remains byte-identical
across read-only/build/test checks. Applied rehearsal writes ordinary files,
then lock, then state through the recoverable journal and converges wholly to
the new identity.

**Failure path:** stop on dirty or unbound tooling, identity mismatch,
noncanonical dependency source, effective Cargo override/vendor
configuration, ownership/hash conflict, invalid legacy baseline, out-of-scope
package change, stale input, migration hazard, or unexpected drift. Do not
remove `--dry-run` until the sealed prior-version plan and rollback limits are
accepted.

## Profile matrix evidence

Run from the repository root.

**Prerequisites:** pinned Rust and Node.js toolchains, plus the pinned pnpm version; frozen dependencies; all local services required by selected profiles; synthetic non-production configuration; and a remotely reachable full commit SHA containing the exact generator/framework source under test.

```bash
REV=<full-lowercase-40-hex-revision>
OMNIUS_RELEASE_REVISION="$REV" cargo xtask profiles generate-verify --jobs 1 --automated-evidence-only
```

**Expected result:** profiles build sequentially, each completed profile retains only its generated binary and report artifacts, and the configured checks produce the schema-v5 report at `target/profile-matrix/report.json`. Each profile row binds resolved modules/providers/services, composition root and executable command, assembled and application-required modules, registered route/task/health IDs, migration range, positive/negative workflow checks, readiness/outage/shutdown checks, retained artifacts, and its `selected`, `generated`, `compiled`, or `assembled` implementation state. Automated-only mode accepts only the defined pending manual record and reports `release_ready: false` until manual evidence is approved.

**Failure path:** a skipped required check, failed phase, stale/missing artifact, hash mismatch, pending manual requirement, or `release_ready: false` is non-passing for release. Fix the owning source or evidence; do not edit the report.

For release enforcement, the runbook uses the same revision-bound task without an evidence-policy flag:

```bash
OMNIUS_RELEASE_REVISION="$REV" cargo xtask profiles generate-verify
```

**Expected result:** enforcement requires `success: true`, `release_ready: true`, and `release.ready: true`, with current bound evidence.

**Failure path:** missing, weakly shaped, stale, failed, pending, or hash-inconsistent evidence remains non-passing. An output file by itself is not approval.

## Web release evidence

The web runbook binds automated command results, retained artifacts, manual accessibility evidence, revision, run ID, specification-manifest hash, and public contract aggregate hash. Its evidence is produced under `target/web-release-evidence/`.

Required coverage includes both TypeScript lines, SDK and web tests/builds, full browser suites, nested public-base behavior, accessibility, security, performance, dependency policy, semantic contract diff, prior-version lifecycle rehearsal, risk review, and SBOM/provenance integration.

Run from the repository root.

**Prerequisites:** complete the steps and binding variables in `release/web-suite-runbook.md`, including `OMNIUS_RELEASE_RUN_ID` and `OMNIUS_RELEASE_REVISION`; install pinned toolchains and browser prerequisites; configure an isolated test backend; record manual accessibility evidence through its schema. Use no production credentials.

```bash
pnpm web:release:gates
```

**Expected result:** the gate evaluates the bound web evidence set rather than only rebuilding the application.

**Failure path:** a missing, pending, stale, failed, or hash-inconsistent document blocks the gate. Reproduce evidence through `scripts/release/web_evidence.py` as specified by the runbook; never edit result status or hashes manually.

## AI/MCP release evidence

The AI/MCP runbook covers exactly eight catalog profiles: `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `mcp-http`, `mcp-enterprise`, `ai-platform`, and `full-reference-ai`.

It requires the full generated-profile matrix, AI architecture gate, merged suite validator, and generator lifecycle test. `scripts/release/ai_mcp_evidence.py` consumes the four bound command-result documents and produces `target/ai-mcp-release-evidence/evidence.json`. The result must match the candidate revision, run ID, specification-manifest hash, contract aggregate hash, and retained artifact digests.

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain and current AI/MCP catalogs. This metadata verification requires no live provider or MCP credential.

```bash
cargo xtask ai verify
cargo xtask profiles verify
```

**Expected result:** the AI architecture/catalog relationships and profile composition validate at the candidate source revision.

**Failure path:** fix the protocol compatibility, provider capability, extension, module, or profile metadata. These two commands are prerequisites only; they do not replace the four bound command results or the evidence producer in `release/ai-mcp-suite-runbook.md`.

## Security and supply-chain gates

Release review must cover:

- Rust and Node dependency advisory and license policies;
- secret-safe logs, fixtures, command results, and generated evidence;
- authentication, authorization, tenant, and outbound-network changes;
- LLM provider capability, region, pricing, safety, and raw-data policy;
- MCP protocol revisions, negotiation, transport, OAuth, cancellation, resume, and conformance;
- storage migration and rollback limitations;
- generated manifest, SDK, SBOM, provenance, and checksum consistency.

CI can create a manifest, SBOM, provenance, and checksum bundle. Repository evidence does not establish artifact signing, registry publication, admission, or environment promotion.

## Evidence retention and binding

CI retains evidence artifacts for seven days. A retained artifact is useful only when its content and hashes bind it to the same run, revision, specification manifest, contract aggregate, and required command. Copying an artifact to a longer-lived store does not change its status or approve it.

## Release decision

Automated evidence is necessary but not production authorization. A release owner must evaluate current bound evidence, manual requirements, rollback readiness, security review, and the target environment's approval policy. Production deployment remains a separate explicit decision.

## Evidence boundary

This page documents repository gates and evidence formats. It makes no claim that a package was published, an image was signed, a candidate was admitted, or a production deployment was promoted.