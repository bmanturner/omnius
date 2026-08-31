---
title: Contributing
description: End-to-end contributor workflow for scoped Omnius changes, evidence, documentation, compatibility, and review.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - contributor
  - maintainer
topics:
  - contributing
  - review
  - quality
capabilities: []
source:
  - Cargo.toml
  - package.json
  - .github/workflows/ci.yml
  - DOCS_PROMPT.md
evidence:
  - .config/nextest.toml
  - crates/generator/tests/module_management.rs
  - contracts/contract-manifest.json
last_verified: 2026-08-30
---

# Contributing

A complete Omnius change updates the owning source, every affected consumer, focused behavioral evidence, generated artifacts, compatibility review, and documentation classification together. Passing a library test or adding a catalog entry is not enough to claim runtime assembly, profile availability, or public exposure.

Start with [Workspace and tooling](./workspace-and-tooling.md), then use the specialized workflow for the surface you are changing.

## Choose one owning boundary

Before editing:

1. Identify the observable behavior and its owner.
2. Locate the existing source, test, generation, and documentation conventions for that owner.
3. Determine whether the change affects a module, profile, public contract, SDK, persistence, LLM provider, MCP protocol, web application, security policy, or release evidence.
4. List every caller and generated consumer that must migrate in the same change.
5. Confirm current implementation, profile availability, and exposure in the canonical coverage matrix.

Do not create a second convention beside an existing one. Prefer a small extension to the owning implementation over a new abstraction, crate, catalog, or generator.

## Repository-wide invariants

Contributions must preserve:

- Rust `1.98.0`, edition 2024, resolver 3, and workspace lint policy;
- Node.js `24.19.0` and pnpm `11.23.0` lockfile discipline;
- deterministic generation and checked-in artifact ownership;
- typed configuration, secret handling, and redacted diagnostics;
- explicit module dependencies, conflicts, and provider slots;
- tenant, authentication, authorization, and outbound-network boundaries;
- versioned public contracts and migration paths;
- deterministic, bounded, synthetic test fixtures;
- the distinction between source implementation, profile selection, runtime assembly, and public exposure.

## Implement a clean cutover

When changing an interface, migrate all repository callers and remove the obsolete path. Avoid compatibility shims unless the documented compatibility policy requires simultaneous versions. Generated output must be changed through its generator, and manual behavior must remain outside generator-owned directories.

For a new module, follow [Creating a module](./creating-a-module.md). For profile or renderer changes, follow [Generator and profile development](./generator-and-profile-development.md).

## Select required evidence

Use the smallest test that proves the changed contract, then add cross-boundary evidence when needed:

- Rust behavior: package-local unit, property, public API, or integration test.
- Generator lifecycle: module-management and base-service tests.
- Contract change: generation check, semantic diff, SDK drift and compatibility.
- Browser behavior: web type checks, unit tests, build, and actual browser scenario.
- LLM provider: public API, version, catalog, fixtures, and applicable evaluations.
- MCP: core protocol/discovery, owning package, transports/auth, and conformance.
- Profile change: catalog verification and generated profile matrix.
- Release-affecting change: current bound release evidence and manual policy.

See [Testing strategy](./testing-strategy.md) for evidence interpretation.

## Run Rust quality checks

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain, `cargo-nextest`, and any explicitly documented local services needed by affected integration tests. Use synthetic configuration and no production credentials.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets
cargo nextest run --workspace --profile ci
cargo test --workspace --doc
cargo test -p xtask
```

**Expected result:** formatting, lint, compilation, nextest, Rust documentation tests, and repository task tests pass under the same command forms used by CI.

**Failure path:** isolate the first failing package or test and fix the owning code. Do not suppress a lint, add retries, drop targets/features, or bypass a required service to obtain a green command.

## Run repository generation checks

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain and internally consistent machine specifications and contract sources.

```bash
cargo xtask profiles verify
cargo xtask specs generate
cargo xtask specs verify
cargo xtask contracts check
```

**Expected result:** profile catalogs validate, machine specifications regenerate and verify, and public contract artifacts have no drift.

**Failure path:** inspect and review intentional generated changes before continuing. Fix source inputs for unintended drift; do not hand-edit generated output or weaken verification.

A public contract change additionally needs a trusted baseline and the semantic-diff workflow in [Contract and SDK generation](./contract-and-sdk-generation.md).

## Run TypeScript checks when affected

Run from the repository root.

**Prerequisites:** pinned Node.js and package-manager versions and `pnpm install --frozen-lockfile`; browser end-to-end checks additionally need their separately configured backend and browser prerequisites.

```bash
pnpm sdk:check:generated
pnpm sdk:typecheck
pnpm sdk:typecheck:ts7
pnpm sdk:test
pnpm sdk:test:boundaries
pnpm sdk:build
pnpm web:typecheck
pnpm web:typecheck:ts7
pnpm web:test
pnpm web:build
```

**Expected result:** generated SDK sources are current, both TypeScript compatibility lines pass, SDK and web behavior pass, SDK boundaries hold, and both builds complete.

**Failure path:** fix contract drift through generation, SDK boundary failures in the manual public layer, and application failures in `web/`. Do not patch `packages/web-sdk/src/internal/generated/` by hand.

## Security review triggers

Request focused security review when a change affects:

- authentication, authorization, tenant context, or session/token handling;
- secret configuration, logging, evidence, or diagnostic content;
- public routes, permissions, capabilities, tools, resources, prompts, or discovery;
- outbound network destinations, provider credentials, webhooks, uploads, or URI handling;
- LLM prompts, tool results, raw responses, routing, safety, cost, or retention;
- MCP negotiation, OAuth, transports, task/subscription state, or extension visibility;
- storage migrations, deletion, export, backup, or rollback;
- dependency, provenance, SBOM, or release-admission policy.

Use the canonical pages under `docs/security/` rather than inventing a local threat model.

## Documentation requirements

Update documentation in the same change when behavior, commands, compatibility, modules, profiles, capabilities, or exposure change. Every page uses the required frontmatter classification and repository-relative evidence paths. Classification must agree with `docs/coverage-matrix.md`.

Do not upgrade a claim because code exists in a library, a profile names a module, an artifact was generated, or a test passed. Runtime assembly requires application wiring; public exposure requires direct exposure evidence.

Examples and commands must be:

- runnable from the repository root;
- explicit about prerequisites and expected result;
- accompanied by a failure path;
- safe to copy without exposing secrets;
- limited to implemented routes, flags, profiles, and guarantees.

## Review checklist

Before review, confirm:

1. The change solves the owning behavior rather than suppressing a symptom.
2. Every caller and generated consumer is migrated.
3. Obsolete code, aliases, fixtures, and documentation are removed.
4. Focused tests defend observable behavior and plausible regressions.
5. Generated artifacts are deterministic and reviewed.
6. Contract, storage, protocol, and SDK compatibility are classified.
7. Security and operations implications have an owner and evidence.
8. Module/profile changes preserve dependency, conflict, provider-slot, and ownership rules.
9. Documentation claims match canonical availability and exposure evidence.
10. Release evidence is current when the change affects a release gate.

## Release boundary

CI and contributor commands produce engineering evidence. They do not establish package publication, artifact signing, deployment admission, environment promotion, or production approval. Follow [Compatibility and release gates](./compatibility-and-release-gates.md) for release-bound evidence and explicit decision boundaries.