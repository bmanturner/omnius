---
title: Testing strategy
description: Layered testing, deterministic evidence, CI coverage, and contributor test selection for Omnius changes.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - contributor
  - maintainer
  - release-engineer
topics:
  - testing
  - continuous-integration
  - evidence
capabilities:
  - ci-quality
source:
  - .config/nextest.toml
  - .github/workflows/ci.yml
  - xtask/src/profiles.rs
evidence:
  - crates/generator/tests/module_management.rs
  - release/web-suite-runbook.md
  - release/ai-mcp-suite-runbook.md
last_verified: 2026-08-30
---

# Testing strategy

Omnius uses layered evidence. A focused unit or contract test answers a narrower question than a generated profile matrix, and ordinary CI is not release approval. Select the smallest layer that can fail for the behavior you changed, then add broader checks only when the change crosses those boundaries.

For tooling setup, see [Workspace and tooling](./workspace-and-tooling.md). For release decisions, see [Compatibility and release gates](./compatibility-and-release-gates.md).

## Evidence layers

| Layer | Question answered | Typical evidence |
| --- | --- | --- |
| Unit and property tests | Does a local invariant hold across examples or generated inputs? | Package-local Rust or Vitest tests |
| Public API and contract tests | Does the externally consumed type or protocol surface remain stable? | Provider, MCP, contract, and SDK tests |
| Integration tests | Do real components cooperate across process or storage boundaries? | HTTP, PostgreSQL, transport, and browser integration tests |
| Generator tests | Are dependencies, conflicts, ownership, upgrades, and repeated renders correct? | `crates/generator/tests/module_management.rs` |
| Profile matrix | Can the declared profile be rendered and exercise its configured checks deterministically? | schema-v3 profile matrix report |
| Release evidence | Have the suite-specific automated and manual policies been satisfied? | web or AI/MCP release-evidence report |

No single row proves the others. In particular, a profile definition, generated artifact, or passing library test does not prove runtime assembly.

## Rust test execution

The repository configures `cargo-nextest` in `.config/nextest.toml`. The default and CI profiles do not retry tests. Shared-resource groups cap concurrency for process, PostgreSQL, Redis, NATS, MinIO, provider, and job tests; integration tests also have explicit timeouts. Preserve these classifications when adding tests that consume the same resources.

### Run the Rust suite under the repository scheduler

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain and `cargo-nextest` are installed. Integration tests additionally require the services and environment explicitly named by their package or test documentation; do not supply production credentials.

```bash
cargo nextest run --workspace --profile ci
```

**Expected result:** workspace tests run under the checked-in nextest scheduling and timeout policy, without retries hiding a failure.

**Failure path:** first rerun the failing package or named test with the same required local services. Diagnose deterministic failures rather than increasing retries or bypassing resource groups. If a service prerequisite is absent, report that prerequisite separately from a product failure.

### Run a focused Rust package test

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain and any test-specific local service documented by that package.

```bash
cargo test -p omnius-generator --test module_management
```

**Expected result:** the generator's module lifecycle contract tests pass, including dependency, conflict, provider-slot, removal, region, backup, doctor, diff, and idempotence behavior represented by the test file.

**Failure path:** use the failing test name to identify the violated generator contract. Do not rewrite generated expectations or weaken conflict checks merely to make the test pass.

## TypeScript and browser test layers

The root scripts separate SDK generation, type checking, tests, boundaries, build, and browser application checks. Preserve that separation: generated-code drift is not equivalent to a type failure, and a browser build is not equivalent to end-to-end behavior.

### Exercise the SDK checks

Run from the repository root.

**Prerequisites:** the pinned Node.js and package-manager versions and a completed `pnpm install --frozen-lockfile`. No application credentials are required for these checks.

```bash
pnpm sdk:check:generated
pnpm sdk:typecheck
pnpm sdk:typecheck:ts7
pnpm sdk:test
pnpm sdk:test:boundaries
pnpm sdk:build
```

**Expected result:** generated sources match current contracts, the SDK type-checks against both configured TypeScript lines, tests and package-boundary checks pass, and the distributable build completes.

**Failure path:** regenerate only through `pnpm sdk:generate` when drift is intentional. For a type, test, boundary, or build failure, fix the owning manual or generated source rather than suppressing the individual check.

### Exercise browser application checks

Run from the repository root.

**Prerequisites:** the pinned Node.js and package-manager versions, installed dependencies, generated SDK sources current with `contracts/`, and any separately documented backend/configuration required by end-to-end tests.

```bash
pnpm web:typecheck
pnpm web:typecheck:ts7
pnpm web:test
pnpm web:build
```

**Expected result:** the browser application type-checks under both configured TypeScript lines, its unit tests pass, and its production build completes.

**Failure path:** isolate the first failing layer. Generated SDK drift belongs to the contract generation workflow; route or component failures belong to `web/`; an unavailable external service is a missing integration prerequisite, not permission to replace the test with a mock.

## CI coverage

`.github/workflows/ci.yml` covers, among other repository gates:

- Rust formatting, linting, checking, nextest, documentation, and xtask tests.
- Specification generation and verification.
- Contract generation checks and semantic diff.
- Generator module-management coverage.
- Frozen Node dependency installation, audit and license checks.
- SDK generation drift, TypeScript compatibility, tests, boundaries, build, and browser coverage.
- Web type checks, release-configuration checks, Playwright suites, and release gates.
- PostgreSQL end-to-end and SQLx metadata checks.
- Profile matrix and supply-chain evidence generation.

The workflow's evidence artifacts are retained for seven days. Retention is not acceptance, and the ordinary profile-matrix CI invocation is explicitly automated evidence rather than release approval.

## Profile matrix procedure

Run from the repository root.

**Prerequisites:** the pinned Rust and Node toolchains, frozen JavaScript dependencies, and every local service required by the selected profiles. Use synthetic non-production configuration.

```bash
cargo xtask profiles generate-verify --jobs 1 --automated-evidence-only
```

**Expected result:** the task builds profiles sequentially, renders and rerenders declared profiles, checks byte identity and generator metadata, runs applicable doctor/diff and profile checks, removes each completed profile's Cargo cache while retaining its binary, and writes a schema-v5 report to `target/profile-matrix/report.json`. Each row retains resolved modules/providers/services, composition root, executable command, assembly/application requirements, registered route/task/health IDs, migration and workflow/lifecycle evidence, retained artifacts, and the resulting implementation state. Web profiles also apply their configured frozen-install, contract, TypeScript, test, build, and end-to-end checks.

**Failure path:** inspect the failing phase and profile in the report. Fix the source catalog, generator, contract, or package behavior that owns the failure. Do not mark pending manual evidence accepted or treat `release_ready: false` as success.

## Test design rules

A durable test should:

1. Assert an observable contract, boundary, invariant, transition, precedence rule, or real error.
2. Fail for a plausible regression, not for harmless refactoring.
3. Be deterministic, isolated, and safe under the checked-in concurrency policy.
4. Use bounded synthetic fixtures and redacted diagnostics.
5. Avoid live provider credentials and production endpoints.
6. Record exact protocol, model, contract, or schema revisions where compatibility depends on them.
7. Keep generated expectations owned by their generator.

For LLM-specific deterministic cases, see [Authoring LLM evaluations](./authoring-llm-evaluations.md). For MCP protocol evidence, see [Extending MCP](./extending-mcp.md).

## Evidence interpretation

A successful command is evidence only for the scope it exercised. Do not upgrade a capability's implementation, profile availability, or exposure classification on the basis of tests alone. The canonical classifications remain in the [Availability and exposure matrix](../reference/availability-and-exposure-matrix.md).