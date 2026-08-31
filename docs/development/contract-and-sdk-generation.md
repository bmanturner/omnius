---
title: Contract and SDK generation
description: Workflow for generating, checking, comparing, and consuming Omnius contracts and the TypeScript web SDK.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - contributor
  - api-owner
  - frontend-contributor
  - release-engineer
topics:
  - contracts
  - openapi
  - asyncapi
  - sdk
  - compatibility
capabilities: []
source:
  - xtask/src/contracts.rs
  - xtask/src/contract_diff.rs
  - contracts/contract-manifest.json
  - packages/web-sdk/package.json
evidence:
  - contracts/openapi.json
  - contracts/permissions.json
  - contracts/capabilities.json
  - .github/workflows/ci.yml
last_verified: 2026-08-30
---

# Contract and SDK generation

Omnius derives checked-in contract artifacts and a TypeScript client from repository source. The canonical artifact inventory and ownership rules are in [Contracts and code generation](../reference/contracts-and-code-generation.md); consumer guidance is in [Generated contracts and SDK](../guides/web/generated-contracts-and-sdk.md) and [Web SDK](../reference/web-sdk.md).

Generated artifacts prove the output of a generator for the selected contract context. They do not prove that a first-party runtime mounts the operation or that any artifact has been published.

## Contract artifact set

`contracts/contract-manifest.json` records the selected contract artifacts and their aggregate metadata. The current manifest requires:

- `contracts/openapi.json`;
- `contracts/permissions.json`;
- `contracts/capabilities.json`.

AsyncAPI is conditional. `cargo xtask contracts generate` includes `contracts/asyncapi.json` only when the selected public profile includes the realtime core. Do not require, fabricate, or hand-create AsyncAPI for a profile whose manifest does not select it.

The manifest also records SDK compatibility metadata. Treat manifest contents as generated source control evidence, not as a deployment registry.

## Generation ownership

- `cargo xtask contracts generate` owns the contract artifact set and manifest.
- The HTTP SDK generator consumes `contracts/openapi.json`.
- The realtime SDK generator consults the manifest and consumes `contracts/asyncapi.json` only when selected.
- SDK-generated source belongs under `packages/web-sdk/src/internal/generated/`.
- Stable manual transports, auth behavior, retries, pagination, realtime management, React adapters, and other public wrappers belong outside that directory.

The HTTP and realtime generation paths check determinism by generating repeatedly. `--check` compares generated output with the checkout and directs intentional drift through the owning generation command.

## Generate contracts

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain and a repository state whose selected profile/spec inputs are internally consistent. No production credentials are required.

```bash
cargo xtask contracts generate
```

**Expected result:** OpenAPI, permissions, capabilities, the conditional AsyncAPI artifact, and the aggregate manifest are regenerated from current source.

**Failure path:** fix the source specification, profile selection, generator, or incompatible existing artifact. Do not edit generated JSON to bypass generation.

## Check checked-in contracts

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain; generated inputs and checked-in artifacts must be present.

```bash
cargo xtask contracts check
```

**Expected result:** regenerating the selected artifact set produces no drift from `contracts/`.

**Failure path:** if the source change is intentional, run the generation command and review every semantic artifact change. If it is not intentional, revert the source of drift rather than accepting regenerated noise.

## Compare contract compatibility

Run from the repository root.

**Prerequisites:** set `BASELINE` to a trusted workspace artifact directory or safe Git revision accepted by the contract-diff command. Ensure the baseline belongs to the compatibility line being evaluated and contains no secrets.

```bash
cargo xtask contracts diff --against "$BASELINE"
```

**Expected result:** the semantic diff classifies changes across OpenAPI, optional AsyncAPI, permissions, capabilities, and manifest metadata as additive, behavioral/schema-compatible, deprecated, or breaking. Breaking changes cause command failure; warnings still require review.

**Failure path:** do not treat a zero exit status as approval of behavioral or deprecation warnings. Resolve unintended breaks, document and gate intended compatibility changes, and regenerate downstream SDK artifacts.

## Generate the web SDK

Run from the repository root.

**Prerequisites:** Node.js `24.19.0`, pnpm `11.23.0`, `pnpm install --frozen-lockfile`, and current contract artifacts. Production API credentials are not required.

```bash
pnpm sdk:generate
```

**Expected result:** HTTP, conditional realtime, and contract metadata sources under `packages/web-sdk/src/internal/generated/` are deterministically regenerated. When realtime is not selected by the manifest, the realtime generator reports that condition instead of inventing a contract.

**Failure path:** fix malformed or inconsistent contract inputs or generator nondeterminism. Do not hand-edit generated TypeScript.

## Check the complete SDK contract

Run from the repository root.

**Prerequisites:** pinned Node.js and package-manager versions, frozen dependencies, and current generated contracts.

```bash
pnpm sdk:check:generated
pnpm sdk:typecheck
pnpm sdk:typecheck:ts7
pnpm sdk:test
pnpm sdk:test:boundaries
pnpm sdk:build
```

**Expected result:** generated output is current, the SDK supports both configured TypeScript lines, behavior and import boundaries pass, and package output builds.

**Failure path:** classify the failure as contract drift, generated-code defect, manual-wrapper compatibility, boundary violation, or package build issue. Fix the owning layer and rerun the complete affected sequence.

## Change workflow

For an intentional public contract change:

1. Change the authoritative Rust/specification source, not generated JSON.
2. Generate contracts.
3. Review artifact semantics, permissions, capabilities, and conditional AsyncAPI selection.
4. Run `contracts check` to confirm determinism.
5. Compare against the trusted compatibility baseline.
6. Generate the SDK.
7. Review generated output and any required manual wrapper changes.
8. Run generated drift, both TypeScript lines, tests, boundaries, and build checks.
9. Update consumers and documentation in the same change.
10. Submit the compatibility and release evidence required by [Compatibility and release gates](./compatibility-and-release-gates.md).

## Compatibility review checklist

Review more than operation names:

- path, method, status, media type, request, response, and error changes;
- required versus optional fields, enum variants, bounds, and nullability;
- permission and capability changes;
- subscription channels, payloads, ordering, replay, and reconnect semantics when AsyncAPI is selected;
- manifest artifact membership and minimum/maximum SDK compatibility metadata;
- SDK public exports, manual adapters, and supported TypeScript lines;
- removal only after the documented deprecation window and migration path.

A change classified as non-breaking can still alter behavior or security policy. Warnings require an owner decision and release evidence.

## Security expectations

Contract changes must not expose secrets, raw provider payloads, internal tenant identifiers, or unredacted diagnostics. Permission additions and authorization changes require security review. Capability metadata must be derived from authoritative implementation evidence, not inferred from a model family, profile name, or generated client.

## Evidence boundary

Passing generation and compatibility checks demonstrates deterministic repository artifacts and the semantic comparison performed. It does not demonstrate registry publication, package publication, signing, deployment, admission, or production promotion.