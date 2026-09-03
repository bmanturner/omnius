---
spec_id: OMNIUS-033
title: Web Profiles, Generator, and Upgrades
version: 0.1.0
status: normative
last_verified: 2026-09-03
---

# Web Profiles, Generator, and Upgrades

## 1. Purpose

Web capabilities MUST participate in the same module/profile/generator model as backend capabilities. Adding web support to an existing project is a supported migration, not a manual copy operation.

## 2. New modules

The extension defines these runtime modules:

- `consumer-contracts`
- `asyncapi-contracts`
- `web-sdk-core`
- `web-react`
- `web-auth`
- `web-authorization`
- `web-realtime`
- `web-uploads`
- `web-feature-flags`
- `web-tenancy`
- `web-static`
- `web-forms`
- `web-local-state`

`web-testing` remains a tooling module and MUST NOT appear in a runtime profile
or lifecycle selection. Its test harness runs separately from generated runtime
state.

Exact dependencies and application-template ownership are in the extension
module catalog. Runtime modules MUST be independently selectable only when
their dependency closure is valid. Provider-like choices MUST use existing
provider-slot/conflict mechanisms rather than ad hoc flags.

## 3. New profiles

The extension defines:

- `web-sdk-only` — contract and framework-neutral SDK without a served UI.
- `web` — authenticated browser application with static production delivery.
- `realtime-web` — authenticated web application with WebSocket/SSE integration.
- `saas-web` — SaaS profile plus organizations, uploads, feature flags, realtime, and web delivery.
- `full-reference-web` — reference/CI coverage of all compatible web modules.

Profiles MUST inherit base profiles rather than duplicate their entire runtime
module lists. Profiles MUST exclude `web-testing` and every other tooling
module.

## 4. Installed lifecycle commands

The lifecycle tool MUST be installed from the canonical repository at a full
immutable release revision:

```bash
REV=<full-lowercase-40-hex-revision>
OMNIUS_RELEASE_REVISION="$REV" cargo install --locked \
  --git https://github.com/bmanturner/omnius.git \
  --rev "$REV" \
  --bin cargo-service \
  omnius-generator
```

The installed CLI MUST support web transitions through the canonical surface:

```text
cargo service new <NAME> --profile web
cargo service add <MODULE>
cargo service remove <MODULE>
cargo service profile set <PROFILE>
cargo service update
cargo service doctor
cargo service diff
```

`cargo-service` is the only public lifecycle convention. Repository contract
generation remains a separate xtask concern and MUST NOT be exposed as a
project-owned lifecycle command.

## 5. Idempotency and ownership

Running the same lifecycle operation twice MUST produce no duplicate files,
dependencies, routes, scripts, or configuration.

The generator MUST distinguish:

- hashed kit-owned and derived files;
- deterministic managed regions;
- application-owned files, which are never overwritten or deleted;
- `Cargo.lock` as a semantically validated shared dependency lock.

Web/SDK/contract application templates MUST be embedded through an explicit
safe inventory. On first selection, the generator creates only missing regular
files and immediately records them as application-owned. Existing regular files
are preserved; symlinks and unsafe paths are refused. Removal and re-add MUST
preserve these application-owned files. Framework Rust, tooling, root `.sqlx`,
and framework migration SQL are forbidden template inventory entries.

## 6. Existing-project adoption

`profile set web` or an explicit web runtime-module addition MUST:

1. Validate exact schema-2 release identity and the current runtime selection.
2. Confirm required backend prerequisites.
3. Add extension runtime-module state without tooling modules.
4. Create missing package-manager workspace and lock policy files as
   application-owned templates.
5. Create missing deterministic contract scripts and SDK/product-shell assets.
6. Create missing development proxy and production static-delivery
   configuration.
7. Preserve every existing application-owned regular file.
8. Resolve and seal the exact Cargo lock/package graph once in a sibling stage.
9. Apply ordinary files, Cargo lock, and state through the durable transaction
   journal.

Conflicts, unsafe paths, dirty ownership, source overrides, or a mismatched
release MUST stop before mutation with a stable diagnostic.

## 7. Removal

Removing web runtime support MUST:

- remove only managed runtime registrations and matching trusted generated
  artifacts;
- preserve application-owned UI, SDK, contract, and configuration files in
  place;
- preserve backend data and migrations;
- explain remaining runtime dependencies;
- remove static routes only after proving no selected runtime module requires
  them;
- leave a clean, locked profile or abort without mutation.

## 8. Update strategy

`cargo service update` MUST support the approved one-way transition from at
least one prior released web-suite identity. Rehearsal fixtures MUST include:

- untouched generated project;
- project with application-owned routes/components;
- project with approved managed-region edits;
- project using web-sdk-only;
- project using saas-web;
- project with an intentionally stale contract;
- project with a dependency override.

Update MUST preserve unrelated application dependency records, bound the
package-graph change to the old/new service-kit closures, validate the
immutable Git source/revision, and write the sealed lock before schema-2 state.

## 9. Monorepo tooling

The baseline uses a pinned Node LTS, Corepack-compatible package-manager declaration, and pnpm workspace. The generator MUST create:

- root `package.json` with `packageManager`.
- `pnpm-workspace.yaml`.
- committed `pnpm-lock.yaml`.
- strict TypeScript configuration.
- scripts for check, generate, test, E2E, and build.
- CI frozen-install behavior.

Alternative package managers require an ADR and adapter rather than conditionals scattered through templates.

## 10. Profile verification

Every profile MUST be generated in a clean directory and run:

- Rust formatting/lint/test/build appropriate to the profile.
- frozen Node install where web is present.
- contract generation/check.
- strict TypeScript check.
- frontend unit tests.
- frontend production build.
- E2E smoke test.
- collision/ownership checks.
- advisory and license policy.

## 11. Acceptance linkage

This specification is satisfied by `AC-WEB-077` through `AC-WEB-080` plus the suite-wide criteria in specification 34.
