---
spec_id: RSK-033
title: Web Profiles, Generator, and Upgrades
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Web Profiles, Generator, and Upgrades

## 1. Purpose

Web capabilities MUST participate in the same module/profile/generator model as backend capabilities. Adding web support to an existing project is a supported migration, not a manual copy operation.

## 2. New modules

The extension defines:

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
- `web-testing`
- `web-forms`
- `web-local-state`

Their exact dependencies and ownership are in the extension module catalog.

Modules MUST be independently selectable only when their dependency closure is valid. Provider-like choices MUST use existing provider-slot/conflict mechanisms rather than ad hoc flags.

## 3. New profiles

The extension defines:

- `web-sdk-only` — contract and framework-neutral SDK without a served UI.
- `web` — authenticated browser application with static production delivery.
- `realtime-web` — authenticated web application with WebSocket/SSE integration.
- `saas-web` — SaaS profile plus organizations, uploads, feature flags, realtime, and web delivery.
- `full-reference-web` — reference/CI coverage of all compatible web modules.

Profiles MUST inherit base profiles rather than duplicate their entire module lists.

## 4. Generator commands

The generator MUST support:

```bash
cargo service add web
cargo service add realtime-web
cargo service remove web
cargo service doctor
cargo service diff
cargo service upgrade
cargo service contracts generate
cargo service contracts check
```

Equivalent `cargo xtask` commands are acceptable. The user-facing surface MUST remain stable and documented.

## 5. Idempotency and ownership

Running an add command twice MUST produce no duplicate files, dependencies, routes, scripts, or configuration.

The generator MUST distinguish:

- kit-owned files: may be replaced from templates with upgrade logic.
- managed regions: may be deterministically changed.
- derived files: regenerated.
- application-owned files: never edited automatically.

Web routes, package scripts, workspace members, Vite proxy rules, and container stages require safe managed ownership. The generator MUST NOT parse and rewrite arbitrary TypeScript source as its normal strategy.

## 6. Existing-project adoption

`add web` MUST:

1. Validate the current kit version and base profile.
2. Confirm required backend prerequisites.
3. Add extension module state.
4. add the package-manager workspace and lockfile policy.
5. add deterministic contract commands.
6. scaffold the SDK and empty product shell.
7. add development proxy configuration.
8. add production static delivery configuration.
9. add tests and CI jobs.
10. run build, contract, and profile verification.

It MUST preserve existing application code. Conflicts MUST stop with a clear diff and remediation path rather than silently overwrite.

## 7. Removal

Removing web support MUST:

- remove kit-owned web artifacts and managed registrations.
- preserve application-owned UI by default, moving or reporting orphaned files rather than deleting them.
- preserve backend data and migrations.
- explain remaining dependencies.
- remove static routes only after proving no profile requires them.
- leave a clean, compiling profile or abort.

## 8. Upgrade strategy

The upgrade engine MUST support at least one prior released web-suite version. Rehearsal fixtures MUST include:

- untouched generated project.
- project with application-owned routes/components.
- project with approved managed-region edits.
- project using web-sdk-only.
- project using saas-web.
- project with an intentionally stale contract.
- project with a dependency override.

Upgrades MUST preserve lockfile integrity and surface code-generation dependency changes.

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
