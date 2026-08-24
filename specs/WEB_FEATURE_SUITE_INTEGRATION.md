---
spec_id: RSK-WEB-INTEGRATION
title: Integrating This Suite Into an Existing Specification Checkout
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Integrating This Suite Into an Existing Specification Checkout

This extension assumes the original Rust Service Kit specification bundle is already present and implementation may already be underway. Integration is therefore additive and preserves every existing identifier.

## Non-destructive policy

The extension:

- Adds numbered specifications beginning with `25-`.
- Adds ADRs beginning with `adr/0009-`.
- Adds tasks `T130` through `T149`.
- Adds acceptance criteria in the `AC-WEB-*` namespace.
- Adds modules and profiles that do not reuse existing IDs.
- Places all machine-readable additions below `machine/extensions/web-application-suite/`.
- Does not replace canonical files such as `machine/module-catalog.yaml`, `machine/tasks.yaml`, or `AGENTS.md`.

The implementation agent MUST NOT renumber, rewrite, or mark existing requirements obsolete solely because this suite was added.

## Machine-catalog integration

`machine/extensions/web-application-suite/merge-plan.yaml` describes the canonical targets. There are two acceptable implementation approaches:

1. **Overlay-aware tooling:** make validators and generators read the base catalogs plus extension catalogs.
2. **Controlled canonical merge:** append the extension entries to the canonical catalogs through a deterministic migration command.

Whichever approach is selected MUST:

- Reject duplicate IDs.
- Preserve order deterministically.
- validate the merged module dependency graph and profiles.
- Record the extension version that was applied.
- Be idempotent.
- Avoid modifying application-owned source files.

Do not copy values manually between YAML files. Implement one repeatable merge or overlay mechanism and test it.

## Work already underway

Existing unblocked backend tasks continue normally. New web tasks become eligible only when their declared prerequisites are complete. Addition of this suite does not authorize broad refactoring.

When the suite reveals a genuine incompatibility:

1. Create an ADR amendment.
2. Add a narrowly scoped prerequisite task.
3. Update traceability.
4. Preserve completed behavior unless the amendment explicitly supersedes it.

## Recommended first integration commit

The first commit should contain only:

- The extension files.
- Validator execution in CI.
- Overlay or merge support for the machine catalogs.
- No React application implementation.

The first implementation milestone is deterministic consumer-contract export. The Vite application is intentionally downstream of that seam.
