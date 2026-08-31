---
title: Permissions
description: Canonical permission identifier vocabulary and the exact empty current generated permission catalog.
status: experimental
implementation: implemented
profile_availability:
  - oauth-provider
public_exposure: generated-only
audience:
  - service-developer
  - client-developer
  - security-engineer
topics:
  - permissions
  - authorization
  - contracts
capabilities: []
source:
  - contracts/permissions.json
  - apps/api-server/src/contracts.rs
  - apps/api-server/src/lib.rs
evidence:
  - apps/api-server/tests/metadata_contract.rs
  - contracts/contract-manifest.json
last_verified: 2026-08-30
---

# Permissions

The checked-in generated permissions artifact is for profile `oauth-provider`, has schema version `1.0.0`, and contains an empty `permissions` array. There are currently **no public permission identifiers to list**.

This is intentional generated output, not an implicit allow-all policy, an implicit deny-all policy, or a default for arbitrary profiles.

## Artifact contract

`contracts/permissions.json` is a required leaf in the current `contracts/contract-manifest.json`. The application source defines:

- an empty `PublicPermissionId` enum;
- `PUBLIC_PERMISSIONS` with length zero;
- `SELECTED_BROWSER_COMMAND_ACTIONS` with length zero;
- exact-coverage validation before canonical serialization.

Focused metadata tests assert the empty array and its agreement with the current profile's selected contract leaves. See [Contracts and code generation](contracts-and-code-generation.md) for regeneration and drift commands.

## Authorization is separate

The empty generated vocabulary does not replace runtime authorization evidence. The checked-in reference API has assembled basic authorization paths, while generated permissions remain empty. A browser role, route guard, OAuth scope, API-key scope, MCP capability, LLM tool capability, or module ID is not automatically a public permission ID.

Do not:

- invent permission identifiers from route names or UI controls;
- infer a permission from an OAuth scope or authentication role;
- treat omission from the artifact as proof that an operation is public;
- use the generated artifact alone to claim runtime policy coverage;
- copy internal policy actions into the public contract without adding them to the authoritative registry and generation path.

## Adding a public permission

A public permission is complete only when the authoritative application registry, exact-coverage checks, generated permission artifact, compatibility classification, client consumers, and runtime authorization behavior agree. Profile selection or a generated artifact alone does not prove the policy is assembled.

Compatibility checks classify permission schema-version, identifier, resource, and action removals or changes as breaking. Added identifiers are additive; declared deprecations are reported separately. See [Compatibility and deprecations](compatibility-and-deprecations.md).
