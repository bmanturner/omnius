---
title: Capability and consumer contracts
description: The canonical boundary between assembled application behavior, emitted machine contracts, generated consumers, and runtime capability negotiation.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - rust-application-developer
  - web-developer
  - ai-application-developer
  - mcp-developer
  - contributor
topics:
  - capabilities
  - contracts
  - code-generation
  - compatibility
capabilities: []
source:
  - specs/26-consumer-contract-generation.md
  - contracts/contract-manifest.json
  - apps/api-server/src/contracts.rs
evidence:
  - contracts/openapi.json
  - contracts/capabilities.json
  - contracts/permissions.json
last_verified: 2026-08-30
---

# Capability and consumer contracts

A public contract describes behavior that consumers may depend on. It must be tied to a specific composition and profile; a schema discovered in source or generated from types is not enough to prove that behavior is reachable.

## Audience path

Backend authors use this page to decide what a composition must emit. Web, AI, and MCP consumers use it to decide which artifact, discovery result, or runtime metadata is authoritative. Contributors should continue to the generation and compatibility pages before changing public identifiers.

## Canonical terms

- A **capability** is externally observable behavior or a protocol surface. It may span multiple modules and processes.
- A **public contract** is deterministic machine-readable material emitted for a named composition/profile and bound to the application types and registrations that own the behavior.
- A **consumer** is any browser app, SDK, mobile client, CLI, test harness, integration, LLM host, or MCP client that relies on that contract.
- A **consumer artifact** is derived output such as an SDK. It inherits the authority and limitations of its input contract; it cannot create backend availability.

Modules and profile selection are defined in [modules, profiles, and composition](modules-profiles-and-composition.md).

## Contract pipeline

```text
application-owned types and registrations
  -> composition-owned collision and exposure checks
  -> canonical deterministic artifacts
  -> manifest hashes and compatibility classification
  -> generated consumer code
  -> runtime capability/contract-hash comparison
```

Each transition needs its own evidence. Deterministic regeneration can prove artifact integrity without proving a listener. A mounted route can prove exposure without proving that a stale committed artifact matches it. Consumer safety requires both sides to agree.

## Contract families

| Family | Authority | Boundary |
|---|---|---|
| OpenAPI | HTTP operations, parameters, auth requirements, success/error schemas, and stable operation IDs for the named contract profile | A committed operation is `generated-only` until concrete route composition proves exposure |
| AsyncAPI | Browser-facing realtime channels, messages, versions, auth, and replay/resume semantics where present | Absence must not be interpreted as realtime support; the current committed manifest contains no AsyncAPI artifact |
| Permissions | Public authorization vocabulary exported by the backend registry | An empty artifact means consumers must not invent permissions from UI roles or source constants |
| Capabilities | Compiled/runtime flags and public transport locations for the contract profile | Consumers must honor negative as well as positive declarations |
| Contract manifest | Profile, module list, generator versions, artifact hashes, aggregate hash, and SDK compatibility bounds | It identifies generated inputs; it is not deployment attestation |
| Protocol discovery | Versioned runtime discovery for surfaces such as MCP or provider capability negotiation | Library discovery types do not prove a mounted transport |

The current committed manifest identifies `oauth-provider`, lists OpenAPI, permissions, and capabilities artifacts, and uses reproducible generation metadata. Its capability artifact declares `auth-oauth-server` available and `web-auth` unavailable. Those statements apply to that artifact set, not every profile or application.

## Producer invariants

A composition that exposes behavior should:

1. derive contract fragments from the same bounded types and registrations used by the application;
2. assign stable operation, event, permission, capability, schema, and protocol identifiers;
3. include expected safe failure shapes and authentication requirements;
4. assemble fragments at the composition root and reject collisions;
5. generate canonical bytes in deterministic order;
6. hash and classify changes for compatibility;
7. omit secrets, internal policy, private dependency detail, and unavailable capabilities;
8. expose only minimally sensitive runtime metadata needed for compatibility.

Renaming a public identifier is a compatibility change even when the wire schema is unchanged.

## Consumer invariants

A consumer should:

- generate from canonical checked-in artifacts rather than scraping a live server or inferring APIs from UI code;
- treat generated files as derived and never patch them by hand;
- validate the service/profile and contract hash expected by the build;
- negotiate only capabilities declared by the relevant runtime or discovery surface;
- preserve safe problem details, request IDs, cancellation, and idempotency semantics;
- render authorization state for usability without treating the UI as the authorization boundary;
- fail visibly on an incompatible contract rather than silently weakening authentication, validation, or protocol requirements.

## Exposure test

Before documenting a public operation, answer all four questions:

1. Is the implementation present?
2. Does the concrete application construct its dependencies?
3. Does that application mount/register the public or operator entry point?
4. Does the emitted contract for that exact profile agree with the assembled behavior?

If only question 4 is true, classify the surface `generated-only`. If only reusable implementation is true, use `library-only` or `unassembled` as directed by the coverage matrix.

## Evidence

- [Consumer contract specification](../../specs/26-consumer-contract-generation.md)
- [Committed contract manifest](../../contracts/contract-manifest.json)
- [Committed capability artifact](../../contracts/capabilities.json)
- [Committed permission artifact](../../contracts/permissions.json)
- [Application contract assembly](../../apps/api-server/src/contracts.rs)
- [Generated OpenAPI artifact](../../contracts/openapi.json)

## Next

- [Contracts and code generation reference](../reference/contracts-and-code-generation.md)
- [Generated web contracts and SDK](../guides/web/generated-contracts-and-sdk.md)
- [Contract and SDK generation](../development/contract-and-sdk-generation.md)
