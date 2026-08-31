---
title: MCP experimental and unassembled surfaces
description: Source-only MCP server-card and progressive-discovery previews, their non-wire status, and the evidence required before promotion.
status: experimental
implementation: source-only
profile_availability:
  - full-reference-ai
public_exposure: unassembled
audience:
  - mcp-developer
  - evaluator
  - contributor
topics:
  - mcp
  - experimental
  - previews
  - discovery
  - roadmap
capabilities:
  - mcp-server-card-preview
  - mcp-progressive-discovery-preview
source:
  - crates/mcp-server-card-preview/src/lib.rs
  - crates/mcp-server-card-preview/src/report.rs
  - crates/mcp-progressive-discovery-preview/src/lib.rs
  - crates/mcp-progressive-discovery-preview/src/service.rs
  - specs/47-mcp-extensions-apps-skills-and-roadmap-readiness.md
evidence:
  - specs/machine/extensions/llm-mcp-suite/module-catalog.yaml
  - specs/machine/extensions/llm-mcp-suite/profiles.yaml
  - apps/api-server/tests/api_service.rs
last_verified: 2026-08-30
---

# MCP experimental and unassembled surfaces

> **Status boundary:** The server-card and progressive-discovery previews are source-only, selected only by `full-reference-ai`, and unassembled. They are not MCP protocol capabilities, proprietary RPCs, public routes, or evidence of a live experimental server.

“Experimental” is a maturity classification, not permission to infer exposure. “Source-only” means inspected source exists without enough runtime assembly evidence to classify the capability implemented. For the shared vocabulary, see the [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md).

## Server-card preview

The server-card preview renders a bounded report only from its own fresh, immutable `AuthorizedMetadataSnapshot`. It is designed as a non-wire preview over metadata admitted for the exact request context, but no first-party application produces and wires that snapshot. It does not add an MCP capability or method, and it is separate from bare `server/discover` and the application-owned `McpExposureFilter` composition required for primitive projections.

The module catalog proposes `GET /.well-known/mcp-preview.json`, but no first-party application mounts that route. A catalog path, profile selection, report type, or generated artifact does not make the route available. The reference API also does not assemble an MCP server.

If a future application exposes a card, promotion requires at least:

- an explicit route and transport owner;
- authentication or deliberately reviewed public-metadata policy;
- tenant-aware and authorization-filtered content;
- bounded fields, sizes, cache policy, and safe error behavior;
- no capability-existence leak beyond the caller's discovery rights;
- lifecycle, telemetry, security, compatibility, and external-client evidence.

Until then, do not publish the proposed path, advertise it to clients, or treat the report as runtime discovery.

## Progressive-discovery preview

The progressive-discovery preview provides internal bounded partitions, search, and page/cursor seams. No route, MCP method, proprietary RPC, or wire type is assembled. Its internal model does not change the supported `server/discover` boundary described in [discovery, versioning, and transports](discovery-versioning-and-transports.md).

A future wire proposal would need revisioned request and response contracts, deterministic ordering, opaque bounded cursors, tenant and authorization filtering before counts or results are revealed, schema and query limits, replay/change semantics, cancellation and deadlines, cache behavior, compatibility review, and official interoperability evidence. Implementing internal pagination alone proves none of these.

Do not emulate progressive discovery with an undocumented transport method. Clients must rely only on the supported protocol surface in [MCP protocol support](../../reference/mcp-protocol-support.md).

## Other non-live MCP classifications

The two previews are not the only non-live surfaces, but the other classifications have canonical owners:

- completion and dedicated progress are **unavailable**, not previews;
- tools, resources, prompts, authentication, elicitation, tasks, subscriptions, Apps, and Skills have implemented libraries but remain **unassembled**;
- MCP profiles are **generated-only** evidence of selection;
- conformance is implemented tooling with **not-applicable** public exposure;
- the repository contains no built-in MCP client.

See the [MCP capability matrix](../../reference/mcp-capability-matrix.md) instead of expanding these into speculative roadmap promises.

## Promotion gate

A preview is not ready for reclassification until repository evidence establishes the full path:

1. a reviewed protocol or HTTP contract with explicit compatibility policy;
2. a concrete application composition root and deliberately mounted transport surface;
3. canonical authentication, tenant resolution, authorization, and resource isolation;
4. bounded schemas, output, caching, deadlines, cancellation, and drain;
5. trusted approval where an operation can cause effects;
6. persistence, migrations, retention, and restart reconciliation if state exists;
7. secret-safe telemetry and audit with an operational owner;
8. negative security cases and external-client conformance against the assembled build;
9. updated capability, availability, exposure, and protocol-support reference evidence.

**Expected result:** while source-only, the preview remains reachable only as library source and cannot be mistaken for a supported wire surface.

**Failure path:** block promotion if any route or method is inferred only from a catalog, profile, specification, generated artifact, fixture, or library type; if authorization leaks filtered metadata; or if runtime, lifecycle, persistence, compatibility, and conformance evidence is missing.

No executable command is documented because neither preview has an assembled target.

## Related guidance

- [Server architecture](server-architecture.md)
- [Apps, Skills, and extensions](apps-skills-and-extensions.md)
- [Client interoperability and conformance](client-interoperability-and-conformance.md)
- [MCP security](../../security/mcp-security.md)
