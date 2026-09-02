---
title: MCP tools, resources, and prompts
description: The assembled reference-record tool and the fail-closed boundary around unselected resource, prompt, and completion primitives.
status: experimental
implementation: implemented
profile_availability:
  - mcp-http
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
public_exposure: assembled
audience:
  - mcp-developer
  - module-provider-author-and-contributor
  - security-privacy-reviewer
topics:
  - mcp
  - tools
  - resources
  - prompts
  - schemas
capabilities:
  - mcp-tools
  - mcp-resources
  - mcp-prompts
source:
  - apps/mcp-server/src/lib.rs
  - crates/mcp-tools/src/projection.rs
  - crates/mcp-resources/src/projection.rs
  - crates/mcp-prompts/src/projection.rs
  - crates/mcp-server-core/src/sdk.rs
  - specs/44-mcp-tools-resources-prompts-and-results.md
evidence:
  - apps/mcp-server/tests/authenticated_mcp.rs
  - crates/mcp-tools/tests/contracts.rs
  - crates/mcp-resources/tests/resource_contracts.rs
  - crates/mcp-prompts/tests/contracts.rs
  - crates/agent-capability-registry/tests/guardrails.rs
last_verified: 2026-09-02
---

# MCP tools, resources, and prompts

> **Assembly status:** `apps/mcp-server` connects `RmcpToolAdapter` to a populated canonical registry and exposes exactly one tool, `reference_records.list.v1`. It contributes no resource or prompt adapter. Those primitives and completion remain unadvertised and return method-not-found. The broader projection libraries remain available for application-owned compositions.

These three surfaces project metadata and operations over the canonical agent registry. They never bypass the controls described in [server architecture](server-architecture.md). The registry remains authoritative for availability, authorization, tenant mode, confirmation, side-effect classification, idempotency, budgets, deadlines, cancellation, and final input/output validation.

## Shared projection rules

Every composed projection list is deterministic after deny-by-default filtering. Invocation treats discovery as stale and performs fresh checks. Draft 2020-12 schemas are evaluated locally with bounded resolution; only local references are supported. A schema may shape data, but it does not authorize a principal, choose a tenant, approve an effect, or prove an implementation exists.

Apply this order whenever an input can reveal or select a protected target:

1. authorize the advertised operation before detailed input validation, avoiding a schema oracle;
2. validate bounded input against the declared schema;
3. resolve the concrete target without performing the effect;
4. reauthorize the resolved target and tenant;
5. dispatch only through the canonical registry;
6. validate the output schema and bounded result before returning it.

Authorization denial and absence must remain indistinguishable to a caller without access. Untrusted arguments cannot supply confirmation or elevate the principal.

## Tools

The reference application exposes `reference_records.list.v1`, backed by the same Axum-independent `ReferenceRecordService::list` used by REST. It is a globally scoped, read-only query requiring `reference-records:read`; optional arguments are `limit`, `cursor`, and `name`. The registry enforces its input/output schemas, no-side-effect classification, global tenant mode, budget, deadline, cancellation, and current authorization on every call.

Tool discovery exposes only eligible registry entries and admitted extensions. A call then follows the authorization-first sequence above. Successful results are bounded and use the implemented complete or `input_required` result states; an `input_required` outcome is not permission to retain a transport session or accept unbound follow-up data.

Tool authors must declare:

- a stable capability and tool identity;
- bounded Draft 2020-12 input and output schemas;
- side-effect and confirmation policy;
- tenant mode and resource authorization needs;
- finite budget, deadline, and cancellation behavior;
- idempotency semantics for effects;
- redacted, bounded result content.

Names such as `acme.records.search` in catalogs are examples, not evidence of a runtime registry entry. The only checked-in live tool is `reference_records.list.v1`; a direct transport-to-executor shortcut is unsupported.

## Resources

The reference application does not contribute resources or resource templates, so their list/read methods return method-not-found rather than empty success.

Resources support exact declarations and full-segment URI templates. URI parsing is bounded and rejects traversal, control characters, backslashes, ambiguous escapes, and decoded delimiters. Template variables cannot occupy an authority or partial segment and cannot be duplicated.

Authorization is operation-specific: discovery of exact resources, discovery of templates, reading, and hierarchy traversal are distinct decisions. A principal denied access must not learn whether the URI, template, range, or child exists. Logical resource URIs do not imply arbitrary network fetching or filesystem access.

The result model can represent text or binary content, MIME metadata, provenance, cache metadata, ranges, and hierarchy. Range and hierarchy seams in library result types do not prove corresponding wire handlers are mounted. Composition must bind each logical URI to an application-owned implementation and preserve tenant isolation through resolution and read.

## Prompts

The reference application does not contribute prompts, so prompt list/get methods return method-not-found rather than empty success.

Prompt catalogs are deterministic and authorize discovery separately from retrieval. Arguments use bounded Draft 2020-12 schemas. Each prompt has immutable identity material—prompt ID, revision, and digest—so a caller can reason about the exact admitted definition.

Prompt rendering must keep untrusted user content separate from privileged system or developer instructions. Retrieved resource data, tool output, App messages, and Skill instructions remain untrusted data; none may inject approval, authorization, tenant identity, or privileged instructions.

No concrete prompt registry is assembled by the reference app. A sample such as `acme.summary` is not a public prompt.

## Unsupported completion surface

MCP completion is unavailable: the repository has no completion source, catalog entry, or contract. Do not emulate it through prompt listing, progressive discovery, or a proprietary RPC. Track exact support in [MCP protocol support](../../reference/mcp-protocol-support.md).

## Integration outcome

**Expected result:** an eligible caller sees a bounded deterministic catalog and can invoke only an authorized, tenant-compatible operation whose input and output satisfy local schemas and whose effect passes trusted approval, deadline, budget, cancellation, and idempotency controls.

**Failure path:** reject with bounded, redacted diagnostics on absence, denial, tenant mismatch, malformed URI, invalid schema, untrusted confirmation, unavailable implementation, exceeded budget, deadline, cancellation, or invalid result. Never reorder detailed validation ahead of the authorization boundary when it would reveal protected structure.

Use the [authenticated MCP quickstart](../../getting-started/mcp-server-quickstart.md) to inspect the mounted reference tool. Applications adding resources or prompts must exercise their changed contracts through the same authenticated transport and external conformance path.

## Related guidance

- [Discovery, versioning, and transports](discovery-versioning-and-transports.md)
- [Authentication, authorization, and tenancy](authentication-authorization-and-tenancy.md)
- [Reliability and idempotency](../../concepts/reliability-and-idempotency.md)
- [MCP security](../../security/mcp-security.md)
- [MCP capability matrix](../../reference/mcp-capability-matrix.md)
