---
title: MCP capability matrix
description: Exact MCP-related profile selections and implementation, profile-availability, and exposure classifications.
status: experimental
implementation: implemented
profile_availability:
  - mcp-local
  - mcp-http
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
public_exposure: generated-only
audience:
  - mcp-developer
  - service-developer
  - operator
topics:
  - mcp
  - profiles
  - capabilities
capabilities:
  - mcp-profiles
source:
  - specs/machine/extensions/llm-mcp-suite/profiles.yaml
  - crates/generator/src/catalog.rs
  - migrations/2026082807_create_mcp_mrtr_state.sql
  - migrations/2026082808_create_mcp_tasks.sql
  - crates/migrations/src/lib.rs
  - docs/coverage-matrix.md
evidence:
  - crates/generator/tests/base_service.rs
  - apps/api-server/tests/api_service.rs
last_verified: 2026-08-30
---

# MCP capability matrix

Under the canonical [module and profile definitions](../concepts/modules-profiles-and-composition.md#canonical-terms), every profile row below is generated selection evidence. MCP rows use the `mcp` family; `ai-platform` and `full-reference-ai` use `ai_mcp`. Assembly additionally requires an actual stdio/HTTP process observation, discover/list/invoke authorization behavior, negative challenge/admission behavior, dependency outage and bounded drain, and operation/capability/transport parity. A library/router test or synthetic fixture cannot satisfy those checks.

## Profile selections

The module lists are the MCP-related direct additions declared by the extension profile; inherited base, web, and LLM modules are omitted from this table.

| Profile | MCP-related direct modules | Selection summary |
|---|---|---|
| `mcp-local` | `agent-capability-registry`, `mcp-server-core`, `mcp-transport-stdio`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-subscriptions-local`, `mcp-conformance` | Stateless stdio, core primitives, elicitation, process-local subscriptions, conformance. |
| `mcp-http` | `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-subscriptions-local`, `mcp-conformance` | Streamable HTTP, OAuth protected-resource policy, core primitives, elicitation, process-local subscriptions, conformance. |
| `mcp-enterprise` | `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-nats`, `mcp-apps`, `mcp-conformance` | HTTP, all authentication policy modules, core primitives, elicitation, tasks, NATS subscriptions, Apps, conformance. |
| `ai-platform` | `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-redis`, `mcp-apps`, `mcp-conformance` | HTTP/OAuth, core primitives, elicitation, tasks, ephemeral Redis subscriptions, Apps, conformance, alongside web and LLM selections. |
| `full-reference-ai` | `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `mcp-transport-stdio`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-nats`, `mcp-apps`, `mcp-skills`, `mcp-server-card-preview`, `mcp-progressive-discovery-preview`, `mcp-conformance` | Both transports, all auth policy modules, core primitives, elicitation/tasks/NATS, Apps, Skills, two source-only previews, conformance, alongside full web and LLM selections. |

Exactly one subscription backplane may occupy provider slot `mcp-subscription-backplane`; local, Redis, and NATS selections conflict with each other.

## Capability classifications

All rows have maturity `experimental`. Profile availability is selection evidence only; use the canonical [availability and exposure matrix](availability-and-exposure-matrix.md) for the repository-wide classification.

| Capability IDs | Implementation | Profiles | Public exposure |
|---|---|---|---|
| `mcp-server-core`, `agent-capability-registry`, `mcp-discovery-versioning`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation` | implemented | all five MCP-related profiles | unassembled |
| `mcp-transport-http`, `mcp-auth-oauth` | implemented | `mcp-http`, `mcp-enterprise`, `ai-platform`, `full-reference-ai` | unassembled |
| `mcp-transport-stdio` | implemented | `mcp-local`, `full-reference-ai` | unassembled |
| `mcp-auth-client-credentials`, `mcp-auth-enterprise` | implemented | `mcp-enterprise`, `full-reference-ai` | unassembled |
| `mcp-tasks`, `mcp-apps` | implemented | `mcp-enterprise`, `ai-platform`, `full-reference-ai` | unassembled |
| `mcp-subscriptions-local` | implemented | `mcp-local`, `mcp-http` | unassembled |
| `mcp-subscriptions-redis` | implemented | `ai-platform` | unassembled |
| `mcp-subscriptions-nats` | implemented | `mcp-enterprise`, `full-reference-ai` | unassembled |
| `mcp-skills` | implemented | `full-reference-ai` | unassembled |
| `mcp-server-card-preview`, `mcp-progressive-discovery-preview` | source-only | `full-reference-ai` | unassembled |
| `mcp-completion`, `mcp-progress` | unavailable | none | unassembled |
| `mcp-conformance` | implemented | all five MCP-related profiles | not-applicable |
| `mcp-profiles` | implemented | all five MCP-related profiles | generated-only |

For exact protocol and transport values, see [MCP protocol support](mcp-protocol-support.md).

## Profile-specific ceilings

### `mcp-local`

The stdio transport library exists, but no checked-in executable starts it. Local subscriptions are process-scoped and nondurable. The strict protocol is stateless even though a compatibility adapter can translate legacy initialization.

### `mcp-http`

The HTTP transport declares POST `/mcp`, but the reference API does not mount it. The OAuth metadata library also mounts no route. Local subscriptions remain nondurable.

### `mcp-enterprise`

The checked-in MRTR migration defines plural `public.mcp_mrtr_states` plus `public.mcp_mrtr_audit_events`; the task migration defines `public.mcp_tasks` and protected input-round storage, and the common migrator embeds both files. No first-party MCP application composes those repositories and workers or proves applied runtime state. Client-credentials and enterprise-auth crates still leave signing, validation, policy, consent, and audit as external ports, and enterprise identity-link persistence remains unverified. NATS source does not prove JetStream durability.

### `ai-platform`

Redis subscription delivery is explicitly ephemeral. Web and LLM profile selections do not supply an assembled MCP server or public endpoint.

### `full-reference-ai`

Skills have no proven persistence adapter or executor sandbox. Server-card and progressive-discovery previews are not wire-visible and must not create proprietary RPC methods. Selecting both transport libraries does not start either transport.

## Conformance boundary

The conformance crate and runbook define planning and synthetic-fixture evidence. No built-in first-party MCP client exists, and no retained successful interoperability result against a live Omnius endpoint is established. `not-applicable` describes the conformance tooling's public exposure, not a passing conformance result.
