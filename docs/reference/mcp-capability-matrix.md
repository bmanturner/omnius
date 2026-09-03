---
title: MCP capability matrix
description: Exact MCP profile selections, the assembled tools-only reference application, and application-owned ceilings.
status: experimental
implementation: implemented
profile_availability:
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
  - apps/mcp-server/src/lib.rs
  - crates/generator/src/catalog.rs
evidence:
  - apps/mcp-server/tests/authenticated_mcp.rs
  - apps/mcp-server/tests/process_lifecycle.rs
  - crates/generator/tests/base_service.rs
last_verified: 2026-09-03
---

# MCP capability matrix

Profile rows are runtime-selection evidence. The checked-in `apps/mcp-server`
is separate runtime evidence for one narrow `mcp-http` reference composition;
it does not promote every selected module. Testing, preview, and conformance
tooling is excluded from all runtime profile state.

There are exactly two MCP profiles, `mcp-http` and `mcp-enterprise`.
`ai-platform` and `full-reference-ai` are combined AI/MCP profiles. All four
select authenticated Streamable HTTP; no profile selects another MCP transport.

## Profile selections

The lists below are the direct MCP-relevant runtime additions; inherited base,
web, and LLM modules are omitted.

| Profile | MCP-related direct runtime modules | Selection summary |
|---|---|---|
| `mcp-http` | `tenancy`, `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-subscriptions-local` | HTTP/OAuth plus reusable primitives, elicitation, and local subscriptions. |
| `mcp-enterprise` | `events-nats`, `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-nats`, `mcp-apps` | HTTP plus enterprise/application-owned auth, tasks, NATS, and Apps contracts. |
| `ai-platform` | `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-redis`, `mcp-apps` | HTTP/OAuth and application-owned MCP contracts alongside inherited web/LLM selection. |
| `full-reference-ai` | `agent-capability-registry`, `mcp-server-core`, `mcp-transport-http`, `auth-oauth-server`, `mcp-auth-oauth`, `mcp-auth-client-credentials`, `mcp-auth-enterprise`, `mcp-tools`, `mcp-resources`, `mcp-prompts`, `mcp-elicitation`, `mcp-tasks`, `mcp-subscriptions-nats`, `mcp-apps`, `mcp-skills` | HTTP plus the full compatible application-owned MCP runtime-contract set alongside inherited web/LLM selection. |

Exactly one subscription backplane may occupy `mcp-subscription-backplane`; local, Redis, and NATS selections conflict.

## Checked-in reference application

| Surface | Runtime behavior |
|---|---|
| Process | dedicated `apps/mcp-server`; profile metadata `mcp-http` |
| MCP route | authenticated `POST /mcp` |
| Metadata | `GET /.well-known/oauth-protected-resource/mcp` |
| Resource/scope | issuer plus `/mcp`; `reference-records:read` |
| Tool | only `reference_records.list.v1` |
| Data | shared `ReferenceRecordService::list` with PostgreSQL repository/pagination |
| Tenant mode | global; tenant-bearing identity rejected |
| Other primitives | unadvertised and method-not-found |
| API separation | `apps/api-server` has no MCP routes; MCP process has no authorization-server routes |

## Capability classifications

| Capability IDs | Implementation | Profiles | Reference-app exposure |
|---|---|---|---|
| `mcp-server-core`, `agent-capability-registry`, `mcp-discovery-versioning` | implemented | all four MCP-containing profiles | assembled |
| `mcp-transport-http`, `mcp-auth-oauth` | implemented | all four | assembled |
| `mcp-tools` | implemented | all four | assembled for `reference_records.list.v1` only |
| `mcp-resources`, `mcp-prompts`, `mcp-elicitation` | implemented libraries | all four | unassembled/method-not-found |
| `mcp-auth-client-credentials`, `mcp-auth-enterprise` | implemented contracts | `mcp-enterprise`, `full-reference-ai` | unassembled |
| `mcp-tasks`, `mcp-apps` | implemented contracts | `mcp-enterprise`, `ai-platform`, `full-reference-ai` | unassembled |
| `mcp-subscriptions-local` | implemented contract | `mcp-http` | unassembled |
| `mcp-subscriptions-redis` | implemented contract | `ai-platform` | unassembled |
| `mcp-subscriptions-nats` | implemented contract | `mcp-enterprise`, `full-reference-ai` | unassembled |
| `mcp-skills` | implemented contract | `full-reference-ai` | unassembled |
| `mcp-server-card-preview`, `mcp-progressive-discovery-preview` | source-only tooling | none | not-applicable |
| `mcp-completion`, `mcp-progress` | unavailable | none | method-not-found |
| `mcp-conformance` | implemented tooling | none | not-applicable |
| `mcp-profiles` | implemented selection | all four | generated-only |

## Application-owned ceilings

The reference app does not assemble resources, prompts, elicitation, subscriptions, tasks, Apps, Skills, client credentials, enterprise managed authorization, or previews. Those modules require concrete product handlers, authorization policy, provider credentials/endpoints, persistence, worker/replay semantics, audit, and lifecycle. Generated profiles fail closed until those requirements are supplied.

`mcp-enterprise` and `full-reference-ai` additionally require real enterprise identity/link/replay/live-state/consent/audit and genuine durable subscription semantics. Core NATS fanout alone is not proof of a durable MCP backplane.

## Conformance boundary

The HTTP-only conformance crate and runbook define planning, opt-in execution, and bounded evidence. Reference integration tests establish the checked-in route/auth/tool contract, but this page claims no retained successful official-runner or Inspector result.
