---
title: MCP client interoperability and conformance
description: Use the HTTP-only conformance planner and Inspector against the dedicated authenticated reference MCP process without overstating release evidence.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - mcp-developer
  - evaluator
  - contributor
topics:
  - mcp
  - clients
  - interoperability
  - conformance
  - release-evidence
capabilities:
  - mcp-conformance
source:
  - crates/mcp-conformance/src/official.rs
  - crates/mcp-conformance/src/execution.rs
  - crates/mcp-conformance/src/evidence.rs
  - specs/48-ai-mcp-testing-conformance-evals-and-operations.md
  - release/ai-mcp-suite-runbook.md
evidence:
  - crates/mcp-conformance/tests/acceptance_contracts.rs
  - crates/mcp-conformance/src/matrix.rs
  - apps/mcp-server/tests/authenticated_mcp.rs
last_verified: 2026-09-03
---

# MCP client interoperability and conformance

`mcp-conformance` is HTTP-only test tooling and is rejected from generated runtime profiles/state. It targets the checked-in `apps/mcp-server` endpoint at `POST /mcp`; it is not itself a server and it does not create OAuth grants or tokens. The repository has no built-in product MCP client.

The harness pins MCP revision `2026-07-28`, `@modelcontextprotocol/conformance@0.2.0-alpha.11`, `@modelcontextprotocol/inspector@2.4.0`, and Node.js 22.19 or newer. It has no alternate transport plan.

## What the harness does

The CLI exposes:

- `synthetic` for deterministic harness bookkeeping;
- `official-plan-http` and explicitly opted-in `official-run` for the pinned official Streamable HTTP runner;
- `official-skip` for honest not-run evidence;
- `inspector-http-plan` and explicitly opted-in `inspector-run-http` for a headless `tools/list` smoke.

It validates an absolute HTTP(S) endpoint without credentials, query, or fragment; invokes pinned tools without a shell; bounds execution time and retained output; and emits redacted evidence. It does not mint credentials, seed reference data, decide release readiness, or turn unsupported primitives into skips.

## Evidence levels

| Evidence | What it establishes | What it does not establish |
|---|---|---|
| Synthetic matrix | deterministic scenario/evidence contracts | official protocol conformance or live authentication |
| Reference app integration tests | exact metadata, bearer failures, tool list/call, unsupported methods, and route separation in the test environment | external-client interoperability or a production deployment |
| Official runner against `apps/mcp-server` | observed HTTP protocol cases for that immutable build/configuration | security review or every deployment topology |
| Inspector session | one external-client interaction | repeatable release conformance by itself |
| Bound release evidence | reviewed result for one revision/environment | future versions or untested profiles |

No retained successful official-runner or Inspector report is claimed by this page.

## Prepare the reference target

1. Start `apps/mcp-server` with resolved PostgreSQL, OAuth issuer/resource, signing material, and cursor configuration.
2. Verify the public metadata route names the exact issuer-plus-`/mcp` resource and `reference-records:read`.
3. Create a non-tenant OAuth grant and live token for that exact resource and scope through the authorization server in `apps/api-server`.
4. Configure the external runner/Inspector to present that token through its approved secret-safe mechanism. Never place a token in the endpoint URL or retained command/evidence.
5. Seed only synthetic reference records and record the immutable application revision and configuration classification.

The planning command for the development listener is:

```bash
cargo run --locked -p omnius-mcp-conformance -- \
  official-plan-http http://127.0.0.1:8090/mcp
```

Execution is deliberately separate and requires `official-run --execute`; use it only after the target and external tool authentication configuration are approved. The Inspector equivalents are `inspector-http-plan` and `inspector-run-http --execute` and require a safe relative config path.

## Required HTTP scenarios

A reference-app evaluation must cover:

- exact `2026-07-28` per-request negotiation and stateless discovery;
- `tools/list` exposing only `reference_records.list.v1` and successful `tools/call` against seeded PostgreSQL data;
- missing, malformed, query, expired, revoked, wrong-audience, insufficient-scope, and tenant-bearing credentials;
- exact protected-resource metadata and API/MCP route separation;
- resources, prompts, elicitation, subscriptions, tasks, Apps, Skills, completion, and progress returning method-not-found;
- host/origin, media, framing, size, session/replay, cancellation, readiness, dependency outage, and bounded drain behavior;
- bounded redaction of HTTP and tool diagnostics.

Optional enterprise/application-owned primitives are evaluated only when a concrete product application actually composes them. They are not required scenarios for the tools-only reference app and must not be reported as passing defaults.

## Profile boundary

The two MCP profiles are `mcp-http` and `mcp-enterprise`; `ai-platform` and `full-reference-ai` are combined AI/MCP profiles. Selection can include the conformance tooling, but only observed execution against a named immutable target produces conformance evidence. Generated output and synthetic fixtures never substitute for that observation.

## Related reference

- [Authenticated MCP server quickstart](../../getting-started/mcp-server-quickstart.md)
- [MCP protocol support](../../reference/mcp-protocol-support.md)
- [MCP capability matrix](../../reference/mcp-capability-matrix.md)
- [Discovery, versioning, and transport](discovery-versioning-and-transports.md)
- [Compatibility and release gates](../../development/compatibility-and-release-gates.md)
