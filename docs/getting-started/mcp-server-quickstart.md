---
title: MCP server library quickstart
description: A deterministic, secret-safe path for evaluating Omnius MCP server contracts without implying that an MCP endpoint or process is assembled.
status: experimental
implementation: implemented
profile_availability:
  - mcp-local
  - mcp-http
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
public_exposure: unassembled
audience:
  - mcp-developer
  - evaluator
topics:
  - mcp
  - quickstart
  - composition
  - verification
capabilities: []
source:
  - crates/mcp-server-core/src/kernel.rs
  - crates/mcp-server-core/src/discovery.rs
  - crates/agent-capability-registry/src/registry.rs
  - crates/mcp-server-core/src/sdk.rs
  - specs/42-mcp-server-architecture-and-capability-exposure.md
evidence:
  - crates/mcp-server-core/tests/kernel_contracts.rs
  - crates/mcp-server-core/tests/discovery_contracts.rs
  - crates/agent-capability-registry/tests/guardrails.rs
last_verified: 2026-08-30
---

# MCP server library quickstart

> **Integration boundary:** Omnius contains implemented MCP libraries and test tooling, but no first-party application mounts `/mcp`, starts an MCP stdio process, or assembles an MCP client. Selecting an MCP profile, generating artifacts, reading a specification, or passing a focused library test does not change that boundary.

This quickstart is a deterministic repository-evaluation path. It does not provide an executable server command because the repository has no first-party MCP application or stdio executable to launch. See the [MCP capability matrix](../reference/mcp-capability-matrix.md) before choosing a surface.

## Prerequisites

Work from the repository root with:

1. a checkout containing the cited source and evidence files;
2. an opaque test principal and tenant with no production identifiers;
3. a single capability declaration with local Draft 2020-12 input and output schemas;
4. explicit authorization, confirmation, budget, deadline, cancellation, and idempotency decisions;
5. synthetic request data containing no credentials, personal data, or production resource identifiers.

A profile name is not a runtime prerequisite. It records selection, not assembly; see [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md).

## Deterministic repository path

1. **Start at the strict kernel boundary.** Inspect `crates/mcp-server-core/src/kernel.rs` and `sdk.rs`. Every client request supplies revision `2026-07-28`, client information, client capabilities, and client identity; the handler adapts that metadata, invokes the configured resolver for canonical tenant and authorization context, and constructs request-scoped extension negotiation for the stateless kernel. The strict handler returns method-not-found for legacy `initialize`; use `server/discover`, and never introduce retained MCP initialization, client, or session state.
2. **Trace the only execution authority.** Follow `crates/agent-capability-registry/src/registry.rs`. A projected MCP operation must re-enter the canonical registry for availability, exposure, authorization, tenant mode, confirmation or approval, idempotency, schema, budget, deadline, and cancellation enforcement.
3. **Confirm the discovery composition boundary.** Follow `crates/mcp-server-core/src/discovery.rs` and `sdk.rs`. `McpExposureFilter` produces an authorized capability projection only when an embedder explicitly invokes it. `StatelessHandlerAdapter::discover` is a provided first-party handler, but it is not wired to that filter or a populated primitive registry and its static `ServerInfo` includes every configured extension. Treat extension metadata as approved before configuration and compose filtered primitive projections deliberately.
4. **Choose a transport policy without claiming a listener.** HTTP and stdio are implemented transport libraries, but neither is mounted by a first-party app. Continue to [discovery, versioning, and transports](../guides/mcp/discovery-versioning-and-transports.md) before designing composition.
5. **Choose only supported projections.** The kernel projects tools, resources, and prompts. Completion is unavailable, and ordinary progress notifications are not implemented. Continue to [tools, resources, and prompts](../guides/mcp/tools-resources-and-prompts.md).
6. **Treat tests as contract evidence.** The cited focused tests demonstrate library behavior. They are not a live endpoint, external-client interoperability result, release report, or evidence that this documentation revision ran verification.

**Expected result:** an application design identifies one canonical capability, one transport, an authenticated and tenant-bound request context, deny-by-default authorization and resource isolation, local schema bounds, explicit approval policy, a finite deadline and cancellation path, and any required persistence or worker composition.

**Failure path:** stop before exposure if any capability bypasses the registry, authorization denial reveals resource existence, a schema admits unbounded data, approval can be supplied by untrusted content, timeout or cancellation cannot reach execution, or durable state has no repository, migration, reconciliation, and lifecycle owner. Do not infer missing assembly from profiles or sample catalogs.

## What application composition must still supply

A real server owner must provide a binary or application composition root, transport listener or stdio process, authentication and secret injection, tenant resolution, concrete capability implementations, lifecycle/readiness integration, bounded telemetry and audit sinks, and persistence plus workers for stateful extensions. HTTP composition must deliberately mount `/mcp`; the checked-in reference API deliberately does not.

No built-in MCP client is available for the opposite side of an interoperability check. An assembled deployment must be exercised with an external client and the pinned conformance tooling described in [client interoperability and conformance](../guides/mcp/client-interoperability-and-conformance.md).

## Continue

- [Server architecture and capability exposure](../guides/mcp/server-architecture.md)
- [Authentication, authorization, and tenancy](../guides/mcp/authentication-authorization-and-tenancy.md)
- [Elicitation, tasks, progress, and subscriptions](../guides/mcp/elicitation-tasks-progress-and-subscriptions.md)
- [MCP protocol support](../reference/mcp-protocol-support.md)
- [Availability and exposure matrix](../reference/availability-and-exposure-matrix.md)
