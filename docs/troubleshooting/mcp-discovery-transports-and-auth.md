---
title: MCP discovery, transports, and auth troubleshooting
description: Diagnose Omnius MCP lifecycle, discovery, HTTP, stdio, OAuth, task, subscription, App, and Skill symptoms while preserving the unassembled runtime boundary.
status: experimental
implementation: partial
profile_availability:
  - mcp-local
  - mcp-http
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
public_exposure: unassembled
audience:
  - mcp-developer
  - operator
  - security-analyst
topics:
  - troubleshooting
  - mcp
  - transports
capabilities: []
source:
  - crates/mcp-server-core/src/discovery.rs
  - crates/mcp-server-core/src/sdk.rs
  - crates/mcp-server-core/src/lib.rs
  - crates/mcp-transport-http/src/lib.rs
  - crates/mcp-transport-stdio/src/lib.rs
  - crates/mcp-auth-oauth/src/lib.rs
  - crates/mcp-tasks/src/lib.rs
evidence:
  - crates/mcp-conformance
  - docs/coverage-matrix.md
  - specs/35-llm-mcp-feature-suite-architecture.md
last_verified: 2026-08-30
---

# MCP discovery, transports, and auth troubleshooting

Omnius implements MCP protocol libraries but no first-party MCP server binary, HTTP mount/listener, stdio executable, or built-in client. The expected API route is absent. Prove a concrete embedding application before treating lifecycle, discovery, transport, or authorization symptoms as protocol defects.

Use the [MCP capability matrix](../reference/mcp-capability-matrix.md), [MCP security](../security/mcp-security.md), and [MCP server architecture](../guides/mcp/server-architecture.md).

## The MCP client cannot connect or receives 404

**Discriminating evidence:** concrete server process/binary, transport, listener/mount, actual URL/path or stdio program identity, revision/profile, and response/exit provenance.

**Likely cause:** no runtime was assembled. HTTP source describes `/mcp`, but no checked-in app mounts it. Stdio is selected by profiles, but no executable exists.

**Safe diagnostic:** inspect the composition/deployment process inventory. Do not guess a public route or point a client at a test harness.

**Resolution:** compose a reviewed server binary/application with one transport, auth/tenant policy, registries, lifecycle, limits, health/drain, and telemetry. Keep public exposure unavailable until then.

**Escalation data:** revision, composition root, process identity, transport/listener/mount inventory, selected modules, response status or safe exit class.

No MCP listener, client, or conformance scenario was run while writing this page.

## Per-request revision or capability metadata is rejected

**Discriminating evidence:** request protocol version, client information, client capabilities, client identity, transport mode, and error category—excluding secrets and content.

**Likely causes:** an unsupported revision, missing or invalid metadata on this request, an unregistered capability, strict stdio receiving legacy `initialize`, or a catalog declaration mistaken for server support.

**Safe diagnostic:** inspect the rejected request and the immutable registry. The strict handler has no initialization state machine: it derives complete context independently for every request and returns method-not-found for `initialize`. Dedicated completion and progress capability support is unavailable; do not advertise it.

**Resolution:** send revision `2026-07-28` and valid client information, capabilities, and identity on every request. If legacy stdio compatibility is explicitly required, compose the compatibility adapter that translates `initialize` to stateless `server/discover`; it does not create retained initialization or session authority. Never add lifecycle state to make a strict client request pass.

## Discovery or primitive listing returns empty, partial, or forbidden

**Discriminating evidence:** whether the call is `server/discover` or a primitive list/projection, the concrete handler composition, authenticated principal/tenant, configured extension catalog, populated registry, explicit exposure-filter use, and safe decision code.

**Likely causes:** per-request context resolution failed, no extension was configured, the core default-empty list handler was never connected to a primitive projection, a composed `McpExposureFilter` correctly removed entries, the registry was not composed, or the tenant/policy denied the projection.

**Safe diagnostic:** keep the boundaries separate. `StatelessHandlerAdapter::discover` returns static server information and every configured extension; it does not invoke `McpExposureFilter`. For tool, resource, or prompt metadata, prove that the application explicitly invokes the filter over the concrete registry. Authorization intentionally occurs before detailed schema validation to avoid discovery oracles.

**Resolution:** preapprove extension metadata before configuring the handler, then connect populated primitive projections through `McpExposureFilter` and reauthorize invocation independently. Never bypass authorization, return a global registry, or expose hidden schemas to explain a denial.

**Escalation data:** request method, handler/application revision, principal/tenant identifiers under need-to-know access, extension catalog and registry versions, filter composition, policy version, decision code.

## HTTP OAuth authentication fails

**Discriminating evidence:** protected-resource metadata availability, issuer/resource/audience/client, scopes, token error class, and server time—without bearer token, code, or secret.

**Likely causes:** metadata route is absent, wrong issuer/resource/audience, unknown/disabled client, insufficient scopes, expired token, or OAuth libraries not composed into the HTTP server.

**Safe diagnostic:** first prove both MCP and metadata routes are mounted. Then compare token/client properties with the concrete resource policy under protected operator access.

**Resolution:** assemble/fix the OAuth resource contract or correct the client request. Do not accept a token merely because it parses, weaken audience/resource checks, or expose secret values.

## Stdio framing is corrupt or the client cannot parse responses

**Discriminating evidence:** process identity/exit status, stdout frame boundaries/byte limits, stderr diagnostics, protocol version, and first safe framing error.

**Likely causes:** diagnostics/banner written to stdout, malformed/oversized frame, partial write/read, wrong executable, or no executable exists.

**Safe diagnostic:** capture only approved non-sensitive protocol fixtures in a disposable environment. Confirm stdout contains protocol frames only and stderr contains diagnostics.

**Resolution:** preserve stdout/stderr separation, bounded framing, cancellation, and deterministic lifecycle. Do not suppress parse errors or mix human logs with stdout.

## A tool/resource/prompt exists but invocation is denied

**Discriminating evidence:** registry/version, principal/tenant, capability/policy decision, operation, schema validation stage, and resource ownership.

**Likely causes:** discovery/use permissions differ, tenant/ownership mismatch, policy changed, or the handler requires an unassembled provider.

**Safe diagnostic:** re-authorize the concrete invocation independently from discovery and compare authoritative ownership/provider composition.

**Resolution:** correct scoped permissions or handler composition. Do not infer invocation permission from discoverability or validate denied input to reveal schema details.

## A task or elicitation never completes

**Discriminating evidence:** task/elicitation identity, durable provider and worker process, state/lease/fencing, approval expiry, cancellation, and effect identity.

**Likely cause:** persistence/worker/expiry handling is unassembled, worker stopped, lease expired, or effect outcome is ambiguous.

**Safe diagnostic:** prove provider and worker composition before inspecting durable state. Reconcile the effect and preserve state transitions.

**Resolution:** compose lifecycle/worker/reconciliation or leave the feature unavailable. Never manually mark complete or retry an ambiguous effect without idempotency.

## Subscription events are missed or cannot replay

**Discriminating evidence:** actual provider, connection interval, sequence/cursor if any, and authoritative resource version.

**Likely cause:** local and Redis-backed subscriptions are ephemeral; NATS adapter source does not prove JetStream durability.

**Resolution:** reconnect and re-read authoritative state. Do not promise replay unless a durable, composed, tested provider contract supplies it.

## An executable Skill is rejected or an App is unsafe to display

**Discriminating evidence:** skill/app kind, integrity/origin/permissions, sandbox/content policy, and registry decision.

**Likely cause:** executable Skills are deliberately rejected because no execution sandbox is available; Apps lack proven complete storage/audit/sandbox composition.

**Resolution:** keep executable Skills rejected and Apps unavailable until isolation, integrity, authorization, storage, audit, and lifecycle are assembled. Do not bypass rejection.

See [scaling jobs, realtime, and MCP](../operations/scaling-jobs-realtime-and-mcp.md) and [incident response](../operations/incident-response.md).