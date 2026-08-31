---
title: MCP security
description: Secure Omnius MCP discovery, transports, registries, authorization, OAuth, tasks, subscriptions, Apps, and Skills within the unassembled runtime boundary.
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
  - security-analyst
  - mcp-developer
  - operator
topics:
  - security
  - mcp
  - authorization
capabilities: []
source:
  - crates/mcp-server-core/src/discovery.rs
  - crates/mcp-server-core/src/sdk.rs
  - crates/mcp-server-core/src/lib.rs
  - crates/mcp-transport-http/src/lib.rs
  - crates/mcp-transport-stdio/src/lib.rs
  - crates/mcp-auth-oauth/src/lib.rs
  - crates/mcp-tools/src/lib.rs
  - migrations/2026082807_create_mcp_mrtr_state.sql
  - migrations/2026082808_create_mcp_tasks.sql
evidence:
  - docs/coverage-matrix.md
  - crates/mcp-conformance
  - specs/35-llm-mcp-feature-suite-architecture.md
last_verified: 2026-08-30
---

# MCP security

Omnius implements MCP registry, discovery, tool/resource/prompt, authorization, OAuth-related, HTTP/stdio transport, task, elicitation, subscription, Apps, and Skills libraries. It does not include a first-party MCP server binary, HTTP mount, listener, stdio executable, or built-in client. The application route expected by API tests is absent. Profile selection and protocol tests do not prove an exposed server.

Apply the shared [security model](security-model.md) and [identity, authorization, and tenancy](../concepts/identity-authorization-and-tenancy.md). Protocol support details belong in the [MCP capability matrix](../reference/mcp-capability-matrix.md).

## Trust boundaries

- **Client to transport:** bind message, connection/process, origin, resource, version, size, timeout, and concurrency limits.
- **Transport to principal:** authenticate the concrete HTTP or stdio deployment context before discovery or use.
- **Principal to registry projection:** the application must explicitly compose `McpExposureFilter` to filter tool, resource, and prompt capability visibility by principal, tenant, availability, exposure, and policy; the bare `server/discover` handler does not invoke it.
- **Registry to handler:** authorize before schema validation so denied callers cannot use validation as a discovery oracle.
- **Handler to effect/data:** enforce tenant ownership, least privilege, destination constraints, idempotency, budget, and audit.
- **Long-running state:** bind task/elicitation/subscription state to principal, tenant, policy, expiry, and durable provider semantics.
- **MCP content to host/browser:** treat text, resources, Apps, Skills, links, schemas, and model-assisted values as untrusted content.

## Required controls

### Discovery and registries

Return only entries the principal is authorized to know. `StatelessHandlerAdapter::discover` returns static server information and every configured extension, so treat extension metadata as preapproved and deliberately connect primitive listing to `McpExposureFilter`. Apply bounded pagination/cursors, stable versioning, input limits, and safe errors. Empty projection is preferable to leaking hidden names or schemas. Generated registries are not public permissions.

### HTTP transport

Source contracts describe POST `/mcp`, but no application mounts it. A future composition must use the shared HTTP shell and explicitly bind authentication, protected-resource metadata, OAuth resource/audience, tenant context, CSRF/CORS distinction, trusted proxy policy, limits, health, drain, and telemetry. Do not add ingress based on the source route alone.

### Stdio transport

Stdio is selected for `mcp-local` and `full-reference-ai`, but no executable is present. A future binary must reserve stdout for protocol frames, put diagnostics on stderr, inherit only approved environment/credentials, constrain working directory and filesystem/network access, and terminate/drain predictably. Shell access is not implied by stdio.

### Authentication and OAuth

OAuth libraries do not provide a mounted authorization server or protected-resource route. Validate issuer/resource/audience/client and token properties according to the concrete topology. Client-credentials and enterprise modules require least-privilege clients and tenant binding. Never accept a bearer token solely because it parses.

### Tools, resources, and prompts

Authorize registry visibility and each invocation independently. Validate bounded schemas after authorization. Treat tool arguments, resource URIs/content, prompt parameters, and results as untrusted. Effects require stable operation identity, destination/tenant controls, approval when applicable, and safe audit outcomes.

### Tasks, elicitation, and subscriptions

Checked-in migrations define MRTR state/audit and task/input-round stores, but applied runtime state and first-party repository, payload-protection, worker, relay, expiry, and reconciliation composition are unproven. Do not promise durable tasks, approval/elicitation expiry, resumability, or replay from schema evidence alone. Local and Redis-backed subscriptions are ephemeral; NATS adapter source does not prove JetStream durability. Completion and dedicated progress support are unavailable.

### Apps and Skills

Apps/Skills lack proven object storage, audit, and execution-sandbox composition. Current skills behavior rejects executable skills. Do not enable execution by bypassing that rejection. Review content origin, CSP/rendering isolation, permissions, integrity, size, destination, and retention before displaying any extension.

## Security review procedure

**Prerequisites**

- a concrete MCP composition root and transport;
- explicit principal/tenant mapping and permission vocabulary;
- registry contents, handler effects, provider credentials, and egress inventory;
- approved non-production client and data;
- threat model, audit destination, lifecycle owner, and stop criteria.

1. Prove the listener/binary exists and identify every external mount; ignore catalogs and OpenAPI as exposure evidence.
2. Authenticate before discovery, confirm configured extension metadata is approved for disclosure, and verify the application explicitly composes a tenant-filtered primitive registry projection rather than relying on bare `server/discover`.
3. Exercise denied discovery/use, malformed/bounded input, cross-tenant object access, replay, timeout, disconnect, and drain.
4. Verify OAuth resource/audience/issuer bindings and safe error behavior.
5. Trace one authorized effect through validation, approval, idempotency, audit, and reconciliation.
6. Verify long-running behavior against the actual provider; label persistence/replay gaps.
7. Inspect stdio stream separation or HTTP security/lifecycle controls as applicable.
8. Reject Apps/Skills behavior that lacks content and execution isolation.

**Expected result:** the server exposes only authorized registries/effects through one bounded, authenticated transport with explicit tenancy, lifecycle, audit, and recovery semantics.

**Failure path:** do not expose the server when composition, auth, tenant projection, sandboxing, persistence, or lifecycle is missing. Fix the composition rather than advertising partial protocol support.

No MCP conformance run, listener, or transport exercise was performed while writing this page. See [MCP troubleshooting](../troubleshooting/mcp-discovery-transports-and-auth.md) and [scaling jobs, realtime, and MCP](../operations/scaling-jobs-realtime-and-mcp.md).