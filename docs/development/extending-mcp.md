---
title: Extending MCP
description: Contributor workflow for MCP protocol extensions, negotiation, transport compatibility, conformance, and security boundaries.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - mcp-contributor
  - maintainer
  - security-reviewer
topics:
  - mcp
  - protocol
  - extensions
  - conformance
capabilities: []
source:
  - specs/machine/extensions/llm-mcp-suite/mcp-extension-registry.yaml
  - crates/mcp-server-core/src/extensions.rs
  - crates/mcp-server-core/src/discovery.rs
  - crates/mcp-server-core/src/sdk.rs
  - crates/mcp-server-core/src/versioning.rs
evidence:
  - crates/mcp-server-core/tests/protocol_contracts.rs
  - crates/mcp-server-core/tests/discovery_contracts.rs
  - crates/mcp-conformance/tests/acceptance_contracts.rs
last_verified: 2026-08-30
---

# Extending MCP

Omnius contains MCP libraries, transports, authentication components, extensions, and conformance support. This checkout does not assemble a first-party MCP host binary or built-in client, and the API server does not establish MCP routes. Treat MCP as library-only and unassembled until application source and runtime evidence prove otherwise.

Read [MCP protocol support](../reference/mcp-protocol-support.md), [Client interoperability and conformance](../guides/mcp/client-interoperability-and-conformance.md), and [MCP security](../security/mcp-security.md) before changing protocol behavior.

## Protocol baseline and registry

The protocol baseline is `2026-07-28`. The machine registry at `specs/machine/extensions/llm-mcp-suite/mcp-extension-registry.yaml` is the authoritative extension inventory for this repository.

The checked-in registry distinguishes:

- stable opt-in extensions: tasks, UI/apps, client credentials, and enterprise authentication;
- experimental opt-in extension: Skills;
- internal preview surfaces: server-card and progressive discovery, which are not wire-visible;
- deprecated or prohibited surfaces: roots, sampling, logging, and HTTP-SSE.

Do not revive a deprecated/prohibited ID, expose an internal preview on the wire, or infer support from the existence of a crate. Registry status, implementation, profile selection, negotiation, assembly, and public exposure are separate facts.

## Core extension boundary

`omnius-mcp-server-core` provides exact extension IDs and revisions, bounded catalog construction, request-scoped negotiation, static server discovery metadata, a standalone authorized capability projection, and protocol versioning. `StatelessHandlerAdapter::discover` is a provided first-party handler, but it returns every configured extension and does not invoke `McpExposureFilter`; an application must explicitly connect that filter to primitive listings.

An extension implementation must:

1. use the exact `McpExtensionId` and `McpExtensionRevision` contract;
2. remain within catalog and request bounds;
3. negotiate per request rather than mutating global support;
4. reject unsupported, deprecated, malformed, or ambiguous IDs with redacted errors;
5. fail closed when authentication, tenant, or authorization context is missing;
6. expose only preapproved extension metadata through the configured `server/discover` catalog;
7. explicitly compose `McpExposureFilter` for authorized primitive projections and route capability execution through the shared registry rather than creating a parallel MCP-only truth.

## Existing package boundaries

The repository separates concerns into packages including:

- core, tools, resources, and prompts;
- HTTP and stdio transports;
- OAuth, client-credentials, and enterprise authentication;
- elicitation, tasks, subscriptions, apps, and skills;
- server-card and progressive-discovery previews;
- conformance support.

Add behavior to the package that owns the protocol concern. Do not place transport framing in a feature crate, authentication policy in discovery, or an experimental extension in the stable core API.

## Decide whether an extension belongs

Before implementation:

1. Determine whether the behavior is part of the pinned MCP baseline, a registry extension, or an application concern.
2. Identify the protocol or specification authority and exact revision.
3. Check whether an existing registered ID already covers it.
4. Define wire visibility, opt-in behavior, and negotiation rules.
5. Identify required authentication, tenant, authorization, and capability context.
6. Establish bounds for payloads, lists, subscriptions, tasks, and retained state.
7. Decide whether the change belongs in an existing crate or a dedicated extension crate.
8. Define HTTP and stdio compatibility expectations.

If no authoritative wire contract exists, keep the experiment internal and non-wire-visible rather than presenting it as protocol support.

## Update machine catalogs

An MCP extension change can require coordinated edits to:

- the extension registry for ID, revision, status, authority, negotiation, and exposure policy;
- the AI/MCP module catalog for composition dependencies and conflicts;
- the AI/MCP profile catalog for intentional selection;
- frontend capability metadata when an application-facing capability actually exists;
- compatibility metadata for the pinned protocol line.

Catalog selection still does not create a host. Do not change exposure classification without first-party assembly and runtime evidence.

## Implement protocol behavior

1. Add exact revisioned types and bounded parsing.
2. Register the extension through the core bounded catalog.
3. Negotiate deterministically per request.
4. Carry authenticated principal, tenant, and authorization context through the operation.
5. Validate all client-provided identifiers, URIs, cursors, and continuation state.
6. Bound body size, list size, task lifetime, subscription state, and concurrency as applicable.
7. Produce typed, stable, redacted protocol errors.
8. Add only disclosure-approved extension metadata to the static server catalog and explicitly wire authorized primitive projections; do not assume the handler applies `McpExposureFilter`.
9. Add transport-neutral contract tests, then HTTP and stdio tests where framing differs.
10. Add conformance cases for success, unsupported revision, downgrade/refusal, malformed input, missing identity, cross-tenant access, and bounds.

## Run core protocol tests

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain. These tests use repository fixtures and require no deployed MCP endpoint or production credentials.

```bash
cargo test -p omnius-mcp-server-core --test protocol_contracts
cargo test -p omnius-mcp-server-core --test discovery_contracts
```

**Expected result:** the pinned protocol surface and deterministic discovery/negotiation contracts pass.

**Failure path:** fix exact versioning, registry construction, request negotiation, or discovery filtering. Do not silently downgrade an unsupported revision or advertise unnegotiated support.

## Run conformance acceptance tests

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain. The package-level suite uses checked-in conformance fixtures; external runtime conformance requires a separately assembled endpoint and runner and is not established by this command.

```bash
cargo test -p omnius-mcp-conformance --test acceptance_contracts
```

**Expected result:** library-level acceptance and refusal cases satisfy the checked-in conformance contract.

**Failure path:** classify the defect as core protocol, extension semantics, transport mapping, authentication/authorization, or fixture compatibility. Preserve fail-closed refusal behavior.

## Verify catalogs and profiles

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain and internally consistent AI/MCP catalogs. No live MCP service or provider credential is required.

```bash
cargo xtask ai verify
cargo xtask profiles verify
```

**Expected result:** MCP extension, module, profile, capability, and compatibility metadata satisfy their machine-readable relationships.

**Failure path:** fix the owning registry or catalog. Do not interpret a passing metadata check as host assembly or runtime conformance.

## Required package-specific tests

In addition to core and conformance tests, run the owning package tests for every changed surface. The repository has focused contracts for tools, resources, prompts, HTTP, stdio, OAuth, client credentials, enterprise authentication, elicitation, tasks, apps, and Skills. A new extension needs equivalent coverage before it can be cataloged as implemented.

Transport changes must preserve equivalent extension negotiation and error semantics across HTTP and stdio while respecting their framing differences. Authentication changes need positive and negative identity, tenant, scope, expiry, and redaction cases.

## Security review

Every wire-visible extension requires review of:

- principal and tenant binding at every request and continuation;
- tool/resource/prompt authorization and confused-deputy risks;
- untrusted URI, argument, metadata, and rendered-content handling;
- task, subscription, and elicitation lifetime bounds;
- replay, cancellation, idempotency, and duplicate delivery behavior;
- outbound access and server-side request forgery controls;
- credential audience, scope, rotation, and redaction;
- discovery minimization and capability fingerprinting;
- transport origin, session, and downgrade behavior;
- audit records that remain useful without retaining sensitive content.

See [MCP security](../security/mcp-security.md) for the canonical threat model rather than redefining it in an extension.

## Compatibility expectations

Changing extension IDs, revisions, negotiation intersection, discovery shape, error codes, cursor semantics, transport framing, or authentication claims is compatibility-sensitive. Add the new revision alongside the accepted compatibility line when simultaneous support is required; do not reinterpret an existing revision.

## Evidence boundary

Core, package, and conformance tests prove library contracts at their tested revisions. Catalogs and profiles prove declared selection. None proves a host binary, mounted endpoint, client interoperability against a live application, deployment, or public exposure.