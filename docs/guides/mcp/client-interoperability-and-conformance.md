---
title: MCP client interoperability and conformance
description: Evidence-qualified use of pinned MCP conformance and Inspector tooling against a separately assembled server, with synthetic-fixture and release-proof boundaries.
status: experimental
implementation: implemented
profile_availability:
  - mcp-local
  - mcp-http
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
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
  - crates/mcp-conformance/src/runner.rs
  - crates/mcp-conformance/src/evidence.rs
  - specs/48-ai-mcp-testing-conformance-evals-and-operations.md
  - release/ai-mcp-suite-runbook.md
evidence:
  - crates/mcp-conformance/tests/acceptance_contracts.rs
  - crates/mcp-conformance/src/bin/mcp-conformance-fixture.rs
  - crates/mcp-conformance/src/matrix.rs
last_verified: 2026-08-30
---

# MCP client interoperability and conformance

> **Evidence boundary:** `mcp-conformance` is implemented test tooling, not an MCP server or client product surface. The repository has no built-in MCP client and no first-party assembled MCP server. Existing focused tests prove planning, redaction, and a synthetic fixture—not live Omnius interoperability or release conformance.

The harness pins MCP revision `2026-07-28`, `@modelcontextprotocol/conformance@0.2.0-alpha.11`, and `@modelcontextprotocol/inspector@2.4.0`. The official toolchain requires Node.js 22.19 or newer. These exact values describe the checked-in planner; current external availability is not inferred.

## What the harness does

The conformance crate provides:

- a planner for official HTTP runner and Inspector work;
- bounded, redacted evidence artifacts;
- an execution boundary that an operator can connect to an assembled target;
- a synthetic matrix adapter and loopback fixture for deterministic harness contracts.

It does not mount `/mcp`, start a production stdio process, implement business capabilities, authenticate a real client, create release evidence automatically, or prove profile readiness. Its `not-applicable` public-exposure classification reflects tooling rather than a callable application surface.

`OfficialConformancePlan` deliberately rejects direct stdio because the official runner accepts an HTTP URL. Its only stdio plan is the test-only loopback bridge, which is evidence for official-runner harness behavior and must not be presented as a production transport. Separately, `InspectorPlan::stdio` accepts an assembled program and arguments and plans an Inspector-owned direct stdio child for a one-shot smoke. That Inspector boundary supplies neither the target executable nor production assembly evidence. HTTP conformance likewise needs an application-owned endpoint; the reference API intentionally has none.

## Evidence levels

Keep these evidence classes separate:

| Evidence | What it can establish | What it cannot establish |
|---|---|---|
| Focused Rust tests | Planner, redaction, artifact, and synthetic-fixture contracts | A live endpoint or external-client compatibility |
| Synthetic matrix adapter | Deterministic scenario bookkeeping | Official protocol conformance |
| Test-only loopback bridge | Harness framing against a fixture | Production stdio assembly |
| Official runner against an assembled target | Observed protocol cases for that target, revision, and configuration | Inspector usability, security review, or every deployment topology |
| Inspector session against an assembled target | Human-observed client interaction | Repeatable release conformance by itself |
| Bounded release evidence record | Reviewed outcome for one immutable build and environment | Future versions or untested profiles |

No completed official-runner or Inspector evidence record for the Omnius server is checked in. Therefore this documentation does not report conformance verification as run.

## Preparing a real interoperability evaluation

Prerequisites are external to the current repository assembly:

1. an immutable application build that deliberately composes the MCP kernel, canonical registry, one transport, authentication, tenant resolution, capabilities, lifecycle, and required persistence/workers;
2. an endpoint or process restricted to synthetic test identities, tenants, resources, and data;
3. revision `2026-07-28` and the pinned compatible tool versions;
4. deny-by-default authorization, trusted confirmation, finite schemas, budgets, deadlines, cancellation, and drain behavior;
5. secret-safe evidence storage with bounded stdout, stderr, HTTP material, and diagnostics;
6. a declared profile and transport scope, including unsupported methods and extensions.

No executable commands are included here because no first-party target exists and a copied invocation would falsely imply one. The checked-in runbook and harness planner are the command authorities after an application owner supplies an actual target and approved environment.

## Required scenarios

A release evaluation should cover observable boundaries, not merely successful listing:

- exact revision negotiation and deterministic discovery;
- capability absence versus authorization denial redaction;
- principal, tenant, and resolved-resource isolation;
- tool input and output schema rejection without schema-oracle leakage;
- trusted confirmation and idempotent effect handling;
- HTTP authority, origin, media, framing, session/replay rejection, cancellation, and drain, or stdio framing, stderr separation, EOF, output backpressure, and shutdown;
- task ownership, transition fencing, expiry, cancellation, and restart reconciliation when tasks are in scope;
- subscription queue bounds, replay gaps, authoritative snapshot reconciliation, provider restart, and drain when subscriptions are in scope;
- extension negotiation and fail-closed behavior for unassembled or unavailable surfaces.

**Expected result:** the evidence names the immutable build, environment, transport, profile, protocol and tool revisions, scenario results, bounded redacted artifacts, and reviewer disposition. Unsupported or unavailable methods remain explicit rather than being skipped silently.

**Failure path:** stop release qualification on target mismatch, tool-version drift, leaked secrets or personal data, ambiguous result attribution, missing negative cases, synthetic-fixture substitution, failed authorization isolation, unbounded artifact capture, deadline or cancellation failure, or absent restart evidence for persistent features. Preserve only the minimum redacted failure evidence permitted by policy.

## Interpreting profile selection

All five MCP profiles select the conformance tooling, but selection means the generator can include that tooling. It does not assemble a target, create an MCP client, execute official suites, or make a conformance claim. Read [modules, profiles, and composition](../../concepts/modules-profiles-and-composition.md) and the [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md) before using generated output as evidence.

## Related reference

- [MCP protocol support](../../reference/mcp-protocol-support.md)
- [MCP capability matrix](../../reference/mcp-capability-matrix.md)
- [Discovery, versioning, and transports](discovery-versioning-and-transports.md)
- [Elicitation, tasks, progress, and subscriptions](elicitation-tasks-progress-and-subscriptions.md)
- [Compatibility and release gates](../../development/compatibility-and-release-gates.md)
