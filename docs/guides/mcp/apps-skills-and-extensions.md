---
title: MCP Apps, Skills, and extensions
description: Admission, trust, lifecycle, approval, persistence, and assembly boundaries for Omnius MCP Apps and Skills extensions.
status: experimental
implementation: implemented
profile_availability:
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
public_exposure: unassembled
audience:
  - mcp-developer
  - module-provider-author-and-contributor
  - security-privacy-reviewer
topics:
  - mcp
  - apps
  - skills
  - extensions
  - supply-chain
capabilities:
  - mcp-apps
  - mcp-skills
source:
  - crates/mcp-apps/src/manifest.rs
  - crates/mcp-apps/src/messaging.rs
  - crates/mcp-apps/src/lifecycle.rs
  - crates/mcp-skills/src/manifest.rs
  - crates/mcp-skills/src/isolation.rs
  - specs/47-mcp-extensions-apps-skills-and-roadmap-readiness.md
evidence:
  - crates/mcp-apps/tests/contracts.rs
  - crates/mcp-skills/tests/contracts.rs
  - specs/machine/extensions/llm-mcp-suite/module-catalog.yaml
last_verified: 2026-09-02
---

# MCP Apps, Skills, and extensions

> **Assembly status:** Apps and Skills contracts are implemented but experimental and unassembled. `apps/mcp-server` contributes neither extension, so their methods are unadvertised and return method-not-found. No object store, lifecycle repository, audit repository, replay store, MCP handler, UI client, Skill artifact adapter, or Skill executor is composed.

Extension negotiation admits a contract; it does not grant authorization, enable an installation, start execution, or prove persistence. Every extension action must return through the canonical registry and the controls in [server architecture](server-architecture.md). Review extension-specific threats in [MCP security](../../security/mcp-security.md) and artifact provenance in [supply-chain security](../../security/supply-chain.md).

## Apps

MCP Apps use the opt-in extension `io.modelcontextprotocol/ui@2026-01-26`. The extension identifier is stable, while this repository's App capability remains classified experimental and unassembled.

An admitted App manifest is signed, immutable, and bounded. The implemented contract accepts Ed25519 signatures, `ui://` resources, HTML media, explicit content-security and sandbox policy, and declared origins. Host messaging is correlated and replay-protected. Resource admission does not make arbitrary network access, filesystem access, or origin trust available.

Lifecycle state is installed but disabled by default, then may be enabled, disabled, or uninstalled through trusted host policy. Durable lifecycle state, object storage, audit, and replay protection are application-owned ports; no concrete repository or storage composition is proven.

The App frame is untrusted. It cannot establish identity or tenant, authorize a capability, satisfy confirmation, choose idempotency, or call business code directly. A trusted host adapter must:

1. resolve the installed manifest and current enabled state;
2. validate origin, sandbox, CSP, correlation, and replay state;
3. bind the canonical principal and tenant;
4. project only admitted registry capabilities;
5. obtain trusted confirmation where policy requires it;
6. dispatch through the canonical registry with budget, deadline, cancellation, and idempotency controls;
7. return only bounded, redacted results.

No concrete App host or UI client exists in the repository, so there is no browser workflow or origin to document as live.

## Skills

MCP Skills use the experimental, opt-in extension `io.modelcontextprotocol/skills@2026-08-22` and are disabled by default. They are selected only by `full-reference-ai`.

A Skill package is signed but remains untrusted instruction data. Admission binds provenance, tenant, principal, server, installation, and leased data-only package reads. `SKILL.md` content has no authority to change system or developer instructions, approve effects, broaden authorization, select another tenant, or request secrets.

Executable package forms are rejected, including Python, JavaScript, and WebAssembly. There is no executor sandbox. Although the profile contract denies network use, no execution runtime exists from which to claim enforced network isolation. Skills therefore cannot be described as runnable automation.

Persistent lifecycle, revocation, and artifact storage are application-owned ports. The catalog declares `mcp_skill_artifacts`, but no inspected migration or adapter proves persistence. A release composition would need trusted key policy, immutable artifact storage, revocation, retention, audit, lease expiry, restart reconciliation, and lifecycle ownership before admitting packages.

## Shared extension rules

For either extension:

- negotiation is explicit and revision-bound;
- absence is safe and must not degrade to an older proprietary behavior;
- signature validity is necessary but does not make content trusted;
- authorization and resource isolation are evaluated at use time;
- confirmation comes from a trusted host or policy decision;
- schema and content limits are enforced locally;
- deadlines, cancellation, and drain reach registry execution;
- persistent lifecycle claims require an implemented repository, migrations, backup/retention, and restart reconciliation;
- extension metadata and errors remain bounded and secret-safe.

**Expected result:** only an admitted, enabled, revision-compatible extension can request a bounded registry projection, and every requested action is freshly authorized for the principal and tenant.

**Failure path:** reject on unsupported revision, invalid signature or provenance, disabled or revoked installation, origin/CSP/sandbox violation, replay or correlation mismatch, tenant mismatch, authorization or confirmation failure, executable Skill content, exceeded bounds, deadline, cancellation, or unavailable persistence. Never treat signed content as privileged instructions.

No executable setup or verification command is documented because the reference app does not host either extension. Experimental source-only MCP previews are cataloged separately in [experimental and unassembled surfaces](experimental-and-unassembled-surfaces.md).

## Related guidance

- [Tools, resources, and prompts](tools-resources-and-prompts.md)
- [Authentication, authorization, and tenancy](authentication-authorization-and-tenancy.md)
- [Data and privacy boundaries](../../concepts/data-and-privacy-boundaries.md)
- [MCP capability matrix](../../reference/mcp-capability-matrix.md)
- [Availability and exposure matrix](../../reference/availability-and-exposure-matrix.md)
