---
spec_id: RSK-ADR-0024
title: Isolate Extensions and Preserve Roadmap-Facing Seams
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Isolate Extensions and Preserve Roadmap-Facing Seams

## Context

MCP is actively settling agentic messaging, HTTP unification, agent identity, result contracts, progressive discovery, file/resource improvements, and SDK generation.

## Decision

Keep extensions as opt-in modules and isolate canonical results, dispatch, identity evidence, tasks/subscriptions, resources, and discovery metadata. Preview modules may prepare internal structures but cannot invent stable wire contracts.

## Consequences

Settled standards can replace adapters without redesigning the application. Some preview code may be deleted rather than promoted.

## Rejected alternatives

- Implement roadmap proposals as proprietary RPCs.
- Put all extensions in core.
- Freeze the internal model to the current tools/call result shape.
