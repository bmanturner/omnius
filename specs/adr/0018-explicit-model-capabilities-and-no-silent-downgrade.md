---
spec_id: OMNIUS-ADR-0018
title: Require Explicit Model Capabilities and Forbid Silent Downgrades
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Require Explicit Model Capabilities and Forbid Silent Downgrades

## Context

Provider and model support differs across structured output, tools, media, citations, reasoning, caching, regions, and limits. Name-based assumptions become stale.

## Decision

Routes declare hard and preferred capabilities. Provider/model revisions declare evidence-backed capabilities. Unsupported routes fail or use explicitly authorized semantically compatible fallback; silent weakening is prohibited.

## Consequences

Routing is predictable and auditable. Capability metadata needs maintenance and provider tests.

## Rejected alternatives

- Best-effort conversion with hidden feature loss.
- Global model enums.
- Provider choice embedded in product handlers.
