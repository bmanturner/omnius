---
spec_id: OMNIUS-ADR-0021
title: Use One Agent Capability Registry Across HTTP, Jobs, LLM Tools, and MCP
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Use One Agent Capability Registry Across HTTP, Jobs, LLM Tools, and MCP

## Context

Duplicated tool definitions and handlers drift in schemas, authorization, tenancy, idempotency, and audit behavior.

## Decision

Create one registry of stable application capabilities and explicit projections. Adapters invoke application services through the registry and cannot bypass its policy metadata.

## Consequences

Business behavior stays consistent across interfaces. The registry becomes a critical reviewed contract and must avoid becoming a service locator for unrelated infrastructure.

## Rejected alternatives

- Separate MCP-only business services.
- Generate capabilities directly from every public HTTP route.
- Let model SDK tools call repositories.
