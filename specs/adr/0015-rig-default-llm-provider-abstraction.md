---
spec_id: OMNIUS-ADR-0015
title: Use Rig as the Default LLM Provider Abstraction
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Use Rig as the Default LLM Provider Abstraction

## Context

The kit needs mature multi-provider support without hand-building every wire client. Rig has broad current provider coverage, streaming, tools, structured output, media/embedding capabilities, provider response identities, raw output access, and GenAI telemetry integration.

## Decision

Pin Rig 0.42.0 as the default provider implementation. Keep Rig entirely behind service-kit-owned provider ports and canonical content contracts. Optional Bedrock and Vertex companion crates remain separate modules.

## Consequences

Provider integration effort is reduced while application contracts remain stable. Rig upgrades require cassette and normalization review. Direct provider adapters remain possible when a capability cannot be represented safely.

## Rejected alternatives

- Expose Rig types throughout the application.
- Write every provider HTTP client from scratch.
- Use several competing provider frameworks simultaneously.
