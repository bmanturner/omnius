---
spec_id: OMNIUS-ADR-0017
title: Use JSON Schema 2020-12 as the Structured Output Boundary
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Use JSON Schema 2020-12 as the Structured Output Boundary

## Context

LLM providers and MCP 2026-07-28 both converge on JSON Schema 2020-12, including non-object roots and composition keywords.

## Decision

Generate owned schemas with Schemars 1.2.2, validate with jsonschema 0.51.0, bound reference resolution, and locally validate every structured result. Provider-native strict output is preferred but never replaces local validation.

## Consequences

One schema dialect serves LLM outputs, tools, MCP, and generated contracts. Complex schemas require explicit resource limits and compatibility tests.

## Rejected alternatives

- Provider-specific schema dialects in domain code.
- Prompt-only JSON as the default.
- Assume structured roots are always objects.
