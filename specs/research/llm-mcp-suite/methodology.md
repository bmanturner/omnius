---
spec_id: OMNIUS-AI-RESEARCH-METHODOLOGY
title: LLM and MCP Research Methodology
version: 0.1.0
status: research
last_verified: 2026-08-24
---

# LLM and MCP Research Methodology

## Scope

The review covered current MCP protocol and roadmap behavior, official Rust MCP implementation, mature Rust LLM provider abstractions, first-party provider output contracts, JSON Schema tooling, telemetry, OAuth standards, security, testing, and operational integration.

## Selection rubric

Candidates were scored on protocol fidelity, maintainer activity, release recency, provider breadth, preservation of provider-specific data, structured output, streaming, tools, media, telemetry, dependency compatibility, testability, documentation, and the ability to remain behind service-kit-owned types.

The research deliberately separated three questions:

1. What is a stable application contract?
2. Which crate best implements the current adapter?
3. Which roadmap seams should be prepared without inventing protocol behavior?

## Source hierarchy

Authoritative protocol specifications, official SDK repositories, provider documentation, crate repositories, standards, and official conformance suites were preferred. Anecdotal popularity was not allowed to override a current protocol mismatch. Exact versions are frozen in the dependency baseline and re-resolved in task `T151` before code is accepted.

## MCP date discipline

Older MCP tutorials are treated as potentially misleading because the `2026-07-28` release removed sessions and initialization, introduced discovery and per-request negotiation, changed subscriptions and result types, moved Tasks to an extension, and deprecated several features. All MCP recommendations were checked against `SRC-AI-001` through `SRC-AI-029`.

## Reproducibility

Every recommendation maps to an acceptance criterion. Machine catalogs, schemas, examples, dependency pins, protocol compatibility, risks, task graph, and hashes are included. The validator checks references and merged composition rather than merely parsing files.
