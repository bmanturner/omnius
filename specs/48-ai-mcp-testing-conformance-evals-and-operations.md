---
spec_id: RSK-048
title: AI and MCP Testing, Conformance, Evaluations, and Operations
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# AI and MCP Testing, Conformance, Evaluations, and Operations

## 1. Test layers

The suite requires unit, property, contract, integration, cassette, conformance, security, load, soak, and failure tests. Live-provider tests are quarantined, budget-capped, opt-in, and never required for ordinary local development. Deterministic provider cassettes and synthetic MCP clients cover the default CI path.

## 2. Provider tests

Each provider adapter has fixtures for text, structured output, tools, streaming, refusals, citations, media, usage, unknown content, malformed events, throttling, timeout, and partial-stream failure where supported. Fixtures assert normalized output and retained raw metadata. Secret scanners verify that recordings contain no credentials or personal data.

## 3. Schema and streaming tests

JSON Schema generation/validation uses official conformance suites where practical plus property and fuzz tests for references, composition, nesting, limits, and arbitrary JSON roots. Stream tests vary chunk boundaries, ordering, duplicate/unknown events, cancellation, backpressure, and truncated tool/JSON deltas.

## 4. MCP conformance

The official MCP conformance framework is a release gate for supported protocol revisions and transports. The MCP Inspector is used for interactive and CLI/TUI diagnostics. Tests cover `server/discover`, per-request negotiation, cache metadata, standard headers, tools/resources/prompts, result types, MRTR, subscriptions, Tasks, auth extensions, cancellation, errors, and legacy compatibility modes.

## 5. Security matrix

Tests attempt horizontal/vertical/cross-tenant access, hidden catalog enumeration, prompt injection, tool-confused-deputy attacks, forged MRTR state, replayed tasks, malicious resource URIs, header injection, oversized payloads, unsafe media, token issuer confusion, client credential reuse, and secret/content leakage through telemetry.

## 6. Evaluations

LLM evaluations are versioned datasets with prompt, route, model/provider revision, expected properties, judge methodology, tolerances, and cost. Deterministic assertions are preferred. Model-graded evaluations require calibration, blinded comparisons where useful, and recorded judge/version. Evals never replace correctness or authorization tests.

## 7. Operations

Runbooks cover provider outage, quota exhaustion, cost anomaly, compromised key, partial stream, stuck tool/job, task/subscription backlog, MCP compatibility failure, and extension rollback. Dashboards separate request, provider, tool, job, and protocol layers.

## 8. Acceptance linkage

This specification is verified by `AC-AI-105` through `AC-AI-112`.
