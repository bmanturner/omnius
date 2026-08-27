---
spec_id: OMNIUS-039
title: LLM Routing, Reliability, Cost, and Quotas
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# LLM Routing, Reliability, Cost, and Quotas

## 1. Route definition

A model route is versioned configuration containing allowed providers/models, required and preferred capabilities, data residency, maximum data classification, latency target, retry/fallback policy, context/output limits, budget, and observability name. Application code requests a route, not a provider-specific model constant.

## 2. Selection

Selection first filters on hard requirements. It MAY then rank by explicit policy such as quality tier, latency, cost, provider health, regional availability, or tenant entitlement. The chosen provider/model and every rejected candidate reason are observable without exposing secrets.

## 3. Reliability

The kit defines separate connect, first-byte, idle-stream, total, and tool-turn deadlines. Retries apply only to classified transient failures and respect idempotency, retry-after, total deadline, and budget. Jittered exponential backoff is the default. A stream is never transparently retried after externally visible output unless the consumer requested a restartable durable operation.

Hedging is disabled by default because it multiplies cost and can duplicate side effects. It MAY be enabled only for non-tool, idempotent requests with explicit cancellation and billing policy.

## 4. Fallback

Fallback requires declared semantic compatibility. It MUST NOT weaken strict schema guarantees, tool availability, data boundaries, safety configuration, context requirements, or output modalities. Fallback reason and route revision are recorded. The caller MAY prohibit fallback.

## 5. Quotas and budgets

Limits may be applied by principal, tenant, API key, route, provider, model, and operation. They include requests, concurrent streams, tokens/units, tool calls, media bytes, and estimated/actual cost. Reservation occurs before dispatch and reconciliation occurs after provider usage is known. Ambiguous usage is retained rather than silently treated as zero.

## 6. Provider health

Circuit state is based on bounded rolling evidence and distinguishes provider-wide, endpoint, region, and model failures. Health status affects routing but does not expose credential or tenant-specific failures globally. Readiness depends on whether required routes retain at least one usable candidate.

## 7. Acceptance linkage

This specification is verified by `AC-AI-033` through `AC-AI-040`.
