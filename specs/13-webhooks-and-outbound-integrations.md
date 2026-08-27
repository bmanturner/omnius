---
spec_id: OMNIUS-013
title: Webhooks and Outbound Integrations
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Webhooks and Outbound Integrations


## Outbound webhooks

Use Svix managed or self-hosted for production. The kit provides a thin adapter, not a delivery platform.

Support application/endpoint lifecycle, secret rotation, event IDs/types, idempotent enqueue, status, replay, test event, suspension, and safe correlation. Local fake is test/development only.

## Public event contract

Stable event ID, type/version, time, tenant/application, data, safe previous attributes, and safe correlation metadata. Public schemas are semver-governed.

## Inbound webhooks

Provider adapters:

1. Apply strict size/header limits.
2. Preserve raw bytes.
3. Verify signature and timestamp before processing.
4. Enforce replay window/deduplication.
5. Parse a versioned provider event.
6. Persist receipt/inbox.
7. Acknowledge to provider contract.
8. Process asynchronously.
9. Reconcile through provider API when ordering/authenticity requires it.

Raw signed bodies are not logged by default.

## SSRF

Central validation for user-configurable URLs:

- HTTPS in production unless explicitly exempted.
- Scheme allowlist and no URL credentials.
- DNS resolution plus resolved-address checks.
- Block loopback, link-local, private, multicast, metadata, and configured internal ranges unless explicitly permitted.
- Re-check redirects/resolutions.
- Bounded or disabled redirects.
- Port policy.
- Connect/response timeouts and response cap.
- Never forward internal auth headers.
- Egress network policy as defense in depth.

## General integration adapter

Define reusable reqwest policy, authentication/rotation, idempotency, retry classification, provider rate limits, bulkhead/circuit behavior when justified, redaction, Wiremock contract tests, sandbox mode, health semantics, and reconciliation. Do not erase provider semantics behind a universal interface.
