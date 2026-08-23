---
spec_id: ADR-0006
title: Use Svix for Production Outbound Webhooks
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Use Svix for Production Outbound Webhooks


## Context

Reliable outbound webhooks require endpoint and secret lifecycle, signing, retries, backoff, replay, suspension, delivery logs, observability, and abuse controls. These are a product in their own right and are not a sensible generic subsystem to recreate in this service kit.

## Decision

Use Svix, managed or self-hosted, for production outbound webhook delivery.

The service kit owns:

- A narrow event/delivery adapter.
- Public event schemas.
- Authorization and tenant mapping.
- Safe metadata correlation.
- Configuration, health, metrics, and test fake.

Svix owns delivery scheduling, signing, retries, endpoint lifecycle, replay, and delivery history.

## Consequences

- The service has a vendor/external-system dependency for production delivery.
- A local fake may demonstrate contracts but cannot be promoted to production.
- Product teams can replace Svix only behind the adapter and with an ADR proving equivalent operational behavior.
- Inbound provider webhooks remain provider-specific adapters.

## Validation

Contract tests cover enqueue, endpoint lifecycle, replay, signature examples, provider failure, redaction, and idempotency. Deployment policy verifies Svix availability and data-residency requirements.
