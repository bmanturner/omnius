---
spec_id: RSK-ADR-0023
title: Map MCP Tasks to Jobs and Subscriptions to Event Providers
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Map MCP Tasks to Jobs and Subscriptions to Event Providers

## Context

The base kit already owns durable jobs, outbox/inbox, cancellation, Redis pub/sub, and NATS. Reimplementing these inside MCP would duplicate difficult infrastructure.

## Decision

Implement Tasks as an adapter over jobs and explicit task state. Implement subscriptions/listen over one selected event backplane. Request progress remains request-scoped.

## Consequences

MCP long-running and event behavior inherits existing durability and operational semantics. Provider-specific guarantees must remain visible.

## Rejected alternatives

- A second MCP queue.
- Store task state only in process memory.
- Promise durable subscriptions over Redis pub/sub.
