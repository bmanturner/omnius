---
spec_id: RSK-ADR-0022
title: Map MCP Identity to the Canonical Principal and Authorization System
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Map MCP Identity to the Canonical Principal and Authorization System

## Context

MCP callers may be users, client applications, workloads, delegated agents, or local processes. Treating all bearer tokens alike loses identity and policy information.

## Decision

Validate current MCP/OAuth metadata and map evidence to the canonical Principal, retaining client, workload, user, delegation, tenant, scopes, and issuer. Use ordinary authorization and audit for every primitive.

## Consequences

MCP gains the same cross-tenant and least-privilege controls as other transports. Identity evidence and principal semantics remain separate.

## Rejected alternatives

- MCP-specific roles table.
- Trust tool annotations as authorization.
- Authorize only the transport endpoint.
