---
spec_id: RSK-018
title: Optional Product and Transport Modules
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Optional Product and Transport Modules


## Principle

These modules are intentionally separate from the kernel. Each must satisfy the standard module contract, but product semantics remain application-owned.

## Organizations

Includes organization, membership, roles, invitations, ownership transfer, suspension, quotas, tenant context, and lifecycle. Depends on PostgreSQL, authentication, authorization, and audit.

## Admin/support

Includes user/tenant lookup, suspension, safe data repair commands, audited impersonation, and controlled feature overrides. Runs on a separate protected surface. No generic “run arbitrary SQL” endpoint.

## Billing and entitlements

Separates:

- Provider adapter.
- Customer/subscription/invoice mirror.
- Product plan and entitlement evaluation.
- Usage metering.
- Webhook reconciliation.
- Grace/dunning policy.
- Audit and repair tooling.

Provider semantics are not erased behind a pretend universal billing model. Stripe or another provider receives its own adapter/ADR. Entitlements are read from authoritative local state after verified webhook/API reconciliation.

## Feature flags

Use the OpenFeature Rust SDK and a provider such as flagd/OFREP where appropriate. The module defines:

- Typed flag keys/defaults.
- Evaluation context allowlist.
- Timeout/caching/failure default.
- Exposure/audit events.
- Removal date/owner for temporary flags.
- No secrets or unbounded context.
- No use of flags to bypass authorization or schema compatibility.

A no-op/static provider supports tests and small deployments.

## Search

Default optional adapter is Meilisearch through its maintained SDK; applications may supply OpenSearch or another provider by ADR.

- Search index is a derived projection, not source of truth.
- Versioned index/schema and aliases.
- Outbox-driven indexing.
- Replay/backfill/reindex.
- Staleness status.
- Tenant filter enforced in index/query.
- Search result IDs reauthorized before sensitive response.

## GraphQL

Use `async-graphql` only when selected.

- Same application services and authorization.
- Depth/complexity/list limits.
- Persisted/allowlisted operations where threat model requires.
- DataLoader batching.
- Introspection policy.
- Separate GraphQL error mapping plus request ID.
- Subscription transport follows realtime spec.
- No business logic in resolvers.

## gRPC

Use `tonic`.

- Interceptors for request ID, tracing, auth, deadlines.
- Canonical status/error detail mapping.
- Message/decompression limits.
- Reflection only on protected/internal surfaces.
- Health service.
- Streaming backpressure and cancellation.
- Same application authorization.

## Localization

Use Project Fluent (`fluent-bundle`) where runtime localization is needed.

- BCP 47 locale negotiation.
- Explicit fallback chain.
- UTC storage and localized rendering.
- Time-zone/currency/plural handling.
- Template/catalog validation.
- Missing-message metrics without user text.
- Email/notification integration.

## Data lifecycle and privacy

Defines export, deletion, anonymization, retention, legal hold, and data inventory. Work is durable, restartable, audited, and reconciles PostgreSQL, object storage, search, queues, and providers.

## Consent/legal

Versioned terms/privacy/consent records with subject, version, time, jurisdiction/source, withdrawal where applicable, and immutable evidence. Legal text itself is externally governed.

## Moderation

Product-specific reports, evidence, actions, appeal, policy version, actor, subject, audit, notification, and retention. Authorization distinguishes reporter, moderator, administrator, and automated system.

## API transport providers

REST is default. GraphQL and gRPC are opt-in adapters, not replacement architectures. All share canonical application services, principal, authorization, tenancy, errors, events, and observability.
