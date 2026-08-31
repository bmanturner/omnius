---
title: Optional product modules
description: Current implementation, profile, exposure, and composition boundaries for optional product and transport modules.
status: experimental
implementation: partial
profile_availability:
  - saas
  - saas-pgmq
  - full-reference
public_exposure: unassembled
audience:
  - rust-application-developer
  - product-architect
  - operator
  - security-reviewer
topics:
  - optional-modules
  - feature-flags
  - localization
  - billing
  - administration
  - consent
  - moderation
  - graphql
  - grpc
capabilities:
  - feature-flag-evaluation
  - localization
  - billing
  - admin
  - consent
  - moderation
  - graphql
  - grpc
source:
  - crates/feature-flags/src/lib.rs
  - crates/localization/src/lib.rs
  - crates/billing/src/lib.rs
  - crates/admin/src/lib.rs
  - crates/privacy/src/lib.rs
  - crates/graphql/src/lib.rs
  - crates/grpc/src/lib.rs
  - specs/18-optional-product-modules.md
evidence:
  - migrations/2026082319_create_billing.sql
  - migrations/2026082320_create_privacy_lifecycle.sql
  - specs/machine/module-catalog.yaml
  - specs/machine/profiles.yaml
  - apps/api-server/src/main.rs
last_verified: 2026-08-30
---

# Optional product modules

Optional modules are capability selections, not hidden features of the reference application. Their implementation ranges from complete libraries to schema-only intent and specification-only design. None of the product surfaces on this page is publicly assembled by the checked-in application; GraphQL, gRPC, and localization are library-only.

Search has separate canonical ownership in [caching, search, and rate limits](caching-search-and-rate-limits.md); its profile selection is likewise not reference-app exposure and is not duplicated here.

Use [modules, profiles, and composition](../../concepts/modules-profiles-and-composition.md) to interpret selection and dependency closure. The [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md) remains the authority for current status, and the [security model](../../security/security-model.md) applies before any new listener or privileged surface is exposed.

## Current capability boundaries

| Capability | Profiles | Implementation | Exposure | What is still absent |
|---|---|---|---|---|
| Feature-flag evaluation | `saas`, `saas-pgmq`, `full-reference` | Implemented | Unassembled | Application construction and any management or browser-facing API |
| Localization | `full-reference` | Implemented | Library-only | Catalogs, locale negotiation, and application wiring |
| Billing | `full-reference` | Partial | Unassembled | Payment provider, checkout/collection, configured webhook, and runtime reconciliation |
| Admin surface | `saas`, `saas-pgmq`, `full-reference` | Implemented | Unassembled | Separate protected listener, policy composition, and application registration |
| Consent | `full-reference` | Partial | Unassembled | Service layer, policy/legal-text management, and public routes |
| Moderation | `full-reference` | Specified-only | Unassembled | Source, migrations, provider, worker, and routes |
| GraphQL transport | `full-reference` | Implemented | Library-only | Schema composition, router mount, and subscription provider wiring |
| gRPC transport | `full-reference` | Implemented | Library-only | Server listener, certificates, service registration, and deployment wiring |

The page-level `partial` classification reflects this mixed set. A migration or selected profile must not promote the incomplete modules.

## Feature-flag evaluation

The feature-flag library provides typed evaluation, allowlisted context, bounded evaluation timeout, caching, fallback behavior, and redacted exposure data. It is an evaluation boundary, not a flag-management product.

A composition must supply a concrete evaluator/provider and an allowlist of context fields. Do not pass arbitrary request attributes, tokens, personal data, or secret values into evaluation or telemetry. Fallback behavior must be explicit and safe for the feature being gated; a provider timeout or stale cache must not silently grant privileged behavior.

There is no assembled persistence model, administration API, browser exposure, or audit workflow for changing flags. A profile selecting the module proves none of those.

## Localization

The localization library implements Fluent-based message selection and BCP 47 locale fallback. `full-reference` includes the library, but no runtime catalogs or request locale-negotiation policy are assembled.

A product composition owns catalog completeness, locale allowlisting, default and fallback policy, interpolation-data classification, missing-message behavior, and release review. Do not expose raw internal keys, secrets, or untrusted markup through translated messages. A library test proves fallback mechanics, not that a deployed application serves localized content.

## Billing is partial

Billing currently provides a local mirror, entitlement and reconciliation concepts, plus a billing migration. It does not include a concrete payment-provider adapter, payment collection, checkout UI, or configured provider webhook. In particular, the repository does not justify claiming Stripe or any other provider.

A future composition must make authority explicit:

- the external provider remains authoritative for provider-side payment state;
- the local mirror and entitlement decision need a documented consistency model;
- inbound events need verified signatures, replay protection, durable admission, and idempotent reconciliation;
- tenant ownership, refunds, disputes, delinquency, retention, and audit behavior need product policy;
- degraded provider state must fail according to an explicit entitlement policy, not an accidental permissive fallback.

Until those components and negative paths are assembled and observed, `full-reference` selection is not a usable billing feature.

## Admin surface

The admin library is designed for a separate protected listener and constrained, audited operations. It does not expose generic SQL, an arbitrary command runner, or an implicit superuser API. The checked-in application does not construct its policy or start its listener.

Treat administration as a distinct trust boundary: require strong authentication, explicit operation authorization, tenant and resource scoping, reason capture, immutable audit evidence, request and response bounds, network isolation, and independent rate limits. Do not mount it into the ordinary public router merely because the profile selects the crate.

Administrative diagnostics must remain redacted. A safe operational surface reports stable identifiers and status classes, not secrets, raw payloads, personal data, database statements, or upstream error text.

## Consent and data lifecycle

The privacy migration records partial schema intent for consent and lifecycle evidence, including immutable version/legal references. It does not provide a consent service, legal-text publication system, policy engine, lifecycle worker, or public route.

Product teams must define what is being consented to, which text/version was presented, the lawful basis, withdrawal semantics, tenant and subject identity, retention, and audit access. Schema presence alone cannot establish legal compliance or prove erasure execution. Use the canonical [data and privacy boundaries](../../concepts/data-and-privacy-boundaries.md) rather than restating lifecycle policy here.

## Moderation is specified-only

Moderation has specification and module-catalog intent only. There is no checked-in implementation, migration, provider integration, review queue, worker, or application route. Do not document a moderation API, automated decision, appeal flow, provider guarantee, or operational command until concrete evidence exists.

A future implementation will need bounded content admission, tenant policy, provider and model provenance where applicable, human-review and appeal boundaries, false-positive handling, privacy and retention policy, auditability, and fail-safe degraded behavior. These are requirements, not current capabilities.

## GraphQL is library-only

The GraphQL crate adapts bounded GraphQL transport behavior to canonical application services, authentication, authorization, tenancy, errors, and observability. It is not an alternative domain implementation. `full-reference` includes the library but does not compose a schema or mount a GraphQL router.

Subscriptions additionally depend on an explicitly selected and assembled realtime provider. Selecting GraphQL and realtime modules in one profile does not wire subscriptions or prove replay behavior. A composition must bound parsing, depth/complexity, variables, batching, response size, execution time, and subscription queues; preserve field-level authorization; and ensure introspection policy is appropriate for the deployment.

No public GraphQL route or subscription endpoint should be inferred from the crate or profile selection data.

## gRPC is library-only

The gRPC crate adapts canonical service contracts to bounded unary and streaming transport. It has seams for authentication and authorizer injection, deadlines, cancellation, backpressure, message limits, health, and protected reflection. It does not start a server listener, load certificates, register application services, or alter network policy.

A production composition must define TLS and client-authentication policy, trusted proxy/peer identity, service and method authorization, tenant propagation, per-message and stream bounds, cancellation and deadline mapping, health exposure, and whether reflection is disabled or separately protected. Library health/reflection support is not evidence that either endpoint is listening.

## Composition gate

Before changing any row from unassembled or library-only, retain evidence of all relevant boundaries:

1. Exact module/profile choice and generated dependency closure.
2. Concrete construction from a checked-in application composition root.
3. Mounted router or registered listener/task, including the effective address and trust boundary.
4. Authentication, authorization, tenancy, privacy, and secret injection.
5. Dependency provisioning, health, bounded failure behavior, and graceful shutdown.
6. Public contract and compatibility review where a transport or API is added.
7. Redacted telemetry and an operator path that does not create a generic privileged backdoor.

Follow [deployment topologies](../../operations/deployment-topologies.md) and [operational readiness](../../operations/health-readiness-and-shutdown.md) for an assembled surface. Verification for this page remains **not run**; profile selection, specifications, migrations, generated artifacts, and library tests are not runtime assembly.