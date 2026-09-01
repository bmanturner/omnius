---
title: Files, notifications, and webhooks
description: Storage, upload, email, notification, webhook, and outbound HTTP boundaries with their distinct assembly and failure semantics.
status: experimental
implementation: implemented
profile_availability:
  - api
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - worker
  - full-reference
public_exposure: assembled
audience:
  - rust-application-developer
  - operator
  - security-reviewer
  - privacy-reviewer
topics:
  - files
  - uploads
  - email
  - notifications
  - webhooks
  - outbound-http
capabilities:
  - object-storage
  - upload-workflow
  - email
  - notifications
  - webhooks-svix
  - webhooks-inbound
  - outbound-http
source:
  - crates/object-storage/src/lib.rs
  - crates/upload-workflow/src/lib.rs
  - crates/email/src/lib.rs
  - crates/notifications/src/lib.rs
  - crates/webhooks-svix/src/lib.rs
  - crates/webhooks-svix/src/postgres_replay.rs
  - migrations/2026082809_create_svix_replay_admission.sql
  - crates/webhooks-inbound/src/lib.rs
  - crates/outbound-http/src/lib.rs
  - specs/12-object-storage-email-and-notifications.md
  - specs/13-webhooks-and-outbound-integrations.md
evidence:
  - migrations/2026082315_create_upload_workflow.sql
  - migrations/2026082701_add_upload_external_identity_and_abandonment.sql
  - migrations/2026082316_create_notifications.sql
  - migrations/2026082317_create_webhook_receipts.sql
  - apps/api-server/src/main.rs
  - specs/machine/profiles.yaml
last_verified: 2026-08-30
---

# Files, notifications, and webhooks

These integration libraries have different exposure states. The page-level `assembled` classification reflects only the account-email path currently wired by the reference OAuth application. It does **not** mean that file APIs, upload routes, a notification worker, inbound or outbound webhook routes, or a public outbound HTTP proxy are assembled.

Apply the canonical [data and privacy boundaries](../../concepts/data-and-privacy-boundaries.md) to stored and transmitted data, then review the provider boundary in [object storage](#object-storage). Use [jobs, events, and scheduling](jobs-events-and-scheduling.md) for at-least-once processing and [backup, recovery, and retention](../../operations/backup-recovery-and-data-retention.md) for persistence obligations. Webhook compositions must reuse the shared [outbound HTTP](#outbound-http-is-not-a-proxy) policy and the surrounding [deployment security controls](../../security/deployment-hardening.md).

## Exposure by capability

| Capability | Profile availability | Implementation | Exposure | Concrete boundary |
|---|---|---|---|---|
| Object storage | [`saas`, `saas-pgmq`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | Implemented | Library-only | No application store construction or route mount |
| Upload workflow | [No profile selection](../../concepts/modules-profiles-and-composition.md) | Implemented | Unassembled | No application route or reconciler is registered |
| Email delivery | [`authenticated-api`, `oauth-provider`, `saas`, `saas-pgmq`, `realtime`, `realtime-durable`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | Implemented | Assembled | Conditional SMTP delivery for account verification, recovery, and invitation only |
| Notifications | [`saas`, `saas-pgmq`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | Implemented | Unassembled | Schema and library exist; no provider or worker is registered |
| Svix outbound webhooks | [`saas`, `saas-pgmq`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | Implemented | Unassembled | Durable replay admission exists; application configuration, route, worker, and health composition do not |
| Inbound webhooks | [`saas`, `saas-pgmq`, `full-reference`](../../concepts/modules-profiles-and-composition.md) | Implemented | Unassembled | Router factory exists; no provider registry, secret injection, queue, worker, or mount |
| Outbound HTTP | [`api` and its derived authenticated, SaaS, realtime, worker, and `full-reference` profiles](../../concepts/modules-profiles-and-composition.md) | Implemented | Library-only | Internal SSRF-resistant client, never a public proxy |

Interpret profile IDs through the canonical [modules, profiles, and composition model](../../concepts/modules-profiles-and-composition.md). The [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md) is authoritative for exact availability and current exposure.

## Object storage

`BlobStore` is a provider-neutral library boundary with local, S3-compatible, Google Cloud Storage, and Azure seams. The application, not callers, owns provider credentials and configuration. Object keys are opaque and tenant-scoped; user filenames are metadata, not storage addresses.

The library's streaming path applies bounded admission, deadlines, cancellation, and integrity checks. A composed application must still define bucket/container lifecycle, encryption and region policy, data classification, tenant deletion, retention, backup, and reconciliation. Interpret [profile selection](../../concepts/modules-profiles-and-composition.md) before making availability or assembly claims.

Failure handling should distinguish policy rejection from transient storage failure:

- reject an invalid tenant scope, unsafe key, oversized object, or integrity mismatch before publication;
- cancel provider work when the request or workflow is cancelled;
- treat timeouts and provider unavailability as bounded retry candidates only where the operation is idempotent;
- never log credentials, provider-signed request material, object contents, or a presigned URL.

## Upload workflow

The upload workflow keeps PostgreSQL as the authoritative state machine. [No profile selects its module](../../concepts/modules-profiles-and-composition.md), so there is no reference-app upload API despite the implemented library and migrations.

A safe lifecycle is:

1. **Initiated:** authorize tenant and principal, allocate an opaque object identity, and record policy.
2. **Quarantined:** accept bytes into non-public storage under bounded size, time, and integrity checks.
3. **Verification:** scan content and verify hash and media type against the recorded intent.
4. **Published:** expose only a clean verified object.
5. **Abandoned or rejected:** retain enough state for bounded cleanup and audit without exposing bytes.

Every transition reauthorizes the operation and uses fenced leases where background reconciliation is required. External storage effects are at least once and must be reconciled idempotently against the database state.

A scanner failure, hash or media-type mismatch, cancellation, lease expiry, or storage outage must not publish an object. Downloads are designed to be proxied through authorization with attachment and `nosniff` response policy rather than returned as presigned GET URLs. The reference application does not currently mount that proxy.

## Email is assembled narrowly

The OAuth-provider application can construct SMTP-backed email for account verification, account recovery, and invitations. That is the only concrete exposure in this page. It is not a general-purpose mail API, notification channel, or proof that a durable email worker is running.

SMTP configuration and required templates are prerequisites for those account flows. Missing configuration or template material must fail safely rather than silently claim delivery. Public errors and logs must not disclose recipients, tokens, message bodies, credentials, or upstream SMTP text.

The email job library uses at-least-once delivery semantics. Exactly-once email delivery is not promised, and the repository does not prove a durable worker composition for queued mail. Handlers therefore need a stable effect identity and provider-aware duplicate strategy.

## Notifications

The notification library and migration model preferences, unsubscribe state, delivery attempts, and audit records. No concrete channel provider or notification worker is registered in the reference application.

Before attempting a channel effect, a composition must:

- resolve and enforce the current tenant-scoped preference and unsubscribe state;
- avoid placing raw destination tokens or message content in diagnostics;
- use stable idempotency for at-least-once attempts;
- distinguish disabled preferences, invalid destination tokens, permanent provider rejection, and transient provider failure;
- bound retries and retain only the audit and delivery data justified by policy.

Database rows and [profile/module selection](../../concepts/modules-profiles-and-composition.md) do not prove delivery. A product must assemble providers, templates, workers, secret injection, health, metrics, and retention before documenting a usable notification feature.

## Outbound webhooks through Svix

The Svix adapter manages provider-side applications and endpoints, endpoint status, signing-secret rotation, and replay requests. Its PostgreSQL replay-admission adapter serializes tenant reservations and durably enforces exact duplicate reuse, overlap conflicts, active limits, cooldown, task binding, terminal completion, and idempotent rejection release. Svix owns delivery infrastructure and retry behavior; the application still owns event admission, authorization, tenant mapping, payload minimization, and the business-event-to-provider record.

Replay is not a substitute for application persistence. An operator surface must authenticate and authorize the actor, require an auditable reason, bound the replay range, and avoid disclosing endpoint secrets or payloads. No such route, provider configuration, worker, or health integration is assembled in the reference application, so the durable adapter remains application-required.

## Inbound webhooks

Inbound webhook verification operates on the bounded raw request body before parsing. A provider implementation must validate the provider identity, signature, timestamp window, endpoint scope, and replay identity using secret material supplied by the host. The receipt store supports deduplication before asynchronous processing.

A representative signature grammar is conceptual only:

```text
Provider-Signature: t=<unix-time>,v1=<redacted-signature>
```

Never put a real signature, webhook secret, customer payload, or replayable request in documentation or logs.

The router factory has a source-local `POST /webhooks/inbound/{provider}` path, but no checked-in application mounts it. It deliberately does not use browser session or CSRF middleware: this is a machine callback boundary with provider-specific authentication. It still requires the shared request shell, body limit, tenant/provider resolution, redacted errors, and denial of unknown providers.

Expected failures include oversized body rejection, unknown provider denial, malformed or stale signature rejection, duplicate receipt handling, and bounded unavailability when admission cannot be persisted. The library does not supply a provider registry, secret source, processing queue, or worker.

## Outbound HTTP is not a proxy

The outbound HTTP library is the common SSRF-resistant client for application-owned integrations. It admits destinations before resolution, validates all resolved addresses, checks the connected peer, handles redirects manually through the same policy, and bounds connect, request, response-body, concurrency, and redirect work. Production policy is HTTPS on the standard secure port; a development-only loopback HTTP exception is separate and must not become a production fallback.

Callers must not accept an arbitrary user URL and forward it through this client as a public fetch service. OAuth remote metadata uses the client internally, but there is no public proxy route.

Fail closed on disallowed scheme, port, host or address; incomplete or changed DNS admission; peer mismatch; redirect to a denied destination; timeout; oversized response; or concurrency exhaustion. Errors and telemetry must redact query strings, credentials, response bodies, tokens, and sensitive host data. See [deployment hardening](../../security/deployment-hardening.md) for the surrounding network and secret boundary.

## Operational readiness

A capability is ready only after the composing application has retained evidence of its mount or registered worker, provider construction, secret source, dependency health, authorization and tenancy checks, data lifecycle, bounded negative paths, redacted observability, and graceful shutdown. For durable effects, duplicate and expired-lease behavior must also be exercised.

Verification for this page remains **not run**. Libraries, migrations, [profile selections](../../concepts/modules-profiles-and-composition.md), and router factories are not runtime evidence.