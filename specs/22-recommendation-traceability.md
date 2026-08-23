---
spec_id: RSK-022
title: Recommendation Traceability
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Recommendation Traceability


This matrix verifies that every substantive recommendation in the original design is represented in a normative specification and a concrete acceptance criterion.

| ID | Recommendation | Specification | Verification |
|---|---|---|---|
| `REC-001` | Use workspace-level explicit composition instead of one enormous feature matrix | `RSK-001; RSK-002` | `AC-GEN-001` |
| `REC-002` | Reserve Cargo features for additive implementation details | `RSK-002` | `AC-GEN-005` |
| `REC-003` | Provide generated profiles, workspace crates, runtime config, and product flags as distinct toggle mechanisms | `RSK-002; RSK-019` | `AC-GEN-001` |
| `REC-004` | Use meaningful crate boundaries rather than one crate per table | `RSK-001` | `AC-GEN-001` |
| `REC-005` | Define module dependencies and conflicts | `RSK-002` | `AC-GEN-002` |
| `REC-006` | Define configuration and validation per module | `RSK-002; RSK-004` | `AC-CFG-005` |
| `REC-007` | Define initialization and startup ordering per module | `RSK-002; RSK-003` | `AC-CORE-002` |
| `REC-008` | Define routes, middleware, and extractors per module | `RSK-002; RSK-005` | `AC-GEN-001` |
| `REC-009` | Expose typed application capabilities rather than raw optional state | `RSK-001; RSK-002` | `AC-GEN-001` |
| `REC-010` | Supervise module background tasks | `RSK-002; RSK-003` | `AC-CORE-004` |
| `REC-011` | Register module liveness/readiness behavior | `RSK-002; RSK-014` | `AC-OBS-004` |
| `REC-012` | Register module metrics and trace attributes | `RSK-002; RSK-014` | `AC-OBS-002` |
| `REC-013` | Participate in graceful shutdown | `RSK-002; RSK-003` | `AC-CORE-004` |
| `REC-014` | Supply module test fixtures and fakes | `RSK-002; RSK-016` | `AC-TEST-002` |
| `REC-015` | Document failure semantics and criticality | `RSK-001; RSK-014` | `AC-OBS-004` |
| `REC-016` | Distinguish required, degraded, and best-effort dependencies | `RSK-001; RSK-014` | `AC-OBS-004` |
| `REC-017` | Avoid a global AppState full of Option handles | `RSK-001` | `AC-GEN-001` |
| `REC-018` | Use source-level modules, not a dynamic Rust plugin ABI | `RSK-001; RSK-002` | `AC-GEN-001` |
| `REC-019` | Layer typed configuration sources | `RSK-004` | `AC-CFG-001` |
| `REC-020` | Strictly validate config at startup | `RSK-004` | `AC-CFG-002` |
| `REC-021` | Separate local/test/staging/production configuration | `RSK-004` | `AC-CFG-003` |
| `REC-022` | Protect secrets from Debug and diagnostics | `RSK-004; RSK-015` | `AC-CFG-004` |
| `REC-023` | Expose build version, revision, and environment metadata | `RSK-003` | `AC-CORE-006` |
| `REC-024` | Detect unknown/misspelled configuration keys | `RSK-004` | `AC-CFG-002` |
| `REC-025` | Order initialization and fail fast | `RSK-003` | `AC-CORE-002` |
| `REC-026` | Implement startup timeout and signal handling | `RSK-003` | `AC-CORE-004` |
| `REC-027` | Propagate cancellation and track tasks | `RSK-003` | `AC-CORE-004` |
| `REC-028` | Drain HTTP, WebSocket, and worker workloads gracefully | `RSK-003; RSK-010; RSK-011` | `AC-CORE-004` |
| `REC-029` | Flush telemetry on shutdown | `RSK-003; RSK-014` | `AC-CORE-004` |
| `REC-030` | Use Axum/Tokio/Tower/tower-http | `RSK-021; ADR-0001` | `AC-CORE-001` |
| `REC-031` | Implement request/correlation IDs | `RSK-005` | `AC-HTTP-001` |
| `REC-032` | Use structured request logging and trace propagation | `RSK-005; RSK-014` | `AC-OBS-002` |
| `REC-033` | Bound bodies, headers, URLs, concurrency, and timeouts | `RSK-005` | `AC-HTTP-003` |
| `REC-034` | Provide compression, CORS, panic boundaries, and security headers | `RSK-005` | `AC-HTTP-005` |
| `REC-035` | Trust forwarded headers only from trusted proxies | `RSK-005` | `AC-HTTP-004` |
| `REC-036` | Use a stable Problem Details error contract | `RSK-005` | `AC-HTTP-002` |
| `REC-037` | Define cursor pagination, filters, sorting, IDs, UTC timestamps, and API versioning | `RSK-005` | `AC-HTTP-006` |
| `REC-038` | Support idempotency keys and optimistic concurrency | `RSK-005; RSK-006` | `AC-HTTP-007` |
| `REC-039` | Create canonical request context with principal and tenant | `RSK-001; RSK-005` | `AC-AUTH-009` |
| `REC-040` | Separate liveness, readiness, startup, diagnostics, and version endpoints | `RSK-014` | `AC-OBS-004` |
| `REC-041` | Reuse configured outbound HTTP clients | `RSK-005; RSK-013` | `AC-HTTP-010` |
| `REC-042` | Set outbound connect/request/idle timeouts and safe retries | `RSK-005; RSK-013` | `AC-WEBHOOK-004` |
| `REC-043` | Configure PostgreSQL URL/TLS and pool lifecycle | `RSK-006` | `AC-DB-005` |
| `REC-044` | Set DB pool min/max/acquire/idle/lifetime and init statements | `RSK-006` | `AC-DB-005` |
| `REC-045` | Define statement/transaction timeout and retry policy | `RSK-006` | `AC-DB-007` |
| `REC-046` | Use migrations with a coordinated production policy | `RSK-006; RSK-017` | `AC-DB-002` |
| `REC-047` | Instrument queries and pool utilization | `RSK-006; RSK-014` | `AC-DB-005` |
| `REC-048` | Support test database creation and deterministic fixtures | `RSK-006; RSK-016` | `AC-DB-009` |
| `REC-049` | Plan read replicas, backups, and restore | `RSK-006; RSK-017` | `AC-DEPLOY-003` |
| `REC-050` | Support rolling expand/migrate/contract migrations | `RSK-006; RSK-017` | `AC-DB-004` |
| `REC-051` | Split Redis by cache, session, rate-limit, pubsub, lock, stream, and jobs | `RSK-007; RSK-002` | `AC-GEN-002` |
| `REC-052` | Use Redis reconnection, TLS, namespace, TTL, serialization, and metrics policies | `RSK-007` | `AC-REDIS-001` |
| `REC-053` | Define cache stampede, negative caching, and invalidation | `RSK-007` | `AC-REDIS-003` |
| `REC-054` | Define fail-open versus fail-closed per Redis use | `RSK-007` | `AC-REDIS-004` |
| `REC-055` | Do not add an async Redis pool without need | `RSK-007; RSK-021` | `AC-REDIS-001` |
| `REC-056` | Provide no-op, in-process, and Redis cache implementations | `RSK-007` | `AC-REDIS-002` |
| `REC-057` | Provide local and S3-compatible object storage plus streaming, checksums, signed URLs, and cleanup | `RSK-012` | `AC-STORAGE-001` |
| `REC-058` | Add upload filename/MIME/malware and authorization controls | `RSK-012` | `AC-STORAGE-002` |
| `REC-059` | Provide transactional outbox | `RSK-010` | `AC-JOB-003` |
| `REC-060` | Provide inbox/deduplication | `RSK-010` | `AC-JOB-004` |
| `REC-061` | Provide an idempotency store | `RSK-005; RSK-006` | `AC-HTTP-007` |
| `REC-062` | Use distributed locks only when truly required | `RSK-007` | `AC-REDIS-008` |
| `REC-063` | Provide optimistic concurrency and audit history | `RSK-005; RSK-009` | `AC-HTTP-008` |
| `REC-064` | Decompose auth into core, session, JWT, password, OIDC, API key, passkey, and authorization modules | `RSK-008; RSK-002` | `AC-GEN-002` |
| `REC-065` | Map every credential mechanism to one Principal | `RSK-008` | `AC-AUTH-009` |
| `REC-066` | Use server-side sessions for first-party browser apps | `RSK-008` | `AC-AUTH-001` |
| `REC-067` | Implement secure cookie, expiry, rotation, device list, revoke, cleanup, and CSRF | `RSK-008` | `AC-AUTH-002` |
| `REC-068` | Use JWT primarily as a resource-server verifier | `RSK-008` | `AC-AUTH-006` |
| `REC-069` | Validate JWT algorithm/signature/issuer/audience/time/JWKS and token class | `RSK-008` | `AC-AUTH-006` |
| `REC-070` | Use short access tokens and rotating refresh tokens with reuse detection when self-issued | `RSK-008` | `AC-AUTH-007` |
| `REC-071` | Use Argon2id, PHC strings, rehash-on-login, and anti-enumeration | `RSK-008` | `AC-AUTH-003` |
| `REC-072` | Use random single-use hashed reset/verification tokens | `RSK-008` | `AC-AUTH-005` |
| `REC-073` | Use OIDC Authorization Code + PKCE, state, nonce, discovery, and safe linking | `RSK-008` | `AC-AUTH-008` |
| `REC-074` | Provide API key prefixes, hashes, scopes, expiry, rotation, last-used, revocation, and audit | `RSK-008` | `AC-AUTH-010` |
| `REC-075` | Support passkeys/WebAuthn as an optional module | `RSK-008` | `AC-AUTH-011` |
| `REC-076` | Keep authentication and authorization separate | `RSK-008; RSK-009` | `AC-AUTHZ-001` |
| `REC-077` | Authorize principal/action/resource/context at application boundary | `RSK-009` | `AC-AUTHZ-001` |
| `REC-078` | Start with RBAC, ownership, tenant membership, and default deny | `RSK-009` | `AC-AUTHZ-002` |
| `REC-079` | Offer Cedar for complex RBAC/ABAC/ReBAC | `RSK-009` | `AC-AUTHZ-005` |
| `REC-080` | Test horizontal, vertical, cross-tenant, list, bulk, and stale-claim access | `RSK-009; RSK-016` | `AC-AUTHZ-003` |
| `REC-081` | WebSocket upgrade auth, origin, frame limits, heartbeat, revalidation, and connection limits | `RSK-011` | `AC-RT-001` |
| `REC-082` | Authorize every WebSocket subscription and command | `RSK-011` | `AC-RT-002` |
| `REC-083` | Use bounded realtime queues and slow-consumer handling | `RSK-011` | `AC-RT-003` |
| `REC-084` | Support reconnect/resume only with real replay storage | `RSK-011` | `AC-RT-006` |
| `REC-085` | Separate domain events from WebSocket transport and include SSE | `RSK-011` | `AC-RT-005` |
| `REC-086` | Provide durable jobs with versioning, retry, timeout, dedupe, priority, scheduling, dead-letter, lease, metrics, and drain | `RSK-010` | `AC-JOB-005` |
| `REC-087` | Use an established job crate/backend rather than custom queue | `RSK-010; RSK-021` | `AC-JOB-001` |
| `REC-088` | Support in-process, Redis, Postgres outbox, NATS, and optional Kafka event adapters by explicit semantics | `RSK-010` | `AC-JOB-008` |
| `REC-089` | Standardize event ID/type/version/time/producer/tenant/correlation/causation/trace/idempotency | `RSK-010` | `AC-JOB-009` |
| `REC-090` | Define scheduler leader, misfire, and catch-up behavior | `RSK-010` | `AC-JOB-007` |
| `REC-091` | Provide signed/replay-protected outbound webhooks with retries, rotation, logs, replay, suspension, and SSRF protection | `RSK-013` | `AC-WEBHOOK-001` |
| `REC-092` | Verify inbound raw-body signatures before parsing and process asynchronously | `RSK-013` | `AC-WEBHOOK-002` |
| `REC-093` | Provide organizations/tenancy | `RSK-009; RSK-018` | `AC-AUTHZ-003` |
| `REC-094` | Provide append-only audit | `RSK-009` | `AC-AUTHZ-007` |
| `REC-095` | Provide protected admin/support and audited impersonation | `RSK-009; RSK-018` | `AC-AUTHZ-008` |
| `REC-096` | Provide email/notifications with providers, templates, retries, preferences, and unsubscribe | `RSK-012` | `AC-MAIL-002` |
| `REC-097` | Provide billing/entitlements with webhook reconciliation and grace policy | `RSK-018` | `AC-WEBHOOK-002` |
| `REC-098` | Provide feature flags by environment/tenant/user/cohort | `RSK-018` | `AC-OPT-001` |
| `REC-099` | Provide versioned derived search and backfills | `RSK-018` | `AC-OPT-002` |
| `REC-100` | Provide optional GraphQL with limits/loaders/authz | `RSK-018` | `AC-OPT-003` |
| `REC-101` | Provide optional gRPC with interceptors/deadlines/health | `RSK-018` | `AC-OPT-003` |
| `REC-102` | Provide localization, time zone, and currency handling | `RSK-018` | `AC-OPT-004` |
| `REC-103` | Provide data export/deletion/retention/anonymization/legal hold | `RSK-018` | `AC-OPT-004` |
| `REC-104` | Provide consent/legal records | `RSK-018` | `AC-OPT-004` |
| `REC-105` | Provide moderation reports/actions/appeals/evidence | `RSK-018` | `AC-AUTHZ-001` |
| `REC-106` | Make OpenAPI generation/validation first-class | `RSK-005` | `AC-HTTP-009` |
| `REC-107` | Separate boundary validation from domain invariants | `RSK-005` | `AC-HTTP-002` |
| `REC-108` | Use structured tracing with JSON production and human local logs | `RSK-014` | `AC-OBS-001` |
| `REC-109` | Propagate OpenTelemetry and redact PII/secrets | `RSK-014` | `AC-OBS-002` |
| `REC-110` | Provide HTTP/DB/Redis/outbound/jobs/realtime/auth/authz/process metrics | `RSK-014` | `AC-OBS-003` |
| `REC-111` | Rate-limit by IP/account/tenant/API key/route/auth state | `RSK-007` | `AC-REDIS-006` |
| `REC-112` | Provide multi-stage non-root container, resource limits, trusted proxy, migration deployment, separate roles, SBOM/provenance | `RSK-017; RSK-015` | `AC-DEPLOY-001` |
| `REC-113` | Provide operational executable modes for server/worker/scheduler/migrate/seed/backfill/reindex/replay/inspect | `RSK-001; RSK-017` | `AC-DEPLOY-002` |
| `REC-114` | Run fmt, clippy, tests, audit, deny, vet, semver, and SBOM checks | `RSK-015; RSK-016` | `AC-SEC-001` |
| `REC-115` | Build test architecture with unit, HTTP, real infra, authz, auth, realtime, job, contract, property, fuzz, and load tests | `RSK-016` | `AC-TEST-002` |
| `REC-116` | Use deterministic clock, IDs, random, and provider fakes | `RSK-016` | `AC-TEST-001` |
| `REC-117` | Test named profiles and pairwise combinations, not only all-features | `RSK-016; RSK-019` | `AC-TEST-001` |
| `REC-118` | Provide minimal/api/authenticated-api/saas/realtime/worker/full profiles | `RSK-019` | `AC-GEN-001` |
| `REC-119` | Use cargo-generate for initial templating and xtask for ongoing management | `RSK-002; RSK-021` | `AC-GEN-001` |
| `REC-120` | Avoid abstracting every database/provider behind lowest-common-denominator traits | `RSK-001; RSK-002` | `AC-GEN-001` |
| `REC-121` | Use traits only for genuinely volatile integrations | `RSK-002` | `AC-GEN-001` |
| `REC-122` | Do not pretend WebSockets, Socket.IO, SSE, and queues share transport semantics | `RSK-011` | `AC-RT-006` |
| `REC-123` | Adopt the researched baseline of Tokio/Axum/Tower/SQLx/Redis/sessions/JWT/Argon2/tracing/utoipa/garde/reqwest/testing/security tools | `RSK-021` | `AC-SEC-002` |
| `REC-124` | Implement in ordered phases and prove boundaries in reference applications before freezing generator | `RSK-020; RSK-023` | `AC-GEN-004` |

**Coverage:** 124 recommendations; 0 intentionally omitted.
