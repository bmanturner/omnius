---
spec_id: OMNIUS-022
title: Recommendation Traceability
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Recommendation Traceability


This matrix verifies that every substantive recommendation in the original design is represented in a normative specification and a concrete acceptance criterion.

| ID | Recommendation | Specification | Verification |
|---|---|---|---|
| `REC-001` | Use workspace-level explicit composition instead of one enormous feature matrix | `OMNIUS-001; OMNIUS-002` | `AC-GEN-001` |
| `REC-002` | Reserve Cargo features for additive implementation details | `OMNIUS-002` | `AC-GEN-005` |
| `REC-003` | Provide generated profiles, workspace crates, runtime config, and product flags as distinct toggle mechanisms | `OMNIUS-002; OMNIUS-019` | `AC-GEN-001` |
| `REC-004` | Use meaningful crate boundaries rather than one crate per table | `OMNIUS-001` | `AC-GEN-001` |
| `REC-005` | Define module dependencies and conflicts | `OMNIUS-002` | `AC-GEN-002` |
| `REC-006` | Define configuration and validation per module | `OMNIUS-002; OMNIUS-004` | `AC-CFG-005` |
| `REC-007` | Define initialization and startup ordering per module | `OMNIUS-002; OMNIUS-003` | `AC-CORE-002` |
| `REC-008` | Define routes, middleware, and extractors per module | `OMNIUS-002; OMNIUS-005` | `AC-GEN-001` |
| `REC-009` | Expose typed application capabilities rather than raw optional state | `OMNIUS-001; OMNIUS-002` | `AC-GEN-001` |
| `REC-010` | Supervise module background tasks | `OMNIUS-002; OMNIUS-003` | `AC-CORE-004` |
| `REC-011` | Register module liveness/readiness behavior | `OMNIUS-002; OMNIUS-014` | `AC-OBS-004` |
| `REC-012` | Register module metrics and trace attributes | `OMNIUS-002; OMNIUS-014` | `AC-OBS-002` |
| `REC-013` | Participate in graceful shutdown | `OMNIUS-002; OMNIUS-003` | `AC-CORE-004` |
| `REC-014` | Supply module test fixtures and fakes | `OMNIUS-002; OMNIUS-016` | `AC-TEST-002` |
| `REC-015` | Document failure semantics and criticality | `OMNIUS-001; OMNIUS-014` | `AC-OBS-004` |
| `REC-016` | Distinguish required, degraded, and best-effort dependencies | `OMNIUS-001; OMNIUS-014` | `AC-OBS-004` |
| `REC-017` | Avoid a global AppState full of Option handles | `OMNIUS-001` | `AC-GEN-001` |
| `REC-018` | Use source-level modules, not a dynamic Rust plugin ABI | `OMNIUS-001; OMNIUS-002` | `AC-GEN-001` |
| `REC-019` | Layer typed configuration sources | `OMNIUS-004` | `AC-CFG-001` |
| `REC-020` | Strictly validate config at startup | `OMNIUS-004` | `AC-CFG-002` |
| `REC-021` | Separate local/test/staging/production configuration | `OMNIUS-004` | `AC-CFG-003` |
| `REC-022` | Protect secrets from Debug and diagnostics | `OMNIUS-004; OMNIUS-015` | `AC-CFG-004` |
| `REC-023` | Expose build version, revision, and environment metadata | `OMNIUS-003` | `AC-CORE-006` |
| `REC-024` | Detect unknown/misspelled configuration keys | `OMNIUS-004` | `AC-CFG-002` |
| `REC-025` | Order initialization and fail fast | `OMNIUS-003` | `AC-CORE-002` |
| `REC-026` | Implement startup timeout and signal handling | `OMNIUS-003` | `AC-CORE-004` |
| `REC-027` | Propagate cancellation and track tasks | `OMNIUS-003` | `AC-CORE-004` |
| `REC-028` | Drain HTTP, WebSocket, and worker workloads gracefully | `OMNIUS-003; OMNIUS-010; OMNIUS-011` | `AC-CORE-004` |
| `REC-029` | Flush telemetry on shutdown | `OMNIUS-003; OMNIUS-014` | `AC-CORE-004` |
| `REC-030` | Use Axum/Tokio/Tower/tower-http | `OMNIUS-021; ADR-0001` | `AC-CORE-001` |
| `REC-031` | Implement request/correlation IDs | `OMNIUS-005` | `AC-HTTP-001` |
| `REC-032` | Use structured request logging and trace propagation | `OMNIUS-005; OMNIUS-014` | `AC-OBS-002` |
| `REC-033` | Bound bodies, headers, URLs, concurrency, and timeouts | `OMNIUS-005` | `AC-HTTP-003` |
| `REC-034` | Provide compression, CORS, panic boundaries, and security headers | `OMNIUS-005` | `AC-HTTP-005` |
| `REC-035` | Trust forwarded headers only from trusted proxies | `OMNIUS-005` | `AC-HTTP-004` |
| `REC-036` | Use a stable Problem Details error contract | `OMNIUS-005` | `AC-HTTP-002` |
| `REC-037` | Define cursor pagination, filters, sorting, IDs, UTC timestamps, and API versioning | `OMNIUS-005` | `AC-HTTP-006` |
| `REC-038` | Support idempotency keys and optimistic concurrency | `OMNIUS-005; OMNIUS-006` | `AC-HTTP-007` |
| `REC-039` | Create canonical request context with principal and tenant | `OMNIUS-001; OMNIUS-005` | `AC-AUTH-009` |
| `REC-040` | Separate liveness, readiness, startup, diagnostics, and version endpoints | `OMNIUS-014` | `AC-OBS-004` |
| `REC-041` | Reuse configured outbound HTTP clients | `OMNIUS-005; OMNIUS-013` | `AC-HTTP-010` |
| `REC-042` | Set outbound connect/request/idle timeouts and safe retries | `OMNIUS-005; OMNIUS-013` | `AC-WEBHOOK-004` |
| `REC-043` | Configure PostgreSQL URL/TLS and pool lifecycle | `OMNIUS-006` | `AC-DB-005` |
| `REC-044` | Set DB pool min/max/acquire/idle/lifetime and init statements | `OMNIUS-006` | `AC-DB-005` |
| `REC-045` | Define statement/transaction timeout and retry policy | `OMNIUS-006` | `AC-DB-007` |
| `REC-046` | Use migrations with a coordinated production policy | `OMNIUS-006; OMNIUS-017` | `AC-DB-002` |
| `REC-047` | Instrument queries and pool utilization | `OMNIUS-006; OMNIUS-014` | `AC-DB-005` |
| `REC-048` | Support test database creation and deterministic fixtures | `OMNIUS-006; OMNIUS-016` | `AC-DB-009` |
| `REC-049` | Plan read replicas, backups, and restore | `OMNIUS-006; OMNIUS-017` | `AC-DEPLOY-003` |
| `REC-050` | Support rolling expand/migrate/contract migrations | `OMNIUS-006; OMNIUS-017` | `AC-DB-004` |
| `REC-051` | Split Redis by cache, session, rate-limit, pubsub, lock, stream, and jobs | `OMNIUS-007; OMNIUS-002` | `AC-GEN-002` |
| `REC-052` | Use Redis reconnection, TLS, namespace, TTL, serialization, and metrics policies | `OMNIUS-007` | `AC-REDIS-001` |
| `REC-053` | Define cache stampede, negative caching, and invalidation | `OMNIUS-007` | `AC-REDIS-003` |
| `REC-054` | Define fail-open versus fail-closed per Redis use | `OMNIUS-007` | `AC-REDIS-004` |
| `REC-055` | Do not add an async Redis pool without need | `OMNIUS-007; OMNIUS-021` | `AC-REDIS-001` |
| `REC-056` | Provide no-op, in-process, and Redis cache implementations | `OMNIUS-007` | `AC-REDIS-002` |
| `REC-057` | Provide local and S3-compatible object storage plus streaming, checksums, signed URLs, and cleanup | `OMNIUS-012` | `AC-STORAGE-001` |
| `REC-058` | Add upload filename/MIME/malware and authorization controls | `OMNIUS-012` | `AC-STORAGE-002` |
| `REC-059` | Provide transactional outbox | `OMNIUS-010` | `AC-JOB-003` |
| `REC-060` | Provide inbox/deduplication | `OMNIUS-010` | `AC-JOB-004` |
| `REC-061` | Provide an idempotency store | `OMNIUS-005; OMNIUS-006` | `AC-HTTP-007` |
| `REC-062` | Use distributed locks only when truly required | `OMNIUS-007` | `AC-REDIS-008` |
| `REC-063` | Provide optimistic concurrency and audit history | `OMNIUS-005; OMNIUS-009` | `AC-HTTP-008` |
| `REC-064` | Decompose auth into core, session, JWT, password, OIDC, API key, passkey, and authorization modules | `OMNIUS-008; OMNIUS-002` | `AC-GEN-002` |
| `REC-065` | Map every credential mechanism to one Principal | `OMNIUS-008` | `AC-AUTH-009` |
| `REC-066` | Use server-side sessions for first-party browser apps | `OMNIUS-008` | `AC-AUTH-001` |
| `REC-067` | Implement secure cookie, expiry, rotation, device list, revoke, cleanup, and CSRF | `OMNIUS-008` | `AC-AUTH-002` |
| `REC-068` | Use JWT primarily as a resource-server verifier | `OMNIUS-008` | `AC-AUTH-006` |
| `REC-069` | Validate JWT algorithm/signature/issuer/audience/time/JWKS and token class | `OMNIUS-008` | `AC-AUTH-006` |
| `REC-070` | Use short access tokens and rotating refresh tokens with reuse detection when self-issued | `OMNIUS-008` | `AC-AUTH-007` |
| `REC-071` | Use Argon2id, PHC strings, rehash-on-login, and anti-enumeration | `OMNIUS-008` | `AC-AUTH-003` |
| `REC-072` | Use random single-use hashed reset/verification tokens | `OMNIUS-008` | `AC-AUTH-005` |
| `REC-073` | Use OIDC Authorization Code + PKCE, state, nonce, discovery, and safe linking | `OMNIUS-008` | `AC-AUTH-008` |
| `REC-074` | Provide API key prefixes, hashes, scopes, expiry, rotation, last-used, revocation, and audit | `OMNIUS-008` | `AC-AUTH-010` |
| `REC-075` | Support passkeys/WebAuthn as an optional module | `OMNIUS-008` | `AC-AUTH-011` |
| `REC-076` | Keep authentication and authorization separate | `OMNIUS-008; OMNIUS-009` | `AC-AUTHZ-001` |
| `REC-077` | Authorize principal/action/resource/context at application boundary | `OMNIUS-009` | `AC-AUTHZ-001` |
| `REC-078` | Start with RBAC, ownership, tenant membership, and default deny | `OMNIUS-009` | `AC-AUTHZ-002` |
| `REC-079` | Offer Cedar for complex RBAC/ABAC/ReBAC | `OMNIUS-009` | `AC-AUTHZ-005` |
| `REC-080` | Test horizontal, vertical, cross-tenant, list, bulk, and stale-claim access | `OMNIUS-009; OMNIUS-016` | `AC-AUTHZ-003` |
| `REC-081` | WebSocket upgrade auth, origin, frame limits, heartbeat, revalidation, and connection limits | `OMNIUS-011` | `AC-RT-001` |
| `REC-082` | Authorize every WebSocket subscription and command | `OMNIUS-011` | `AC-RT-002` |
| `REC-083` | Use bounded realtime queues and slow-consumer handling | `OMNIUS-011` | `AC-RT-003` |
| `REC-084` | Support reconnect/resume only with real replay storage | `OMNIUS-011` | `AC-RT-006` |
| `REC-085` | Separate domain events from WebSocket transport and include SSE | `OMNIUS-011` | `AC-RT-005` |
| `REC-086` | Provide durable jobs with versioning, retry, timeout, dedupe, priority, scheduling, dead-letter, lease, metrics, and drain | `OMNIUS-010` | `AC-JOB-005` |
| `REC-087` | Use an established job crate/backend rather than custom queue | `OMNIUS-010; OMNIUS-021` | `AC-JOB-001` |
| `REC-088` | Support in-process, Redis, Postgres outbox, NATS, and optional Kafka event adapters by explicit semantics | `OMNIUS-010` | `AC-JOB-008` |
| `REC-089` | Standardize event ID/type/version/time/producer/tenant/correlation/causation/trace/idempotency | `OMNIUS-010` | `AC-JOB-009` |
| `REC-090` | Define scheduler leader, misfire, and catch-up behavior | `OMNIUS-010` | `AC-JOB-007` |
| `REC-091` | Provide signed/replay-protected outbound webhooks with retries, rotation, logs, replay, suspension, and SSRF protection | `OMNIUS-013` | `AC-WEBHOOK-001` |
| `REC-092` | Verify inbound raw-body signatures before parsing and process asynchronously | `OMNIUS-013` | `AC-WEBHOOK-002` |
| `REC-093` | Provide organizations/tenancy | `OMNIUS-009; OMNIUS-018` | `AC-AUTHZ-003` |
| `REC-094` | Provide append-only audit | `OMNIUS-009` | `AC-AUTHZ-007` |
| `REC-095` | Provide protected admin/support and audited impersonation | `OMNIUS-009; OMNIUS-018` | `AC-AUTHZ-008` |
| `REC-096` | Provide email/notifications with providers, templates, retries, preferences, and unsubscribe | `OMNIUS-012` | `AC-MAIL-002` |
| `REC-097` | Provide billing/entitlements with webhook reconciliation and grace policy | `OMNIUS-018` | `AC-WEBHOOK-002` |
| `REC-098` | Provide feature flags by environment/tenant/user/cohort | `OMNIUS-018` | `AC-OPT-001` |
| `REC-099` | Provide versioned derived search and backfills | `OMNIUS-018` | `AC-OPT-002` |
| `REC-100` | Provide optional GraphQL with limits/loaders/authz | `OMNIUS-018` | `AC-OPT-003` |
| `REC-101` | Provide optional gRPC with interceptors/deadlines/health | `OMNIUS-018` | `AC-OPT-003` |
| `REC-102` | Provide localization, time zone, and currency handling | `OMNIUS-018` | `AC-OPT-004` |
| `REC-103` | Provide data export/deletion/retention/anonymization/legal hold | `OMNIUS-018` | `AC-OPT-004` |
| `REC-104` | Provide consent/legal records | `OMNIUS-018` | `AC-OPT-004` |
| `REC-105` | Provide moderation reports/actions/appeals/evidence | `OMNIUS-018` | `AC-AUTHZ-001` |
| `REC-106` | Make OpenAPI generation/validation first-class | `OMNIUS-005` | `AC-HTTP-009` |
| `REC-107` | Separate boundary validation from domain invariants | `OMNIUS-005` | `AC-HTTP-002` |
| `REC-108` | Use structured tracing with JSON production and human local logs | `OMNIUS-014` | `AC-OBS-001` |
| `REC-109` | Propagate OpenTelemetry and redact PII/secrets | `OMNIUS-014` | `AC-OBS-002` |
| `REC-110` | Provide HTTP/DB/Redis/outbound/jobs/realtime/auth/authz/process metrics | `OMNIUS-014` | `AC-OBS-003` |
| `REC-111` | Rate-limit by IP/account/tenant/API key/route/auth state | `OMNIUS-007` | `AC-REDIS-006` |
| `REC-112` | Provide multi-stage non-root container, resource limits, trusted proxy, migration deployment, separate roles, SBOM/provenance | `OMNIUS-017; OMNIUS-015` | `AC-DEPLOY-001` |
| `REC-113` | Provide operational executable modes for server/worker/scheduler/migrate/seed/backfill/reindex/replay/inspect | `OMNIUS-001; OMNIUS-017` | `AC-DEPLOY-002` |
| `REC-114` | Run fmt, clippy, tests, audit, deny, vet, semver, and SBOM checks | `OMNIUS-015; OMNIUS-016` | `AC-SEC-001` |
| `REC-115` | Build test architecture with unit, HTTP, real infra, authz, auth, realtime, job, contract, property, fuzz, and load tests | `OMNIUS-016` | `AC-TEST-002` |
| `REC-116` | Use deterministic clock, IDs, random, and provider fakes | `OMNIUS-016` | `AC-TEST-001` |
| `REC-117` | Test named profiles and pairwise combinations, not only all-features | `OMNIUS-016; OMNIUS-019` | `AC-TEST-001` |
| `REC-118` | Provide minimal/api/authenticated-api/saas/realtime/worker/full profiles | `OMNIUS-019` | `AC-GEN-001` |
| `REC-119` | Use cargo-generate for initial templating and xtask for ongoing management | `OMNIUS-002; OMNIUS-021` | `AC-GEN-001` |
| `REC-120` | Avoid abstracting every database/provider behind lowest-common-denominator traits | `OMNIUS-001; OMNIUS-002` | `AC-GEN-001` |
| `REC-121` | Use traits only for genuinely volatile integrations | `OMNIUS-002` | `AC-GEN-001` |
| `REC-122` | Do not pretend WebSockets, Socket.IO, SSE, and queues share transport semantics | `OMNIUS-011` | `AC-RT-006` |
| `REC-123` | Adopt the researched baseline of Tokio/Axum/Tower/SQLx/Redis/sessions/JWT/Argon2/tracing/utoipa/garde/reqwest/testing/security tools | `OMNIUS-021` | `AC-SEC-002` |
| `REC-124` | Implement in ordered phases and prove boundaries in reference applications before freezing generator | `OMNIUS-020; OMNIUS-023` | `AC-GEN-004` |

**Coverage:** 124 recommendations; 0 intentionally omitted.
