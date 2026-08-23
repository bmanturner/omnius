---
spec_id: RSK-023
title: Autonomous Agent Task Graph
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Autonomous Agent Task Graph


Tasks are dependency-ordered. A task is complete only when its acceptance criterion and relevant profile commands pass.

| Task | Phase | Work | Depends on | Required output | Acceptance |
|---|---:|---|---|---|---|
| `T000` | 0 | Create repository/workspace skeleton | — | workspace manifests, rust-toolchain, CI stub | `AC-REPO-001` |
| `T001` | 0 | Resolve and record foundational dependency graph | T000 | compatibility workspace, cargo tree report, lockfile | `AC-DB-001` |
| `T002` | 0 | Resolve axum-login/tower-sessions/store stack | T001 | auth compatibility report | `AC-AUTH-009` |
| `T003` | 0 | Spike Apalis Redis and PGMQ providers | T001 | provider compatibility report and ADR | `AC-JOB-001` |
| `T004` | 0 | Install dependency policy and supply-chain tooling | T001 | deny.toml, vet config, audit/SBOM CI | `AC-SEC-001` |
| `T005` | 0 | Implement spec/profile/catalog validators | T000 | xtask specs/profiles verify | `AC-GEN-005` |
| `T010` | 1 | Implement core IDs, clock, errors, build metadata | T001 | core crate | `AC-CORE-006` |
| `T011` | 1 | Implement layered config and secret wrappers | T010 | config crate and examples | `AC-CFG-001` |
| `T012` | 1 | Implement telemetry bootstrap | T010;T011 | tracing/metrics initialization | `AC-OBS-001` |
| `T013` | 1 | Implement runtime supervisor and cancellation | T010;T012 | runtime supervisor | `AC-CORE-004` |
| `T014` | 1 | Implement HTTP shell and middleware order | T010;T013 | Axum router shell | `AC-HTTP-003` |
| `T015` | 1 | Implement Problem Details and request IDs | T014 | error mapping/request ID | `AC-HTTP-002` |
| `T016` | 1 | Implement probes, readiness cache, and drain | T013;T014 | health endpoints and shutdown | `AC-OBS-004` |
| `T017` | 1 | Complete minimal reference service | T011;T012;T015;T016 | minimal profile app | `AC-CORE-001` |
| `T020` | 2 | Build deterministic test-support crate | T010 | clock, IDs, principals, config builders | `AC-TEST-001` |
| `T021` | 2 | Install nextest and test groups | T004;T020 | nextest config | `AC-TEST-001` |
| `T022` | 2 | Build Testcontainers harness | T020 | container lifecycle and readiness | `AC-TEST-002` |
| `T023` | 2 | Build Wiremock/provider fake harness | T020 | HTTP contract test tools | `AC-TEST-002` |
| `T024` | 2 | Build profile-generation test harness | T005;T021 | clean-directory profile tests | `AC-GEN-001` |
| `T030` | 3 | Implement SQLx PostgreSQL pool and health | T022;T016 | postgres module | `AC-DB-005` |
| `T031` | 3 | Implement migration command and compatibility checks | T030 | migration runner/status | `AC-DB-002` |
| `T032` | 3 | Implement reference domain and checked queries | T030;T031 | CRUD domain/persistence | `AC-DB-006` |
| `T033` | 3 | Implement transaction and transient retry helpers | T032 | transaction services | `AC-DB-007` |
| `T034` | 3 | Implement idempotency and optimistic concurrency | T032;T033 | idempotency/ETag modules | `AC-HTTP-007` |
| `T035` | 3 | Implement cursor pagination and validation | T032 | pagination contracts | `AC-HTTP-006` |
| `T036` | 3 | Implement OpenAPI and outbound HTTP policies | T014;T015 | OpenAPI/reqwest module | `AC-HTTP-009` |
| `T037` | 3 | Complete API reference/profile | T031;T034;T035;T036 | api profile | `AC-DB-004` |
| `T040` | 4 | Implement identity schema and canonical Principal | T031 | identity core | `AC-AUTH-009` |
| `T041` | 4 | Implement password, verification, and recovery | T040 | password flows | `AC-AUTH-003` |
| `T042` | 4 | Implement sessions, cookie policy, CSRF, lifecycle | T002;T040;T041 | session auth | `AC-AUTH-001` |
| `T043` | 4 | Implement JWT/JWKS verification | T040;T023 | bearer auth | `AC-AUTH-006` |
| `T044` | 4 | Implement OIDC client/account linking | T040;T023 | OIDC adapter | `AC-AUTH-008` |
| `T045` | 4 | Implement API keys/service accounts | T040 | API key module | `AC-AUTH-010` |
| `T046` | 4 | Implement optional WebAuthn and TOTP | T040;T041 | MFA modules | `AC-AUTH-011` |
| `T047` | 4 | Complete authenticated API profile | T042;T043;T045 | authenticated profile | `AC-AUTH-002` |
| `T050` | 5 | Implement built-in authorization provider | T040 | authorization service | `AC-AUTHZ-002` |
| `T051` | 5 | Implement organizations/memberships/tenant context | T050;T031 | tenant module | `AC-AUTHZ-003` |
| `T052` | 5 | Implement audit log and security event sink | T050;T031 | audit module | `AC-AUTHZ-007` |
| `T053` | 5 | Implement protected admin and impersonation | T051;T052 | admin module | `AC-AUTHZ-008` |
| `T054` | 5 | Implement optional Cedar provider | T050 | Cedar adapter | `AC-AUTHZ-005` |
| `T055` | 5 | Run cross-transport authorization matrix | T050;T051;T052 | authorization conformance | `AC-AUTHZ-001` |
| `T060` | 6 | Implement Redis core and health | T001;T022 | Redis module | `AC-REDIS-001` |
| `T061` | 6 | Implement Moka/Redis/no-op cache | T060 | cache providers | `AC-REDIS-002` |
| `T062` | 6 | Implement local rate limits | T060;T014 | governor layers | `AC-REDIS-006` |
| `T063` | 6 | Implement optional Redis session store | T002;T060;T042 | session provider variant | `AC-REDIS-005` |
| `T064` | 6 | Implement Redis ephemeral pubsub | T060 | fan-out provider | `AC-REDIS-004` |
| `T070` | 7 | Implement typed job/event interfaces | T033 | jobs core | `AC-JOB-002` |
| `T071` | 7 | Implement transactional outbox/inbox | T070;T031 | outbox/inbox | `AC-JOB-003` |
| `T072` | 7 | Implement Apalis Redis job provider | T003;T060;T070 | Redis jobs | `AC-JOB-005` |
| `T073` | 7 | Implement optional PGMQ provider if gate passed | T003;T070 | PGMQ jobs | `AC-JOB-001` |
| `T074` | 7 | Implement scheduler and leases | T070;T071 | scheduler | `AC-JOB-007` |
| `T075` | 7 | Implement NATS JetStream provider | T070;T022 | NATS events | `AC-JOB-008` |
| `T076` | 7 | Implement worker/admin diagnostics and drain | T072;T074;T016 | worker profile | `AC-JOB-006` |
| `T080` | 8 | Define realtime protocol and registry | T040;T050 | realtime core | `AC-RT-002` |
| `T081` | 8 | Implement SSE | T080 | SSE adapter | `AC-RT-006` |
| `T082` | 8 | Implement WebSocket upgrade/message lifecycle | T080;T014 | WebSocket adapter | `AC-RT-001` |
| `T083` | 8 | Implement Redis/NATS fan-out providers | T064;T075;T080 | multi-instance fan-out | `AC-RT-005` |
| `T084` | 8 | Implement bounded queues, slow-consumer, drain | T082;T083 | backpressure/drain | `AC-RT-003` |
| `T090` | 9 | Implement object_store port/providers | T022;T051 | object storage | `AC-STORAGE-001` |
| `T091` | 9 | Implement upload quarantine/scanner/reconciliation | T090;T070 | upload workflow | `AC-STORAGE-002` |
| `T092` | 9 | Implement lettre/MiniJinja email module | T023;T070 | email adapter/templates | `AC-MAIL-001` |
| `T093` | 9 | Implement notification preferences/orchestration | T051;T052;T092 | notification module | `AC-MAIL-003` |
| `T094` | 9 | Implement Svix outbound adapter | T071;T023 | webhook delivery adapter | `AC-WEBHOOK-001` |
| `T095` | 9 | Implement inbound webhook framework | T071;T023 | signature/replay/inbox | `AC-WEBHOOK-002` |
| `T096` | 9 | Implement centralized SSRF/outbound policy | T036;T023 | URL policy | `AC-WEBHOOK-003` |
| `T100` | 10 | Implement OpenFeature provider interface | T011 | feature flags | `AC-OPT-001` |
| `T101` | 10 | Implement search projection provider | T071;T051 | search module | `AC-OPT-002` |
| `T102` | 10 | Implement billing/entitlement skeleton and reconciliation | T052;T095 | billing module | `AC-WEBHOOK-002` |
| `T103` | 10 | Implement optional GraphQL adapter | T050;T014 | GraphQL module | `AC-OPT-003` |
| `T104` | 10 | Implement optional tonic gRPC adapter | T050;T013 | gRPC module | `AC-OPT-003` |
| `T105` | 10 | Implement localization module | T011 | Fluent module | `AC-OPT-004` |
| `T106` | 10 | Implement privacy lifecycle/consent/moderation contracts | T051;T052;T070 | product modules | `AC-OPT-004` |
| `T110` | 11 | Implement cargo-generate base template | T017;T037;T047 | initial template | `AC-GEN-001` |
| `T111` | 11 | Implement module add/remove/doctor/diff | T005;T110 | xtask module manager | `AC-GEN-002` |
| `T112` | 11 | Implement managed-region ownership enforcement | T111 | safe generator edits | `AC-GEN-003` |
| `T113` | 11 | Implement upgrade engine and rehearsals | T112 | upgrade command/tests | `AC-GEN-004` |
| `T114` | 11 | Generate and verify every profile | T113 | profile fixtures | `AC-GEN-001` |
| `T120` | 12 | Run load, soak, and failure suite | T114 | performance/failure reports | `AC-TEST-003` |
| `T121` | 12 | Complete security/supply-chain review | T114;T004 | security report, vetted graph | `AC-SEC-002` |
| `T122` | 12 | Complete deployment/runbooks/recovery rehearsal | T114 | deployment artifacts/runbooks | `AC-DEPLOY-003` |
| `T123` | 12 | Complete traceability and release artifacts | T120;T121;T122 | SBOM, provenance, signed bundle | `AC-SEC-003` |

## Parallelism guidance

- Documentation, threat modeling, and test design may proceed alongside code after their interfaces are fixed.
- Provider spikes may run in parallel in Phase 0.
- Do not parallelize multiple changes to the composition root or generator manifests without serialized integration.
- A dependent phase may prepare tests but cannot merge production wiring before prerequisites pass.
- Every phase ends with a generated clean-directory profile run, not only workspace tests.
