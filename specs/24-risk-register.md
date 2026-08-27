---
spec_id: OMNIUS-024
title: Risk Register
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Risk Register


Likelihood and impact are qualitative initial ratings. Owners are capability owners, not individual names.

| ID | Risk | Trigger/indicator | Impact | Likelihood | Mitigation | Owner |
|---|---|---|---:|---:|---|---|
| `R-001` | Foundational version drift` | A crate update introduces duplicate Tokio/Hyper/Axum/Tower/SQLx/rustls/OTel lines` | High` | High` | Central pins, grouped updates, cargo tree gate, compatibility spike` | Platform |
| `R-002` | SQLx 0.9 pressure` | Agent chooses newest SQLx despite session-store 0.8 compatibility` | High` | Medium` | ADR-0003, exact baseline, negative dependency test` | Persistence |
| `R-003` | Session stack mismatch` | axum-login, tower-sessions core, and store versions do not align` | High` | Medium` | Phase 0 miniature workspace; use re-exported compatible versions; block implementation` | Identity |
| `R-004` | Job backend immaturity` | Stable Apalis uses an older Redis line and emits future-incompatibility warnings; PostgreSQL alternatives may require prerelease or operational SQL` | High` | High` | ADR-0011 isolation and review deadline; PGMQ opt-in; block toolchain drift; no custom queue` | Async |
| `R-005` | Module combinatorial explosion` | Too many theoretically supported combinations` | High` | High` | Named profiles, provider slots, selected pairwise tests, reject unsupported combinations` | Platform |
| `R-006` | Cargo feature misuse` | Mutually exclusive architectures unified unexpectedly` | High` | Medium` | Workspace composition, features only additive, profile validator` | Platform |
| `R-007` | Generator overwrites app code` | Upgrade/add/remove mutates application-owned files` | Critical` | Low` | Ownership classes, managed IDs, dry-run, backup patch, corruption refusal, rehearsals` | Generator |
| `R-008` | Migration destroys data` | Module removal/down migration drops tables or breaks rolling deployment` | Critical` | Medium` | Forward-only history, expand/contract, no automatic data removal, migration CI` | Persistence |
| `R-009` | Global optional state` | Option-filled AppState hides missing capabilities and runtime failures` | Medium` | Medium` | Typed route state and compile-time composition` | Platform |
| `R-010` | Secret leakage` | Config/debug/error/telemetry/provider payload exposes credentials` | Critical` | Medium` | secrecy, redaction tests, sensitive header marking, bounded diagnostics` | Security |
| `R-011` | High-cardinality telemetry` | User/tenant/URL/error values overload metrics/traces` | High` | Medium` | Label allowlist, cardinality tests/budget, aggregate classes` | Observability |
| `R-012` | Probe storm` | Readiness checks synchronously hit all dependencies` | High` | Medium` | Cached async dependency status, no fan-out per probe` | Operations |
| `R-013` | Proxy spoofing` | Untrusted forwarded headers bypass IP policy or generate wrong URLs` | Critical` | Medium` | Trusted immediate-peer ranges, bounded parser, security tests` | HTTP |
| `R-014` | Auth protocol reinvention` | Agent writes JWT/OIDC/WebAuthn logic to resolve integration friction` | Critical` | Low` | Explicit prohibition, approved crates, stop condition` | Identity |
| `R-015` | Session fixation/CSRF` | Browser session controls are incomplete` | Critical` | Medium` | Rotation, __Host cookie, tower-http CSRF/origin protection, conformance tests` | Identity |
| `R-016` | Stale authorization claims` | Long-lived JWT roles/scopes outlive permission changes` | High` | Medium` | Short tokens, authoritative checks for sensitive actions, session/revocation linkage` | Authorization |
| `R-017` | Tenant leakage` | Query/cache/job/object/search path omits tenant scope` | Critical` | Medium` | Canonical tenant context, constraints, permission matrix, cross-store tests` | Tenancy |
| `R-018` | Cedar overuse` | Policy engine absorbs business invariants and becomes opaque` | Medium` | Medium` | Built-in provider default; Cedar optional; invariants remain code/DB` | Authorization |
| `R-019` | Cache becomes source of truth` | Failure/miss semantics corrupt correctness` | High` | Medium` | Explicit cache port/results, fail policy, authoritative reads` | Cache |
| `R-020` | Redis lock stale owner` | Simple lock allows irreversible duplicate work` | Critical` | Low` | No default locks; fencing/ADR; prefer constraints/idempotency/queue` | Cache |
| `R-021` | At-least-once side effects` | Job/event retry duplicates email/payment/webhook/business action` | Critical` | High` | Idempotency, outbox/inbox/effect records, provider idempotency keys` | Async |
| `R-022` | Unbounded realtime queues` | Slow clients consume memory` | Critical` | Medium` | Bounded queues, coalesce/resync/disconnect, load tests` | Realtime |
| `R-023` | Revoked realtime identity persists` | Long-lived connection keeps access after session/role change` | High` | Medium` | Periodic/revocation revalidation, subscription invalidation` | Realtime |
| `R-024` | SSRF/DNS rebinding` | Webhook or integration URL reaches metadata/internal network` | Critical` | Medium` | Central resolver/address checks, redirect recheck, egress policy, tests` | Integrations |
| `R-025` | Unsafe uploads` | Uploaded content is trusted by MIME/name or served executable` | Critical` | Medium` | Random keys, limits, checksum, quarantine, scanner hook, safe disposition` | Storage |
| `R-026` | Webhook platform scope creep` | Kit implements retries, signatures, logs, replay, endpoint management itself` | High` | Medium` | Svix default and local fake only` | Integrations |
| `R-027` | OpenTelemetry version churn` | OTel crates update out of sync` | Medium` | High` | Pin as one set, grouped update, export compatibility test` | Observability |
| `R-028` | Testcontainer flakiness` | Tests use sleeps, shared state, or leaked containers` | Medium` | Medium` | Readiness conditions, per-test isolation, nextest groups, deterministic clocks` | Quality |
| `R-029` | All-features false confidence` | Unified features compile but real profiles fail` | High` | High` | Generate/compile/test every named profile and invalid combinations` | Quality |
| `R-030` | Over-abstraction` | Generic repositories/providers erase useful behavior and slow development` | Medium` | High` | Require two implementations/real boundary; thin adapter rule` | Architecture |
| `R-031` | Under-abstraction at volatile providers` | Provider types leak through application services` | Medium` | Medium` | Narrow ports for external providers only` | Architecture |
| `R-032` | Supply-chain compromise` | Malicious/compromised dependency or build script enters graph` | Critical` | Low` | vet, deny, source policy, review proc macros/build scripts, provenance` | Security |
| `R-033` | Prerelese dependency default` | Agent adopts RC to get a feature` | High` | Medium` | Prerelease gate and ADR; experimental profile only` | Security |
| `R-034` | Config hot reload partial state` | Security settings reload inconsistently` | High` | Low` | Very limited reload; atomic module support only` | Configuration |
| `R-035` | Backup exists but restore fails` | Operational assumptions not rehearsed` | Critical` | Medium` | Scheduled restore rehearsal and explicit RPO/RTO` | Operations |
| `R-036` | Reference profile becomes production recommendation` | Full composition carries unnecessary attack surface` | Medium` | Medium` | Label full-reference as CI/demo only; profile docs` | Platform |
| `R-037` | Specification task acceptance drift` | A task criterion requires capabilities implemented only by its descendants` | High` | Low` | Validate task-to-criterion phase ownership; correct mappings through an accepted ADR` | Platform |
| `R-038` | Inactive locked dependency advisory becomes reachable` | A feature or target adds an active path to `rsa 0.9.10` while RUSTSEC-2023-0071 is ignored` | Critical` | Low` | ADR-0012; all-target reachability gate; PostgreSQL-only SQLx; Security-owned exception expiring 2026-11-23` | Security |
| `R-039` | OIDC public verification depends on an RSA release with a private-key timing advisory` | Workspace code adds private RSA operations, an unapproved active path, or the exception passes its review date` | Critical` | Low` | ADR-0015; public-key verification only; dependency-path gate; Security-owned exception expiring 2026-11-23` | Security |

## Risk handling

- Critical risks block release until controlled or explicitly accepted by the accountable owner.
- High risks require tests and an operational detection signal.
- A trigger observed during implementation updates this register and may require an ADR.
- Accepted residual risk has an expiry/review date.
- Dependency and security risks are re-evaluated on every baseline update.
