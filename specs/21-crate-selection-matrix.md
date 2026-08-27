---
spec_id: OMNIUS-021
title: Crate Selection and Compatibility Matrix
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Crate Selection and Compatibility Matrix


## Selection rule

“Battle-hardened” is not reduced to popularity. Admission weighs stable releases, maintenance, documentation, ecosystem role, security record, license, MSRV, dependency convergence, and whether an established external service is more appropriate.

The observed version is the reviewed baseline as of August 23, 2026. Phase 0 must resolve exact patches and record the lockfile. Default profiles may not drift to a different major/minor line automatically.

## Matrix

| Area | Selected component | Baseline | Status | Rationale | Constraint/alternative | Source |
|---|---|---:|---|---|---|---|
| Toolchain | `Rust` | 1.98.0 | **Default** | Current stable; edition 2024; pin for reproducibility. | Do not use `stable` floating in release builds. | `SRC-RUST-001` |
| Runtime | `tokio` | 1.53.1 | **Default** | De facto async runtime; broad ecosystem fit. | Do not add a second runtime. | `SRC-TOKIO-001` |
| HTTP | `axum` | 0.8.9 | **Default** | Tokio/Tower-native, maintained under Tokio ecosystem. | Actix/Rocket are valid elsewhere but would split architecture. | `SRC-AXUM-001` |
| Services | `tower` | 0.5.3 | **Default** | Standard service/layer model used by Axum and Tonic. | Avoid custom middleware framework. | `SRC-TOWER-001` |
| HTTP middleware | `tower-http` | 0.7.0 | **Default** | Maintained common middleware; now includes CSRF/cross-origin protection. | Avoid miscellaneous one-off middleware crates when tower-http covers it. | `SRC-TOWERHTTP-001` |
| Runtime utilities | `tokio-util` | 0.7.x | **Default** | CancellationToken, codec/task utilities; aligned with Tokio. | Phase 0 pins exact patch. | `SRC-TOKIO-002` |
| Serialization | `serde / serde_json` | 1.x | **Default** | Rust ecosystem standard. | No replacement abstraction. | `SRC-AXUM-001` |
| Errors | `thiserror` | 2.x | **Default** | Typed reusable errors. | `anyhow` limited to binaries/tools. | `SRC-RUST-001` |
| CLI errors | `anyhow` | 1.x | **Limited** | Excellent contextual errors in composition/ops commands. | Not exposed from library/domain APIs. | `SRC-RUST-001` |
| Config | `config` | 0.15.25 | **Default** | Layered, typed configuration. | Figment considered; config has broader neutral adoption. | `SRC-CONFIG-001` |
| Secrets | `secrecy` | 0.10.3 | **Default** | Explicit secret exposure and redacted formatting. | Not a secret manager. | `SRC-SECRECY-001` |
| CLI | `clap` | 4.6.6 | **Default** | Mature derive/builder CLI. | No custom parser. | `SRC-CLAP-001` |
| Validation | `garde` | 0.23.0 | **Default** | Typed derive validation, context, nested reports. | `validator` is acceptable by ADR; one library only. | `SRC-GARDE-001` |
| OpenAPI | `utoipa` | 5.5.0 | **Default in API profiles** | Established code-first OpenAPI integration. | `aide` rejected as simultaneous second schema stack. | `SRC-UTOIPA-001` |
| Problem Details | `local thin type` | RFC 9457 | **Default** | Small stable wire contract; no need for an obscure framework. | Must conform exactly; not a new error framework. | `SRC-RFC9457` |
| HTTP client | `reqwest` | 0.13.4 | **Default** | Mature async client; reusable pools; rustls support. | No per-request client construction. | `SRC-REQWEST-001` |
| Database | `sqlx` | 0.8.6 | **Default** | Async SQL, checked queries, migrations; compatible surrounding ecosystem. | 0.9.0 upgrade is gated; Diesel not mixed into baseline. | `SRC-SQLX-001` |
| Database latest | `sqlx` | 0.9.0 | **Candidate** | Current observed release. | Not default until session/jobs/telemetry graph converges. | `SRC-SQLX-002` |
| Redis | `redis` | 1.6.0 | **Optional foundation** | Official client; async multiplexed connections and reconnection manager. | No default deadpool/bb8 for async use. | `SRC-REDIS-001` |
| Local cache | `moka` | 0.12.16 | **Optional default** | Mature bounded concurrent cache. | Do not use unbounded DashMap as cache. | `SRC-MOKA-001` |
| Sessions | `axum-login` | 0.18.0 | **Default authenticated profile** | Integrates auth backend and sessions with Axum. | Pin to compatible tower-sessions graph in Phase 0. | `SRC-AXUMLOGIN-001` |
| Session middleware | `tower-sessions` | 0.15.x compatible line | **Default authenticated profile** | Established Tower session layer with provider stores. | Exact core/store versions are compatibility-gated. | `SRC-SESSIONS-001` |
| Session SQL store | `tower-sessions-sqlx-store` | 0.15.0 candidate | **Default after Phase 0** | Maintained store currently targets SQLx 0.8. | Do not write a custom store if graph resolves. | `SRC-SESSIONS-002` |
| Password hash | `argon2` | 0.5.3 | **Default password auth** | RustCrypto Argon2id/PHC implementation. | Never custom KDF. | `SRC-ARGON2-001` |
| JWT | `jsonwebtoken` | 11.0.0 | **Default bearer module** | Widely adopted JWT/JWK support. | Do not parse/verify JWT manually. | `SRC-JWT-001` |
| OIDC | `openidconnect` | 4.0.1 | **Optional auth** | Protocol-aware OIDC client/verifier. | OAuth alone is not identity. | `SRC-OIDC-001` |
| OAuth client | `oauth2` | 5.0.0 | **Optional auth** | PKCE and OAuth client flows. | No custom protocol implementation. | `SRC-OAUTH-001` |
| Passkeys | `webauthn-rs` | 0.5.5+ | **Optional auth** | Security-focused WebAuthn implementation. | Minimum line must include current security fixes. | `SRC-WEBAUTHN-001` |
| TOTP | `totp-rs` | 6.0.0 | **Optional auth** | Maintained TOTP implementation. | Seed storage/replay remain app responsibilities. | `SRC-TOTP-001` |
| Policy engine | `cedar-policy` | 4.12.x | **Optional** | Official Cedar engine for RBAC/ABAC/ReBAC. | Basic provider remains simpler default. | `SRC-CEDAR-001` |
| Rate limit | `governor` | 0.10.4 | **Default local** | Established GCRA implementation. | Not a distributed-global limiter. | `SRC-GOVERNOR-001` |
| Rate limit layer | `tower-governor` | 0.8.0 | **Default local** | Tower/Axum adapter for governor. | Global quotas require edge/Redis design. | `SRC-TOWERGOV-001` |
| Object storage | `object_store` | 0.14.1 | **Default optional** | Apache-maintained multi-cloud/local abstraction. | Official SDK may be used for provider-only features. | `SRC-OBJECTSTORE-001` |
| Object alternative | `opendal` | current stable | **Candidate** | Broader backend matrix. | Only by ADR; do not compile both by default. | `SRC-OPENDAL-001` |
| Email | `lettre` | 0.11.23 | **Default optional** | Mature message/SMTP implementation. | Provider HTTP APIs remain separate adapters. | `SRC-LETTRE-001` |
| Templates | `minijinja` | 2.24.0 | **Default notifications** | Mature runtime templates. | Askama is alternative for compile-time templates, not simultaneous. | `SRC-MINIJINJA-001` |
| Jobs | `apalis + apalis-redis` | 0.7.4 | **Default Redis jobs by ADR-0011** | Stable Tower-inspired job processing and Redis backend. | Isolated Redis 0.32.7 line and future-incompatibility controls are mandatory; prerelease upgrades excluded. | `SRC-APALIS-001` |
| Postgres jobs | `pgmq` | 0.33.7 | **Optional provider** | Avoids custom queue when PGMQ SQL installation is acceptable. | Phase 0 passed on SQLx 0.8.6; operators own versioned embedded SQL installation. | `SRC-PGMQ-001` |
| Rejected jobs | `sqlxmq` | 0.6.0 | **Rejected default** | Stable release targets old SQLx line. | May be reconsidered after maintained compatible release. | `SRC-SQLXMQ-001` |
| Rejected jobs | `apalis-postgres` | 1.0 prerelease | **Rejected default** | Prerelease at verification time. | No RC in default profile. | `SRC-APALISPG-001` |
| Events | `async-nats` | 0.50.0 | **Optional** | Official async NATS client including JetStream. | Redis Pub/Sub remains ephemeral only. | `SRC-NATS-001` |
| Webhooks | `Svix client/service` | 2.0.0 | **Default production outbound** | Purpose-built, mature webhook delivery/retry platform. | Local fake only for tests/dev. | `SRC-SVIX-001` |
| Tracing | `tracing` | 0.1.x | **Default** | Rust standard structured instrumentation. | No parallel logging facade in application code. | `SRC-TRACING-001` |
| Trace subscriber | `tracing-subscriber` | 0.3.23 | **Default** | Filtering, formatting, layering. | Centralized bootstrap. | `SRC-TRACINGSUB-001` |
| OTel bridge | `tracing-opentelemetry` | 0.33.0 | **Default optional export** | Maintained bridge. | Version line pinned with OTel. | `SRC-TRACINGOTEL-001` |
| OTLP | `opentelemetry-otlp` | 0.32.0 | **Default optional export** | Standard exporter. | Exporter failure is best effort. | `SRC-OTLP-001` |
| Metrics | `metrics` | 0.24.6 | **Default** | Stable facade decouples instrumentation/exporter. | Avoid high-cardinality labels. | `SRC-METRICS-001` |
| Prometheus | `metrics-exporter-prometheus` | 0.18.3 | **Default metrics exporter** | Straightforward scrape endpoint/recorder. | Expose only on admin surface. | `SRC-PROM-001` |
| Integration tests | `testcontainers` | 0.28.0 | **Default test support** | Real disposable infrastructure. | Do not replace with mocks alone. | `SRC-TESTCONTAINERS-001` |
| Test runner | `cargo-nextest` | current stable CLI | **Default tool** | Isolation, groups, partitions, timeouts. | Retries only temporary diagnosed flakes. | `SRC-NEXTEST-001` |
| HTTP mocks | `wiremock` | current stable | **Default test support** | Behavioral provider contract tests. | No production dependency. | `SRC-WIREMOCK-001` |
| Property tests | `proptest` | current stable | **Default test support** | State/parser invariant generation. | Use selectively, not as replacement for examples. | `SRC-PROPTEST-001` |
| Fuzzing | `cargo-fuzz` | current stable CLI | **Default security tooling** | libFuzzer integration for untrusted parsers. | CI smoke plus scheduled longer runs. | `SRC-FUZZ-001` |
| GraphQL | `async-graphql` | 7.2.1 | **Optional** | Mature integrated GraphQL server. | Not included unless selected. | `SRC-GRAPHQL-001` |
| gRPC | `tonic` | 0.14.6 | **Optional** | Tokio/Tower-native gRPC. | Shares application services. | `SRC-TONIC-001` |
| Feature flags | `open-feature` | 0.3.x | **Optional** | Vendor-neutral evaluation API. | Provider selected separately; no auth bypass. | `SRC-OPENFEATURE-001` |
| Localization | `fluent-bundle` | 0.16.x | **Optional** | Project Fluent runtime localization. | Not in kernel. | `SRC-FLUENT-001` |
| Search | `meilisearch-sdk` | 0.33.x | **Optional default adapter** | Straightforward search projection client. | Search remains derived; OpenSearch by ADR. | `SRC-MEILI-001` |
| Generator | `cargo-generate` | current stable CLI | **Initial generation** | Established project templating. | Ongoing changes use owned xtask. | `SRC-GENERATE-001` |
| Advisories | `cargo-audit` | current stable CLI | **Required** | RustSec advisory scanning. | No unowned permanent ignores. | `SRC-AUDIT-001` |
| Policy | `cargo-deny` | current stable CLI | **Required** | Licenses, sources, advisories, duplicates. | CI blocking. | `SRC-DENY-001` |
| Supply-chain review | `cargo-vet` | current stable CLI | **Required release** | Audits/imports dependency reviews. | Policy maintained as code. | `SRC-VET-001` |
| SBOM | `cargo-cyclonedx` | current stable CLI | **Required release** | CycloneDX component inventory. | Attached to release. | `SRC-CYCLONEDX-001` |
| API compatibility | `cargo-semver-checks` | current stable CLI | **Required public crates** | Detects unintended breaking API changes. | Run against previous release. | `SRC-SEMVER-001` |

## Compatibility gates

### Foundational duplicate gate

`cargo tree -d` must show no unexplained duplicate major lines for Tokio, Hyper, Axum, Tower, SQLx, rustls, Serde, OpenTelemetry, or tower-sessions core. Duplicate utility crates are reviewed but not automatically prohibited.

### SQLx gate

The initial line is 0.8.6. Upgrading requires:

- Session store and auth stack compiling on one SQLx line.
- Job providers not forcing a conflicting line in shared types.
- Migration/query macro compatibility.
- Testcontainers and offline metadata workflow.
- Clean migration and performance tests.
- Accepted ADR and release note.

### Authentication gate

Resolve `axum-login`, `tower-sessions`, and selected store in a miniature workspace before core implementation. Use the versions that are mutually supported, even when their package version numbers differ.

### OpenTelemetry gate

Pin `tracing-opentelemetry`, `opentelemetry`, SDK, semantic conventions, and OTLP exporter as one tested set. They change together.

### Prerelease gate

A prerelease may be used only in an experimental non-default profile with an ADR, exact pin, and upgrade/removal plan.
