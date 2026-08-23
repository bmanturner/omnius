---
spec_id: RSK-RES-SOURCES
title: Primary Source Registry
version: 0.1.0
status: evidence
last_verified: 2026-08-23
---

# Primary Source Registry


All dependency facts should be rechecked during Phase 0. This registry favors official documentation, project repositories, standards, and security guidance.

| ID | Source | URL | Use |
|---|---|---|---|
| `SRC-RUST-001` | Rust 1.98.0 release | <https://blog.rust-lang.org/2026/08/20/Rust-1.98.0/> | Current stable toolchain at verification date. |
| `SRC-CARGO-001` | Cargo features | <https://doc.rust-lang.org/cargo/reference/features.html> | Feature unification and optional dependency behavior. |
| `SRC-CARGO-002` | Cargo workspaces | <https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html> | Workspace structure. |
| `SRC-TOKIO-001` | Tokio 1.53.1 docs | <https://docs.rs/tokio/1.53.1/tokio/> | Async runtime. |
| `SRC-TOKIO-002` | Tokio graceful shutdown | <https://tokio.rs/tokio/topics/shutdown> | Cancellation and task shutdown guidance. |
| `SRC-AXUM-001` | Axum 0.8.9 docs | <https://docs.rs/axum/0.8.9/axum/> | HTTP framework and Tower integration. |
| `SRC-TOWER-001` | Tower 0.5.3 docs | <https://docs.rs/tower/0.5.3/tower/> | Service/layer abstraction. |
| `SRC-TOWERHTTP-001` | tower-http 0.7.0 docs | <https://docs.rs/tower-http/0.7.0/tower_http/> | HTTP middleware, including CSRF/cross-origin protection. |
| `SRC-SQLX-001` | SQLx 0.8.6 docs | <https://docs.rs/sqlx/0.8.6/sqlx/> | Selected compatible database line. |
| `SRC-SQLX-002` | SQLx 0.9.0 docs | <https://docs.rs/sqlx/0.9.0/sqlx/> | Current release observed but compatibility-gated. |
| `SRC-REDIS-001` | redis 1.6.0 docs | <https://docs.rs/redis/1.6.0/redis/> | Official Redis client; async multiplexed connection guidance. |
| `SRC-MOKA-001` | Moka 0.12.16 docs | <https://docs.rs/moka/0.12.16/moka/> | Bounded concurrent in-memory cache. |
| `SRC-CONFIG-001` | config 0.15.25 docs | <https://docs.rs/config/0.15.25/config/> | Layered configuration. |
| `SRC-SECRECY-001` | secrecy 0.10.3 docs | <https://docs.rs/secrecy/0.10.3/secrecy/> | Secret wrappers and explicit exposure. |
| `SRC-CLAP-001` | clap 4.6.6 docs | <https://docs.rs/clap/4.6.6/clap/> | CLI parsing. |
| `SRC-GARDE-001` | garde 0.23.0 docs | <https://docs.rs/garde/0.23.0/garde/> | Validation. |
| `SRC-UTOIPA-001` | utoipa 5.5.0 docs | <https://docs.rs/utoipa/5.5.0/utoipa/> | OpenAPI generation. |
| `SRC-REQWEST-001` | reqwest 0.13.4 docs | <https://docs.rs/reqwest/0.13.4/reqwest/> | Outbound HTTP client. |
| `SRC-SESSIONS-001` | tower-sessions 0.15.0 docs | <https://docs.rs/tower-sessions/0.15.0/tower_sessions/> | Session middleware. |
| `SRC-SESSIONS-002` | tower-sessions SQLx store source | <https://docs.rs/crate/tower-sessions-sqlx-store/0.15.0/source/Cargo.toml> | Shows SQLx 0.8 dependency and compatibility constraint. |
| `SRC-AXUMLOGIN-001` | axum-login 0.18.0 docs | <https://docs.rs/axum-login/0.18.0/axum_login/> | Authentication/session integration. |
| `SRC-ARGON2-001` | RustCrypto Argon2 0.5.3 docs | <https://docs.rs/argon2/0.5.3/argon2/> | Argon2id password hashing. |
| `SRC-JWT-001` | jsonwebtoken 11 docs | <https://docs.rs/jsonwebtoken/11.0.0/jsonwebtoken/> | JWT signing/verifying. |
| `SRC-OIDC-001` | openidconnect 4.0.1 docs | <https://docs.rs/openidconnect/4.0.1/openidconnect/> | OIDC client and verification. |
| `SRC-OAUTH-001` | oauth2 5 docs | <https://docs.rs/oauth2/5.0.0/oauth2/> | OAuth 2 client and PKCE. |
| `SRC-WEBAUTHN-001` | webauthn-rs 0.5.5 docs | <https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/> | WebAuthn/passkeys. |
| `SRC-TOTP-001` | totp-rs 6.0.0 docs | <https://docs.rs/totp-rs/6.0.0/totp_rs/> | TOTP. |
| `SRC-CEDAR-001` | cedar-policy 4.12 docs | <https://docs.rs/cedar-policy/4.12.0/cedar_policy/> | Optional policy engine. |
| `SRC-OBJECTSTORE-001` | object_store 0.14.1 docs | <https://docs.rs/object_store/0.14.1/object_store/> | Apache object storage abstraction. |
| `SRC-OPENDAL-001` | OpenDAL docs | <https://docs.rs/opendal/latest/opendal/> | Optional broad object-storage provider matrix. |
| `SRC-LETTRE-001` | lettre 0.11.23 docs | <https://docs.rs/lettre/0.11.23/lettre/> | Email construction and SMTP. |
| `SRC-MINIJINJA-001` | MiniJinja 2.24 docs | <https://docs.rs/minijinja/2.24.0/minijinja/> | Runtime templates. |
| `SRC-APALIS-001` | Apalis 0.7.4 docs | <https://docs.rs/apalis/0.7.4/apalis/> | Stable job framework line. |
| `SRC-APALISPG-001` | apalis-postgres prerelease docs | <https://docs.rs/apalis-postgres/latest/apalis_postgres/> | Prerelease adapter excluded from defaults. |
| `SRC-PGMQ-001` | pgmq 0.33.7 docs | <https://docs.rs/pgmq/0.33.7/pgmq/> | Optional PostgreSQL queue client. |
| `SRC-SQLXMQ-001` | sqlxmq 0.6.0 crate | <https://crates.io/crates/sqlxmq/0.6.0> | Targets old SQLx line; rejected default. |
| `SRC-NATS-001` | async-nats 0.50.0 docs | <https://docs.rs/async-nats/0.50.0/async_nats/> | NATS and JetStream. |
| `SRC-SVIX-001` | Svix Rust 1.99.1 docs | <https://docs.rs/svix/1.99.1/svix/> | Webhook delivery client. |
| `SRC-SVIX-002` | Svix webhook reliability docs | <https://docs.svix.com/retries> | Delivery retry behavior. |
| `SRC-TRACING-001` | tracing docs | <https://docs.rs/tracing/latest/tracing/> | Structured diagnostics. |
| `SRC-TRACINGSUB-001` | tracing-subscriber 0.3.23 docs | <https://docs.rs/tracing-subscriber/0.3.23/tracing_subscriber/> | Subscriber/filter/formatting. |
| `SRC-TRACINGOTEL-001` | tracing-opentelemetry 0.33 docs | <https://docs.rs/tracing-opentelemetry/0.33.0/tracing_opentelemetry/> | Trace bridge. |
| `SRC-OTLP-001` | opentelemetry-otlp 0.32 docs | <https://docs.rs/opentelemetry-otlp/0.32.0/opentelemetry_otlp/> | OTLP exporter. |
| `SRC-METRICS-001` | metrics 0.24.6 docs | <https://docs.rs/metrics/0.24.6/metrics/> | Metrics facade. |
| `SRC-PROM-001` | metrics-exporter-prometheus 0.18.3 docs | <https://docs.rs/metrics-exporter-prometheus/0.18.3/metrics_exporter_prometheus/> | Prometheus exporter. |
| `SRC-GOVERNOR-001` | governor 0.10.4 docs | <https://docs.rs/governor/0.10.4/governor/> | Rate-limiting algorithm. |
| `SRC-TOWERGOV-001` | tower-governor 0.8.0 docs | <https://docs.rs/tower_governor/0.8.0/tower_governor/> | Tower/Axum integration. |
| `SRC-TESTCONTAINERS-001` | testcontainers 0.28 docs | <https://docs.rs/testcontainers/0.28.0/testcontainers/> | Disposable integration infrastructure. |
| `SRC-NEXTEST-001` | cargo-nextest docs | <https://nexte.st/> | Test runner and groups. |
| `SRC-WIREMOCK-001` | wiremock docs | <https://docs.rs/wiremock/latest/wiremock/> | HTTP integration fakes. |
| `SRC-PROPTEST-001` | proptest docs | <https://docs.rs/proptest/latest/proptest/> | Property testing. |
| `SRC-FUZZ-001` | Rust Fuzz Book | <https://rust-fuzz.github.io/book/> | cargo-fuzz guidance. |
| `SRC-AUDIT-001` | RustSec cargo-audit | <https://rustsec.org/> | Advisory scanning. |
| `SRC-DENY-001` | cargo-deny docs | <https://embarkstudios.github.io/cargo-deny/> | License/source/advisory/duplicate policy. |
| `SRC-VET-001` | cargo-vet docs | <https://mozilla.github.io/cargo-vet/> | Supply-chain review. |
| `SRC-CYCLONEDX-001` | cargo-cyclonedx | <https://github.com/CycloneDX/cyclonedx-rust-cargo> | SBOM. |
| `SRC-SEMVER-001` | cargo-semver-checks | <https://github.com/obi1kenobi/cargo-semver-checks> | Rust API compatibility. |
| `SRC-GRAPHQL-001` | async-graphql 7.2.1 docs | <https://docs.rs/async-graphql/7.2.1/async_graphql/> | Optional GraphQL. |
| `SRC-TONIC-001` | tonic 0.14.6 docs | <https://docs.rs/tonic/0.14.6/tonic/> | Optional gRPC. |
| `SRC-OPENFEATURE-001` | OpenFeature Rust SDK 0.3 docs | <https://docs.rs/open-feature/0.3.0/open_feature/> | Feature flag API. |
| `SRC-FLUENT-001` | fluent-bundle 0.16 docs | <https://docs.rs/fluent-bundle/0.16.0/fluent_bundle/> | Localization. |
| `SRC-MEILI-001` | meilisearch-sdk 0.33 docs | <https://docs.rs/meilisearch-sdk/0.33.0/meilisearch_sdk/> | Optional search. |
| `SRC-GENERATE-001` | cargo-generate docs | <https://cargo-generate.github.io/cargo-generate/> | Initial project templating. |
| `SRC-OWASP-AUTH` | OWASP Authentication Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> | Authentication controls. |
| `SRC-OWASP-SESSION` | OWASP Session Management Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html> | Session/cookie controls. |
| `SRC-OWASP-REST` | OWASP REST Security Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> | API security. |
| `SRC-OWASP-SSRF` | OWASP SSRF Prevention Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> | Outbound URL controls. |
| `SRC-RFC9457` | RFC 9457 Problem Details | <https://www.rfc-editor.org/rfc/rfc9457.html> | HTTP error contract. |
