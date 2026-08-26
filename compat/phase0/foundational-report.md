# Phase 0 foundational compatibility report

Date: 2026-08-23  
Task: T001  
Decision: pass

## Reproduction

The workspace-root `Cargo.lock` resolves the production dependency baseline. This directory contains the compatibility member, spike binaries, checked-query metadata source, and captured `cargo-tree-duplicates.txt`. Run from the repository root:

```text
SQLX_OFFLINE=true cargo check --workspace --all-targets
cargo run -p rsk-phase0-compatibility --bin rsk-phase0-compatibility
cargo run -p rsk-phase0-compatibility --bin otel_flush
cargo tree -d
```

The checks ran with `rustc 1.98.0 (88d9e12ae 2026-08-18)` and `cargo 1.98.0 (797e8a9bc 2026-08-05)`, edition 2024, resolver 3.

## Resolved foundation

| Family | Resolved line |
|---|---|
| Tokio | `tokio 1.53.1`; `tokio-util 0.7.19` |
| HTTP | `axum 0.8.9`; `hyper 1.11.0`; `tower 0.5.3`; application middleware `tower-http 0.7.0` |
| Serialization | `serde 1.0.229`; `serde_json 1.0.151` |
| PostgreSQL | `sqlx`, `sqlx-core`, `sqlx-macros`, and `sqlx-postgres` all `0.8.6` |
| TLS | `rustls 0.23.43`; `tokio-rustls 0.26.4`; `rustls-webpki 0.103.15` |
| Redis core | `redis 1.6.0` |
| OpenTelemetry | API, OTLP, and protocol `0.32.0`; SDK and semantic conventions `0.32.1`; `tracing-opentelemetry 0.33.0` |

There is one major/minor line for Tokio, Hyper, Axum, Tower, SQLx, rustls, Serde, and OpenTelemetry. Cargo reports some same-version packages more than once because resolver 3 separates host/proc-macro and target feature sets; these are not incompatible version lines.

Two explained utility duplicates remain:

- `tower-http 0.6.11` is private to Reqwest 0.13 compression support; public server middleware remains `0.7.0`. Both use Tower 0.5.3, and no `tower-http` type crosses the outbound-client boundary.
- `webpki-roots 0.26.11` is retained by SQLx 0.8.6 and wraps the current `webpki-roots 1.0.9` data. Both feed rustls 0.23 and do not create a second TLS implementation.

The lockfile contains SQLx MySQL/SQLite macro support at 0.8.6, but the service enables only the PostgreSQL runtime feature. It does not introduce another SQLx line.

## TLS provider and roots

The selected crypto provider is rustls **ring**. Direct rustls uses `default-features = false` plus `ring`, Reqwest uses `rustls-no-provider`, SQLx uses `tls-rustls-ring`, and OTLP uses `tls-ring`. The final lockfile contains `ring 0.17.14` and no `aws-lc-rs` package.

The selected trust strategy is the embedded Mozilla WebPKI root set for deterministic containers and local development. Reqwest receives an explicit `rustls::ClientConfig` built from `webpki_roots::TLS_SERVER_ROOTS`; Redis, SQLx, and OTLP enable their WebPKI-root features. Provider installation occurs before client construction. Workload-specific private roots may be added later by typed configuration, but must not replace verification or silently enable native roots.

## SQLx 0.8.6 and offline metadata

SQLx is pinned exactly to 0.8.6 with `runtime-tokio`, `tls-rustls-ring`, `postgres`, `macros`, `migrate`, `json`, `time`, and `uuid`. `cargo tree -d` proves all SQLx crates resolve on 0.8.6. Production query macros must be prepared against the migration-complete schema using pinned `sqlx-cli 0.8.6`:

```text
cargo sqlx migrate run --source migrations
cargo sqlx prepare -- --bin sqlx_offline
SQLX_OFFLINE=true cargo check --bin sqlx_offline
```

This workflow was exercised against PostgreSQL 17 in a disposable container. The migration applied, the checked query returned `offline-ready`, `cargo sqlx prepare` wrote the committed `.sqlx` metadata, the container was stopped, and `SQLX_OFFLINE=true cargo check --bin sqlx_offline` succeeded without a database URL. Production metadata is regenerated whenever migrations or checked queries change. The migration verification task owns the complete empty-to-head and supported-version upgrade rehearsals.

## OpenTelemetry lifecycle

The OTLP crate disables defaults and enables only gRPC/Tonic, traces, metrics, ring TLS, and WebPKI roots. This avoids its default blocking Reqwest/HTTP exporter stack. The `otel_flush` spike exported a span to a deliberately closed local endpoint: `SdkTracerProvider::force_flush()` reported the connection failure, then `shutdown_with_timeout(1s)` completed within its bound.

Shutdown must call and inspect `force_flush()` before `shutdown_with_timeout()`. OpenTelemetry SDK 0.32 can return `Ok(())` from shutdown after worker completion even when the final export failed, so shutdown alone is not delivery evidence. Export failure remains best effort operationally, but it is observable.

## Dependency admission

All listed crates solve established runtime, protocol, database, or telemetry capabilities that the standard library does not provide. They are crates.io releases, compile on the pinned toolchain, and are maintained/documented by the Rust, Tokio, SQLx, Redis, rustls, Serde, OpenTelemetry, and tracing ecosystems. The baseline introduces no git or prerelease source. The supply-chain task performs the blocking license, advisory, source, maintenance, and unsafe-code gates before Phase 0 exits.

| Direct dependency | Purpose and reason existing code is insufficient | Exact baseline | Duplicate/profile effect |
|---|---|---|---|
| Tokio / tokio-util | Async runtime, signals, timers, cancellation; the standard library has no equivalent async runtime | `1.53.1` / `0.7.19` | Sole runtime; every networked profile |
| Axum / Tower / tower-http / Hyper | HTTP routing and standard middleware/service model; avoids a custom framework | `0.8.9` / `0.5.3` / `0.7.0` / `1.11.0` | One Axum/Tower/Hyper line; minimal and API profiles |
| Serde / serde_json | Ecosystem wire/config serialization | `1.0.229` / `1.0.151` | One Serde line; all profiles |
| thiserror / anyhow | Typed library errors and binary-only context | `2.0.20` / `1.0.104` | No foundational duplicate; all/library and tool-only respectively |
| SQLx | Checked PostgreSQL queries, pools, and migrations; custom persistence infrastructure is prohibited | `0.8.6` | One SQLx line; database profiles |
| Redis | Maintained async Redis protocol/client and reconnection manager | `1.6.0` | Core Redis line; Redis profiles; job-provider exception is decided separately in T003 |
| Reqwest | Bounded pooled outbound HTTP without a custom client | `0.13.4` | Shares Hyper/rustls; API/integration profiles |
| rustls / webpki-roots | Established TLS primitives and deterministic trust roots | `0.23.43` / `1.0.9` | Ring only; all TLS clients |
| OpenTelemetry family | Standard trace/metric export protocol and SDK | API/OTLP/protocol `0.32.0`; SDK/semantic conventions `0.32.1`; bridge `0.33.0` | One OTel line; telemetry-enabled profiles |
| tracing / tracing-subscriber | Structured instrumentation and centralized subscriber | `0.1.44` / `0.3.23` | One tracing line; all profiles |

Primary references: [Rust 1.98.0](https://blog.rust-lang.org/2026/08/20/Rust-1.98.0/), [Axum](https://docs.rs/axum/0.8.9), [SQLx 0.8.6](https://docs.rs/sqlx/0.8.6), [rustls process-wide provider](https://docs.rs/rustls/0.23.43/rustls/crypto/struct.CryptoProvider.html), [Reqwest TLS features](https://docs.rs/crate/reqwest/0.13.4/features), and [OpenTelemetry Rust](https://docs.rs/opentelemetry_sdk/0.32.1).
