# Session compatibility report

Date: 2026-08-23  
Task: T002  
Criterion: AC-COMPAT-001  
Decision: pass

## Selected stable family

| Component | Exact version | Relevant configuration |
|---|---:|---|
| `axum-login` | 0.18.0 | Uses Axum 0.8 and `tower-sessions` 0.14 |
| `tower-sessions` | 0.14.0 | Defaults disabled; provider stores are explicit |
| `tower-sessions-core` | 0.14.0 | Single resolved line |
| `tower-sessions-sqlx-store` | 0.15.0 | Defaults disabled; PostgreSQL feature only |
| `tower-sessions-redis-store` | 0.16.0 | Defaults disabled; Redis provider variant only |
| SQLx | 0.8.6 | Single resolved SQLx line |
| Fred | 10.1.0 | Defaults disabled; `enable-rustls-ring` selected explicitly |

`cargo tree -i tower-sessions-core` resolves every middleware/store through `tower-sessions-core 0.14.0`. `cargo tree -i sqlx` resolves the application and PostgreSQL session store through `sqlx 0.8.6`. Axum remains 0.8.9 and Tower remains 0.5.3.

The `session_stack` binary constructs a secure `SessionManagerLayer<PostgresStore>`, builds an `axum-login` authentication manager using an `AuthnBackend`, and constructs the Redis store with a Fred pool. It ran successfully without opening external connections:

```text
cargo run -p omnius-phase0-compatibility --bin session_stack
```

## TLS provider handling

`tower-sessions-redis-store` exposes an `enable-rustls` feature that selects Fred's AWS-LC feature. The kit does not enable that feature. Instead, the provider crate keeps defaults disabled and the workspace pins Fred 10.1.0 with `enable-rustls-ring`. Cargo feature unification enables the store's TLS path with ring while preserving the process-wide provider decision. `cargo tree -i ring` includes Fred, both session stores remain on rustls 0.23.43, and the final lockfile contains no `aws-lc-rs`.

The Redis session provider uses Fred because that is the maintained store's native client. It does not share connection types with the separate `redis 1.6.0` core capability; provider SDK types remain inside the session adapter.

## Dependency admission

- `axum-login` supplies the established Axum authentication/session integration; implementing an authentication middleware framework is prohibited.
- `tower-sessions` and its maintained SQLx/Redis stores supply session lifecycle and persistence; a project-authored session engine or store is prohibited.
- Fred is admitted only as the Redis store's internal provider client and to select ring TLS. It is not exposed as the general Redis capability.
- All packages are stable crates.io releases, compile on Rust 1.98.0, and align with Axum 0.8, Tower 0.5, SQLx 0.8.6, Tokio 1.53.1, and rustls 0.23.43.
- T004 owns the blocking advisory, license, source, maintenance, and unsafe-code policy results for the complete resolved graph.

Primary references: [axum-login 0.18.0](https://docs.rs/axum-login/0.18.0), [tower-sessions 0.14.0](https://docs.rs/tower-sessions/0.14.0), [tower-sessions-sqlx-store 0.15.0](https://docs.rs/tower-sessions-sqlx-store/0.15.0), [tower-sessions-redis-store 0.16.0](https://docs.rs/tower-sessions-redis-store/0.16.0), and [Fred 10.1.0](https://docs.rs/fred/10.1.0).
