---
title: Configuration reference
description: Configuration layers, reference application keys and values, validation errors, and the unavailable inspect-config surface.
status: experimental
implementation: specified-only
profile_availability: []
public_exposure: unassembled
audience:
  - service-developer
  - operator
topics:
  - configuration
  - validation
  - reference-application
capabilities:
  - inspect-config
source:
  - crates/config/src/lib.rs
  - apps/api-server/src/main.rs
  - apps/server/src/main.rs
  - config/reference.toml
  - specs/04-configuration-and-secrets.md
evidence:
  - apps/api-server/tests/api_service.rs
last_verified: 2026-09-03
---

# Configuration reference

> **Availability:** the layered configuration loader is implemented and assembled in the checked-in services. This page owns the separate `inspect-config` capability, which is specified-only, selected by no verified profile, and unassembled. Neither checked-in server CLI exposes an `inspect-config` command.

For operating guidance and secret handling, see [Environment and secrets](environment-and-secrets.md) and [Configuration and secrets](../guides/backend/configuration-and-secrets.md).

## Reference API command-line inputs

| Option | Type | Current parser behavior |
|---|---|---|
| `--config PATH` | path | Required base file; defaults to `config/reference.toml`. |
| `--environment ENVIRONMENT` | `development`, `test`, or `production` | Defaults to `development`. |
| `--environment-config PATH` | optional path | Adds an environment-specific layer when the file exists. |
| `--local-config PATH` | optional path | Adds a local layer when the file exists; rejected in production. |
| `--listen-address ADDRESS` | optional socket address | Adds an explicit `server.listen_address` override. |

The application constructs `ConfigLoader::new("OMNIUS", deployment)`.

## Layer precedence

Lowest to highest precedence is fixed:

1. caller-provided compiled defaults;
2. required base file;
3. optional environment file;
4. optional local file;
5. process environment;
6. explicit overrides.

Optional files are added only when their paths exist. A local file is rejected in `production` before loading. Environment keys use `OMNIUS__SECTION__FIELD`, with `__` separating the prefix and every nested field. Environment values are parsed when the underlying configuration library can parse them.

The target application structure uses strict Serde deserialization and Garde validation. Unknown keys fail where the target type has `deny_unknown_fields`; invalid values do not silently fall back.

## Generated service configuration

A generated service uses `config/base.toml` as the required, secret-free base file and `config/reference.toml` as its selected runtime overlay. The generated CLI defaults `--config` to the base file and `--environment-config` to the reference overlay; an explicit `--environment-config PATH` replaces that overlay path. The same precedence above applies, so the selected overlay overrides base values, hierarchical process environment overrides both files, and explicit CLI overrides win last.

The reference overlay is a manager-derived artifact. It renders typed TOML
values for selected framework configuration fields that have safe catalog
defaults, including PostgreSQL pool, migration, idempotency, OpenAPI, and
outbound HTTP policy. Strict deserialization rejects unknown fields, and
validation rejects invalid values. `add`, `remove`, `profile set`, `update`,
`doctor`, and `diff` treat `config/reference.toml` as classified generated
state; reconcile it through `cargo service`, not a project-owned `xtask`.

Idempotency and OpenAPI are independent. Idempotency configuration owns only
idempotent request storage behavior; it does not add pagination, reference
routes, a cursor signing key, or OpenAPI state. OpenAPI can be selected without
idempotency.

The local HTTP limiter uses the application-scoped
`application_rate_limit` table. It may transform the application router before
the one HTTP finalizer mounts it; it does not create or mount a parallel
example router.

Persisted generated profiles deliberately omit the required PostgreSQL
connection secret:

| Configuration path | Exact process environment key | Contract |
|---|---|---|
| `postgres.url` | `OMNIUS__POSTGRES__URL` | Required PostgreSQL connection URL. |

TOML strings are literal strings. Writing `${OMNIUS__POSTGRES__URL}`,
`${POSTGRES_URL}`, or any other `${...}` expression in TOML does **not** read
the process environment. Supply hierarchical `OMNIUS__...` keys or a fully
resolved higher-precedence configuration file instead.

## Checked-in reference values

The following values are from `config/reference.toml`. They are reference-application configuration, not generic library defaults and not proof that another generated profile accepts the same schema.

### Service, HTTP, static delivery, and health

| Key | Checked-in value |
|---|---|
| `telemetry.service` | `api-reference` |
| `telemetry.version` | `0.1.0` |
| `telemetry.environment` | `development` |
| `telemetry.filter` | `info` |
| `telemetry.format` | `pretty` |
| `telemetry.prometheus` | `false` |
| `server.listen_address` | `127.0.0.1:8080` |
| `server.listener_shutdown_timeout` | `10s` |
| `server.telemetry_flush_timeout` | `2s` |
| `http.max_body_bytes` | `2097152` |
| `http.max_header_bytes` | `65536` |
| `http.max_header_count` | `100` |
| `http.max_in_flight` | `1024` |
| `http.header_read_timeout` | `5s` |
| `http.handler_timeout` | `30s` |
| `http.trusted_origins` | `http://localhost:5173` |
| `static_delivery.asset_dir` | `web/dist` |
| `static_delivery.base_path` | `/` |
| `static_delivery.fallback` | `spa` |
| `static_delivery.production_required` | `true` |
| `static_delivery.source_maps` | `disabled` |
| `static_delivery.security.hsts.boundary` | `none` |
| `static_delivery.security.content_security_policy.connect_src` | `'self'` |
| `static_delivery.precompressed.gzip` | `true` |
| `static_delivery.precompressed.brotli` | `true` |
| `static_delivery.precompressed.zstd` | `true` |
| `health.refresh_interval` | `5s` |
| `health.stale_after` | `15s` |
| `health.shutdown_timeout` | `1s` |

### PostgreSQL, request semantics, outbound HTTP, and migrations

| Key | Checked-in value |
|---|---|
| `postgres.url` | File contains literal `${POSTGRES_URL}` text; use `OMNIUS__POSTGRES__URL` or a fully resolved higher-precedence layer. |
| `postgres.tls_mode` | `verify-full` |
| `postgres.min_connections` / `max_connections` | `1` / `10` |
| `postgres.connect_timeout` / `acquire_timeout` | `10s` / `5s` |
| `postgres.idle_timeout` | `10m` |
| `postgres.max_lifetime` / `max_lifetime_jitter` | `30m` / `5m` |
| `postgres.application_name` | `api-reference` |
| `postgres.initialization_sql` | `SET search_path TO public` |
| `postgres.statement_timeout` / `lock_timeout` | `15s` / `3s` |
| `postgres.health_timeout` / `shutdown_timeout` | `6s` / `10s` |
| `postgres.transaction_retry.max_attempts` | `3` |
| `postgres.transaction_retry.base_delay` / `max_delay` / `max_jitter` | `25ms` / `1s` / `100ms` |
| `postgres.transaction_retry.isolation` | `serializable` |
| `idempotency.enabled` | `true` |
| `idempotency.ttl` | `24h` |
| `idempotency.max_response_bytes` | `65536` |
| `pagination.cursor_signing_key` | File contains literal `${CURSOR_SIGNING_KEY}` text; use `OMNIUS__PAGINATION__CURSOR_SIGNING_KEY`, and supply exactly 32 bytes. |
| `openapi.document_route_enabled` / `docs_route_enabled` | `true` / `true` |
| `openapi.max_document_bytes` | `4194304` |
| `outbound_http.connect_timeout` / `total_timeout` | `5s` / `30s` |
| `outbound_http.response_body_limit_bytes` | `2097152` |
| `outbound_http.max_redirects` | `5` |
| `outbound_http.user_agent` | `api-reference/0.3.0` |
| `outbound_http.proxy.mode` | `disabled` |
| `migrations.run_on_startup` | `false` |
| `migrations.operation_timeout` | `15m` |

### Authentication and tenancy

| Key | Checked-in value |
|---|---|
| `auth.session.enabled` / `store` | `true` / `postgres` |
| `auth.session.cookie_name` | `__Host-omnius_session` |
| `auth.session.secure` / `http_only` / `same_site` | `true` / `true` / `lax` |
| `auth.session.idle_timeout` / `absolute_timeout` | `12h` / `30d` |
| `auth.password.login_provider` / `max_concurrency` | `email` / `2` |
| `auth.password.policy.memory_kib` / `iterations` / `parallelism` | `19456` / `2` / `1` |
| `auth.password.policy.min_password_bytes` / `max_password_bytes` | `12` / `1024` |
| `auth.password.policy.recovery_ttl` / `verification_ttl` | `15m` / `24h` |
| `auth.password.pepper.version` | `1` |
| `auth.password.pepper.secret` | File text references `PASSWORD_PEPPER`; value not reproduced. |
| `auth.registration.mode` / `local_identity_provider` | `invite_only` / `email` |
| `auth.registration.invitation_ttl` / `response_floor` | `7d` / `500ms` |
| `auth.registration.public_app_url` | File text references `PUBLIC_APP_URL`. |
| `auth.registration.invitation_token_pepper` | File text references `REGISTRATION_INVITATION_PEPPER`; value not reproduced. |
| `auth.api_key.enabled` | `true` |
| `auth.api_key.pepper` | File text references `API_KEY_PEPPER`; value not reproduced. |
| `auth.api_key.max_scopes` / `max_key_lifetime` / `last_used_write_interval` | `32` / `90d` / `5m` |
| `auth.authorization_server.enabled` | `true` |
| `auth.authorization_server.issuer` | File text references `OAUTH_ISSUER`. |
| `auth.authorization_server.token_pepper` | File text references `OAUTH_TOKEN_PEPPER`; value not reproduced. |
| `auth.authorization_server.authorization_request_ttl` / `authorization_code_ttl` | `10m` / `2m` |
| `auth.authorization_server.access_token_ttl` / `id_token_ttl` / `refresh_token_ttl` | `10m` / `10m` / `30d` |
| `auth.authorization_server.client_metadata_cache_ttl` | `15m` |
| `auth.authorization_server.max_authorization_request_bytes` / `max_client_metadata_bytes` | `16384` / `65536` |
| `auth.authorization_server.dynamic_client_registration` | `false` |
| `auth.authorization_server.resources[]` | Reference resource uses the configured issuer URI, name `Omnius API`, minimum assurance `aal1`, and scope `api:read`. |
| `auth.authorization_server.signing_keys[]` | Active `RS256` key with `kid` `reference-active`; the private key placeholder and public-modulus placeholder are not reproduced. Public JWK material is not private key material. |
| `auth.jwt.enabled` | `false` |
| `auth.jwt.audiences` / `algorithms` / `token_types` | `omnius-api` / `RS256` / `at+jwt` |
| `auth.jwt.clock_skew` / `cache_ttl` / `min_refresh_interval` | `30s` / `15m` / `30s` |
| `auth.jwt.max_token_lifetime` / `max_token_bytes` / `max_jwks_bytes` | `1h` / `16384` / `262144` |
| `auth.jwt.max_keys_per_issuer` / `max_kid_bytes` | `64` / `128` |
| `tenancy.enabled` / `max_list_items` | `true` / `100` |

OAuth rate-limit entries `authorize`, `token`, `register`, and `revoke` each define `replenish_every`, `burst_size`, and `identity_buckets`. Their checked-in replenish/burst pairs are `100ms/60`, `250ms/30`, `1s/5`, and `250ms/30`; identity-bucket ceilings are respectively `65536`, `65536`, `16384`, and `65536`.

### Email

| Key | Checked-in value |
|---|---|
| `email.from.address` / `display_name` | `accounts@example.test` / `Omnius` |
| `email.provider.provider` / `port` / `tls` | `smtp` / `465` / `implicit` |
| `email.provider.relay` / `username` / `password` | File text references `SMTP_RELAY`, `SMTP_USERNAME`, and `SMTP_PASSWORD`; values not reproduced. |
| `email.templates.directory` | File text references `EMAIL_TEMPLATE_DIR`. |
| `email.templates.allowed_templates` | The three checked-in account templates listed in `config/reference.toml`. |

## Loader errors

The public safe classifications are:

| Classification | Safe display |
|---|---|
| `InvalidPrefix` | `invalid configuration service prefix` |
| `LocalFileInProduction` | `local configuration files are disabled in production` |
| `Build` | `configuration source loading failed` |
| `Deserialize` | `configuration deserialization failed` |
| `Validation` | `configuration validation failed` |

The error retains an internal diagnostic but its `Debug` representation substitutes `[REDACTED]`. This is a narrow guarantee for this error type, not a promise that every downstream log or library redacts secrets.

## Placeholder limitation

The configuration loader has no interpolation pass or external secret-provider abstraction. `${NAME}` in any TOML layer is ordinary text, not an environment lookup. The checked-in reference API file still contains such text for application-owned values, so those entries are not executable secret bindings. Generated reference overlays do not emit placeholder strings: they contain only safe resolved defaults and omit required secret fields for the hierarchical process environment or another fully resolved higher-precedence layer.
