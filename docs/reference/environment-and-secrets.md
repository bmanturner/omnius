---
title: Environment and secrets
description: Environment key syntax, secret-bearing configuration fields, redaction boundaries, and unsupported assumptions.
status: experimental
implementation: implemented
profile_availability:
  - minimal
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
  - service-developer
  - operator
  - security-engineer
topics:
  - environment
  - secrets
  - configuration
capabilities: []
source:
  - crates/config/src/lib.rs
  - apps/api-server/src/main.rs
  - apps/server/src/main.rs
  - config/reference.toml
evidence:
  - apps/api-server/tests/api_service.rs
last_verified: 2026-09-03
---

# Environment and secrets

The configuration loader supports process-environment overrides. It does not provide an Omnius-specific vault, KMS, rotation service, or interpolation pass. See [Configuration](configuration.md) for the complete layer order and checked-in reference values.

## Environment key syntax

The checked-in reference API and generated services use service prefix `OMNIUS`. A nested configuration path maps to an environment name by uppercasing each segment and joining it with `__`:

| Configuration path | Environment override |
|---|---|
| `health.shutdown_timeout` | `OMNIUS__HEALTH__SHUTDOWN_TIMEOUT` |
| `telemetry.environment` | `OMNIUS__TELEMETRY__ENVIRONMENT` |
| `server.listen_address` | `OMNIUS__SERVER__LISTEN_ADDRESS` |

The prefix must be 1–64 ASCII characters, begin with an uppercase letter, and otherwise contain only uppercase letters, digits, and underscores. Environment values have higher precedence than file layers and lower precedence than explicit application overrides. Parsing and schema validation still apply; a malformed override fails loading rather than falling back.

Only the first two examples above are exercised by focused reference-application tests. The third follows the source-defined naming transformation and strict application schema; it was not run for this documentation pass.

## Generated persisted-profile secrets

The thin generated-service framework has one required persisted-profile secret
binding: `OMNIUS__POSTGRES__URL` for `postgres.url`. It is not written to
generated `config/reference.toml`. Idempotency has no pagination dependency or
cursor-signing secret. Other application-selected providers may declare their
own endpoint or credential requirements and remain fail-closed until supplied.

Generated Compose supplies a development-only PostgreSQL URL and explicitly
sets `OMNIUS__MIGRATIONS__RUN_ON_STARTUP=false` because its one-shot `migrate`
service owns local migration execution. Outside that local topology, operators
must supply the PostgreSQL key and retain the selected direct-launch migration
policy.

## Checked-in reference-application fields

The checked-in reference application schema directly wraps several fields in `SecretString`, and its checked-in reference file uses additional secret-looking placeholder text. This table describes that application-owned file, not the generated secret-free overlay. The names below are identifiers, not credentials.

| Configuration field | Reference placeholder or source | Evidence boundary |
|---|---|---|
| `postgres.url` | `POSTGRES_URL` | Literal placeholder text only; use `OMNIUS__POSTGRES__URL` as the actual hierarchical override. |
| `pagination.cursor_signing_key` | `CURSOR_SIGNING_KEY` | Literal placeholder text owned by the checked-in reference application; it is not a generated-service or idempotency requirement. |
| `auth.password.pepper.secret` | `PASSWORD_PEPPER` | Direct secret-typed field. |
| `auth.registration.invitation_token_pepper` | `REGISTRATION_INVITATION_PEPPER` | Direct secret-typed field. |
| `auth.api_key.pepper` | `API_KEY_PEPPER` | Direct secret-typed field; the app exposes it only for canonical validation and clears local byte buffers. |
| `auth.authorization_server.issuer` | `OAUTH_ISSUER` | Configuration value, not secret material. |
| `auth.authorization_server.token_pepper` | `OAUTH_TOKEN_PEPPER` | Secret token material. |
| `auth.authorization_server.signing_keys[].public_jwk` | `OAUTH_SIGNING_JWK_N` plus checked-in exponent | Public-key material; integrity-sensitive but not private-key material. |
| `auth.authorization_server.signing_keys[].private_key_pkcs8_pem` | `OAUTH_SIGNING_PRIVATE_KEY_PKCS8_PEM` | Private signing key. |
| `auth.registration.public_app_url` | `PUBLIC_APP_URL` | Configuration value, not secret material. |
| `email.provider.relay` | `SMTP_RELAY` | Infrastructure configuration; sensitivity depends on deployment. |
| `email.provider.username` | `SMTP_USERNAME` | Credential identifier. |
| `email.provider.password` | `SMTP_PASSWORD` | Credential secret. |
| `email.templates.directory` | `EMAIL_TEMPLATE_DIR` | Filesystem configuration, not secret material. |

## `${…}` strings do not interpolate

The Omnius loader constructs file and environment sources but has no placeholder expansion or secret-provider stage. A TOML value such as `"${POSTGRES_URL}"` remains those literal characters. Setting `POSTGRES_URL` does nothing unless application code separately consumes it; generated services do not.

Use the exact hierarchical `OMNIUS__SECTION__FIELD` key or provide a fully resolved higher-precedence configuration file. Generated external dependency bindings such as `${NAME:?message}` appear only in Compose YAML, where Compose enforces that the operator supplies the variable; they are not TOML interpolation.

## Redaction boundary

`SecretString` redacts ordinary debug formatting, and the configuration load error's safe `Display`/`Debug` paths do not reveal retained diagnostics. That protection is intentionally narrow:

- code with `ExposeSecret` can access plaintext;
- a consumer can forward plaintext to another library;
- not every error, log, metric, trace, or crash path is proven secret-safe by the loader tests;
- public JWK material and URLs should not be confused with private key or pepper material.

Never place real credentials in checked-in files, shell history, documentation examples, generated contract artifacts, URLs, or diagnostic bundles. Resolve and rotate secrets through deployment-specific controls outside this repository's loader contract.

## Production restrictions

A local configuration file is rejected when deployment environment is `production`. This prevents the local layer from being used in production; it does not validate filesystem permissions, secret provenance, rotation, or external secret storage. Unknown fields and invalid values fail strict deserialization or validation.
