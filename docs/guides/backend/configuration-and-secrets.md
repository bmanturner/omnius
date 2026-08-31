---
title: Configuration and secrets
description: Load Omnius configuration predictably, inject secrets safely, and distinguish assembled configuration behavior from specified-only inspection tooling.
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
  - developer
  - operator
topics:
  - backend
  - configuration
  - secrets
capabilities:
  - configuration
  - configuration-loader
  - configuration-secrets
source:
  - crates/config/src/lib.rs
  - apps/server/src/main.rs
  - apps/api-server/src/main.rs
  - config/minimal.toml
  - config/reference.toml
  - specs/04-configuration-and-secrets.md
evidence:
  - apps/server/tests/minimal_service.rs
last_verified: 2026-08-30
---

# Configuration and secrets

Omnius has an assembled configuration loader used by both server binaries. It combines checked-in files, an environment-specific file when requested, environment variables, and explicit programmatic overrides. Secret redaction is implemented, but secret delivery and rotation remain deployment responsibilities.

For the profile-by-profile classification, use the [availability and exposure matrix](../../reference/availability-and-exposure-matrix.md). The `inspect-config` capability is specified only and unassembled; there is no supported command that prints the effective configuration.

## Loading order

Later layers override earlier layers:

1. application defaults;
2. the required base file passed with `--config`;
3. an optional environment file;
4. an optional local file;
5. environment variables under the `OMNIUS__` prefix;
6. explicit overrides supplied by the binary.

Nested environment keys use double underscores. For example, `OMNIUS__POSTGRES__URL` targets `postgres.url`. Treat every environment value as process input: its final type is still checked during deserialization.

Local configuration is never discovered implicitly. A caller must pass it explicitly, and production mode rejects a local file rather than silently loading it. Unknown-key rejection is provided by application configuration structs that opt in to `deny_unknown_fields`; the loader alone does not make every arbitrary structure strict.

## Files and environments

Use checked-in configuration for non-secret, reviewable settings. Use the environment layer or an explicit deployment integration for credentials and key material.

The `${POSTGRES_URL}`-style values in `config/reference.toml` are secret placeholders, not defaults. The loader does **not** expand `${...}` expressions. A deployment that uses the reference file must replace the value through a supported layer, such as `OMNIUS__POSTGRES__URL`, or render a protected environment-specific file before startup.

Do not commit a production local file. Do not use a local file as a production secret store.

## Secret boundary

`SecretString` prevents ordinary debug and display formatting from exposing a value. Code must explicitly expose the inner value at the integration boundary that needs it, such as a PostgreSQL connector.

Redaction is not encryption, access control, or rotation. The repository does not implement a secret-manager client or a general rotation protocol. Supply secrets through the process manager or deployment platform, restrict who can read that configuration, and restart or otherwise reconfigure the affected provider according to that provider's lifecycle.

Never put a real database URL, signing key, API key, password, or cookie in documentation, shell history, logs, screenshots, or support output.

## Minimal assembled example

The minimal profile is the safest way to exercise the assembled loader because it has no external service dependency.

**Prerequisites**

- run from the repository root;
- install the Rust toolchain required by this repository;
- keep `127.0.0.1:8080` free;
- do not add production secrets to `config/minimal.toml`.

```bash
cargo run -p omnius-minimal-server -- server --config config/minimal.toml
```

**Expected result:** the minimal server accepts the checked-in file and listens on `127.0.0.1:8080`.

**Failure path:** startup stops on a missing file, malformed value, unknown application field, invalid environment selection, or occupied listener. In production mode, requesting a local file is also rejected. Fix the input; do not bypass deserialization or secret checks.

This is a documented verification recipe and was not run as part of this documentation work.

## Production checklist

- Select an approved profile and verify every capability in the [availability matrix](../../reference/availability-and-exposure-matrix.md).
- Keep only non-secret settings in the base file.
- Inject every placeholder through a supported layer; never assume placeholder expansion.
- Use an explicit environment file only when the deployment controls its permissions and provenance.
- Keep local configuration disabled in production.
- Capture startup failures without dumping the deserialized configuration.
- Verify the concrete binary you deploy. A configuration type, profile selection, or checked-in example does not prove that a provider is assembled.

## Related pages

- [Runtime configuration reference](../../reference/configuration.md)
- [Environment variables and secrets](../../reference/environment-and-secrets.md)
- [Profiles and capabilities](../../concepts/modules-profiles-and-composition.md)
- [Security model](../../security/security-model.md)
- [Configuration troubleshooting](../../troubleshooting/startup-and-configuration.md)
