---
spec_id: OMNIUS-004
title: Configuration and Secrets
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Configuration and Secrets


## Crates

Use `config`, Serde, `secrecy`, `clap`, and `garde` for semantic validation.

## Precedence

1. Compiled defaults.
2. Base file.
3. Environment-specific file.
4. Local uncommitted development file.
5. Environment variables.
6. Explicit CLI overrides.

Production never implicitly reads `.env`.

## Conventions

- Environment keys: `<SERVICE>__SECTION__FIELD`.
- Durations and byte sizes include units.
- URLs use typed parsing.
- Unknown top-level and security-sensitive keys are rejected.
- Deprecated keys become errors after their announced removal release.

Each module owns typed config and validates required values, mutual exclusions, schemes, production controls, timeout/pool relationships, cookie/origin policy, TLS, secret presence, and unsupported runtime states.

## Secrets

Secrets:

- Use `SecretString` or equivalent.
- Avoid `Debug`, `Display`, serialization, traces, metrics, and error context.
- Are exposed only immediately before use.
- Come from production secret injection.
- Support rotation.
- Never appear in examples, snapshots, tests, or diagnostics.

Repositories may contain `${DATABASE_URL}`-style placeholders, never plausible keys.

## Diagnostics

`inspect-config` emits effective non-secret config, value sources, redacted secret presence/source, validation result, profile/modules, and development warnings. Output must be safe for incident attachment after review.

## Reload

Initial dynamic reload is limited to log filters, selected sampling, feature-provider refresh, and explicitly safe thresholds. Database URLs, signing keys, proxy ranges, origins, and policy changes require atomic module-specific support.

## Acceptance

- Invalid production cookie/origin policy fails startup.
- Unknown sensitive keys fail.
- Secret formatting never reveals values.
- Precedence tests are deterministic.
- Every profile has redacted example config.
