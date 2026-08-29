---
spec_id: ADR-0004
title: Normalize Authentication into a Canonical Principal
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Normalize Authentication into a Canonical Principal


## Context

First-party browser sessions, bearer JWTs, OIDC identities, API keys, passkeys, and TOTP have different transport and lifecycle semantics. Application services should not duplicate authorization logic for each credential type.

## Decision

Every successful authentication mechanism produces the canonical `Principal`.

- Browser sessions use `axum-login` and its compatible `tower-sessions` stack.
- Passwords use RustCrypto Argon2id.
- JWT verification uses `jsonwebtoken`.
- OIDC/OAuth clients use `openidconnect` and `oauth2`.
- WebAuthn uses `webauthn-rs`.
- TOTP uses `totp-rs`.
- API keys are high-entropy opaque credentials stored by secure hash.
- Authorization consumes `Principal` and is enforced in application services.
- By default, the service kit is an OAuth resource server. The opt-in `auth-oidc` module is an upstream OpenID Connect relying party.
- The opt-in `auth-oauth-server` module is the sole first-party OAuth Authorization Server and OpenID Provider; identities and verified tokens it issues or accepts still map through `Principal`.

## Consequences

- Sessions and JWTs may coexist without duplicating business policy.
- Credential-specific fields do not leak into domain APIs.
- Assurance level and authentication time are explicit authorization inputs.
- Revocation semantics remain mechanism-specific.
- A user record may link multiple external identities.

## Validation

The conformance suite runs the same permission matrix using session, JWT, and API-key principals where applicable. Security tests cover rotation, revocation, expiration, CSRF, replay, issuer/audience validation, and cross-tenant access.
