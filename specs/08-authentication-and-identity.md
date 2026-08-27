---
spec_id: OMNIUS-008
title: Authentication and Identity
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Authentication and Identity


## Canonical principal

All mechanisms map to:

```rust
pub struct Principal {
    pub subject_id: SubjectId,
    pub kind: PrincipalKind,
    pub tenant_id: Option<TenantId>,
    pub auth_method: AuthMethod,
    pub authenticated_at: OffsetDateTime,
    pub assurance: AssuranceLevel,
    pub scopes: Vec<Scope>,
}
```

Domain/application code never consumes raw cookies, JWT claims, OIDC types, or API-key rows.

## Browser sessions

Use `axum-login` with the compatible `tower-sessions` stack. Phase 0 selects a mutually compatible SQLx or Redis store; do not hand-write a store while a maintained one exists.

Defaults:

- Opaque high-entropy session identifier.
- `__Host-` cookie, `Secure`, `HttpOnly`, `Path=/`, no `Domain`.
- `SameSite=Lax` unless a documented flow requires otherwise.
- Idle and absolute expiry.
- Rotation after login, privilege change, recovery, password reset, or MFA enrollment.
- Revoke current/device/all sessions.
- Device/session metadata.
- Cleanup task.
- CSRF/origin protection.
- Authentication hash invalidating sessions after sensitive changes.

PostgreSQL is default for the authenticated API profile; Redis is optional when already required.

## Passwords

Use RustCrypto Argon2id and PHC strings. Calibrate on deployment hardware with a security minimum, unique random salt, optional managed pepper, rehash-on-login, constant-time library verification, generic errors, bounded input, optional breached-password adapter, and session invalidation after change.

Never implement a hash/KDF or comparison.

## Verification and recovery

Tokens are random, single-use, short-lived, purpose/subject scoped, stored hashed, rate-limited, invalidated after use/security change, and audited without the value. Recovery cannot be weaker than enrollment without explicit risk acceptance.

## JWT

Use `jsonwebtoken`. Allowlist algorithms; control `kid`; validate signature, issuer, audience, expiry, not-before, and required claims; apply bounded skew; distinguish token classes; cache/refresh JWKS safely; bound size; prevent algorithm confusion; map to `Principal`.

The kit is a resource server, not an authorization server.

Self-issued access tokens use asymmetric signing, short lifetime, key rotation/JWKS, and opaque hashed rotating refresh tokens with reuse detection and revocation linkage.

## OIDC/OAuth client

Use `openidconnect` and `oauth2`: Authorization Code + PKCE, state, nonce, issuer validation, JWKS rotation, exact redirect URIs, tightly controlled protocol redirects, proof for account linking, multiple identities, explicit unlink/recovery, and correct distinction between ID and access tokens.

Persist pending authorization secrets in shared server-side storage before redirecting the browser. Keep only an opaque handle in the server-side session, and atomically delete the shared record before callback validation so retries, failures, multiple instances, and restarts cannot replay a flow.

## API keys/service accounts

Use visible identifier plus secret; store only a hash; show once; record name, owner, scopes, tenant, expiry, last use; support overlap rotation and immediate revoke; distinguish service identities; audit lifecycle.

## Passkeys

Use `webauthn-rs` at or above security-fixed baseline. Validate RP ID/origins, persist ceremony state, define discoverable credential behavior, track counter/transports, require recent auth for lifecycle, and test multiple authenticators. Do not parse WebAuthn yourself.

## TOTP

Use `totp-rs`; encrypt seeds, confirm enrollment, bound skew, prevent replay, issue hashed one-time recovery codes, rate-limit verification, and represent resulting assurance in `Principal`.

## Security events

Emit safe typed events for login, logout, session lifecycle, password/recovery, identity link/unlink, API-key lifecycle, MFA/passkey lifecycle, refresh reuse, and administrative identity action. Never include credential material.
