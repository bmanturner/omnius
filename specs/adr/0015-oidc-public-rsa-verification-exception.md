---
spec_id: ADR-0015
title: Bound the OIDC Public RSA Verification Exception
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Bound the OIDC Public RSA Verification Exception

## Context

The pinned `openidconnect 4.0.1` crate implements standards-compliant OpenID Connect discovery and ID-token validation, and unconditionally activates `rsa 0.9.10` for RSA signature verification. That release is covered by RUSTSEC-2023-0071 because its private-key operations can leak private-key information through timing. The production OIDC adapter supplies only provider-published public JWKs and performs verification; it never constructs, imports, stores, or uses an RSA private key through this dependency. The non-shipping phase-0 compatibility crate names `openidconnect` directly only to keep the pinned dependency compilable in the baseline graph and contains no RSA operation. No patched `rsa` release or selectable alternative verification backend is available through the pinned `openidconnect` release.

## Decision

Temporarily accept the active `rsa 0.9.10` path only for public-key verification performed by `openidconnect 4.0.1`. Ignore RUSTSEC-2023-0071 in `cargo-deny` and `cargo-audit` with Security ownership and an expiry of 2026-11-23. The exception is valid only while all of these statements remain true:

- the only parents of `openidconnect 4.0.1` on the active workspace path are `rsk-auth-oidc` and the non-shipping, code-free `rsk-phase0-compatibility` dependency probe;
- the OIDC adapter performs public-key signature verification only;
- no workspace code passes RSA private-key material into `openidconnect` or `rsa`;
- OIDC provider keys come from validated discovery/JWKS responses and are never generated locally; and
- no compatible patched `openidconnect` release or alternative backend is available.

CI must continue to assert that exact dependency path and run the full advisory scanners. Security reviews the exception before its expiry and removes it as soon as the pinned OIDC library can avoid the affected release. Any private-key operation, unapproved active dependency path, or broadened use invalidates this decision.

## Consequences

The shipped graph contains a crate release named by a critical advisory, but the vulnerable private-key operation and secret required for exploitation are absent. Public verification remains delegated to the pinned OIDC library rather than reimplemented locally. The separate inactive SQLx exception in ADR-0012 remains independently bounded; this decision does not authorize private RSA operations or any other advisory.
