---
spec_id: ADR-0014
title: Use AWS-LC for JWT Verification
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Use AWS-LC for JWT Verification

## Context

The resource-server JWT capability uses the pinned `jsonwebtoken 11.0.0` crate. That release requires exactly one cryptographic backend. Its `rust_crypto` feature activates `rsa 0.9.10`, which is covered by RUSTSEC-2023-0071. Although the JWT capability performs only public-key signature verification and the advisory concerns private-key timing leakage, selecting that backend creates an active vulnerable dependency path and fails the workspace advisory policy.

The alternative `aws_lc_rs` feature provides the asymmetric verification algorithms required by RSK-008 without activating the affected RustCrypto RSA package. AWS-LC is already compatible with the workspace targets and keeps signature parsing and verification inside the approved `jsonwebtoken`/cryptographic-library boundary.

## Decision

Build `jsonwebtoken 11.0.0` with `default-features = false` and exactly the `aws_lc_rs` and `use_pem` features. The JWT module remains verifier-only, allowlists asymmetric algorithms, and never performs private-key signing.

Pin and vet the resulting AWS-LC build dependencies through the existing cargo-deny, cargo-vet, and cargo-audit gates. Keep the `untrusted 0.7` duplicate exception explicit until AWS-LC converges with the workspace's ring/webpki line. Any future backend change requires a new compatibility and advisory review rather than an unrecorded feature switch.

## Consequences

The active dependency graph avoids RUSTSEC-2023-0071 and uses AWS-LC's compiled native implementation for JWT verification. Builds now require the supported AWS-LC CMake toolchain and carry the corresponding vetted native dependencies. The separate inactive SQLx advisory exception in ADR-0012 remains narrowly scoped and does not authorize an active RSA path.
