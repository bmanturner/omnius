---
spec_id: ADR-0012
title: Bound the Inactive SQLx RSA Advisory Exception
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Bound the Inactive SQLx RSA Advisory Exception

## Context

`cargo-audit` scans every package recorded in `Cargo.lock`. SQLx 0.8.6 records its optional MySQL driver, which records `rsa 0.9.10` and therefore RUSTSEC-2023-0071, even when only the PostgreSQL driver is enabled. The advisory has no fixed release. `cargo tree --target all -i rsa@0.9.10` is empty for the all-feature workspace graph: no selected target or feature compiles the package, and the service kit performs no RSA operation through SQLx.

## Decision

Temporarily ignore RUSTSEC-2023-0071 in `.cargo/audit.toml` with Security ownership and an expiry of 2026-11-23. The exception is valid only while all of these statements remain true:

- SQLx is configured without MySQL features.
- The all-target active dependency graph has no path to `rsa 0.9.10`.
- `cargo-deny` independently reports no active advisory.
- No workspace crate adds a direct or transitive active use of the affected RSA release.

CI checks RSA reachability before running `cargo-audit`. An active path fails the build and invalidates this exception. Review the exception before its expiry and remove it as soon as SQLx stops locking the affected optional package or RustSec publishes a fixed compatible path.

## Consequences

The locked package remains visible in SBOM and audit output policy, but it is not shipped. The exception cannot be copied to another advisory or extended without a fresh applicability review, owner, mitigation, expiry, and ADR/risk update.
