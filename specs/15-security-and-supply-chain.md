---
spec_id: OMNIUS-015
title: Security and Software Supply Chain
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Security and Software Supply Chain


## Threat model

Assume untrusted internet input, malicious authenticated users, compromised API keys, buggy providers, dependency vulnerabilities, and operator mistakes. Each module documents assets, trust boundaries, abuse cases, and controls.

## Build policy

Required:

- Committed `Cargo.lock`.
- crates.io releases only by default.
- Reviewed exact foundational baseline.
- Automated update PRs in bounded groups.
- `cargo-audit` on every PR and scheduled.
- `cargo-deny` for advisories, licenses, sources, bans/duplicates.
- `cargo-vet` policies/imports.
- CycloneDX SBOM.
- `cargo-semver-checks` for public crates.
- Provenance/attestation in release pipeline.
- Review of build scripts, proc macros, native libraries, and unsafe code.
- No ignored advisory without owner, applicability, mitigation, expiry, and ADR/risk entry.

## Dependency policy

Allowlist licenses compatible with intended distribution. Deny unknown/git sources by default. Treat duplicate foundational versions as errors unless explicitly permitted. Minimize enabled features and direct dependencies.

A new major line receives a compatibility spike before merge. Release candidates never become defaults solely to obtain compatibility.

## Application hardening

- Request/response limits and timeouts.
- Least-privilege DB/Redis/NATS/object/provider credentials.
- Separate migration and runtime DB roles where practical.
- Secure cookies, CSRF, origin policy.
- Token/JWK validation and key rotation.
- Central authorization.
- Tenant isolation.
- SSRF and upload controls.
- Safe error format and redaction.
- Audit trails.
- Idempotency/replay protection.
- Admin surface isolation.
- No public debug/profiling endpoints.

## Cryptography

Use established RustCrypto, rustls, WebAuthn, and JWT/OIDC libraries. No custom cryptographic primitive or protocol. Randomness comes from OS-backed CSPRNG. Algorithms/parameters are allowlisted and versioned.

## Secrets

Production secrets use a managed store/injection mechanism. Define rotation and overlap for DB/provider credentials, JWT signing keys, webhook secrets, encryption keys, and API keys. Avoid long-lived static cloud keys where workload identity exists.

## Data protection

Classify data and define encryption, access, log policy, retention, export, deletion, legal hold, and breach-response ownership. Encryption at rest does not replace authorization.

## Vulnerability response

The release process records dependency inventory and build provenance. A critical applicable advisory triggers triage, patched build, targeted tests, compatibility check, SBOM update, and release notes. Unsupported generated-service versions have a published policy.
