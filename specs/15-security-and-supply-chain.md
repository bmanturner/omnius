---
spec_id: OMNIUS-015
title: Security and Software Supply Chain
version: 0.1.0
status: normative
last_verified: 2026-09-03
---

# Security and Software Supply Chain


## Threat model

Assume untrusted internet input, malicious authenticated users, compromised API keys, buggy providers, dependency vulnerabilities, and operator mistakes. Each module documents assets, trust boundaries, abuse cases, and controls.

## Build policy

Required:

- Committed `Cargo.lock`.
- Reviewed exact foundational baseline and minimized enabled features/direct
  dependencies.
- Automated update PRs in bounded groups.
- `cargo-audit` on every PR and on a schedule.
- `cargo-deny` for advisories, licenses, sources, bans, and duplicates.
- `cargo-vet` policies/imports.
- CycloneDX SBOM and release provenance/attestation.
- `cargo-semver-checks` for public crates.
- Review of build scripts, proc macros, native libraries, and unsafe code.
- No ignored advisory without owner, applicability, mitigation, expiry, and an
  ADR or risk entry.

Allowlist licenses compatible with intended distribution. Deny unknown Git
sources by default and treat duplicate foundational versions as errors unless
explicitly permitted. A new major line receives a compatibility spike before
merge; release candidates never become defaults solely to obtain
compatibility.

## Generated-service framework provenance

The one deliberate Git dependency is the generated service's managed
`service-kit` alias. It must name package `omnius-service-kit`, use the exact
version, disable default features, select only the runtime-module features, and
use this source byte-for-byte:

```toml
git = "https://github.com/bmanturner/omnius.git"
rev = "<full-lowercase-40-hex-revision>"
```

Cargo's `version` requirement validates the package version at the commit; the
full immutable `rev` selects the commit. SSH or credentialed URLs, alternate
URL spellings, branches, tags, short/uppercase/non-hex revisions, paths,
registries, and mixed Omnius revisions are rejected. Generated manifests may
inherit this single declaration into members, but may not declare another
`omnius-*` package or the generator.

Strict schema-2 state binds the same canonical repository, complete revision,
framework version, profile/modules/features, ownership hashes, and semantic
lock identity. Validation recursively inspects workspace members and normal,
development, build, and target-specific dependency tables. It also rejects
manifest `[patch]`/`[replace]`, Cargo `paths`, and any dependency or source
substitution.

Before lifecycle resolution, every `.cargo/config` and `.cargo/config.toml` in
the exact staging directory's ancestor chain and effective `CARGO_HOME` is
inspected. Source replacement affecting canonical Omnius, Cargo paths, or an
Omnius patch/replace makes `doctor` non-clean and blocks every mutation.

## Bound tooling and sealed resolution

A mutating `cargo-service` command runs only from a clean build bound to an
immutable revision. The build records staged, unstaged, and non-ignored
untracked source state; dirty and unbound builds may run `--help`, `--version`,
`doctor`, and `diff`, but cannot run `new`, `add`, `remove`, `profile set`, or
`update`. Except for `update`, the CLI release must exactly match the project
release.

Each mutation acquires the project lifecycle lock, recovers any incomplete
transaction, and resolves once in an exact sibling stage. It records the
locked before graph, performs only the missing-lock or targeted framework
resolution required by the lifecycle operation, verifies the candidate with
`cargo metadata --format-version 1 --locked`, and seals exact lock bytes,
package graphs, expected input hashes, and file operations. The alias edge,
canonical service-kit package ID, all reachable `omnius-*` sources, and
state/manifest/revision agreement must match. Package-record changes are
limited to the union of the old and new dependency closures rooted at
`omnius-service-kit`; unrelated application packages must remain identical.
`--dry-run` performs the same resolution and sealing without applying it.

Apply never invokes Cargo. A durable, fsynced journal records the operation
order, expected hashes, and original bytes. Ordinary files are written first,
then `Cargo.lock`, then schema-2 state, each by fsync plus rename with directory
fsync. Recovery after interruption restores the complete old identity or
finishes the complete sealed new identity; stale inputs fail before writes.

Lifecycle `--offline` means cache-only Cargo resolution from the canonical
source. It is not vendoring. Vendoring is permitted only as an explicit
build/deployment preparation:

```console
cargo vendor --locked
cargo build --locked --offline
```

The emitted source-replacement configuration deliberately makes provenance
non-clean, so `doctor` reports it and every lifecycle mutation remains blocked
until that configuration is removed. Do not commit a vendor tree or claim that
vendored preparation changes the canonical lock source.

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
