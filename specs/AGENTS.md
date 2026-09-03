---
spec_id: OMNIUS-AGENT
title: Autonomous Implementation Agent Contract
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Autonomous Implementation Agent Contract


## Mission

Build the service kit described by this bundle. Optimize for a small, secure, coherent system whose supported combinations are continuously proven, not for producing the most code.

## Non-negotiable rules

1. **Run Phase 0 first.** Create a disposable compatibility workspace, resolve the proposed graph, and record actual versions plus duplicate Tokio, Hyper, Axum, Tower, SQLx, rustls, Serde, and OpenTelemetry lines.
2. **Never substitute silently.** A crate, version line, backend, authentication approach, or architecture change requires an ADR and traceability update.
3. **Do not hand-roll established infrastructure.** Do not create a custom framework, session engine, JWT/JWK parser, OAuth/OIDC implementation, password hash, WebAuthn implementation, object-store client, webhook delivery system, migration engine, observability protocol, or durable queue.
4. **Thin adapters are expected.** Project code may normalize a crate behind a narrow port, add configuration/lifecycle/telemetry, coordinate a transaction, or enforce application semantics.
5. **Compile at every task boundary.**
6. **Test real infrastructure.** Mocks alone are insufficient for PostgreSQL, Redis, NATS, object storage, migrations, cookies, auth flows, and shutdown.
7. **Use secure defaults.** Development relaxations must be explicit and impossible to activate accidentally in production.
8. **Leave no placeholders.** Production paths contain no placeholder macro, unimplemented production path, panic-based normal error handling, disabled security control, or plausible credential.
9. **No project-authored unsafe code** without a security ADR and focused review.
10. **Preserve data.** Removing a module never automatically reverses migrations, drops tables, deletes objects, or erases audit history.
11. **Protect application-owned code.** Generator changes are limited to kit-owned files and declared managed regions.
12. **Use UTC internally.**
13. **Default deny** on missing identity, missing tenant, unknown permission, malformed forwarded data, invalid signature, and ambiguous security configuration.

## Dependency admission gate

Before adding a direct dependency, record:

- The problem it solves.
- Why the standard library or an existing selected crate is insufficient.
- Latest stable release and proposed baseline.
- License and source.
- MSRV and toolchain fit.
- Release/maintenance activity.
- Documentation quality.
- Security advisories and unsafe-code footprint.
- Foundational dependencies it duplicates.
- Alternatives considered.
- Profiles/modules that require it.

A dependency MUST NOT enter a default profile without an ADR if it:

- Is only usable as a release candidate or prerelease.
- Forces a second incompatible foundational runtime/data/telemetry line.
- Is archived, effectively abandoned, or materially undocumented.
- Uses a denied license or unreviewed git source.
- Duplicates a selected foundational capability.
- Has a known unmitigated advisory affecting enabled code.

## Required repository commands

The implementation MUST expose equivalent commands through `cargo xtask`:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --locked
cargo test --doc --workspace --locked
cargo check --workspace --all-targets --locked
cargo deny check
cargo audit
cargo vet
cargo cyclonedx --all
cargo semver-checks
cargo xtask profiles verify
cargo xtask specs verify
cargo xtask migrations verify
```

`--all-features` is not a substitute for profile testing. Cargo features are additive and can conceal invalid combinations.

## Code rules

- `thiserror` for reusable/domain errors; `anyhow` only in binaries and operational tooling.
- HTTP types, SQLx row types, provider SDK types, and crate-specific auth types do not leak into domain services.
- No global `AppState` full of `Option<T>`.
- No generic repository trait without two real implementations or a demonstrated test seam.
- Reuse configured clients and pools.
- Bound request bodies, frames, queues, concurrency, pagination, retries, and retention.
- Every retry documents safety/idempotency.
- Every long-lived task is supervised, observable, cancellable, and drained.
- Every externally supplied URL passes centralized SSRF policy.
- Every log/trace field and metric label is assessed for secrets, PII, and cardinality.
- Public module APIs are documented and semver-checked.
- Production code avoids `unwrap()`; `expect()` is limited to statically proven invariants and includes a precise message.

## Task protocol

For every task:

1. Read its dependencies and acceptance IDs.
2. State affected contracts/files in the task record.
3. Implement tests with the behavior.
4. Run the smallest relevant command set.
5. Run profile verification at phase end.
6. Update generated docs/examples.
7. Update traceability when scope changes.
8. Commit atomically using the task ID.

Recommended subject:

```text
<type>(<module>): <imperative summary> [T###]
```

## Stop conditions

Stop and create a blocking ADR/risk when:

- The dependency graph cannot resolve coherently.
- A required integration has no stable compatible release.
- Implementation would weaken a security invariant.
- A migration cannot support rolling deployment.
- Correctness would depend on an unbounded queue or best-effort delivery.
- A generator action could overwrite application code.
- A recommendation cannot be implemented or verified as specified.

Do not resolve a stop condition by silently implementing a replacement framework.
