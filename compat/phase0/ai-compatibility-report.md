# AI Dependency Compatibility Report

- Verified: 2026-08-29
- Toolchain: Rust 1.98.0, Cargo resolver 3
- Owning task: T151

## Decision

The exact LLM/MCP dependency baseline is admitted through the existing `omnius-phase0-compatibility` workspace member. The integrated lock contains the reviewed Rig 0.42.0 family, RMCP 3.1.4, Schemars 1.2.2, and jsonschema 0.51.0 graph. Provider and SDK types remain adapter-private; admission does not make any provider or MCP transport runtime-enabled.

| Dependency | Problem solved | Exact policy | License / MSRV | Decision |
|---|---|---|---|---|
| `schemars` 1.2.2 | Owned Rust-to-JSON-Schema generation | defaults off; `derive,std` | MIT / 1.74 | Admit |
| `jsonschema` 0.51.0 | Local Draft 2020-12 compilation and validation | defaults off; no remote retrieval | MIT / 1.85 | Admit |
| `rig-core` 0.42.0 | Direct OpenAI, Anthropic, Gemini, and OpenRouter adapter implementation | defaults off; `reqwest,rustls`; application contracts remain owned | MIT / upstream pins development to 1.94 but publishes no formal MSRV | Admit behind LLM adapters |
| `rig-agent` 0.42.0 | Bounded agent execution implementation | defaults off; **never** enable `rmcp` | MIT / no formal MSRV | Admit behind LLM adapter |
| `rig-bedrock` 0.42.0 | AWS Bedrock Converse companion adapter | separate profile-selected module; defaults off | MIT; AWS graph Apache-2.0 / resolved graph compiles on 1.98 | Admit only as optional companion |
| `rig-vertexai` 0.42.0 | Google Vertex AI companion adapter | separate profile-selected module; defaults off | MIT; Google graph Apache-2.0 / resolved graph compiles on 1.98 | Admit only as optional companion |
| `rmcp` 3.1.4 | Official MCP 2026-07-28 server SDK | defaults off; server, stdio, Streamable HTTP server, elicitation, request-state only | Apache-2.0 / 1.88 | Admit behind MCP adapters |

The standard library cannot replace multi-provider protocol normalization, JSON Schema evaluation, or the official MCP wire implementation. Hand-written provider or MCP clients were rejected because they would duplicate volatile wire protocols and weaken upstream conformance evidence. Competing provider frameworks and RMCP 2.x were rejected.

## Maintenance and implementation hotspots

- All Rig 0.42.0 crates resolve from upstream revision `d5a34986a1ad57f1e9c5984b82f8d7438ffc717e`. The published crates declare no formal MSRV; the upstream development toolchain is Rust 1.94, and the complete selected graph compiles on Omnius Rust 1.98. Rig upgrades require normalized provider-cassette and raw-output retention review.
- RMCP is the official Rust MCP SDK. Version 3.1.4 declares Rust 1.88, supports the suite's `2026-07-28` protocol, and contains the DNS-rebinding fix introduced before this version. Its build script can invoke `git config` only in a vendored two-level `.git/.githooks` layout; the crates.io build layout does not trigger that branch, and vendoring must preserve this review.
- Schemars 1.2.2 and jsonschema 0.51.0 declare Rust 1.74 and 1.85 respectively. Their reviewed revisions and exact checksums are retained in `Cargo.lock`; remote schema retrieval stays disabled.
- `rig-derive` and `schemars_derive` are the admitted proc-macro additions. RMCP macros remain disabled. Bedrock and Vertex bring separately reviewed AWS and Google credential/TLS graphs; they remain profile-selected companions and require the owned outbound, endpoint-allowlist, and workload-identity policies when adapters are implemented.


## Feature and protocol controls

- Rig defaults are prohibited: they enable system proxy discovery and a provider-selected TLS path that bypass the centralized outbound/TLS policy. Provider adapters must inject the approved HTTP boundary.
- `rig-agent`'s `rmcp` feature is prohibited. It resolves RMCP 2.x and the suite does not implement an MCP client.
- RMCP defaults are prohibited. `auth` is an outbound OAuth client and is not the inbound protected-resource implementation required by the suite; client transports and macros remain off.
- RMCP adapters must advertise only protocol `2026-07-28`, use `NeverSessionManager`, set `legacy_session_mode` false, require stateless protocol metadata, and preserve explicit Host/Origin allowlists.
- Deprecated Roots, Sampling, Logging, HTTP+SSE, sessions, and initialization behavior are not registered by any default profile.

## Integrated resolution

The compatibility member resolved and compiled the candidate graph on Rust 1.98.0. Foundational lines remained converged:

| Family | Resolved line |
|---|---|
| Tokio | 1.53.1 |
| Hyper | 1.11.0 |
| Axum | 0.8.9 |
| Tower | 0.5.3 |
| SQLx | 0.8.6 |
| rustls | 0.23.43 |
| Serde | 1.0.229 |
| OpenTelemetry / SDK | 0.32.0 / 0.32.1 |
| Reqwest | 0.13.4 |

Provider-isolated duplicates are explicit in `deny.toml`: AWS Bedrock requires `http` 0.2 and `http-body` 0.4; Rig requires `convert_case` 0.11 and `ordered-float` 5; RMCP requires `pastey` 0.2. Existing base64/SHA-2 and proc-macro transition lines remain classified. No second Tokio, Axum, Tower, SQLx, rustls, Serde, or OpenTelemetry line was admitted.

Resolved companion versions include `aws-config` 1.11.0, `aws-sdk-bedrockruntime` 1.142.0, `google-cloud-aiplatform-v1` 1.16.0, and `google-cloud-auth` 1.16.0. These crates stay out of profiles that do not select the corresponding companion module.

## Security and supply chain

- Direct source revisions reviewed: Rig `d5a34986a1ad57f1e9c5984b82f8d7438ffc717e`; RMCP `4a738b9dd99eaca418b614afa433a0cbdaf8d056`; Schemars `ed6186319d5ebf1959a03f558df375d2bb5c44a6`; jsonschema `b7fd606646d1e7faefa9c0411569ee2f6b6cb161`.
- Rig and RMCP production sources contain no direct unsafe blocks. Schemars forbids unsafe. jsonschema's vetted `bytecount` dependency contains its bounded SIMD unsafe implementation.
- RMCP 3.1.4 is outside the affected range for RUSTSEC-2026-0189. Exact Host/Origin policy remains mandatory.
- `cargo audit` scanned 879 locked dependencies. Its only warning is the pre-existing allowed `lru` 0.16.4 RUSTSEC-2026-0253 path through optional Async GraphQL; no AI dependency introduces it.
- The compatibility check also emits the existing ADR-0011 Apalis Redis 0.7.4 never-type fallback warning. That provider remains isolated on the pinned Rust 1.98 baseline and blocks a toolchain upgrade until a stable fixed Apalis release passes its conformance suite.
- `cargo-deny` passes advisories, bans, licenses, and sources. New duplicate exceptions are reason-bound to OMNIUS-ADR-0015 or OMNIUS-ADR-0019.
- `cargo-vet` succeeds after recording safe-to-deploy exemptions for the exact locked Rig, RMCP, AWS, Google, and support graph. Upgrades require new evidence rather than inheriting these versions' exemptions.

## Verified commands

```text
cargo check -p omnius-phase0-compatibility
cargo audit
cargo deny check
cargo vet --locked
cargo xtask ai verify
```

All five commands passed against the integrated graph during T151. `cargo xtask ai verify` is the permanent exact-pin, minimal-feature, direct-dependency ownership, public-type boundary, lifecycle-metadata, and deprecated-default guard.
