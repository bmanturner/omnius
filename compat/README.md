# Compatibility harnesses

Nothing under `compat/` ships in production artifacts. These directories hold Phase 0 and web-workspace evidence that backs dependency admission decisions.

| Path | Purpose |
| --- | --- |
| `phase0/` | Non-production Phase 0 compatibility harness. Cargo package `omnius-phase0-compatibility` (`publish = false`); it is a workspace member so it builds and lints with the workspace, but no other crate depends on it. It is exempt from the production rules in `xtask/src/ai.rs` (`compatibility_harness`) and is referenced by `specs/machine/dependency-baseline.toml`. |
| `phase1/` | Only `minimal-profile-measurements.txt`; there is no code. |
| `web-w0/` | Node web workspace (`package.json`, `dependency-admission.md`) for the W0 frontend dependency evidence. |

Do not add production dependencies on `compat/phase0`.
