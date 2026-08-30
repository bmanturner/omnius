---
spec_id: ADR-0033
title: Align LLM and MCP Task Acceptance Ownership
version: 0.1.0
status: accepted
last_verified: 2026-08-29
---

# Align LLM and MCP Task Acceptance Ownership

## Context

The extracted LLM/MCP task catalog mechanically assigned four consecutive acceptance criteria to every task. That allocation conflicts with the dependency graph and the normative subjects of specifications 35, 46, 47, 48, and 49.

`T150` is limited to append-only overlay integration, but it was assigned registry, SDK-boundary, and runtime-observability behavior that can exist only after `T151`. The integration handoff also requires the Phase A0 dependency and protocol compatibility gate before provider or MCP implementation, while the machine task title omitted that output.

The same mechanical allocation rotates criteria after `T172`: task persistence criteria land on MRTR, subscription criteria land on Tasks, Apps criteria land on subscriptions, conformance criteria land on preview modules, and profile/generator criteria land on the conformance task. Completing those tasks under the extracted mapping would require implementing later tasks before their declared dependencies and would make task-level evidence misleading.

## Decision

Keep every stable task and acceptance identifier. Amend only task scope, dependency, and acceptance ownership so the first dependency-ordered task capable of producing each behavior owns its evidence:

| Task | Effective acceptance ownership |
|---|---|
| `T150` | `AC-AI-001` |
| `T151` | `AC-AI-002` through `AC-AI-008` |
| `T172` | `AC-AI-089`, `AC-AI-090` |
| `T173` | `AC-AI-091` through `AC-AI-093` |
| `T174` | `AC-AI-094` through `AC-AI-096` |
| `T175` | `AC-AI-097` through `AC-AI-099` |
| `T176` | `AC-AI-100` through `AC-AI-104` |
| `T177` | `AC-AI-107`, `AC-AI-108`, `AC-AI-111` |
| `T178` | `AC-AI-105`, `AC-AI-106`, `AC-AI-109`, `AC-AI-110`, `AC-AI-112` |
| `T179` | `AC-AI-113` through `AC-AI-120` |

All other task-to-criterion mappings remain unchanged.

`T151` also owns the Phase A0 dependency-admission and compatibility evidence required before provider or MCP production modules begin. Its effective dependencies include `T001`, `T004`, and `T023` in addition to the existing runtime, identity, authorization, and overlay prerequisites. This does not satisfy later provider cassette, RMCP conformance, or release criteria early; it establishes the coherent admitted graph and shared registry boundary those tasks require.

## Consequences

- No task, criterion, recommendation, module, profile, migration, or public contract identifier is removed or renumbered.
- `T150` can be completed without implementing its dependent registry task.
- Tasks, subscriptions, Apps, previews, test suites, conformance, and release evidence are verified by the task that implements the corresponding normative behavior.
- Every `AC-AI-*` criterion still has exactly one AI task owner.
- Existing one-to-one `REC-AI-*` to `AC-AI-*` mappings remain unchanged; this amendment changes execution ownership, not recommendation meaning.
- Validators must reject regression to the mechanically rotated mapping.

## Risk and traceability

Risk `R-AI-037` tracks future drift between task titles, normative specification subjects, and acceptance ownership. `LLM_MCP_FEATURE_SUITE_TRACEABILITY.md` records the effective task allocation while preserving all existing recommendation mappings.

## Validation

- The merged task graph is acyclic and every dependency precedes its consumer.
- Every `AC-AI-001` through `AC-AI-120` is referenced by exactly one AI task.
- Task output subjects and criterion specifications agree for the amended ranges.
- Base, web, LLM/MCP, and Rust `cargo xtask specs verify` validators pass on the final merged tree.
