---
title: Evaluations and conformance
description: Deterministic datasets, offline provider fixtures, assertions, judge limitations, report admission, and release-evidence boundaries.
status: experimental
implementation: implemented
profile_availability:
  - llm-runtime
  - llm-api
  - llm-agent
  - ai-worker
  - ai-platform
  - full-reference-ai
public_exposure: not-applicable
audience:
  - evaluator
  - ai-application-developer
  - release-engineer
topics:
  - llm
  - evaluations
  - conformance
  - fixtures
  - release-gates
capabilities:
  - llm-evals
source:
  - crates/llm-evals/src/dataset.rs
  - crates/llm-evals/src/runner.rs
  - crates/llm-evals/src/offline.rs
  - crates/llm-evals/src/report.rs
  - crates/llm-evals/src/hashing.rs
evidence:
  - crates/llm-evals/tests/evaluation.rs
  - crates/llm-evals/tests/report_admission.rs
  - crates/llm-evals/tests/corpus_replay.rs
  - crates/llm-evals/tests/properties.rs
  - crates/llm-evals/tests/offline_fixtures.rs
  - crates/llm-evals/fixtures/provider-contracts/v1/manifest.json
  - crates/llm-evals/fixtures/adversarial/v1/regressions.json
last_verified: 2026-08-30
---

# Evaluations and conformance

`llm-evals` is an experimental, implemented evaluation library selected by all six LLM extension profiles. Its public exposure is **not applicable** because evaluation is an evidence workflow rather than a public application surface.

No evaluation result is reported as run for this documentation revision.

## Reproducible evaluation identity

An evaluation result is meaningful only when it binds the inputs and execution policy that produced it. Preserve:

- dataset identity, version, and canonical hash;
- case identity and deterministic ordering;
- exact prompt revision and execution-policy revision;
- model/provider identity admitted by policy;
- evaluator and assertion revisions;
- offline cassette or live-run classification;
- seed and blinded ordering when a judge comparison uses them;
- content-free environment and provenance metadata.

A mutable dataset name, prompt alias, or model family is not enough to reproduce a result.

## Deterministic assertions first

Run deterministic checks before any model judge. Suitable checks include schema validity, exact expected state, bounded numeric/string invariants, refusal class, citation presence, allowed tool plan, stream terminal validity, redaction, and capability-selection outcome.

A judge model can score qualities that deterministic assertions cannot express, but it remains a fallible model. Use a fixed rubric, seeded and blinded ordering, explicit admissible outputs, and a separate usage budget. Judge disagreement, refusal, malformed output, or missing capability is an evaluation outcome—not permission to invent a score.

Model judging is not ground truth and must never override a deterministic safety, authorization, schema, or conformance failure.

## Offline fixtures

Versioned provider cassettes allow deterministic replay without credentials or network access. The fixture set includes provider-contract and adversarial corpora. Fixture data must be synthetic or explicitly admitted; do not capture production prompts, outputs, credentials, personal data, private reasoning, or provider wire payloads into a cassette.

Offline replay can prove that parsers, normalization, assertions, report admission, and known regressions behave against those bytes. It cannot prove:

- current provider availability or behavior;
- credentials, region, quota, or model access;
- runtime composition or public HTTP exposure;
- pricing, latency, throughput, or provider-side retention;
- a production safety, routing, media, tool, or budget policy;
- interoperability beyond the captured fixture revision.

## Capability and failure coverage

A conformance corpus should include negative cases, not only good answers. Cover required-capability mismatch, fallback rejection, retry exhaustion under one deadline, malformed and unknown content, refusal, structured-output failure, stream ordering and missing terminal, unauthorized or unapproved tools, ambiguous usage, redaction, unsafe egress, oversized media/content, and cancellation.

The expected outcome for many cases is rejection. A system that obtains an answer by weakening the requirement has failed conformance.

## Report admission

Reports are another data boundary. Admission validates bounded structure and canonical provenance before a result can be compared or promoted. Reports should carry safe aggregate outcomes and reason codes rather than raw model content.

Reject a report when:

- required hashes or revisions are absent or inconsistent;
- an input, output, diagnostic, or metadata field exceeds its bound;
- content violates redaction/admission policy;
- deterministic assertions did not complete;
- judge output is malformed or outside the rubric;
- fixture/live classification is ambiguous;
- the report claims a capability or runtime surface the evidence did not exercise.

A release runbook describes a process. It is not an admitted report, passing result, or promoted artifact.

## Current evidence limitations

Repository evidence does **not** establish:

- an `llm_eval_runs` migration or durable evaluation repository;
- an application, CLI, operator workflow, or administrative UI invoking the library;
- a CI job that ran these evaluations for this revision;
- retained provider-contract results for live accounts;
- a signed release decision or successful release gate;
- runtime assembly of any profile that selects `llm-evals`.

Accordingly, do not present the focused tests, fixtures, profile selection, or `release/ai-mcp-suite-runbook.md` as current conformance results.

## Review sequence

For an evaluation proposal, first inspect the dataset and redaction policy, then the deterministic assertions, offline fixtures, judge rubric, budget, and report-admission requirements. The expected artifact is a bounded, revision-bound report whose claims are no broader than the exercised fixture or live environment. A failed admission or missing provenance blocks comparison and release use.

See [authoring LLM evaluations](../../development/authoring-llm-evaluations.md), [compatibility and release gates](../../development/compatibility-and-release-gates.md), [LLM provider operations](../../operations/llm-provider-operations.md), and [safety and media](safety-and-media.md).
