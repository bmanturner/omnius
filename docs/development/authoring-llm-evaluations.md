---
title: Authoring LLM evaluations
description: Workflow for deterministic, content-safe LLM evaluation datasets, assertions, replay, admission, and property tests.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: not-applicable
audience:
  - ai-contributor
  - evaluator
  - maintainer
  - security-reviewer
topics:
  - llm
  - evaluations
  - conformance
  - fixtures
capabilities: []
source:
  - crates/llm-evals/src/dataset.rs
  - crates/llm-evals/src/runner.rs
  - crates/llm-evals/src/report.rs
evidence:
  - crates/llm-evals/tests/evaluation.rs
  - crates/llm-evals/tests/offline_fixtures.rs
  - crates/llm-evals/tests/report_admission.rs
  - crates/llm-evals/tests/properties.rs
last_verified: 2026-08-30
---

# Authoring LLM evaluations

The `omnius-llm-evals` crate is non-published evaluation tooling. It validates bounded datasets, deterministic assertions, replay, and content-free evidence reports. It is not a CLI, application host, live provider benchmark, or production admission service.

Read [Evaluations and conformance](../guides/ai/evaluations-and-conformance.md) for the operator-facing model, [Adding an LLM provider](./adding-an-llm-provider.md) for adapter requirements, and [LLM safety and data governance](../security/llm-safety-and-data-governance.md) before adding a corpus.

## Dataset contract

The dataset schema version is `1.0.0`. A dataset is bounded by case-count and byte-size limits and must identify its exact evaluation route, provider, model, and model revision. Prompt content is addressed by content hash rather than copied into reports.

Every case needs at least one deterministic assertion and positive deadline and cost ceilings. This prevents an evaluation from passing merely because a request returned something.

Supported deterministic assertions include:

- response content SHA equality;
- JSON Pointer presence;
- JSON Pointer equality;
- numeric microunit equality within a declared tolerance.

Optional comparisons can describe controlled pairwise evaluation. A model-judge assertion is acceptable only with calibrated, content-addressed evidence, a declared tolerance, and an optional deterministic blind seed. A judge must not replace deterministic assertions.

## Choose the correct fixture corpus

Checked-in fixture families live below `crates/llm-evals/fixtures/`, including:

- `provider-contracts/v1` for provider normalization and compatibility cases;
- `adversarial/v1` for bounded hostile or malformed inputs.

Add a case to the narrowest existing versioned corpus when its schema and purpose fit. A schema or semantic break requires a new corpus version rather than mutating historical replay expectations.

Fixtures must be synthetic, minimal, content-addressed, and free of credentials, production prompts, customer content, raw provider logs, and personal data.

## Author a deterministic case

1. Fix the provider, model, model revision, and evaluation route.
2. Store prompt/response fixture content in the appropriate versioned corpus.
3. Compute and record the content reference through the repository's hashing implementation.
4. Add at least one deterministic assertion tied to the behavior under review.
5. Set a positive request deadline and cost ceiling.
6. Add a comparison only when it answers a stated compatibility question.
7. If a model judge is necessary, add calibration evidence and tolerance without removing deterministic checks.
8. Keep report metadata content-free.
9. Add or update replay and admission expectations.

Do not make a test depend on a current external provider response. Provider model behavior can change independently of the repository and is not deterministic CI evidence.

## Run evaluation contract tests

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain. Tests use checked-in offline fixtures and require no provider credentials or network access.

```bash
cargo test -p omnius-llm-evals --test evaluation
cargo test -p omnius-llm-evals --test offline_fixtures
```

**Expected result:** dataset validation, bounded execution semantics, deterministic assertions, and offline fixture contracts pass.

**Failure path:** fix the dataset schema, bounds, content reference, assertion, or fixture. Do not add network access or loosen determinism to accept a changing provider response.

## Run replay and admission tests

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain and unchanged versioned fixture inputs. No live provider credentials are required.

```bash
cargo test -p omnius-llm-evals --test corpus_replay
cargo test -p omnius-llm-evals --test report_admission
```

**Expected result:** versioned corpora replay with their declared semantics, and content-free reports satisfy admission rules and canonical hashing/version requirements.

**Failure path:** distinguish an intentional corpus version change from accidental fixture drift. Preserve historical corpus versions; create a new version when interpretation changes. Never make admission accept content-bearing or unhashed reports.

## Run property tests

Run from the repository root.

**Prerequisites:** the pinned Rust toolchain. Property tests must remain deterministic and bounded under the repository test scheduler.

```bash
cargo test -p omnius-llm-evals --test properties
```

**Expected result:** generated inputs preserve dataset, hashing, bounds, report, and assertion invariants covered by the property suite.

**Failure path:** minimize the failing case, fix the invariant, and retain it as regression evidence where the existing property strategy does not already preserve it.

## Report safety

Evaluation reports are content-free evidence. They may carry canonical hashes, schema/version metadata, route/provider/model identifiers, results, timing, and bounded cost accounting defined by the report schema. They must not embed prompts, responses, credentials, raw provider payloads, or hidden judge content.

A report hash proves the canonical report bytes. It does not prove that a live provider is currently available, that a deployment uses the evaluated model, or that release policy accepted the result.

## Review checklist

Before accepting a new evaluation, confirm:

- exact provider, model, revision, route, and corpus version;
- authoritative capability evidence for the assertion;
- positive deadline and cost ceiling;
- at least one deterministic assertion;
- bounded fixture and dataset size;
- content-addressed prompt and response material;
- synthetic, secret-free, non-customer fixture content;
- stable replay semantics;
- calibrated evidence for any model judge;
- content-free canonical report behavior;
- failure messages that are useful but redacted;
- no hidden dependency on network availability or wall-clock ordering.

## Compatibility expectations

Dataset schema, assertion meaning, canonical hashing, report schema, corpus interpretation, and admission policy are compatibility-sensitive. Version semantic changes and retain old replay fixtures. New assertion kinds require parser, runner, report, property, and admission coverage.

## Evidence boundary

The evaluation crate and tests establish offline tooling contracts. They do not provide an operator CLI, application wiring, a public endpoint, live-provider conformance, or release authorization.