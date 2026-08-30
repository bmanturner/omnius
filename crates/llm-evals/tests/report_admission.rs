//! Adversarial admission contracts for serialized evaluation reports.
#![allow(
    clippy::expect_used,
    reason = "fixed adversarial fixture setup must fail immediately when malformed"
)]

use std::fmt::Write as _;

use omnius_llm_evals::{EvaluationReport, ReportAdmissionError, ReportBounds};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_BYTES: usize = 64 * 1024;
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SHA_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const SHA_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn bounds(
    max_bytes: usize,
    max_cases: usize,
    max_executions_per_case: usize,
    max_assertions_per_case: usize,
    max_route_capabilities: usize,
    max_identifier_bytes: usize,
    max_diagnostic_source_bytes: u64,
) -> ReportBounds {
    ReportBounds::new(
        max_bytes,
        max_cases,
        max_executions_per_case,
        max_assertions_per_case,
        max_route_capabilities,
        max_identifier_bytes,
        max_diagnostic_source_bytes,
    )
    .expect("positive report bounds")
}

fn generous_bounds() -> ReportBounds {
    bounds(MAX_BYTES, 8, 2, 8, 8, 160, 1_024)
}

fn execution(role: &str, input_tokens: u64, output_tokens: u64, cost: u64) -> Value {
    json!({
        "role": role,
        "evidence": {
            "route": {
                "id": "chat",
                "revision": 1,
                "required_capabilities": [],
                "preferred_capabilities": []
            },
            "provider": "offline",
            "model": "fixture-model",
            "model_revision": "revision-1"
        },
        "input_sha256": SHA_B,
        "response_sha256": SHA_C,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_microunits": cost
        }
    })
}

fn valid_report() -> Value {
    let mut report = json!({
        "schema_version": "1.0.0",
        "runner_version": "1.0.0",
        "dataset_id": "dataset",
        "dataset_version": "version-1",
        "dataset_sha256": SHA_A,
        "executor_evidence_sha256": null,
        "judge_evidence_sha256": null,
        "reproducibility_sha256": SHA_D,
        "cases": [{
            "case_id": "case-1",
            "outcome": "passed",
            "executions": [execution("primary", 10, 20, 30)],
            "assertions": [{
                "id": "response-sha",
                "target": "primary",
                "passed": true
            }],
            "judge": null,
            "rejected_judge": null,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cost_microunits": 30
            },
            "unattributed_usage": {
                "input_tokens": null,
                "output_tokens": null,
                "cost_microunits": 0
            },
            "diagnostic": null
        }],
        "totals": {
            "passed": 1,
            "failed": 0,
            "timed_out": 0,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cost_microunits": 30
            }
        }
    });
    refresh_reproducibility(&mut report);
    report
}

fn add_failing_judge(report: &mut Value, score_microunits: u64) {
    report["cases"][0]["outcome"] = json!("failed");
    report["cases"][0]["judge"] = json!({
        "methodology_id": "pairwise",
        "methodology_version": "version-1",
        "rubric_sha256": SHA_D,
        "calibration": {
            "dataset_id": "judge-calibration",
            "dataset_version": "version-1",
            "evidence_sha256": SHA_E
        },
        "evidence": {
            "route": {
                "id": "judge",
                "revision": 1,
                "required_capabilities": [],
                "preferred_capabilities": []
            },
            "provider": "offline",
            "model": "fixture-judge",
            "model_revision": "revision-1"
        },
        "score_microunits": score_microunits,
        "passed": false,
        "blinded": false,
        "order_sha256": SHA_E,
        "usage": {
            "input_tokens": 1,
            "output_tokens": 2,
            "cost_microunits": 5
        }
    });
    report["cases"][0]["usage"] = usage(11, 22, 35);
    report["totals"]["passed"] = json!(0);
    report["totals"]["failed"] = json!(1);
    report["totals"]["usage"] = usage(11, 22, 35);
    refresh_reproducibility(report);
}

fn usage(input_tokens: u64, output_tokens: u64, cost_microunits: u64) -> Value {
    json!({
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_microunits": cost_microunits
    })
}

fn encoded(report: &Value) -> Vec<u8> {
    serde_json::to_vec(report).expect("report JSON encoding")
}

fn admit_report(
    bytes: &[u8],
    bounds: ReportBounds,
) -> Result<EvaluationReport, ReportAdmissionError> {
    let value: Value = serde_json::from_slice(bytes).expect("report JSON decoding");
    let trusted_sha256 = canonical_sha256(&value);
    EvaluationReport::from_json(bytes, &trusted_sha256, bounds)
}

fn refresh_reproducibility(report: &mut Value) {
    let material = json!({
        "runner_version": report["runner_version"].clone(),
        "dataset_sha256": report["dataset_sha256"].clone(),
        "executor_evidence_sha256": report["executor_evidence_sha256"].clone(),
        "judge_evidence_sha256": report["judge_evidence_sha256"].clone(),
        "cases": report["cases"].clone()
    });
    report["reproducibility_sha256"] = Value::String(canonical_sha256(&material));
}

fn canonical_sha256(value: &Value) -> String {
    let mut canonical = value.clone();
    canonicalize(&mut canonical);
    let bytes = serde_json::to_vec(&canonical).expect("canonical JSON encoding");
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

fn canonicalize(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(canonicalize),
        Value::Object(object) => {
            let mut entries = std::mem::take(object).into_iter().collect::<Vec<_>>();
            for (_, nested) in &mut entries {
                canonicalize(nested);
            }
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            object.extend(entries);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[test]
fn from_json_accepts_consistent_runner_report() {
    let bytes = encoded(&valid_report());

    let report =
        admit_report(&bytes, generous_bounds()).expect("consistent report should be admitted");

    assert_eq!(report.totals().passed(), 1);
}

#[test]
fn from_json_rejects_report_bytes_outside_trusted_digest() {
    let trusted_sha256 = canonical_sha256(&valid_report());
    let mut report = valid_report();
    report["cases"][0]["usage"]["cost_microunits"] = json!(0);
    let bytes = encoded(&report);

    let error = EvaluationReport::from_json(&bytes, &trusted_sha256, generous_bounds())
        .expect_err("modified report must differ from its trusted digest");

    assert_eq!(error, ReportAdmissionError::TrustedDigestMismatch);
}

#[test]
fn from_json_rejects_forged_totals() {
    let mut report = valid_report();
    report["totals"]["passed"] = json!(0);
    report["totals"]["failed"] = json!(1);

    let error = admit_report(&encoded(&report), generous_bounds())
        .expect_err("forged totals must be rejected");

    assert_eq!(error, ReportAdmissionError::InconsistentTotals);
}

#[test]
fn from_json_rejects_forged_reproducibility_digest() {
    let mut report = valid_report();
    report["reproducibility_sha256"] = Value::String("0".repeat(64));

    let error = admit_report(&encoded(&report), generous_bounds())
        .expect_err("forged reproducibility digest must be rejected");

    assert_eq!(error, ReportAdmissionError::ReproducibilityMismatch);
}

#[test]
fn from_json_rejects_uppercase_sha256_evidence() {
    let mut report = valid_report();
    report["cases"][0]["executions"][0]["input_sha256"] = Value::String(SHA_B.to_ascii_uppercase());
    refresh_reproducibility(&mut report);

    let error = admit_report(&encoded(&report), generous_bounds())
        .expect_err("uppercase digest evidence must be rejected");

    assert_eq!(error, ReportAdmissionError::InvalidDigest);
}

#[test]
fn from_json_rejects_source_larger_than_byte_bound() {
    let bytes = encoded(&valid_report());
    let admission_bounds = bounds(bytes.len() - 1, 8, 2, 8, 8, 160, 1_024);

    let error = admit_report(&bytes, admission_bounds)
        .expect_err("oversized report source must be rejected");

    assert_eq!(error, ReportAdmissionError::TooManyBytes);
}

#[test]
fn from_json_rejects_excessive_case_count() {
    let mut report = valid_report();
    let mut second = report["cases"][0].clone();
    second["case_id"] = json!("case-2");
    report["cases"]
        .as_array_mut()
        .expect("cases array")
        .push(second);
    report["totals"]["passed"] = json!(2);
    report["totals"]["usage"] = usage(20, 40, 60);
    refresh_reproducibility(&mut report);
    let admission_bounds = bounds(MAX_BYTES, 1, 2, 8, 8, 160, 1_024);

    let error = admit_report(&encoded(&report), admission_bounds)
        .expect_err("excessive case count must be rejected");

    assert_eq!(error, ReportAdmissionError::CaseCount);
}

#[test]
fn from_json_rejects_excessive_execution_count() {
    let mut report = valid_report();
    report["cases"][0]["executions"]
        .as_array_mut()
        .expect("executions array")
        .push(execution("comparison", 1, 2, 3));
    report["cases"][0]["usage"] = usage(11, 22, 33);
    report["totals"]["usage"] = usage(11, 22, 33);
    refresh_reproducibility(&mut report);
    let admission_bounds = bounds(MAX_BYTES, 8, 1, 8, 8, 160, 1_024);

    let error = admit_report(&encoded(&report), admission_bounds)
        .expect_err("excessive execution count must be rejected");

    assert_eq!(error, ReportAdmissionError::ExecutionCount);
}

#[test]
fn from_json_rejects_excessive_assertion_count() {
    let mut report = valid_report();
    report["cases"][0]["assertions"]
        .as_array_mut()
        .expect("assertions array")
        .push(json!({
            "id": "response-sha-2",
            "target": "primary",
            "passed": true
        }));
    refresh_reproducibility(&mut report);
    let admission_bounds = bounds(MAX_BYTES, 8, 2, 1, 8, 160, 1_024);

    let error = admit_report(&encoded(&report), admission_bounds)
        .expect_err("excessive assertion count must be rejected");

    assert_eq!(error, ReportAdmissionError::AssertionCount);
}

#[test]
fn from_json_rejects_excessive_route_capability_count() {
    let mut report = valid_report();
    report["cases"][0]["executions"][0]["evidence"]["route"]["required_capabilities"] =
        json!(["chat", "tools"]);
    refresh_reproducibility(&mut report);
    let admission_bounds = bounds(MAX_BYTES, 8, 2, 8, 1, 160, 1_024);

    let error = admit_report(&encoded(&report), admission_bounds)
        .expect_err("excessive capability count must be rejected");

    assert_eq!(error, ReportAdmissionError::CapabilityCount);
}

#[test]
fn from_json_rejects_identifier_larger_than_bound() {
    let mut report = valid_report();
    report["dataset_id"] = json!("dataset-too-long");
    let admission_bounds = bounds(MAX_BYTES, 8, 2, 8, 8, 8, 1_024);

    let error = admit_report(&encoded(&report), admission_bounds)
        .expect_err("oversized identifier must be rejected");

    assert_eq!(error, ReportAdmissionError::InvalidIdentifier);
}

#[test]
fn from_json_rejects_passed_outcome_with_failed_assertion() {
    let mut report = valid_report();
    report["cases"][0]["assertions"][0]["passed"] = json!(false);
    refresh_reproducibility(&mut report);

    let error = admit_report(&encoded(&report), generous_bounds())
        .expect_err("passed outcome with failed evidence must be rejected");

    assert_eq!(error, ReportAdmissionError::InconsistentCase);
}

#[test]
fn from_json_rejects_passed_case_usage_not_supported_by_execution_evidence() {
    let mut report = valid_report();
    report["cases"][0]["usage"] = usage(10, 20, 31);
    report["totals"]["usage"] = usage(10, 20, 31);
    refresh_reproducibility(&mut report);

    let error = admit_report(&encoded(&report), generous_bounds())
        .expect_err("unsupported passed-case usage must be rejected");

    assert_eq!(error, ReportAdmissionError::InconsistentCase);
}

#[test]
fn from_json_rejects_failed_case_usage_below_retained_execution_evidence() {
    let mut report = valid_report();
    report["cases"][0]["outcome"] = json!("failed");
    report["cases"][0]["usage"] = usage(0, 0, 0);
    report["cases"][0]["diagnostic"] = json!({
        "code": "execution_failed",
        "source_bytes": null,
        "source_sha256": null
    });
    report["totals"]["passed"] = json!(0);
    report["totals"]["failed"] = json!(1);
    report["totals"]["usage"] = usage(0, 0, 0);
    refresh_reproducibility(&mut report);

    let error = admit_report(&encoded(&report), generous_bounds())
        .expect_err("failed-case usage must cover retained execution evidence");

    assert_eq!(error, ReportAdmissionError::InconsistentCase);
}

#[test]
fn from_json_rejects_judge_score_above_million_point_scale() {
    let mut report = valid_report();
    add_failing_judge(&mut report, 1_000_001);

    let error = admit_report(&encoded(&report), generous_bounds())
        .expect_err("out-of-range judge score must be rejected");

    assert_eq!(error, ReportAdmissionError::InvalidJudgeEvidence);
}

#[test]
fn from_json_rejects_judge_usage_absent_from_case_usage() {
    let mut report = valid_report();
    add_failing_judge(&mut report, 500_000);
    report["cases"][0]["usage"] = usage(10, 20, 30);
    report["totals"]["usage"] = usage(10, 20, 30);
    refresh_reproducibility(&mut report);

    let error = admit_report(&encoded(&report), generous_bounds())
        .expect_err("unaccounted judge usage must be rejected");

    assert_eq!(error, ReportAdmissionError::InconsistentCase);
}

#[test]
fn from_json_rejects_excessive_diagnostic_source_evidence() {
    let mut report = valid_report();
    report["cases"][0]["outcome"] = json!("failed");
    report["cases"][0]["assertions"][0]["passed"] = json!(false);
    report["cases"][0]["diagnostic"] = json!({
        "code": "deterministic_assertion_failed",
        "source_bytes": 101,
        "source_sha256": SHA_E
    });
    report["totals"]["passed"] = json!(0);
    report["totals"]["failed"] = json!(1);
    refresh_reproducibility(&mut report);
    let admission_bounds = bounds(MAX_BYTES, 8, 2, 8, 8, 160, 100);

    let error = admit_report(&encoded(&report), admission_bounds)
        .expect_err("excessive diagnostic source evidence must be rejected");

    assert_eq!(error, ReportAdmissionError::DiagnosticSourceBytes);
}
