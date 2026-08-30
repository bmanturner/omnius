//! Trusted canonical cassette admission and offline evidence contracts.
#![allow(
    clippy::expect_used,
    reason = "fixed cassette fixtures must fail immediately when their assumptions drift"
)]

use std::error::Error;

use async_trait::async_trait;
use omnius_llm_evals::{
    CaseOutcome, DatasetBounds, DiagnosticCode, DiagnosticRetention, EvaluationDataset,
    EvaluationReport, EvaluationResultRepository, EvaluationRunner, OfflineCaseExecutor,
    OfflineFixtureError, OfflineFixtureLimits, OfflineModelJudge, ResultRepositoryError,
    RunnerLimits,
};
use serde_json::{Value, json};

const DATASET: &[u8] = include_bytes!("../fixtures/provider-contracts/v1/dataset.json");
const EXECUTOR_CASSETTE: &[u8] =
    include_bytes!("../fixtures/provider-contracts/v1/executor-cassette.json");
const JUDGE_CASSETTE: &[u8] =
    include_bytes!("../fixtures/provider-contracts/v1/judge-cassette.json");

const EXECUTOR_CANONICAL_SHA256: &str =
    "d3aac63a9fe263cdc45afcc5d5aaf2756efb1eb349651eb84340a8192104d679";
const JUDGE_CANONICAL_SHA256: &str =
    "9a40503e47623eb84fed851b1e1b3d1f0bf3eff3560d3565daa91a0a0d1e2705";
const DUPLICATE_EXECUTOR_CANONICAL_SHA256: &str =
    "94ec4dbc86f4422b69656417ca955e279527ee2cd328fc4a81e9f8f5f415c811";
const UNSAFE_RAW_EXECUTOR_CANONICAL_SHA256: &str =
    "ff4284484b64e245fb4f46d10df2a00fde18fb470f0c41f139bd135406fc19d6";
const UNSAFE_METADATA_DIGEST_EXECUTOR_CANONICAL_SHA256: &str =
    "607521878ec3168c56a425ac0a0e0391b1e0d8d4acf9d05f357cc4af6295d086";

struct NullRepository;

#[async_trait]
impl EvaluationResultRepository for NullRepository {
    async fn store(&self, _report: &EvaluationReport) -> Result<(), ResultRepositoryError> {
        Ok(())
    }
}

fn fixture_limits() -> Result<OfflineFixtureLimits, Box<dyn Error>> {
    Ok(OfflineFixtureLimits::new(64, 256 * 1024, 512)?)
}

fn dataset_bounds() -> Result<DatasetBounds, Box<dyn Error>> {
    Ok(DatasetBounds::new(64, 256 * 1024)?)
}

fn runner_limits() -> Result<RunnerLimits, Box<dyn Error>> {
    Ok(RunnerLimits::new(
        dataset_bounds()?,
        4,
        2_000,
        20_000,
        DiagnosticRetention::Redacted {
            max_diagnostics: 16,
            max_source_bytes: 4_096,
        },
    )?)
}

fn diagnostic(report: &EvaluationReport, case_id: &str) -> Option<DiagnosticCode> {
    report
        .cases()
        .iter()
        .find(|case| case.case_id() == case_id)
        .and_then(|case| case.diagnostic())
        .map(omnius_llm_evals::RedactedDiagnostic::code)
}

#[test]
fn cassette_admission_rejects_duplicate_entries_and_unbounded_raw_fields()
-> Result<(), Box<dyn Error>> {
    let mut duplicate: Value = serde_json::from_slice(EXECUTOR_CASSETTE)?;
    let first = duplicate["entries"][0].clone();
    duplicate["entries"]
        .as_array_mut()
        .ok_or("cassette entries are not an array")?
        .push(first);
    let duplicate_bytes = serde_json::to_vec(&duplicate)?;
    let duplicate_error = OfflineCaseExecutor::from_json(
        &duplicate_bytes,
        DUPLICATE_EXECUTOR_CANONICAL_SHA256,
        fixture_limits()?,
    )
    .expect_err("duplicate lookup must be rejected");

    let mut unsafe_raw: Value = serde_json::from_slice(EXECUTOR_CASSETTE)?;
    unsafe_raw["entries"][0]["safe_raw_metadata"]["raw_body"] =
        json!("sk-live-forbidden-provider-body");
    let unsafe_raw_bytes = serde_json::to_vec(&unsafe_raw)?;
    let raw_error = OfflineCaseExecutor::from_json(
        &unsafe_raw_bytes,
        UNSAFE_RAW_EXECUTOR_CANONICAL_SHA256,
        fixture_limits()?,
    )
    .expect_err("content-bearing raw metadata must be rejected");
    let mut unsafe_digest: Value = serde_json::from_slice(EXECUTOR_CASSETTE)?;
    unsafe_digest["entries"][0]["safe_raw_metadata"]["provider_request_id_sha256"] =
        json!("sk-live-forbidden-provider-request");
    let unsafe_digest_bytes = serde_json::to_vec(&unsafe_digest)?;
    let digest_error = OfflineCaseExecutor::from_json(
        &unsafe_digest_bytes,
        UNSAFE_METADATA_DIGEST_EXECUTOR_CANONICAL_SHA256,
        fixture_limits()?,
    )
    .expect_err("raw request identity must be hashed");
    let rendered = format!(
        "{duplicate_error:?}{duplicate_error}{raw_error:?}{raw_error}{digest_error:?}{digest_error}"
    );

    assert_eq!(
        (
            duplicate_error,
            raw_error,
            digest_error,
            rendered.contains("sk-live-forbidden-provider-body"),
            rendered.contains("sk-live-forbidden-provider-request"),
        ),
        (
            OfflineFixtureError::DuplicateEntry,
            OfflineFixtureError::InvalidJson,
            OfflineFixtureError::InvalidMetadata,
            false,
            false,
        )
    );
    Ok(())
}

#[test]
fn cassette_admission_requires_a_valid_matching_trusted_digest() -> Result<(), Box<dyn Error>> {
    let executor_mismatch = OfflineCaseExecutor::from_json(
        EXECUTOR_CASSETTE,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        fixture_limits()?,
    )
    .expect_err("a mismatched executor digest must be rejected");
    let judge_mismatch = OfflineModelJudge::from_json(
        JUDGE_CASSETTE,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        fixture_limits()?,
    )
    .expect_err("a mismatched judge digest must be rejected");
    let executor_malformed =
        OfflineCaseExecutor::from_json(EXECUTOR_CASSETTE, "not-a-sha256", fixture_limits()?)
            .expect_err("a malformed executor digest must be rejected");
    let judge_malformed = OfflineModelJudge::from_json(JUDGE_CASSETTE, "ABCDEF", fixture_limits()?)
        .expect_err("a malformed judge digest must be rejected");

    assert_eq!(
        (
            executor_mismatch,
            judge_mismatch,
            executor_malformed,
            judge_malformed,
        ),
        (
            OfflineFixtureError::DigestMismatch,
            OfflineFixtureError::DigestMismatch,
            OfflineFixtureError::InvalidExpectedDigest,
            OfflineFixtureError::InvalidExpectedDigest,
        )
    );
    Ok(())
}

#[test]
fn canonical_digest_is_independent_of_json_whitespace_and_key_order() -> Result<(), Box<dyn Error>>
{
    let executor: Value = serde_json::from_slice(EXECUTOR_CASSETTE)?;
    let reordered_executor = json!({
        "entries": executor["entries"].clone(),
        "cassette_id": executor["cassette_id"].clone(),
        "schema_version": executor["schema_version"].clone(),
    });
    let judge: Value = serde_json::from_slice(JUDGE_CASSETTE)?;
    let reordered_judge = json!({
        "entries": judge["entries"].clone(),
        "cassette_id": judge["cassette_id"].clone(),
        "schema_version": judge["schema_version"].clone(),
    });
    let executor = OfflineCaseExecutor::from_json(
        &serde_json::to_vec_pretty(&reordered_executor)?,
        EXECUTOR_CANONICAL_SHA256,
        fixture_limits()?,
    )?;
    let judge = OfflineModelJudge::from_json(
        &serde_json::to_vec_pretty(&reordered_judge)?,
        JUDGE_CANONICAL_SHA256,
        fixture_limits()?,
    )?;

    assert_eq!(
        (executor.canonical_sha256(), judge.canonical_sha256()),
        (EXECUTOR_CANONICAL_SHA256, JUDGE_CANONICAL_SHA256)
    );
    Ok(())
}

#[tokio::test]
async fn executor_fails_closed_when_prompt_or_execution_revision_differs()
-> Result<(), Box<dyn Error>> {
    let mut changed: Value = serde_json::from_slice(DATASET)?;
    changed["cases"][0]["primary"]["input"]["prompt"]["revision"] = json!(999);
    changed["cases"][1]["primary"]["target"]["model_revision"] =
        json!("different-immutable-revision");
    let dataset = EvaluationDataset::from_json(&serde_json::to_vec(&changed)?, dataset_bounds()?)?;
    let executor = OfflineCaseExecutor::from_json(
        EXECUTOR_CASSETTE,
        EXECUTOR_CANONICAL_SHA256,
        fixture_limits()?,
    )?;
    let judge =
        OfflineModelJudge::from_json(JUDGE_CASSETTE, JUDGE_CANONICAL_SHA256, fixture_limits()?)?;
    let report = EvaluationRunner::new(&executor, Some(&judge), &NullRepository, runner_limits()?)
        .run(&dataset)
        .await?;

    assert_eq!(
        (
            diagnostic(&report, "text"),
            diagnostic(&report, "structured_object"),
        ),
        (
            Some(DiagnosticCode::ExecutionRevisionMismatch),
            Some(DiagnosticCode::ExecutionRevisionMismatch),
        )
    );
    Ok(())
}

#[tokio::test]
async fn fixed_judge_requires_exact_methodology_calibration_and_candidate_order()
-> Result<(), Box<dyn Error>> {
    let mut changed: Value = serde_json::from_slice(DATASET)?;
    let judged = changed["cases"]
        .as_array_mut()
        .and_then(|cases| {
            cases
                .iter_mut()
                .find(|case| case["id"].as_str() == Some("judged_pair"))
        })
        .ok_or("judged fixture case is missing")?;
    judged["judge"]["calibration"]["evidence_sha256"] =
        json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let dataset = EvaluationDataset::from_json(&serde_json::to_vec(&changed)?, dataset_bounds()?)?;
    let executor = OfflineCaseExecutor::from_json(
        EXECUTOR_CASSETTE,
        EXECUTOR_CANONICAL_SHA256,
        fixture_limits()?,
    )?;
    let judge =
        OfflineModelJudge::from_json(JUDGE_CASSETTE, JUDGE_CANONICAL_SHA256, fixture_limits()?)?;
    let report = EvaluationRunner::new(&executor, Some(&judge), &NullRepository, runner_limits()?)
        .run(&dataset)
        .await?;
    let judged = report
        .cases()
        .iter()
        .find(|case| case.case_id() == "judged_pair")
        .ok_or("judged report case is missing")?;

    assert_eq!(
        (
            judged.outcome(),
            judged.judge(),
            diagnostic(&report, "judged_pair")
        ),
        (
            CaseOutcome::Failed,
            None,
            Some(DiagnosticCode::JudgeEvidenceInvalid),
        )
    );
    Ok(())
}
