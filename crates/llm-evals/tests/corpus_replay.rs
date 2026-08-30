//! Deterministic provider corpus replay and evidence-accounting contracts.
#![allow(
    clippy::expect_used,
    reason = "fixed committed corpus assertions must fail immediately when assumptions drift"
)]

use std::{error::Error, fmt::Write as _, sync::Mutex};

use async_trait::async_trait;
use omnius_llm_evals::{
    CandidateRole, CaseOutcome, DatasetBounds, DiagnosticCode, DiagnosticRetention,
    EvaluationDataset, EvaluationReport, EvaluationResultRepository, EvaluationRunner,
    OfflineCaseExecutor, OfflineFixtureLimits, OfflineModelJudge, OfflinePayloadKind, ReportBounds,
    ResultRepositoryError, RunnerLimits,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const DATASET: &[u8] = include_bytes!("../fixtures/provider-contracts/v1/dataset.json");
const EXECUTOR_CASSETTE: &[u8] =
    include_bytes!("../fixtures/provider-contracts/v1/executor-cassette.json");
const JUDGE_CASSETTE: &[u8] =
    include_bytes!("../fixtures/provider-contracts/v1/judge-cassette.json");
const MANIFEST: &[u8] = include_bytes!("../fixtures/provider-contracts/v1/manifest.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusManifest {
    schema_version: String,
    dataset_sha256: String,
    cassette_sha256: String,
    judge_cassette_sha256: String,
    case_count: usize,
    cassette_id: String,
    judge_cassette_id: String,
    required_cases: Vec<String>,
}

#[derive(Default)]
struct RecordingRepository {
    reports: Mutex<Vec<EvaluationReport>>,
}

#[async_trait]
impl EvaluationResultRepository for RecordingRepository {
    async fn store(&self, report: &EvaluationReport) -> Result<(), ResultRepositoryError> {
        self.reports
            .lock()
            .map_err(|_| {
                ResultRepositoryError::new(omnius_llm_evals::RedactedDiagnostic::new(
                    omnius_llm_evals::DiagnosticCode::RepositoryFailed,
                ))
            })?
            .push(report.clone());
        Ok(())
    }
}

fn canonical_sha256(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut value: Value = serde_json::from_slice(bytes)?;
    canonicalize(&mut value);
    let digest = Sha256::digest(serde_json::to_vec(&value)?);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(encoded)
}

fn canonicalize(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(canonicalize),
        Value::Object(object) => {
            let mut entries = std::mem::take(object).into_iter().collect::<Vec<_>>();
            for (_, value) in &mut entries {
                canonicalize(value);
            }
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            object.extend(entries);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn fixture_limits() -> Result<OfflineFixtureLimits, Box<dyn Error>> {
    Ok(OfflineFixtureLimits::new(64, 256 * 1024, 512)?)
}

fn dataset_bounds() -> Result<DatasetBounds, Box<dyn Error>> {
    Ok(DatasetBounds::new(64, 256 * 1024)?)
}

fn report_bounds() -> Result<ReportBounds, Box<dyn Error>> {
    Ok(ReportBounds::new(256 * 1024, 64, 2, 64, 64, 256, 4_096)?)
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

#[test]
fn committed_dataset_digest_and_case_inventory_are_pinned() -> Result<(), Box<dyn Error>> {
    let manifest: CorpusManifest = serde_json::from_slice(MANIFEST)?;
    let dataset = EvaluationDataset::from_json(DATASET, dataset_bounds()?)?;
    let actual_cases = dataset
        .cases()
        .iter()
        .map(|case| case.id().to_owned())
        .collect::<Vec<_>>();

    assert_eq!(
        (
            manifest.schema_version.as_str(),
            dataset.sha256()?,
            dataset.cases().len(),
            actual_cases,
        ),
        (
            "1.0.0",
            manifest.dataset_sha256,
            manifest.case_count,
            manifest.required_cases,
        )
    );
    Ok(())
}

#[test]
fn committed_cassette_canonical_digests_and_safe_metadata_are_pinned() -> Result<(), Box<dyn Error>>
{
    let manifest: CorpusManifest = serde_json::from_slice(MANIFEST)?;
    let executor = OfflineCaseExecutor::from_json(
        EXECUTOR_CASSETTE,
        &manifest.cassette_sha256,
        fixture_limits()?,
    )?;
    let judge = OfflineModelJudge::from_json(
        JUDGE_CASSETTE,
        &manifest.judge_cassette_sha256,
        fixture_limits()?,
    )?;
    let throttled = executor
        .safe_raw_metadata(
            "offline.provider.contracts",
            "1.0.0",
            "throttled",
            CandidateRole::Primary,
        )
        .ok_or("missing throttled metadata")?;

    assert_eq!(
        canonical_sha256(EXECUTOR_CASSETTE)?,
        manifest.cassette_sha256
    );
    assert_eq!(
        canonical_sha256(JUDGE_CASSETTE)?,
        manifest.judge_cassette_sha256
    );
    assert_eq!(
        (
            executor.canonical_sha256(),
            judge.canonical_sha256(),
            executor.cassette_id(),
            judge.cassette_id(),
            executor.entry_count(),
            judge.entry_count(),
        ),
        (
            manifest.cassette_sha256.as_str(),
            manifest.judge_cassette_sha256.as_str(),
            manifest.cassette_id.as_str(),
            manifest.judge_cassette_id.as_str(),
            18,
            3,
        )
    );
    assert_eq!(
        (
            throttled.status_code(),
            throttled.payload_kind(),
            throttled.serialized_bytes(),
            throttled.provider_request_id_sha256().map(str::len),
        ),
        (
            Some(429),
            Some(OfflinePayloadKind::Object),
            Some(77),
            Some(64),
        )
    );
    Ok(())
}

#[tokio::test]
async fn offline_replay_is_byte_stable_and_exercises_all_outcome_branches()
-> Result<(), Box<dyn Error>> {
    let manifest: CorpusManifest = serde_json::from_slice(MANIFEST)?;
    let dataset = EvaluationDataset::from_json(DATASET, dataset_bounds()?)?;
    let executor = OfflineCaseExecutor::from_json(
        EXECUTOR_CASSETTE,
        &manifest.cassette_sha256,
        fixture_limits()?,
    )?;
    let judge = OfflineModelJudge::from_json(
        JUDGE_CASSETTE,
        &manifest.judge_cassette_sha256,
        fixture_limits()?,
    )?;
    let first_repository = RecordingRepository::default();
    let second_repository = RecordingRepository::default();
    let first = EvaluationRunner::new(&executor, Some(&judge), &first_repository, runner_limits()?)
        .run(&dataset)
        .await?;
    let second = EvaluationRunner::new(
        &executor,
        Some(&judge),
        &second_repository,
        runner_limits()?,
    )
    .run(&dataset)
    .await?;
    let first_bytes = serde_json::to_vec(&first)?;
    let second_bytes = serde_json::to_vec(&second)?;
    let first_sha256 = first.canonical_sha256()?;
    let report_round_trip_stable =
        EvaluationReport::from_json(&first_bytes, &first_sha256, report_bounds()?)? == first;

    assert_eq!(
        (
            first,
            first_bytes,
            first_repository
                .reports
                .lock()
                .map_err(|_| "first report lock")?
                .len(),
            second_repository
                .reports
                .lock()
                .map_err(|_| "second report lock")?
                .len(),
            report_round_trip_stable,
        ),
        (second, second_bytes, 1, 1, true)
    );
    Ok(())
}

#[tokio::test]
async fn offline_report_accounts_for_partial_unknown_usage_and_fixed_judging()
-> Result<(), Box<dyn Error>> {
    let manifest: CorpusManifest = serde_json::from_slice(MANIFEST)?;
    let dataset = EvaluationDataset::from_json(DATASET, dataset_bounds()?)?;
    let executor = OfflineCaseExecutor::from_json(
        EXECUTOR_CASSETTE,
        &manifest.cassette_sha256,
        fixture_limits()?,
    )?;
    let judge = OfflineModelJudge::from_json(
        JUDGE_CASSETTE,
        &manifest.judge_cassette_sha256,
        fixture_limits()?,
    )?;
    let repository = RecordingRepository::default();
    let report = EvaluationRunner::new(&executor, Some(&judge), &repository, runner_limits()?)
        .run(&dataset)
        .await?;
    let totals = report.totals();
    let usage = totals.usage();
    let judged = report
        .cases()
        .iter()
        .find(|case| case.case_id() == "judged_pair")
        .and_then(|case| case.judge())
        .ok_or("missing fixed judge report")?;
    let low_score = report
        .cases()
        .iter()
        .find(|case| case.case_id() == "judged_low_score")
        .and_then(|case| case.judge())
        .ok_or("missing low-score judge report")?;
    let diagnostic = |case_id: &str| {
        report
            .cases()
            .iter()
            .find(|case| case.case_id() == case_id)
            .and_then(|case| case.diagnostic())
            .map(omnius_llm_evals::RedactedDiagnostic::code)
    };
    let partial_outcome = report
        .cases()
        .iter()
        .find(|case| case.case_id() == "partial")
        .map(omnius_llm_evals::CaseReport::outcome);

    assert_eq!(
        (totals.passed(), totals.failed(), totals.timed_out()),
        (12, 5, 0)
    );
    assert_eq!(
        (
            usage.input_tokens(),
            usage.output_tokens(),
            usage.cost_microunits(),
        ),
        (Some(102), Some(48), 356)
    );
    assert_eq!(
        (
            judged.methodology_version(),
            judged.score_microunits(),
            judged.blinded(),
            low_score.score_microunits(),
            low_score.passed(),
        ),
        ("1.0.0", 875_000, true, 650_000, false)
    );
    assert_eq!(
        (
            report.executor_evidence_sha256(),
            report.judge_evidence_sha256(),
        ),
        (
            Some(manifest.cassette_sha256.as_str()),
            Some(manifest.judge_cassette_sha256.as_str()),
        )
    );
    assert_eq!(
        (
            diagnostic("malformed"),
            diagnostic("throttled"),
            diagnostic("timeout"),
            diagnostic("judged_low_score"),
            diagnostic("judged_error"),
        ),
        (
            Some(DiagnosticCode::ProviderFailed),
            Some(DiagnosticCode::ProviderFailed),
            Some(DiagnosticCode::TransportFailed),
            Some(DiagnosticCode::JudgeScoreBelowTolerance),
            Some(DiagnosticCode::JudgeFailed),
        )
    );
    assert_eq!(partial_outcome, Some(CaseOutcome::Passed));
    Ok(())
}

#[tokio::test]
async fn fixtures_reports_debug_and_errors_are_free_of_sensitive_markers()
-> Result<(), Box<dyn Error>> {
    let manifest: CorpusManifest = serde_json::from_slice(MANIFEST)?;
    let dataset = EvaluationDataset::from_json(DATASET, dataset_bounds()?)?;
    let executor = OfflineCaseExecutor::from_json(
        EXECUTOR_CASSETTE,
        &manifest.cassette_sha256,
        fixture_limits()?,
    )?;
    let judge = OfflineModelJudge::from_json(
        JUDGE_CASSETTE,
        &manifest.judge_cassette_sha256,
        fixture_limits()?,
    )?;
    let repository = RecordingRepository::default();
    let report = EvaluationRunner::new(&executor, Some(&judge), &repository, runner_limits()?)
        .run(&dataset)
        .await?;
    let secret = b"sk-live-fixture-secret";
    let error = OfflineCaseExecutor::from_json(
        secret,
        &manifest.cassette_sha256,
        OfflineFixtureLimits::new(1, 1, 1)?,
    )
    .expect_err("oversized fixture must be rejected");
    let report_debug = format!("{report:?}{executor:?}{judge:?}{error:?}{error}");
    let mut scanned = Vec::new();
    scanned.extend_from_slice(DATASET);
    scanned.extend_from_slice(EXECUTOR_CASSETTE);
    scanned.extend_from_slice(JUDGE_CASSETTE);
    scanned.extend_from_slice(&serde_json::to_vec(&report)?);
    scanned.extend_from_slice(report_debug.as_bytes());
    let scanned = String::from_utf8(scanned)?;
    let lower = scanned.to_ascii_lowercase();
    let forbidden = [
        "sk-live-",
        "bearer ey",
        "private key",
        "password=",
        "api_key",
    ];
    let durable = serde_json::to_string(&report)?;

    assert!(
        forbidden.iter().all(|marker| !lower.contains(marker))
            && !report_debug.contains("sk-live-fixture-secret")
            && !durable.contains("Deterministic offline answer.")
            && !durable.contains("Candidate primary")
            && !durable.contains("usable prefix")
            && !durable.contains("Calibrated below tolerance")
            && !durable.contains("Judge provider failure input")
    );
    Ok(())
}
