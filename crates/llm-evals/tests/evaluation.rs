//! Evaluation runner admission, orchestration, and redaction contracts.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use omnius_llm_core::{
    CompletionStatus, LlmOutputPart, LlmRequestId, LlmResponse, Route, TextOutputPart, Usage,
};
use omnius_llm_evals::{
    BlindedOrder, CandidateRole, CaseExecutionRequest, CaseExecutor, CaseExecutorError,
    CaseOutcome, DatasetBounds, DatasetError, DeterministicAssertion, DiagnosticCode,
    DiagnosticRetention, EvalCase, EvalExecutionResult, EvalInvocation, EvalTolerances, EvalUsage,
    EvaluationDataset, EvaluationInput, EvaluationReport, EvaluationResultRepository,
    EvaluationRunner, ExecutionTarget, JudgeCalibration, JudgeMethodology, JudgeRequest,
    JudgeResult, ModelJudge, ModelJudgeError, PromptRevisionReference, RedactedDiagnostic,
    ReportBounds, ResultRepositoryError, RunError, RunnerLimits,
};
use serde_json::Value;
use time::OffsetDateTime;

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SECRET: &str = "private prompt and response payload";

fn route(revision: u64) -> Route {
    match Route::new("chat".to_owned(), Some(revision), Vec::new(), Vec::new()) {
        Ok(route) => route,
        Err(error) => panic!("valid test route rejected: {error}"),
    }
}

fn exact_target(
    route: Route,
    provider: &str,
    model: &str,
    model_revision: &str,
) -> ExecutionTarget {
    match ExecutionTarget::new(
        route,
        provider.to_owned(),
        model.to_owned(),
        model_revision.to_owned(),
    ) {
        Ok(target) => target,
        Err(error) => panic!("valid execution target rejected: {error}"),
    }
}

fn target(model_revision: &str) -> ExecutionTarget {
    exact_target(route(3), "provider-a", "model-a", model_revision)
}

fn invocation(model_revision: &str, prompt_revision: u64) -> EvalInvocation {
    EvalInvocation::new(
        EvaluationInput::prompt_reference(PromptRevisionReference::new(
            "prompt-a".to_owned(),
            prompt_revision,
            HASH_A.to_owned(),
        )),
        target(model_revision),
    )
}

fn provider_assertion(id: &str, role: CandidateRole) -> DeterministicAssertion {
    DeterministicAssertion::JsonPointerEquals {
        id: id.to_owned(),
        target: role,
        pointer: "/provider".to_owned(),
        expected: Value::String("provider-a".to_owned()),
    }
}

fn case(id: &str, cost_ceiling: u64, deadline_ms: u64) -> EvalCase {
    EvalCase::new(
        id.to_owned(),
        invocation("model-revision-1", 1),
        None,
        vec![provider_assertion(
            "provider_matches",
            CandidateRole::Primary,
        )],
        None,
        EvalTolerances::new(0, None),
        deadline_ms,
        cost_ceiling,
    )
}

fn case_with_expected_value(expected: Value) -> EvalCase {
    EvalCase::new(
        "case-map".to_owned(),
        invocation("model-revision-1", 1),
        None,
        vec![DeterministicAssertion::JsonPointerEquals {
            id: "object_matches".to_owned(),
            target: CandidateRole::Primary,
            pointer: "/provider_metadata".to_owned(),
            expected,
        }],
        None,
        EvalTolerances::new(0, None),
        100,
        10,
    )
}

fn calibrated_judge(blind_seed: Option<u64>) -> JudgeMethodology {
    JudgeMethodology::new(
        "quality-rubric".to_owned(),
        "2.1.0".to_owned(),
        HASH_B.to_owned(),
        exact_target(
            route(9),
            "judge-provider",
            "judge-model",
            "judge-revision-4",
        ),
        Some(JudgeCalibration::new(
            "judge-calibration".to_owned(),
            "2026.08".to_owned(),
            HASH_A.to_owned(),
        )),
        blind_seed,
    )
}

fn judged_case(id: &str, blind_seed: Option<u64>) -> EvalCase {
    EvalCase::new(
        id.to_owned(),
        invocation("model-revision-1", 1),
        Some(invocation("model-revision-2", 2)),
        vec![
            provider_assertion("primary_provider", CandidateRole::Primary),
            provider_assertion("comparison_provider", CandidateRole::Comparison),
        ],
        Some(calibrated_judge(blind_seed)),
        EvalTolerances::new(0, Some(700_000)),
        500,
        100,
    )
}

fn bounds(max_cases: usize, max_bytes: usize) -> DatasetBounds {
    match DatasetBounds::new(max_cases, max_bytes) {
        Ok(bounds) => bounds,
        Err(error) => panic!("valid test bounds rejected: {error}"),
    }
}

fn dataset(cases: Vec<EvalCase>, dataset_version: &str) -> EvaluationDataset {
    match EvaluationDataset::new(
        "regression".to_owned(),
        dataset_version.to_owned(),
        cases,
        bounds(32, 1_000_000),
    ) {
        Ok(dataset) => dataset,
        Err(error) => panic!("valid test dataset rejected: {error}"),
    }
}

fn response(text: &str) -> LlmResponse {
    let text = match TextOutputPart::new("text-1".to_owned(), text.to_owned(), None) {
        Ok(text) => text,
        Err(error) => panic!("valid output rejected: {error}"),
    };
    let request_id = match LlmRequestId::new("request-1".to_owned()) {
        Ok(request_id) => request_id,
        Err(error) => panic!("valid request identifier rejected: {error}"),
    };
    match LlmResponse::new(
        request_id,
        "response-1".to_owned(),
        "provider-a".to_owned(),
        "model-a".to_owned(),
        CompletionStatus::Completed,
        None,
        vec![LlmOutputPart::Text(text)],
        Usage::new(Some(4), Some(3)),
        OffsetDateTime::UNIX_EPOCH,
    ) {
        Ok(response) => response,
        Err(error) => panic!("valid response rejected: {error}"),
    }
}

#[derive(Default)]
struct MemoryRepository {
    reports: Mutex<Vec<EvaluationReport>>,
}

#[async_trait]
impl EvaluationResultRepository for MemoryRepository {
    async fn store(&self, report: &EvaluationReport) -> Result<(), ResultRepositoryError> {
        match self.reports.lock() {
            Ok(mut reports) => reports.push(report.clone()),
            Err(_) => {
                return Err(ResultRepositoryError::new(RedactedDiagnostic::new(
                    DiagnosticCode::RepositoryFailed,
                )));
            }
        }
        Ok(())
    }
}

struct ActiveGuard<'a>(&'a AtomicUsize);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct RecordingExecutor {
    calls: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
    delay: Duration,
    cost: u64,
    wrong_revision: bool,
    secret_response: bool,
}

impl RecordingExecutor {
    fn new(delay: Duration, cost: u64) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            delay,
            cost,
            wrong_revision: false,
            secret_response: false,
        }
    }
}

#[async_trait]
impl CaseExecutor for RecordingExecutor {
    fn evidence_sha256(&self) -> Option<&str> {
        None
    }

    async fn execute(
        &self,
        request: CaseExecutionRequest<'_>,
    ) -> Result<EvalExecutionResult, CaseExecutorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(active, Ordering::SeqCst);
        let _guard = ActiveGuard(&self.active);
        tokio::time::sleep(self.delay).await;
        let evidence = if self.wrong_revision {
            target("unexpected-revision")
        } else {
            request.invocation().target().clone()
        };
        let role = match request.role() {
            CandidateRole::Primary => "primary",
            CandidateRole::Comparison => "comparison",
        };
        let response_text = if self.secret_response {
            format!("{SECRET}-{role}")
        } else {
            role.to_owned()
        };
        Ok(EvalExecutionResult::new(
            response(&response_text),
            evidence,
            EvalUsage::new(Some(4), Some(3), self.cost),
        ))
    }
}

struct RecordingJudge {
    called: AtomicUsize,
    debug_leaked: AtomicBool,
    first_was_primary: AtomicBool,
}

impl RecordingJudge {
    fn new() -> Self {
        Self {
            called: AtomicUsize::new(0),
            debug_leaked: AtomicBool::new(false),
            first_was_primary: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl ModelJudge for RecordingJudge {
    fn evidence_sha256(&self) -> Option<&str> {
        None
    }

    async fn judge(&self, request: JudgeRequest<'_>) -> Result<JudgeResult, ModelJudgeError> {
        self.called.fetch_add(1, Ordering::SeqCst);
        self.debug_leaked
            .store(format!("{request:?}").contains(SECRET), Ordering::SeqCst);
        let first_text = request
            .first()
            .response()
            .output()
            .first()
            .and_then(LlmOutputPart::as_text);
        self.first_was_primary.store(
            first_text.is_some_and(|text| text.ends_with("primary")),
            Ordering::SeqCst,
        );
        Ok(JudgeResult::new(
            900_000,
            request.methodology().judge().clone(),
            EvalUsage::new(Some(2), Some(1), 5),
        ))
    }
}

fn limits(
    max_concurrency: usize,
    max_deadline_ms: u64,
    total_cost: u64,
    retention: DiagnosticRetention,
) -> RunnerLimits {
    match RunnerLimits::new(
        bounds(32, 1_000_000),
        max_concurrency,
        max_deadline_ms,
        total_cost,
        retention,
    ) {
        Ok(limits) => limits,
        Err(error) => panic!("valid runner limits rejected: {error}"),
    }
}

#[test]
fn dataset_hash_is_deterministic_and_versioned() {
    let first = dataset(vec![case("case-a", 10, 100)], "1.2.3");
    let encoded = match first.to_canonical_json() {
        Ok(encoded) => encoded,
        Err(error) => panic!("dataset encoding failed: {error}"),
    };
    let parsed = match EvaluationDataset::from_json(&encoded, bounds(32, 1_000_000)) {
        Ok(parsed) => parsed,
        Err(error) => panic!("canonical dataset did not parse: {error}"),
    };
    assert_eq!(first.sha256(), parsed.sha256());

    let next = dataset(vec![case("case-a", 10, 100)], "1.2.4");
    assert_ne!(first.sha256(), next.sha256());

    let mut left_map = serde_json::Map::new();
    left_map.insert("z".to_owned(), Value::Bool(true));
    left_map.insert("a".to_owned(), Value::Bool(false));
    let mut right_map = serde_json::Map::new();
    right_map.insert("a".to_owned(), Value::Bool(false));
    right_map.insert("z".to_owned(), Value::Bool(true));
    let left = dataset(
        vec![case_with_expected_value(Value::Object(left_map))],
        "1.2.3",
    );
    let right = dataset(
        vec![case_with_expected_value(Value::Object(right_map))],
        "1.2.3",
    );
    assert_eq!(left.sha256(), right.sha256());

    let mut wire: Value = match serde_json::from_slice(&encoded) {
        Ok(wire) => wire,
        Err(error) => panic!("test JSON parse failed: {error}"),
    };
    wire["schema_version"] = Value::String("2.0.0".to_owned());
    let unsupported = match serde_json::to_vec(&wire) {
        Ok(unsupported) => unsupported,
        Err(error) => panic!("test JSON encode failed: {error}"),
    };
    assert_eq!(
        EvaluationDataset::from_json(&unsupported, bounds(32, 1_000_000)).err(),
        Some(DatasetError::UnsupportedSchemaVersion)
    );

    let mut unknown_wire: Value = match serde_json::from_slice(&encoded) {
        Ok(wire) => wire,
        Err(error) => panic!("test JSON parse failed: {error}"),
    };
    unknown_wire["cases"][0]["expected"][0]["unsupported"] = Value::Bool(true);
    let unknown = match serde_json::to_vec(&unknown_wire) {
        Ok(unknown) => unknown,
        Err(error) => panic!("test JSON encode failed: {error}"),
    };
    assert_eq!(
        EvaluationDataset::from_json(&unknown, bounds(32, 1_000_000)).err(),
        Some(DatasetError::InvalidJson)
    );

    let mut zero_revision_wire: Value = match serde_json::from_slice(&encoded) {
        Ok(wire) => wire,
        Err(error) => panic!("test JSON parse failed: {error}"),
    };
    zero_revision_wire["cases"][0]["primary"]["target"]["route"]["revision"] =
        Value::Number(0_u64.into());
    let zero_revision = match serde_json::to_vec(&zero_revision_wire) {
        Ok(zero_revision) => zero_revision,
        Err(error) => panic!("test JSON encode failed: {error}"),
    };
    assert_eq!(
        EvaluationDataset::from_json(&zero_revision, bounds(32, 1_000_000)).err(),
        Some(DatasetError::InvalidJson)
    );
}

#[test]
fn dataset_admission_enforces_case_and_byte_bounds() {
    let cases = vec![case("case-a", 10, 100), case("case-b", 10, 100)];
    assert_eq!(
        EvaluationDataset::new(
            "regression".to_owned(),
            "1.0.0".to_owned(),
            cases,
            bounds(1, 1_000_000),
        )
        .err(),
        Some(DatasetError::CaseCount)
    );
    assert_eq!(
        EvaluationDataset::from_json(b"{}", bounds(1, 1)).err(),
        Some(DatasetError::TooManyBytes)
    );

    let malformed_pointer = EvalCase::new(
        "case-pointer".to_owned(),
        invocation("model-revision-1", 1),
        None,
        vec![DeterministicAssertion::JsonPointerPresent {
            id: "bad_pointer".to_owned(),
            target: CandidateRole::Primary,
            pointer: "/bad~2escape".to_owned(),
        }],
        None,
        EvalTolerances::new(0, None),
        100,
        10,
    );
    assert_eq!(
        EvaluationDataset::new(
            "regression".to_owned(),
            "1.0.0".to_owned(),
            vec![malformed_pointer],
            bounds(2, 1_000_000),
        )
        .err(),
        Some(DatasetError::InvalidJsonPointer)
    );
}

#[test]
fn uncalibrated_model_judge_is_denied() {
    let judge = JudgeMethodology::new(
        "quality-rubric".to_owned(),
        "2.1.0".to_owned(),
        HASH_B.to_owned(),
        exact_target(
            route(9),
            "judge-provider",
            "judge-model",
            "judge-revision-4",
        ),
        None,
        None,
    );
    let invalid = EvalCase::new(
        "case-a".to_owned(),
        invocation("model-revision-1", 1),
        None,
        vec![provider_assertion(
            "provider_matches",
            CandidateRole::Primary,
        )],
        Some(judge),
        EvalTolerances::new(0, Some(700_000)),
        100,
        10,
    );
    assert_eq!(
        EvaluationDataset::new(
            "regression".to_owned(),
            "1.0.0".to_owned(),
            vec![invalid],
            bounds(2, 1_000_000),
        )
        .err(),
        Some(DatasetError::UncalibratedJudge)
    );
}

#[tokio::test]
async fn exact_revision_evidence_is_required_before_assertions() {
    let executor = RecordingExecutor {
        wrong_revision: true,
        ..RecordingExecutor::new(Duration::ZERO, 1)
    };
    let repository = MemoryRepository::default();
    let runner = EvaluationRunner::new(
        &executor,
        None,
        &repository,
        limits(
            1,
            1_000,
            100,
            DiagnosticRetention::Redacted {
                max_diagnostics: 4,
                max_source_bytes: 1_000,
            },
        ),
    );
    let report = match runner
        .run(&dataset(vec![case("case-a", 10, 100)], "1.0.0"))
        .await
    {
        Ok(report) => report,
        Err(error) => panic!("runner failed before report: {error}"),
    };
    assert_eq!(report.cases()[0].outcome(), CaseOutcome::Failed);
    assert_eq!(
        report.cases()[0].diagnostic().map(RedactedDiagnostic::code),
        Some(DiagnosticCode::ExecutionRevisionMismatch)
    );
    assert_eq!(report.cases()[0].usage().cost_microunits(), 1);
    assert_eq!(report.cases()[0].executions().len(), 1);
}

#[tokio::test]
async fn deterministic_assertions_gate_model_judging() {
    let executor = RecordingExecutor::new(Duration::ZERO, 1);
    let judge = RecordingJudge::new();
    let repository = MemoryRepository::default();
    let mut gated = judged_case("case-a", None);
    gated = EvalCase::new(
        gated.id().to_owned(),
        gated.primary().clone(),
        gated.comparison().cloned(),
        vec![DeterministicAssertion::JsonPointerEquals {
            id: "must_fail_first".to_owned(),
            target: CandidateRole::Primary,
            pointer: "/provider".to_owned(),
            expected: Value::String("different-provider".to_owned()),
        }],
        gated.judge().cloned(),
        gated.tolerances(),
        gated.deadline_ms(),
        gated.cost_ceiling_microunits(),
    );
    let runner = EvaluationRunner::new(
        &executor,
        Some(&judge),
        &repository,
        limits(1, 1_000, 1_000, DiagnosticRetention::Discard),
    );
    let report = match runner.run(&dataset(vec![gated], "1.0.0")).await {
        Ok(report) => report,
        Err(error) => panic!("runner failed before report: {error}"),
    };
    assert_eq!(report.cases()[0].outcome(), CaseOutcome::Failed);
    assert_eq!(judge.called.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rejected_judge_results_retain_charged_content_free_evidence() {
    struct InvalidScoreJudge;

    #[async_trait]
    impl ModelJudge for InvalidScoreJudge {
        fn evidence_sha256(&self) -> Option<&str> {
            None
        }

        async fn judge(&self, request: JudgeRequest<'_>) -> Result<JudgeResult, ModelJudgeError> {
            Ok(JudgeResult::new(
                1_000_001,
                request.methodology().judge().clone(),
                EvalUsage::new(Some(2), Some(1), 5),
            ))
        }
    }

    let executor = RecordingExecutor::new(Duration::ZERO, 1);
    let repository = MemoryRepository::default();
    let report = match EvaluationRunner::new(
        &executor,
        Some(&InvalidScoreJudge),
        &repository,
        limits(1, 1_000, 1_000, DiagnosticRetention::Discard),
    )
    .run(&dataset(
        vec![judged_case("case-rejected-judge", None)],
        "1.0.0",
    ))
    .await
    {
        Ok(report) => report,
        Err(error) => panic!("invalid judge evidence failed before report: {error}"),
    };

    let case = &report.cases()[0];
    let Some(rejected) = case.rejected_judge() else {
        panic!("rejected judge evidence was not retained");
    };
    assert_eq!(case.outcome(), CaseOutcome::Failed);
    assert_eq!(case.diagnostic(), None);
    assert_eq!(case.usage().cost_microunits(), 7);
    assert_eq!(rejected.score_microunits(), None);
    assert_eq!(rejected.usage().cost_microunits(), 5);
    assert_eq!(rejected.diagnostic(), None);
    assert_eq!(rejected.evidence(), calibrated_judge(None).judge());
    let encoded = match serde_json::to_vec(&report) {
        Ok(encoded) => encoded,
        Err(error) => panic!("rejected judge report encoding failed: {error}"),
    };
    let trusted_sha256 = match report.canonical_sha256() {
        Ok(digest) => digest,
        Err(error) => panic!("rejected judge report hashing failed: {error}"),
    };
    let admission_bounds = match ReportBounds::new(64 * 1024, 4, 2, 8, 8, 160, 1_024) {
        Ok(bounds) => bounds,
        Err(error) => panic!("valid report bounds rejected: {error}"),
    };
    let admitted = match EvaluationReport::from_json(&encoded, &trusted_sha256, admission_bounds) {
        Ok(admitted) => admitted,
        Err(error) => panic!("rejected judge report failed admission: {error}"),
    };
    assert_eq!(admitted, report);
}

#[tokio::test]
async fn blinded_order_is_seed_deterministic_and_content_independent() {
    let expected = BlindedOrder::derive(42, HASH_A, "case-a");
    assert_eq!(expected, BlindedOrder::derive(42, HASH_A, "case-a"));

    let executor = RecordingExecutor {
        secret_response: true,
        ..RecordingExecutor::new(Duration::ZERO, 1)
    };
    let judge = RecordingJudge::new();
    let repository = MemoryRepository::default();
    let runner = EvaluationRunner::new(
        &executor,
        Some(&judge),
        &repository,
        limits(1, 1_000, 1_000, DiagnosticRetention::Discard),
    );
    let evaluation = dataset(vec![judged_case("case-a", Some(42))], "1.0.0");
    let dataset_hash = match evaluation.sha256() {
        Ok(hash) => hash,
        Err(error) => panic!("dataset hash failed: {error}"),
    };
    let expected = BlindedOrder::derive(42, &dataset_hash, "case-a");
    let report = match runner.run(&evaluation).await {
        Ok(report) => report,
        Err(error) => panic!("blinded run failed before report: {error}"),
    };
    assert_eq!(
        judge.first_was_primary.load(Ordering::SeqCst),
        expected == BlindedOrder::PrimaryFirst
    );
    assert!(!judge.debug_leaked.load(Ordering::SeqCst));
    assert!(
        report.cases()[0]
            .judge()
            .is_some_and(omnius_llm_evals::JudgeReport::blinded)
    );
    let encoded = match serde_json::to_string(&report) {
        Ok(encoded) => encoded,
        Err(error) => panic!("report encoding failed: {error}"),
    };
    assert!(!encoded.contains(SECRET));
}

#[tokio::test]
async fn runner_enforces_total_cost_deadline_and_concurrency() {
    let preflight_executor = RecordingExecutor::new(Duration::ZERO, 1);
    let repository = MemoryRepository::default();
    let runner = EvaluationRunner::new(
        &preflight_executor,
        None,
        &repository,
        limits(2, 1_000, 15, DiagnosticRetention::Discard),
    );
    let over_budget = dataset(
        vec![case("case-a", 10, 100), case("case-b", 10, 100)],
        "1.0.0",
    );
    assert_eq!(
        runner.run(&over_budget).await.err(),
        Some(RunError::CostBudgetExceeded)
    );
    assert_eq!(preflight_executor.calls.load(Ordering::SeqCst), 0);

    let expensive_executor = RecordingExecutor::new(Duration::ZERO, 11);
    let expensive_runner = EvaluationRunner::new(
        &expensive_executor,
        None,
        &repository,
        limits(
            1,
            1_000,
            100,
            DiagnosticRetention::Redacted {
                max_diagnostics: 1,
                max_source_bytes: 1_000,
            },
        ),
    );
    let expensive_report = match expensive_runner
        .run(&dataset(vec![case("case-expensive", 10, 100)], "1.0.0"))
        .await
    {
        Ok(report) => report,
        Err(error) => panic!("expensive run failed before report: {error}"),
    };
    assert_eq!(expensive_report.cases()[0].outcome(), CaseOutcome::Failed);
    assert_eq!(expensive_report.cases()[0].usage().cost_microunits(), 11);

    let slow_executor = RecordingExecutor::new(Duration::from_millis(50), 1);
    let timeout_runner = EvaluationRunner::new(
        &slow_executor,
        None,
        &repository,
        limits(1, 1_000, 100, DiagnosticRetention::Discard),
    );
    let timeout_report = match timeout_runner
        .run(&dataset(vec![case("case-timeout", 10, 5)], "1.0.0"))
        .await
    {
        Ok(report) => report,
        Err(error) => panic!("timeout run failed before report: {error}"),
    };
    assert_eq!(timeout_report.cases()[0].outcome(), CaseOutcome::TimedOut);
    assert_eq!(
        timeout_report.cases()[0].usage().cost_microunits(),
        10,
        "a timed-out provider call must conservatively retain its full reserved exposure",
    );

    let concurrent_executor = RecordingExecutor::new(Duration::from_millis(10), 1);
    let concurrency_runner = EvaluationRunner::new(
        &concurrent_executor,
        None,
        &repository,
        limits(2, 1_000, 100, DiagnosticRetention::Discard),
    );
    let concurrent_report = match concurrency_runner
        .run(&dataset(
            vec![
                case("case-1", 10, 100),
                case("case-2", 10, 100),
                case("case-3", 10, 100),
                case("case-4", 10, 100),
            ],
            "1.0.0",
        ))
        .await
    {
        Ok(report) => report,
        Err(error) => panic!("concurrency run failed before report: {error}"),
    };
    assert_eq!(concurrent_report.totals().passed(), 4);
    assert_eq!(concurrent_executor.max_active.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn report_and_error_diagnostics_never_retain_content() {
    struct FailingExecutor;

    #[async_trait]
    impl CaseExecutor for FailingExecutor {
        fn evidence_sha256(&self) -> Option<&str> {
            None
        }

        async fn execute(
            &self,
            _request: CaseExecutionRequest<'_>,
        ) -> Result<EvalExecutionResult, CaseExecutorError> {
            let diagnostic = RedactedDiagnostic::from_sensitive(
                DiagnosticCode::ProviderFailed,
                SECRET.as_bytes(),
            );
            Err(CaseExecutorError::new(
                diagnostic,
                EvalUsage::new(Some(3), None, 7),
            ))
        }
    }

    let repository = Arc::new(MemoryRepository::default());
    let runner = EvaluationRunner::new(
        &FailingExecutor,
        None,
        repository.as_ref(),
        limits(
            1,
            1_000,
            100,
            DiagnosticRetention::Redacted {
                max_diagnostics: 1,
                max_source_bytes: 1_000,
            },
        ),
    );
    let report = match runner
        .run(&dataset(vec![case("case-a", 10, 100)], "1.0.0"))
        .await
    {
        Ok(report) => report,
        Err(error) => panic!("runner failed before report: {error}"),
    };
    let encoded = match serde_json::to_string(&report) {
        Ok(encoded) => encoded,
        Err(error) => panic!("report encoding failed: {error}"),
    };
    assert!(!encoded.contains(SECRET));
    assert!(
        report.cases()[0]
            .diagnostic()
            .and_then(RedactedDiagnostic::source_sha256)
            .is_some()
    );

    let error = CaseExecutorError::new(
        RedactedDiagnostic::from_sensitive(DiagnosticCode::ProviderFailed, SECRET.as_bytes()),
        EvalUsage::new(Some(3), None, 7),
    );
    assert!(!format!("{error:?} {error}").contains(SECRET));
    let injected = format!(r#"{{"code":"{SECRET}","source_bytes":null,"source_sha256":null}}"#);
    assert!(serde_json::from_str::<RedactedDiagnostic>(&injected).is_err());
}
