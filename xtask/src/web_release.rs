use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::profiles::ProfileResult;

const EVIDENCE_SCHEMA: &str = include_str!("../../release/web-release-evidence.schema.json");
const MANUAL_ACCESSIBILITY_SCHEMA: &str =
    include_str!("../../release/web-manual-accessibility-evidence.schema.json");
const SPEC_MANIFEST_PATH: &str = "specs/machine/spec-manifest.json";
const WEB_SUITE_MANIFEST_PATH: &str = "specs/WEB_FEATURE_SUITE_MANIFEST.json";
const ACCEPTANCE_PATH: &str =
    "specs/machine/extensions/web-application-suite/acceptance-criteria.yaml";
const RECOMMENDATION_PATH: &str =
    "specs/machine/extensions/web-application-suite/recommendation-traceability.csv";
const PROFILE_REPORT_PATH: &str = "target/profile-matrix/report.json";
const WEB_CRITERIA_COUNT: usize = 80;

#[derive(Serialize)]
pub(crate) struct ReleaseReport {
    schema_version: u32,
    pub(crate) ready: bool,
    binding: ReleaseBinding,
    tool_versions: BTreeMap<String, String>,
    contract_aggregate_hashes: BTreeMap<String, String>,
    evidence_schema_sha256: String,
    manual_accessibility_schema_sha256: String,
    evidence: Vec<ReleaseEvidence>,
    traceability: TraceabilityReport,
    known_risk_sources: Vec<&'static str>,
    accepted_exceptions: Vec<AcceptedException>,
    web_suite_manifest_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ReleaseBinding {
    run_id: Option<String>,
    revision: Option<String>,
    spec_manifest_sha256: Option<String>,
    contract_aggregate_sha256: Option<String>,
}

impl ReleaseBinding {
    fn evidence_binding(&self) -> Option<EvidenceBinding> {
        Some(EvidenceBinding {
            run_id: self.run_id.clone()?,
            revision: self.revision.clone()?,
            spec_manifest_sha256: self.spec_manifest_sha256.clone()?,
            contract_aggregate_sha256: self.contract_aggregate_sha256.clone()?,
        })
    }

    fn complete(&self) -> bool {
        self.evidence_binding().is_some()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvidenceStatus {
    Passed,
    Blocked,
    Failed,
}

#[derive(Serialize)]
struct ReleaseEvidence {
    id: &'static str,
    required: bool,
    status: EvidenceStatus,
    detail: String,
    artifacts: Vec<String>,
}

impl ReleaseEvidence {
    fn passed(&self) -> bool {
        self.status == EvidenceStatus::Passed
    }
}

#[derive(Serialize)]
struct TraceabilityReport {
    complete: bool,
    passed: bool,
    detail: String,
    coverage: Vec<CoverageRecord>,
}

#[derive(Serialize)]
struct CoverageRecord {
    acceptance_id: String,
    recommendation_ids: Vec<String>,
    title: String,
    verification: String,
    specification: String,
    checks: Vec<String>,
    artifacts: Vec<String>,
    status: EvidenceStatus,
    detail: String,
}

#[derive(Serialize)]
struct AcceptedException {
    criterion: String,
    rationale: String,
    expires_or_review: String,
}

#[derive(Debug, Deserialize)]
struct AcceptanceCatalog {
    criteria: Vec<AcceptanceCriterion>,
}

#[derive(Debug, Deserialize)]
struct AcceptanceCriterion {
    id: String,
    title: String,
    verification: String,
    spec: String,
}

#[derive(Debug, Deserialize)]
struct RecommendationRow {
    recommendation_id: String,
    acceptance_id: String,
}

#[derive(Debug, Deserialize)]
struct SpecManifest {
    schema_version: u32,
    documents: Vec<SpecManifestDocument>,
}

#[derive(Debug, Deserialize)]
struct SpecManifestDocument {
    path: String,
    bytes: usize,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceBinding {
    run_id: String,
    revision: String,
    spec_manifest_sha256: String,
    contract_aggregate_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceDocument {
    schema_version: u32,
    evidence_id: String,
    status: EvidenceStatus,
    detail: String,
    generated_at: String,
    binding: EvidenceBinding,
    checks: Vec<EvidenceCheck>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceCheck {
    id: String,
    status: EvidenceStatus,
    command: String,
    artifacts: Vec<EvidenceArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceArtifact {
    path: String,
    sha256: String,
}

pub(crate) fn build(
    workspace: &Path,
    _work_root: &Path,
    profiles: &[ProfileResult],
    matrix_success: bool,
) -> ReleaseReport {
    let tool_versions = read_tool_versions(workspace);
    let contract_aggregate_hashes = profiles
        .iter()
        .filter_map(|profile| {
            profile
                .contract_aggregate_sha256
                .as_ref()
                .map(|hash| (profile.profile.clone(), hash.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let binding = ReleaseBinding {
        run_id: release_run_id(),
        revision: current_revision(workspace),
        spec_manifest_sha256: validated_spec_manifest_sha256(workspace).ok(),
        contract_aggregate_sha256: crate::contracts::aggregate_sha256(workspace).ok(),
    };
    let evidence = release_evidence(
        workspace,
        profiles,
        matrix_success,
        &contract_aggregate_hashes,
        &binding,
    );
    let traceability = build_traceability(workspace, profiles, &evidence);
    let web_suite_manifest_sha256 = hash_file(&workspace.join(WEB_SUITE_MANIFEST_PATH));
    let ready = binding.complete()
        && evidence.iter().all(|item| !item.required || item.passed())
        && traceability.complete
        && traceability.passed
        && web_suite_manifest_sha256.is_some()
        && tool_versions
            .values()
            .all(|version| version != "unavailable");

    ReleaseReport {
        schema_version: 3,
        ready,
        binding,
        tool_versions,
        contract_aggregate_hashes,
        evidence_schema_sha256: sha256(EVIDENCE_SCHEMA.as_bytes()),
        manual_accessibility_schema_sha256: sha256(MANUAL_ACCESSIBILITY_SCHEMA.as_bytes()),
        evidence,
        traceability,
        known_risk_sources: vec![
            "specs/machine/risk-register.yaml",
            "specs/machine/extensions/web-application-suite/risk-register.yaml",
        ],
        accepted_exceptions: Vec::new(),
        web_suite_manifest_sha256,
    }
}

fn release_evidence(
    workspace: &Path,
    profiles: &[ProfileResult],
    matrix_success: bool,
    contract_aggregate_hashes: &BTreeMap<String, String>,
    binding: &ReleaseBinding,
) -> Vec<ReleaseEvidence> {
    let web_profiles = profiles
        .iter()
        .filter(|profile| is_web_profile(profile))
        .collect::<Vec<_>>();
    let browser_profiles = web_profiles
        .iter()
        .filter_map(|profile| {
            profile
                .checks
                .iter()
                .find(|check| check.name == "web-e2e-smoke" && check.required)
        })
        .collect::<Vec<_>>();
    let browser_success = browser_profiles.len() == 4
        && browser_profiles
            .iter()
            .all(|check| check.executed && check.success && !check.artifacts.is_empty());
    let matrix_status = if matrix_success && web_profiles.len() == 5 {
        EvidenceStatus::Passed
    } else {
        EvidenceStatus::Failed
    };
    let contract_status = if contract_aggregate_hashes.len() == 5
        && contract_aggregate_hashes
            .values()
            .all(|hash| is_sha256(hash))
    {
        EvidenceStatus::Passed
    } else {
        EvidenceStatus::Failed
    };
    let browser_status = if browser_success {
        EvidenceStatus::Passed
    } else if browser_profiles
        .iter()
        .any(|check| check.executed && !check.success)
    {
        EvidenceStatus::Failed
    } else {
        EvidenceStatus::Blocked
    };
    let expected_binding = binding.evidence_binding();

    vec![
        ReleaseEvidence {
            id: "generated-profile-matrix",
            required: true,
            status: matrix_status,
            detail: format!(
                "{} profiles evaluated; {} web profiles; {} passed",
                profiles.len(),
                web_profiles.len(),
                profiles.iter().filter(|profile| profile.success).count()
            ),
            artifacts: vec![PROFILE_REPORT_PATH.to_owned()],
        },
        ReleaseEvidence {
            id: "contract-aggregate-hashes",
            required: true,
            status: contract_status,
            detail: format!(
                "{} generated web profile contract hashes recorded",
                contract_aggregate_hashes.len()
            ),
            artifacts: vec![PROFILE_REPORT_PATH.to_owned()],
        },
        ReleaseEvidence {
            id: "generated-profile-browser-smoke",
            required: true,
            status: browser_status,
            detail: format!(
                "{} generated served web profiles produced cross-browser smoke evidence",
                browser_profiles.len()
            ),
            artifacts: browser_profiles
                .iter()
                .flat_map(|check| check.artifacts.iter().cloned())
                .collect(),
        },
        file_evidence(
            workspace,
            "root-reference-browser-accessibility-security-performance",
            "target/web-release-evidence/browser-a11y-performance.json",
            expected_binding.as_ref(),
        ),
        manual_accessibility_evidence(workspace, expected_binding.as_ref()),
        file_evidence(
            workspace,
            "dependency-advisory-review",
            "target/web-release-evidence/dependency-advisories.json",
            expected_binding.as_ref(),
        ),
        file_evidence(
            workspace,
            "contract-breaking-change-report",
            "target/web-release-evidence/contract-diff.json",
            expected_binding.as_ref(),
        ),
        file_evidence(
            workspace,
            "prior-release-upgrade-rehearsal",
            "target/web-release-evidence/lifecycle-upgrade.json",
            expected_binding.as_ref(),
        ),
        file_evidence(
            workspace,
            "semantic-wrapper-review",
            "target/web-release-evidence/semantic-wrapper-review.json",
            expected_binding.as_ref(),
        ),
        file_evidence(
            workspace,
            "risk-review",
            "target/web-release-evidence/risk-review.json",
            expected_binding.as_ref(),
        ),
        file_evidence(
            workspace,
            "sbom-and-provenance-integration",
            "target/web-release-evidence/sbom-provenance.json",
            expected_binding.as_ref(),
        ),
        static_files_evidence(
            workspace,
            "release-notes-and-operational-runbook",
            &[
                "release/web-suite-release-notes.md",
                "release/web-suite-runbook.md",
            ],
        ),
    ]
}

fn read_tool_versions(workspace: &Path) -> BTreeMap<String, String> {
    let package = fs::read_to_string(workspace.join("package.json"))
        .ok()
        .and_then(|contents| serde_json::from_str::<serde_json::Value>(&contents).ok());
    let package_value = |pointer: &str| {
        package
            .as_ref()
            .and_then(|document| document.pointer(pointer))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unavailable")
            .to_owned()
    };
    BTreeMap::from([
        ("node".to_owned(), package_value("/engines/node")),
        (
            "package_manager".to_owned(),
            package_value("/packageManager"),
        ),
        (
            "typescript".to_owned(),
            package_value("/devDependencies/typescript"),
        ),
        (
            "typescript_next".to_owned(),
            package_value("/devDependencies/typescript7"),
        ),
        (
            "browser_library".to_owned(),
            package_value("/devDependencies/@playwright~1test"),
        ),
        (
            "test_tool".to_owned(),
            package_value("/devDependencies/vitest"),
        ),
        (
            "generator".to_owned(),
            package_value("/devDependencies/orval"),
        ),
    ])
}

fn release_run_id() -> Option<String> {
    nonempty_environment("OMNIUS_RELEASE_RUN_ID").or_else(|| {
        let run = nonempty_environment("GITHUB_RUN_ID")?;
        let attempt = nonempty_environment("GITHUB_RUN_ATTEMPT")?;
        Some(format!("github-{run}-{attempt}"))
    })
}

fn current_revision(workspace: &Path) -> Option<String> {
    if let Some(revision) = nonempty_environment("OMNIUS_RELEASE_REVISION")
        .or_else(|| nonempty_environment("GITHUB_SHA"))
    {
        return Some(revision);
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let revision = String::from_utf8(output.stdout).ok()?;
    let revision = revision.trim();
    (!revision.is_empty()).then_some(revision.to_owned())
}

fn nonempty_environment(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn manual_accessibility_evidence(
    workspace: &Path,
    expected_binding: Option<&EvidenceBinding>,
) -> ReleaseEvidence {
    let path = std::env::var_os("OMNIUS_ACCESSIBILITY_REVIEW_EVIDENCE").map_or_else(
        || workspace.join("web/e2e/manual-accessibility-review.pending.json"),
        PathBuf::from,
    );
    let artifact = display_path(workspace, &path);
    let Some(expected_binding) = expected_binding else {
        return ReleaseEvidence {
            id: "manual-accessibility-review",
            required: true,
            status: EvidenceStatus::Blocked,
            detail:
                "current run, revision, specification manifest, or contract binding is unavailable"
                    .to_owned(),
            artifacts: vec![artifact],
        };
    };
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return ReleaseEvidence {
                id: "manual-accessibility-review",
                required: true,
                status: EvidenceStatus::Blocked,
                detail: format!("manual keyboard and screen-reader evidence is absent: {error}"),
                artifacts: vec![artifact],
            };
        }
    };
    let document = serde_json::from_slice::<serde_json::Value>(&bytes);
    if document.as_ref().is_ok_and(|value| {
        matches!(
            value.get("status").and_then(serde_json::Value::as_str),
            Some("pending" | "blocked")
        )
    }) {
        return ReleaseEvidence {
            id: "manual-accessibility-review",
            required: true,
            status: EvidenceStatus::Blocked,
            detail: "human keyboard and screen-reader review is explicitly pending or blocked"
                .to_owned(),
            artifacts: vec![artifact],
        };
    }
    let validation = validate_json_schema(MANUAL_ACCESSIBILITY_SCHEMA, &bytes)
        .and_then(|()| validate_manual_binding(&bytes, expected_binding));
    match validation {
        Ok(()) => ReleaseEvidence {
            id: "manual-accessibility-review",
            required: true,
            status: EvidenceStatus::Passed,
            detail: format!(
                "current human keyboard and screen-reader evidence is approved; sha256:{}",
                sha256(&bytes)
            ),
            artifacts: vec![artifact],
        },
        Err(error) => ReleaseEvidence {
            id: "manual-accessibility-review",
            required: true,
            status: EvidenceStatus::Failed,
            detail: format!("manual accessibility evidence was rejected: {error}"),
            artifacts: vec![artifact],
        },
    }
}

fn validate_manual_binding(bytes: &[u8], expected: &EvidenceBinding) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("parse manual accessibility evidence")?;
    let binding: EvidenceBinding = serde_json::from_value(
        value
            .get("binding")
            .cloned()
            .context("manual accessibility evidence has no binding")?,
    )
    .context("parse manual accessibility evidence binding")?;
    ensure!(
        binding == *expected,
        "manual accessibility evidence binding does not match the current run"
    );
    Ok(())
}

fn static_files_evidence(
    workspace: &Path,
    id: &'static str,
    relative_paths: &[&str],
) -> ReleaseEvidence {
    let artifacts = relative_paths
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<Vec<_>>();
    let hashes = relative_paths
        .iter()
        .filter_map(|path| {
            let full_path = workspace.join(path);
            let bytes = fs::read(full_path).ok()?;
            (!bytes.is_empty()).then_some((*path, sha256(&bytes)))
        })
        .collect::<Vec<_>>();
    ReleaseEvidence {
        id,
        required: true,
        status: if hashes.len() == relative_paths.len() {
            EvidenceStatus::Passed
        } else {
            EvidenceStatus::Blocked
        },
        detail: if hashes.len() == relative_paths.len() {
            hashes
                .iter()
                .map(|(path, hash)| format!("{path}=sha256:{hash}"))
                .collect::<Vec<_>>()
                .join("; ")
        } else {
            "one or more required release documents are absent or empty".to_owned()
        },
        artifacts,
    }
}

fn file_evidence(
    workspace: &Path,
    id: &'static str,
    relative: &str,
    expected_binding: Option<&EvidenceBinding>,
) -> ReleaseEvidence {
    let Some(expected_binding) = expected_binding else {
        return ReleaseEvidence {
            id,
            required: true,
            status: EvidenceStatus::Blocked,
            detail:
                "current run, revision, specification manifest, or contract binding is unavailable"
                    .to_owned(),
            artifacts: vec![relative.to_owned()],
        };
    };
    let path = workspace.join(relative);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return ReleaseEvidence {
                id,
                required: true,
                status: EvidenceStatus::Blocked,
                detail: format!("required release evidence is absent: {error}"),
                artifacts: vec![relative.to_owned()],
            };
        }
    };
    match validate_evidence_document(workspace, id, &bytes, expected_binding) {
        Ok(document) => {
            let mut artifacts = vec![relative.to_owned()];
            artifacts.extend(
                document
                    .checks
                    .iter()
                    .flat_map(|check| check.artifacts.iter().map(|artifact| artifact.path.clone())),
            );
            artifacts.sort();
            artifacts.dedup();
            ReleaseEvidence {
                id,
                required: true,
                status: document.status,
                detail: format!("{}; sha256:{}", document.detail, sha256(&bytes)),
                artifacts,
            }
        }
        Err(error) => ReleaseEvidence {
            id,
            required: true,
            status: EvidenceStatus::Failed,
            detail: format!("release evidence was rejected: {error}"),
            artifacts: vec![relative.to_owned()],
        },
    }
}

fn validate_evidence_document(
    workspace: &Path,
    expected_id: &str,
    bytes: &[u8],
    expected_binding: &EvidenceBinding,
) -> Result<EvidenceDocument> {
    validate_json_schema(EVIDENCE_SCHEMA, bytes)?;
    let document: EvidenceDocument =
        serde_json::from_slice(bytes).context("parse bound release evidence")?;
    ensure!(document.schema_version == 2, "unsupported evidence schema");
    ensure!(
        document.evidence_id == expected_id,
        "evidence ID `{}` does not match expected `{expected_id}`",
        document.evidence_id
    );
    ensure!(
        document.binding == *expected_binding,
        "evidence binding does not match the current run"
    );
    ensure!(
        !document.detail.trim().is_empty() && !document.generated_at.trim().is_empty(),
        "evidence detail and generation time must be non-empty"
    );
    let mut check_ids = BTreeSet::new();
    for check in &document.checks {
        ensure!(
            check_ids.insert(check.id.as_str()),
            "evidence contains duplicate check `{}`",
            check.id
        );
        ensure!(
            !check.command.trim().is_empty(),
            "evidence check `{}` has no command",
            check.id
        );
        for artifact in &check.artifacts {
            validate_artifact(workspace, artifact)
                .with_context(|| format!("validate artifact for evidence check `{}`", check.id))?;
        }
    }
    let derived_status = combined_status(document.checks.iter().map(|check| check.status));
    ensure!(
        document.status == derived_status,
        "evidence status is inconsistent with its checks"
    );
    Ok(document)
}

fn validate_json_schema(schema: &str, bytes: &[u8]) -> Result<()> {
    let schema: serde_json::Value =
        serde_json::from_str(schema).context("parse evidence schema")?;
    let document: serde_json::Value =
        serde_json::from_slice(bytes).context("parse evidence JSON")?;
    let validator = jsonschema::validator_for(&schema).context("compile evidence schema")?;
    let errors = validator
        .iter_errors(&document)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    ensure!(
        errors.is_empty(),
        "evidence does not satisfy the full schema: {}",
        errors.join("; ")
    );
    Ok(())
}

fn validate_artifact(workspace: &Path, artifact: &EvidenceArtifact) -> Result<()> {
    let relative = Path::new(&artifact.path);
    ensure!(
        !relative.is_absolute()
            && relative
                .components()
                .all(|component| { matches!(component, Component::Normal(_) | Component::CurDir) }),
        "evidence artifact path must stay within the workspace"
    );
    ensure!(is_sha256(&artifact.sha256), "artifact SHA-256 is malformed");
    let actual = hash_file(&workspace.join(relative)).context("evidence artifact is absent")?;
    ensure!(
        actual == artifact.sha256,
        "evidence artifact hash does not match current contents"
    );
    Ok(())
}

fn build_traceability(
    workspace: &Path,
    profiles: &[ProfileResult],
    evidence: &[ReleaseEvidence],
) -> TraceabilityReport {
    match try_build_traceability(workspace, profiles, evidence) {
        Ok(coverage) => {
            let passed = coverage
                .iter()
                .all(|record| record.status == EvidenceStatus::Passed);
            TraceabilityReport {
                complete: true,
                passed,
                detail: if passed {
                    "all 80 web acceptance criteria and recommendations have current passing evidence"
                        .to_owned()
                } else {
                    "all 80 web acceptance criteria and recommendations are mapped; blocked or failed evidence remains explicit"
                        .to_owned()
                },
                coverage,
            }
        }
        Err(error) => TraceabilityReport {
            complete: false,
            passed: false,
            detail: format!("web traceability catalog was rejected: {error}"),
            coverage: Vec::new(),
        },
    }
}

fn try_build_traceability(
    workspace: &Path,
    profiles: &[ProfileResult],
    evidence: &[ReleaseEvidence],
) -> Result<Vec<CoverageRecord>> {
    let acceptance: AcceptanceCatalog = serde_yaml::from_str(
        &fs::read_to_string(workspace.join(ACCEPTANCE_PATH))
            .with_context(|| format!("read {ACCEPTANCE_PATH}"))?,
    )
    .with_context(|| format!("parse {ACCEPTANCE_PATH}"))?;
    ensure!(
        acceptance.criteria.len() == WEB_CRITERIA_COUNT,
        "expected {WEB_CRITERIA_COUNT} web acceptance criteria"
    );
    let mut reader = csv::Reader::from_path(workspace.join(RECOMMENDATION_PATH))
        .with_context(|| format!("read {RECOMMENDATION_PATH}"))?;
    let recommendations = reader
        .deserialize::<RecommendationRow>()
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse {RECOMMENDATION_PATH}"))?;
    ensure!(
        recommendations.len() == WEB_CRITERIA_COUNT,
        "expected {WEB_CRITERIA_COUNT} web recommendations"
    );

    let mut criteria_by_number = BTreeMap::new();
    for criterion in acceptance.criteria {
        let number = web_id_number(&criterion.id, "AC-WEB-")?;
        ensure!(
            (1..=WEB_CRITERIA_COUNT).contains(&number),
            "acceptance ID is outside AC-WEB-001..080"
        );
        ensure!(
            criteria_by_number.insert(number, criterion).is_none(),
            "duplicate web acceptance criterion"
        );
    }
    let mut recommendations_by_number = BTreeMap::new();
    for recommendation in recommendations {
        let number = web_id_number(&recommendation.recommendation_id, "REC-WEB-")?;
        ensure!(
            recommendation.acceptance_id == format!("AC-WEB-{number:03}"),
            "recommendation {} does not map to its paired acceptance criterion",
            recommendation.recommendation_id
        );
        ensure!(
            recommendations_by_number
                .insert(number, recommendation.recommendation_id)
                .is_none(),
            "duplicate web recommendation"
        );
    }

    (1..=WEB_CRITERIA_COUNT)
        .map(|number| {
            let criterion = criteria_by_number
                .remove(&number)
                .with_context(|| format!("AC-WEB-{number:03} is missing"))?;
            let recommendation = recommendations_by_number
                .remove(&number)
                .with_context(|| format!("REC-WEB-{number:03} is missing"))?;
            let checks = criterion_checks(number);
            ensure!(
                !checks.is_empty(),
                "AC-WEB-{number:03} has no concrete check mapping"
            );
            let sources = checks
                .iter()
                .map(|check| resolve_check(check, profiles, evidence))
                .collect::<Vec<_>>();
            let status = combined_status(sources.iter().map(|source| source.status));
            let mut artifacts = sources
                .iter()
                .flat_map(|source| source.artifacts.iter().cloned())
                .collect::<Vec<_>>();
            artifacts.sort();
            artifacts.dedup();
            ensure!(
                !artifacts.is_empty(),
                "AC-WEB-{number:03} has no concrete artifact mapping"
            );
            let detail = sources
                .iter()
                .filter(|source| source.status != EvidenceStatus::Passed)
                .map(|source| format!("{}: {}", source.check, source.detail))
                .collect::<Vec<_>>();
            Ok(CoverageRecord {
                acceptance_id: criterion.id,
                recommendation_ids: vec![recommendation],
                title: criterion.title,
                verification: criterion.verification,
                specification: criterion.spec,
                checks: checks.iter().map(|check| (*check).to_owned()).collect(),
                artifacts,
                status,
                detail: if detail.is_empty() {
                    "all mapped current-run checks passed".to_owned()
                } else {
                    detail.join("; ")
                },
            })
        })
        .collect()
}

struct ResolvedCheck {
    check: String,
    status: EvidenceStatus,
    detail: String,
    artifacts: Vec<String>,
}

fn resolve_check(
    check: &str,
    profiles: &[ProfileResult],
    evidence: &[ReleaseEvidence],
) -> ResolvedCheck {
    if let Some(name) = check.strip_prefix("profile:") {
        return resolve_profile_check(name, profiles);
    }
    if let Some(name) = check.strip_prefix("release:") {
        if let Some(item) = evidence.iter().find(|item| item.id == name) {
            return ResolvedCheck {
                check: check.to_owned(),
                status: item.status,
                detail: item.detail.clone(),
                artifacts: if item.artifacts.is_empty() {
                    vec![PROFILE_REPORT_PATH.to_owned()]
                } else {
                    item.artifacts.clone()
                },
            };
        }
    }
    ResolvedCheck {
        check: check.to_owned(),
        status: EvidenceStatus::Blocked,
        detail: "mapped check is not present in the current release report".to_owned(),
        artifacts: vec![PROFILE_REPORT_PATH.to_owned()],
    }
}

fn resolve_profile_check(name: &str, profiles: &[ProfileResult]) -> ResolvedCheck {
    let web_profiles = profiles
        .iter()
        .filter(|profile| is_web_profile(profile))
        .collect::<Vec<_>>();
    let checks = web_profiles
        .iter()
        .filter_map(|profile| profile.checks.iter().find(|check| check.name == name))
        .filter(|check| check.required)
        .collect::<Vec<_>>();
    let expected = if name == "web-e2e-smoke" { 4 } else { 5 };
    let status =
        if checks.len() == expected && checks.iter().all(|check| check.executed && check.success) {
            EvidenceStatus::Passed
        } else if checks.iter().any(|check| check.executed && !check.success) {
            EvidenceStatus::Failed
        } else {
            EvidenceStatus::Blocked
        };
    let mut artifacts = checks
        .iter()
        .flat_map(|check| check.artifacts.iter().cloned())
        .collect::<Vec<_>>();
    artifacts.push(PROFILE_REPORT_PATH.to_owned());
    artifacts.sort();
    artifacts.dedup();
    ResolvedCheck {
        check: format!("profile:{name}"),
        status,
        detail: format!(
            "{} of {expected} required web profile checks are present for `{name}`",
            checks.len()
        ),
        artifacts,
    }
}

fn criterion_checks(number: usize) -> &'static [&'static str] {
    match number {
        1 => &["release:release-notes-and-operational-runbook"],
        2 | 5 | 21 | 22 => &["profile:web-typecheck-ts6", "profile:web-typecheck-ts7"],
        3 | 4 | 77 => &["release:generated-profile-matrix"],
        6 => &["profile:web-build"],
        7 => &["profile:web-build", "release:contract-aggregate-hashes"],
        8..=10 => &["release:root-reference-browser-accessibility-security-performance"],
        11..=17 | 19 => &["profile:web-contracts-check"],
        18 => &["release:contract-breaking-change-report"],
        20 => &[
            "profile:web-contracts-check",
            "release:root-reference-browser-accessibility-security-performance",
        ],
        23..=27 => &["profile:web-test"],
        28 => &["release:semantic-wrapper-review"],
        29 => &["profile:web-contracts-check", "profile:web-build"],
        30 => &["profile:web-contracts-check"],
        31..=40 => &["release:root-reference-browser-accessibility-security-performance"],
        41 => &["profile:web-contracts-check", "profile:web-test"],
        42 | 46 | 47 => &["profile:web-test"],
        43..=45 | 48..=59 => &["release:root-reference-browser-accessibility-security-performance"],
        60 => &["release:sbom-and-provenance-integration"],
        61 => &["profile:web-test", "profile:web-typecheck-ts6"],
        62 => &["release:root-reference-browser-accessibility-security-performance"],
        63 => &["profile:web-test"],
        64..=66 | 68 => &["release:root-reference-browser-accessibility-security-performance"],
        67 | 69 | 70 => &["profile:web-test"],
        71..=73 => &["release:root-reference-browser-accessibility-security-performance"],
        74 => &["release:dependency-advisory-review"],
        75 => &[
            "release:root-reference-browser-accessibility-security-performance",
            "release:manual-accessibility-review",
        ],
        76 => &["release:root-reference-browser-accessibility-security-performance"],
        78 | 80 => &["release:prior-release-upgrade-rehearsal"],
        79 => &[
            "release:generated-profile-matrix",
            "release:contract-aggregate-hashes",
            "release:generated-profile-browser-smoke",
        ],
        _ => &[],
    }
}

fn combined_status(statuses: impl IntoIterator<Item = EvidenceStatus>) -> EvidenceStatus {
    let mut status = EvidenceStatus::Passed;
    for item in statuses {
        match item {
            EvidenceStatus::Failed => return EvidenceStatus::Failed,
            EvidenceStatus::Blocked => status = EvidenceStatus::Blocked,
            EvidenceStatus::Passed => {}
        }
    }
    status
}

fn web_id_number(id: &str, prefix: &str) -> Result<usize> {
    let suffix = id
        .strip_prefix(prefix)
        .with_context(|| format!("ID `{id}` does not start with `{prefix}`"))?;
    ensure!(
        suffix.len() == 3,
        "ID `{id}` is not zero-padded to three digits"
    );
    suffix
        .parse::<usize>()
        .with_context(|| format!("ID `{id}` has a non-numeric suffix"))
}

fn is_web_profile(profile: &ProfileResult) -> bool {
    profile
        .checks
        .iter()
        .any(|check| check.name == "web-workspace")
}

fn validated_spec_manifest_sha256(workspace: &Path) -> Result<String> {
    let manifest_path = workspace.join(SPEC_MANIFEST_PATH);
    let manifest_bytes = fs::read(&manifest_path).context("read specification manifest")?;
    let manifest: SpecManifest =
        serde_json::from_slice(&manifest_bytes).context("parse specification manifest")?;
    ensure!(
        manifest.schema_version == 1 && !manifest.documents.is_empty(),
        "specification manifest has an unsupported or empty schema"
    );
    let mut paths = BTreeSet::new();
    for document in manifest.documents {
        let relative = Path::new(&document.path);
        ensure!(
            !relative.is_absolute()
                && relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "specification manifest contains an unsafe document path"
        );
        ensure!(
            paths.insert(document.path.clone()),
            "specification manifest contains a duplicate document path"
        );
        let contents = fs::read(workspace.join("specs").join(relative))
            .with_context(|| format!("read specification document `{}`", document.path))?;
        ensure!(
            contents.len() == document.bytes && sha256(&contents) == document.sha256,
            "specification manifest entry `{}` is stale",
            document.path
        );
    }
    Ok(sha256(&manifest_bytes))
}

fn hash_file(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|contents| sha256(&contents))
}

fn sha256(contents: &[u8]) -> String {
    format!("{:x}", Sha256::digest(contents))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn display_path(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnius_test_support::CleanDirectory;

    #[test]
    fn release_report_fails_closed_when_evidence_is_absent() -> anyhow::Result<()> {
        let workspace = CleanDirectory::new("web-release-report")?;
        fs::write(
            workspace.path().join("package.json"),
            serde_json::to_vec(&serde_json::json!({
                "packageManager": "pnpm@11.23.0",
                "engines": {"node": "24.19.0"},
                "devDependencies": {
                    "typescript": "6.0.2",
                    "typescript7": "npm:typescript@7.0.2",
                    "@playwright/test": "1.62.1",
                    "vitest": "4.1.11",
                    "orval": "8.26.0"
                }
            }))?,
        )?;
        let report = build(workspace.path(), workspace.path(), &[], false);
        assert!(!report.ready);
        assert!(
            report
                .evidence
                .iter()
                .filter(|item| item.required)
                .any(|item| !item.passed())
        );
        assert!(report.accepted_exceptions.is_empty());
        Ok(())
    }

    #[test]
    fn reads_every_required_pinned_tool_version() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let versions = read_tool_versions(&workspace);
        assert_eq!(versions.len(), 7);
        assert!(versions.values().all(|value| value != "unavailable"));
    }

    #[test]
    fn bound_evidence_rejects_minimal_and_stale_documents() -> anyhow::Result<()> {
        let workspace = CleanDirectory::new("bound-web-evidence")?;
        let binding = test_binding();
        let minimal = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "status": "passed"
        }))?;
        assert!(
            validate_evidence_document(workspace.path(), "browser", &minimal, &binding).is_err()
        );

        let artifact_path = workspace.path().join("target/proof.json");
        fs::create_dir_all(artifact_path.parent().context("proof path has no parent")?)?;
        fs::write(&artifact_path, b"proof")?;
        let stale = full_evidence_document(
            "browser",
            EvidenceBinding {
                revision: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
                ..binding.clone()
            },
            "target/proof.json",
            &sha256(b"proof"),
        )?;
        assert!(validate_evidence_document(workspace.path(), "browser", &stale, &binding).is_err());
        Ok(())
    }

    #[test]
    fn bound_evidence_accepts_current_binding_and_artifact_hash() -> anyhow::Result<()> {
        let workspace = CleanDirectory::new("current-web-evidence")?;
        let artifact_path = workspace.path().join("target/proof.json");
        fs::create_dir_all(artifact_path.parent().context("proof path has no parent")?)?;
        fs::write(&artifact_path, b"proof")?;
        let binding = test_binding();
        let evidence = full_evidence_document(
            "browser",
            binding.clone(),
            "target/proof.json",
            &sha256(b"proof"),
        )?;
        let document =
            validate_evidence_document(workspace.path(), "browser", &evidence, &binding)?;
        assert_eq!(document.status, EvidenceStatus::Passed);
        Ok(())
    }

    #[test]
    fn traceability_maps_every_web_acceptance_and_recommendation() -> anyhow::Result<()> {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let coverage = try_build_traceability(&workspace, &[], &[])?;
        assert_eq!(coverage.len(), WEB_CRITERIA_COUNT);
        assert_eq!(coverage[0].acceptance_id, "AC-WEB-001");
        assert_eq!(coverage[0].recommendation_ids, ["REC-WEB-001"]);
        assert_eq!(coverage[79].acceptance_id, "AC-WEB-080");
        assert_eq!(coverage[79].recommendation_ids, ["REC-WEB-080"]);
        assert!(coverage.iter().all(|record| !record.checks.is_empty()));
        assert!(coverage.iter().all(|record| !record.artifacts.is_empty()));
        assert!(
            coverage
                .iter()
                .any(|record| record.status == EvidenceStatus::Blocked)
        );
        Ok(())
    }

    fn test_binding() -> EvidenceBinding {
        EvidenceBinding {
            run_id: "test-run-1".to_owned(),
            revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            spec_manifest_sha256: "1".repeat(64),
            contract_aggregate_sha256: "2".repeat(64),
        }
    }

    fn full_evidence_document(
        evidence_id: &str,
        binding: EvidenceBinding,
        artifact_path: &str,
        artifact_sha256: &str,
    ) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "evidenceId": evidence_id,
            "status": "passed",
            "detail": "focused check passed",
            "generatedAt": "2026-08-27T00:00:00Z",
            "binding": {
                "runId": binding.run_id,
                "revision": binding.revision,
                "specManifestSha256": binding.spec_manifest_sha256,
                "contractAggregateSha256": binding.contract_aggregate_sha256
            },
            "checks": [{
                "id": "focused-check",
                "status": "passed",
                "command": "focused-check --json",
                "artifacts": [{
                    "path": artifact_path,
                    "sha256": artifact_sha256
                }]
            }]
        }))
        .map_err(Into::into)
    }
}
