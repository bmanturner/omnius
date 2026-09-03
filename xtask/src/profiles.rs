use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};

use omnius_generator::{
    CANONICAL_REPOSITORY, KIT_VERSION, ModuleCatalog as GeneratorModuleCatalog,
    ProfileCatalog as GeneratorProfileCatalog, ProjectManager, ProviderSelection, ReleaseIdentity,
    RenderError, RenderRequest, ResolvedProfile, bundled_profile_catalog, render_project,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub(crate) struct ProfileSummary {
    pub(crate) modules: usize,
    pub(crate) profiles: usize,
}

pub(crate) fn verify(root: &Path) -> Result<ProfileSummary> {
    let overlay = crate::extensions::Overlay::verify(root)?;
    let module_document = overlay.yaml_value(root, "machine/module-catalog.yaml")?;
    let module_source = serde_yaml::to_string(&module_document)?;
    let modules = GeneratorModuleCatalog::from_overlay_yaml(&module_source)?;
    let profile_document = overlay.yaml_value(root, "machine/profiles.yaml")?;
    let profile_source = serde_yaml::to_string(&profile_document)?;
    let profiles = GeneratorProfileCatalog::from_overlay_yaml(&profile_source, &modules)?;
    Ok(ProfileSummary {
        modules: modules.modules.len(),
        profiles: profiles.profiles().len(),
    })
}

static PROFILE_E2E_GATE: Mutex<()> = Mutex::new(());

const BASE_MATRIX_CHECKS: &[&str] = &[
    "render-fresh",
    "render-repeat",
    "byte-identical",
    "metadata-artifacts",
    "doctor-clean",
    "diff-clean",
    "cargo-test",
    "build-cache-cleanup",
    "profile-info",
    "composition-manifest",
    "migration-policy",
    "application-requirements",
    "application-fixture-origin",
    "startup-readiness",
    "registered-routes-tasks-health",
    "representative-workflow",
    "negative-workflow",
    "dependency-outage",
    "bounded-shutdown",
    "runtime-contract-parity",
];
const WEB_MATRIX_CHECKS: &[&str] = &[
    "web-workspace",
    "web-frozen-install",
    "web-contracts-check",
    "web-typecheck-ts6",
    "web-typecheck-ts7",
    "web-test",
    "web-build",
    "web-e2e-smoke",
];
const WEB_PROFILE_MODULE: &str = "web-sdk-core";
const WEB_E2E_MODULE: &str = "web-react";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckStatus {
    Passed,
    Failed,
    Blocked,
    Skipped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileKind {
    Base,
    Web,
    Mcp,
    Ai,
    AiMcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReleasePolicy {
    Enforced,
    AutomatedEvidenceOnly,
    ReportOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ImplementationState {
    Selected,
    Generated,
    Compiled,
    Assembled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct MigrationRange {
    minimum: String,
    maximum: String,
}

#[derive(Serialize)]
pub(crate) struct MatrixReport {
    schema_version: u32,
    expected_profiles: usize,
    web_profiles: usize,
    passed_profiles: usize,
    matrix_success: bool,
    release_ready: bool,
    release_policy: ReleasePolicy,
    success: bool,
    profiles: Vec<ProfileResult>,
    release: crate::web_release::ReleaseReport,
}

impl MatrixReport {
    pub(crate) fn expected_profiles(&self) -> usize {
        self.expected_profiles
    }
}

#[derive(Serialize)]
pub(crate) struct ProfileResult {
    pub(crate) profile: String,
    service: String,
    kind: ProfileKind,
    pub(crate) success: bool,
    resolved_modules: Vec<String>,
    resolved_providers: Vec<ProviderSelection>,
    resolved_services: Vec<String>,
    composition_root: Option<String>,
    executable_command: Option<String>,
    assembled_modules: Vec<String>,
    application_required_modules: Vec<String>,
    application_required_contributions: BTreeMap<String, Vec<String>>,
    application_fixture: ApplicationFixtureEvidence,
    registered_route_ids: Vec<String>,
    registered_task_ids: Vec<String>,
    registered_health_ids: Vec<String>,
    registered_operation_ids: Vec<String>,
    registered_capability_ids: Vec<String>,
    registered_transport_ids: Vec<String>,
    migration_range: Option<MigrationRange>,
    positive_workflow_checks: Vec<String>,
    negative_workflow_checks: Vec<String>,
    readiness_checks: Vec<String>,
    outage_checks: Vec<String>,
    shutdown_checks: Vec<String>,
    retained_artifacts: Vec<String>,
    implementation_state: ImplementationState,
    pub(crate) contract_aggregate_sha256: Option<String>,
    pub(crate) checks: Vec<CheckResult>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ApplicationFixtureEvidence {
    synthetic: bool,
    source: Option<String>,
    used_for_classification: bool,
}

#[derive(Serialize)]
pub(crate) struct CheckResult {
    pub(crate) name: &'static str,
    pub(crate) required: bool,
    pub(crate) executed: bool,
    pub(crate) status: CheckStatus,
    pub(crate) success: bool,
    command: Option<String>,
    pub(crate) detail: String,
    pub(crate) criteria: Vec<String>,
    recommendations: Vec<String>,
    pub(crate) artifacts: Vec<String>,
}

#[derive(Clone)]
struct ProfilePlan {
    id: String,
    kind: ProfileKind,
    resolved: ResolvedProfile,
    web: bool,
    e2e: bool,
}

#[derive(Default)]
struct ProfileEvidence {
    assembled_modules: Vec<String>,
    application_required_modules: Vec<String>,
    application_required_contributions: BTreeMap<String, Vec<String>>,
    application_fixture: ApplicationFixtureEvidence,
    migration_range: Option<MigrationRange>,
    registered_route_ids: Vec<String>,
    registered_task_ids: Vec<String>,
    registered_health_ids: Vec<String>,
    registered_operation_ids: Vec<String>,
    registered_capability_ids: Vec<String>,
    registered_transport_ids: Vec<String>,
    concrete_registrar_modules: Vec<String>,
    positive_workflow_checks: Vec<String>,
    negative_workflow_checks: Vec<String>,
    readiness_checks: Vec<String>,
    outage_checks: Vec<String>,
    shutdown_checks: Vec<String>,
}

fn profile_plans(
    catalog: &GeneratorProfileCatalog,
    modules: &GeneratorModuleCatalog,
) -> Result<Vec<ProfilePlan>> {
    catalog
        .profiles()
        .iter()
        .map(|profile| {
            let resolved = catalog.resolve(&profile.id, modules)?;
            let web = resolved
                .modules()
                .iter()
                .any(|module| module == WEB_PROFILE_MODULE);
            let has_mcp = resolved
                .modules()
                .iter()
                .any(|module| module.starts_with("mcp-"));
            let has_ai = resolved
                .modules()
                .iter()
                .any(|module| module.starts_with("llm-"));
            let e2e = resolved
                .modules()
                .iter()
                .any(|module| module == WEB_E2E_MODULE);
            ensure!(
                !e2e || web,
                "profile `{}` enables web E2E without web",
                profile.id
            );
            let kind = match (has_ai, has_mcp, web) {
                (true, true, _) => ProfileKind::AiMcp,
                (true, false, _) => ProfileKind::Ai,
                (false, true, _) => ProfileKind::Mcp,
                (false, false, true) => ProfileKind::Web,
                (false, false, false) => ProfileKind::Base,
            };
            Ok(ProfilePlan {
                id: profile.id.clone(),
                kind,
                resolved,
                web,
                e2e,
            })
        })
        .collect()
}

fn cargo_target_root(workspace: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || workspace.join("target"),
        |target| {
            let target = PathBuf::from(target);
            if target.is_absolute() {
                target
            } else {
                workspace.join(target)
            }
        },
    )
}

pub(crate) fn generate_verify(workspace: &Path, arguments: &[String]) -> Result<MatrixReport> {
    let (jobs, report_path, release_policy) = matrix_arguments(workspace, arguments)?;
    let modules = GeneratorModuleCatalog::bundled()?;
    let catalog = bundled_profile_catalog()?;
    let plans = profile_plans(catalog, &modules)?;
    ensure!(!plans.is_empty(), "bundled profile catalog is empty");
    let work_root = cargo_target_root(workspace).join("profile-matrix/work");
    if work_root.exists() {
        fs::remove_dir_all(&work_root).with_context(|| format!("reset {}", work_root.display()))?;
    }
    fs::create_dir_all(&work_root)?;
    let cargo_target = cargo_target_root(workspace).join("profile-matrix/cargo");
    fs::create_dir_all(&cargo_target)?;

    let worker_count = jobs.min(plans.len()).max(1);
    let mut partitions = vec![Vec::new(); worker_count];
    for (index, plan) in plans.iter().enumerate() {
        partitions[index % worker_count].push(plan);
    }
    let mut results = thread::scope(|scope| -> Result<Vec<ProfileResult>> {
        let handles = partitions
            .into_iter()
            .map(|partition| {
                let work_root = &work_root;
                let cargo_target = &cargo_target;
                scope.spawn(move || {
                    partition
                        .into_iter()
                        .map(|plan| {
                            verify_generated_profile(workspace, work_root, cargo_target, plan)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let mut results = Vec::with_capacity(plans.len());
        for handle in handles {
            results.extend(
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("profile matrix worker panicked"))?,
            );
        }
        Ok(results)
    })?;
    let order = plans
        .iter()
        .enumerate()
        .map(|(index, plan)| (plan.id.as_str(), index))
        .collect::<HashMap<_, _>>();
    results.sort_by_key(|result| {
        order
            .get(result.profile.as_str())
            .copied()
            .unwrap_or(usize::MAX)
    });
    let passed_profiles = results.iter().filter(|result| result.success).count();
    let matrix_success = results.len() == plans.len() && passed_profiles == plans.len();
    let release = crate::web_release::build(workspace, &work_root, &results, matrix_success);
    let release_ready = release.ready;
    let release_policy_passed = match release_policy {
        ReleasePolicy::Enforced => release_ready,
        ReleasePolicy::AutomatedEvidenceOnly => release.automated_ready,
        ReleasePolicy::ReportOnly => true,
    };
    let report = MatrixReport {
        schema_version: 5,
        expected_profiles: plans.len(),
        web_profiles: plans.iter().filter(|plan| plan.web).count(),
        passed_profiles,
        matrix_success,
        release_ready,
        release_policy,
        success: matrix_success && release_policy_passed,
        profiles: results,
        release,
    };
    let parent = report_path
        .parent()
        .context("matrix report path has no parent")?;
    fs::create_dir_all(parent)?;
    fs::write(&report_path, encode_report(&report)?)
        .with_context(|| format!("write {}", report_path.display()))?;
    ensure!(
        report.success,
        "profile matrix or web release evidence failed; see {}",
        report_path.display()
    );
    Ok(report)
}

fn encode_report(report: &MatrixReport) -> Result<String> {
    let mut encoded = serde_json::to_string_pretty(report)?;
    encoded.push('\n');
    Ok(encoded)
}

fn matrix_arguments(
    workspace: &Path,
    arguments: &[String],
) -> Result<(usize, PathBuf, ReleasePolicy)> {
    let mut jobs = 1;
    let mut report = cargo_target_root(workspace).join("profile-matrix/report.json");
    let mut release_policy = ReleasePolicy::Enforced;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--jobs" => {
                index += 1;
                let value = arguments.get(index).context("--jobs requires a value")?;
                jobs = value.parse().context("--jobs must be a positive integer")?;
                ensure!(jobs > 0, "--jobs must be a positive integer");
            }
            "--report" => {
                index += 1;
                let value = arguments.get(index).context("--report requires a path")?;
                report = PathBuf::from(value);
                if report.is_relative() {
                    report = workspace.join(report);
                }
            }
            "--automated-evidence-only" => {
                ensure!(
                    release_policy == ReleasePolicy::Enforced,
                    "release policy modes are mutually exclusive"
                );
                release_policy = ReleasePolicy::AutomatedEvidenceOnly;
            }
            "--matrix-only" => {
                ensure!(
                    release_policy == ReleasePolicy::Enforced,
                    "release policy modes are mutually exclusive"
                );
                release_policy = ReleasePolicy::ReportOnly;
            }
            argument => bail!("unknown profiles generate-verify argument `{argument}`"),
        }
        index += 1;
    }
    validate_release_policy(release_policy, running_in_ci())?;

    Ok((jobs, report, release_policy))
}

fn validate_release_policy(release_policy: ReleasePolicy, ci: bool) -> Result<()> {
    ensure!(
        !(ci && release_policy == ReleasePolicy::ReportOnly),
        "--matrix-only is a local diagnostic mode and cannot satisfy CI release readiness"
    );
    Ok(())
}

fn running_in_ci() -> bool {
    ["CI", "GITHUB_ACTIONS"].iter().any(|name| {
        std::env::var(name)
            .is_ok_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true"))
    })
}

#[allow(clippy::too_many_lines)] // The profile verification sequence is one ordered evidence ledger.
fn verify_generated_profile(
    workspace: &Path,
    work_root: &Path,
    cargo_target: &Path,
    plan: &ProfilePlan,
) -> ProfileResult {
    let profile = plan.id.as_str();
    let service = format!("matrix-{profile}");
    let destination = work_root.join(profile);
    let expected_checks =
        BASE_MATRIX_CHECKS.len() + if plan.web { WEB_MATRIX_CHECKS.len() } else { 0 };
    let mut checks = Vec::with_capacity(expected_checks);
    let mut evidence = ProfileEvidence::default();
    verify_render_checks(&destination, &service, profile, &mut checks);
    verify_catalog_checks(&destination, &plan.resolved, &mut checks);
    verify_composition_evidence(&destination, &plan.resolved, &mut checks, &mut evidence);
    let profile_target = cargo_target.join(profile);
    if plan.web {
        verify_web_checks(
            workspace,
            &destination,
            &profile_target,
            plan.e2e,
            &mut checks,
        );
    }
    verify_build_checks(
        &destination,
        &profile_target,
        &service,
        &plan.resolved,
        &mut checks,
        &mut evidence,
    );
    if plan.web {
        if plan.e2e && !evidence.application_required_modules.is_empty() {
            record_blocked(
                &mut checks,
                "web-e2e-smoke",
                "untouched generated root lacks required application contributions",
            );
        } else {
            verify_web_e2e_check(
                workspace,
                &destination,
                &profile_target,
                &service,
                profile,
                plan.e2e,
                &mut checks,
            );
        }
    }
    let generated = check_passed(&checks, "render-fresh");
    let compiled = generated && check_passed(&checks, "cargo-test");
    let composition_root = generated.then(|| relative_report_path(workspace, &destination));
    let executable = profile_target.join("debug").join(&service);
    record_check(
        &mut checks,
        "build-cache-cleanup",
        cleanup_profile_build_cache(&profile_target, &executable, compiled),
    );
    for missing in BASE_MATRIX_CHECKS
        .iter()
        .chain(plan.web.then_some(WEB_MATRIX_CHECKS).into_iter().flatten())
    {
        if !checks.iter().any(|check| check.name == *missing) {
            let required = *missing != "web-e2e-smoke" || plan.e2e;
            record_skipped(&mut checks, missing, required, "check was not executed");
        }
    }
    let contract_aggregate_sha256 = checks
        .iter()
        .find(|check| check.name == "web-contracts-check" && check.success)
        .and_then(|_| read_contract_aggregate_sha256(&destination).ok());
    let success = checks.len() == expected_checks
        && checks
            .iter()
            .filter(|check| check.required)
            .all(|check| check.status == CheckStatus::Passed);
    let executable_command =
        compiled.then(|| format!("{} server", relative_report_path(workspace, &executable)));
    let mut retained_artifacts = checks
        .iter()
        .flat_map(|check| check.artifacts.iter().cloned())
        .collect::<BTreeSet<_>>();
    if let Some(root) = &composition_root {
        retained_artifacts.insert(root.clone());
    }
    if compiled {
        retained_artifacts.insert(relative_report_path(workspace, &executable));
    }
    let resolved_modules = plan.resolved.modules().to_vec();
    let resolved_providers = plan.resolved.providers().to_vec();
    let resolved_services: Vec<String> = plan
        .resolved
        .runtime_dependencies()
        .iter()
        .map(|dependency| dependency.as_str().to_owned())
        .collect();
    let implementation_state = derive_implementation_state(
        generated,
        compiled,
        &resolved_modules,
        &resolved_services,
        &evidence,
        &checks,
    );
    ProfileResult {
        profile: profile.to_owned(),
        service,
        kind: plan.kind,
        success,
        resolved_modules,
        resolved_providers,
        resolved_services,
        composition_root,
        executable_command,
        assembled_modules: evidence.assembled_modules,
        application_required_modules: evidence.application_required_modules,
        application_required_contributions: evidence.application_required_contributions,
        application_fixture: evidence.application_fixture,
        registered_route_ids: evidence.registered_route_ids,
        registered_task_ids: evidence.registered_task_ids,
        registered_health_ids: evidence.registered_health_ids,
        registered_operation_ids: evidence.registered_operation_ids,
        registered_capability_ids: evidence.registered_capability_ids,
        registered_transport_ids: evidence.registered_transport_ids,
        migration_range: evidence.migration_range,
        positive_workflow_checks: evidence.positive_workflow_checks,
        negative_workflow_checks: evidence.negative_workflow_checks,
        readiness_checks: evidence.readiness_checks,
        outage_checks: evidence.outage_checks,
        shutdown_checks: evidence.shutdown_checks,
        retained_artifacts: retained_artifacts.into_iter().collect(),
        implementation_state,
        contract_aggregate_sha256,
        checks,
    }
}

fn cleanup_profile_build_cache(
    profile_target: &Path,
    executable: &Path,
    compiled: bool,
) -> Result<String> {
    let retained_binary = profile_target.with_extension("retained-binary");
    if retained_binary.exists() {
        fs::remove_file(&retained_binary)
            .with_context(|| format!("remove stale {}", retained_binary.display()))?;
    }
    if compiled {
        ensure!(
            executable.is_file(),
            "generated profile binary is missing before build-cache cleanup"
        );
        fs::rename(executable, &retained_binary).with_context(|| {
            format!(
                "stage generated profile binary {}",
                retained_binary.display()
            )
        })?;
    }
    if profile_target.exists() {
        fs::remove_dir_all(profile_target)
            .with_context(|| format!("remove {}", profile_target.display()))?;
    }
    if compiled {
        let parent = executable
            .parent()
            .context("generated profile binary has no parent directory")?;
        fs::create_dir_all(parent)?;
        fs::rename(&retained_binary, executable)
            .with_context(|| format!("retain {}", executable.display()))?;
    }
    Ok(if compiled {
        format!(
            "removed generated Cargo cache and retained {}",
            executable.display()
        )
    } else {
        "removed generated Cargo cache; no binary was produced".to_owned()
    })
}

fn check_passed(checks: &[CheckResult], name: &str) -> bool {
    checks
        .iter()
        .any(|check| check.name == name && check.status == CheckStatus::Passed)
}

fn relative_report_path(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn derive_implementation_state(
    generated: bool,
    compiled: bool,
    resolved_modules: &[String],
    resolved_services: &[String],
    evidence: &ProfileEvidence,
    checks: &[CheckResult],
) -> ImplementationState {
    let assembled = compiled
        && !resolved_modules.is_empty()
        && evidence.application_required_modules.is_empty()
        && !evidence.application_fixture.synthetic
        && !evidence.application_fixture.used_for_classification
        && !evidence.concrete_registrar_modules.is_empty()
        && evidence.assembled_modules == evidence.concrete_registrar_modules
        && !evidence.positive_workflow_checks.is_empty()
        && !evidence.negative_workflow_checks.is_empty()
        && !evidence.readiness_checks.is_empty()
        && !evidence.shutdown_checks.is_empty()
        && (resolved_services.is_empty() || !evidence.outage_checks.is_empty())
        && [
            "composition-manifest",
            "migration-policy",
            "startup-readiness",
            "registered-routes-tasks-health",
            "representative-workflow",
            "negative-workflow",
            "dependency-outage",
            "bounded-shutdown",
            "runtime-contract-parity",
        ]
        .iter()
        .all(|name| check_passed(checks, name));
    if assembled {
        ImplementationState::Assembled
    } else if compiled {
        ImplementationState::Compiled
    } else if generated {
        ImplementationState::Generated
    } else {
        ImplementationState::Selected
    }
}

fn verify_render_checks(
    destination: &Path,
    service: &str,
    profile: &str,
    checks: &mut Vec<CheckResult>,
) {
    let rendered = record_check(
        checks,
        "render-fresh",
        verification_release_identity()
            .map_err(|error| omnius_generator::RenderError::Canonical(error.to_string()))
            .and_then(|release_identity| {
                render_project(RenderRequest {
                    service_name: service,
                    profile,
                    destination,
                    release_identity: &release_identity,
                })
            })
            .map(|outcome| format!("{} files", outcome.files)),
    );
    if !rendered {
        record_skipped(
            checks,
            "render-repeat",
            true,
            "blocked by render-fresh failure",
        );
        record_skipped(
            checks,
            "byte-identical",
            true,
            "blocked by render-fresh failure",
        );
        return;
    }
    let first_hash = hash_tree(destination);
    let repeated_ok = record_check(
        checks,
        "render-repeat",
        verification_release_identity()
            .map_err(|error| omnius_generator::RenderError::Canonical(error.to_string()))
            .and_then(|release_identity| {
                match render_project(RenderRequest {
                    service_name: service,
                    profile,
                    destination,
                    release_identity: &release_identity,
                }) {
                    Err(RenderError::DestinationExists(path)) if path == destination => {
                        Ok("existing destination refused".to_owned())
                    }
                    Ok(_) => Err(RenderError::Canonical(
                        "repeat render unexpectedly accepted an existing destination".to_owned(),
                    )),
                    Err(error) => Err(error),
                }
            }),
    );
    if !repeated_ok {
        record_skipped(
            checks,
            "byte-identical",
            true,
            "blocked by render-repeat failure",
        );
        return;
    }
    let byte_result = first_hash.and_then(|before| {
        hash_tree(destination).and_then(|after| {
            ensure!(before == after, "rendered bytes changed on repeat");
            Ok("tree hashes match".to_owned())
        })
    });
    record_check(checks, "byte-identical", byte_result);
}

fn verify_catalog_checks(
    destination: &Path,
    resolved: &ResolvedProfile,
    checks: &mut Vec<CheckResult>,
) {
    record_check(
        checks,
        "metadata-artifacts",
        validate_metadata_artifacts(destination, resolved),
    );

    let manager_checks = GeneratorModuleCatalog::bundled()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .map(|catalog| {
            let release_identity = verification_release_identity()?;
            let manager = ProjectManager::new(destination, &release_identity, &catalog);
            let doctor = manager.doctor().map_err(anyhow::Error::from)?;
            ensure!(
                doctor.healthy,
                "doctor diagnostics: {:?}",
                doctor.diagnostics
            );
            let diff = manager.diff().map_err(anyhow::Error::from)?;
            ensure!(
                diff.is_empty(),
                "diff contains {} operations",
                diff.operations.len()
            );
            Ok(())
        });
    match manager_checks {
        Ok(result) => {
            let clean = result.is_ok();
            record_check(
                checks,
                "doctor-clean",
                result.map(|()| "healthy".to_owned()),
            );
            if clean {
                record_check(
                    checks,
                    "diff-clean",
                    Ok::<_, anyhow::Error>("empty".to_owned()),
                );
            } else {
                record_skipped(
                    checks,
                    "diff-clean",
                    true,
                    "blocked by doctor-clean failure",
                );
            }
        }
        Err(error) => {
            record_check(checks, "doctor-clean", Err(error));
            record_skipped(
                checks,
                "diff-clean",
                true,
                "blocked by catalog load failure",
            );
        }
    }
}
fn verification_release_identity() -> Result<ReleaseIdentity> {
    let revision = std::env::var("OMNIUS_RELEASE_REVISION")
        .or_else(|_| std::env::var("GITHUB_SHA"))
        .context(
            "OMNIUS_RELEASE_REVISION or GITHUB_SHA must name a remotely reachable release commit",
        )?;
    ReleaseIdentity::new(KIT_VERSION, CANONICAL_REPOSITORY, revision).map_err(anyhow::Error::from)
}
fn verify_composition_evidence(
    destination: &Path,
    resolved: &ResolvedProfile,
    checks: &mut Vec<CheckResult>,
    evidence: &mut ProfileEvidence,
) {
    let catalog = match GeneratorModuleCatalog::bundled() {
        Ok(catalog) => catalog,
        Err(error) => {
            let detail = Err(anyhow::anyhow!(error.to_string()));
            record_check(checks, "composition-manifest", detail);
            record_skipped(
                checks,
                "application-requirements",
                true,
                "blocked by module catalog load failure",
            );
            record_skipped(
                checks,
                "application-fixture-origin",
                true,
                "blocked by module catalog load failure",
            );
            return;
        }
    };
    let selected_source = fs::read_to_string(destination.join("apps/service/src/composition.rs"));
    let manifest_result = selected_source
        .map_err(anyhow::Error::from)
        .and_then(|source| {
            let actual = managed_composition_modules(&source)?;
            let expected = resolved.modules().iter().cloned().collect::<BTreeSet<_>>();
            ensure!(
                actual == expected,
                "consumer composition modules differ: expected {expected:?}, got {actual:?}"
            );
            Ok("consumer composition manifest matches selected modules".to_owned())
        });
    record_check(checks, "composition-manifest", manifest_result);

    for module_id in resolved.modules() {
        let Some(module) = catalog
            .modules
            .iter()
            .find(|module| &module.id == module_id)
        else {
            continue;
        };
        if module.composition.registrar {
            evidence.concrete_registrar_modules.push(module.id.clone());
        }
        let mut requirements = module
            .composition
            .application_requirements
            .iter()
            .map(|requirement| requirement.as_str().to_owned())
            .collect::<Vec<_>>();
        if module.id == "llm-embeddings" {
            requirements
                .push("specified-only:missing-authoritative-embedding-operation-contract".into());
        }
        if requirements.is_empty() {
            continue;
        }
        evidence
            .application_required_modules
            .push(module.id.clone());
        evidence
            .application_required_contributions
            .insert(module.id.clone(), requirements);
    }
    record_check(
        checks,
        "application-requirements",
        Ok::<_, anyhow::Error>(format!(
            "{} module(s) require application contributions",
            evidence.application_required_modules.len()
        )),
    );
    record_check(
        checks,
        "application-fixture-origin",
        Ok::<_, anyhow::Error>(
            "untouched generated root; no synthetic application fixture used".to_owned(),
        ),
    );
}

#[allow(clippy::too_many_lines)] // Build checks share one mutable evidence record and execution order.
fn verify_build_checks(
    destination: &Path,
    cargo_target: &Path,
    service: &str,
    resolved: &ResolvedProfile,
    checks: &mut Vec<CheckResult>,
    evidence: &mut ProfileEvidence,
) {
    const RUNTIME_CHECKS: &[&str] = &[
        "startup-readiness",
        "registered-routes-tasks-health",
        "representative-workflow",
        "negative-workflow",
        "dependency-outage",
        "bounded-shutdown",
        "runtime-contract-parity",
    ];
    let cargo_test = run_command(
        Command::new(env!("CARGO"))
            .current_dir(destination)
            .arg("check")
            .arg("--locked")
            .arg("--workspace")
            .arg("--all-targets")
            .arg("--manifest-path")
            .arg(destination.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(cargo_target),
    )
    .and_then(|check| {
        run_command(
            Command::new(env!("CARGO"))
                .current_dir(destination)
                .env("OMNIUS_WEB_ASSET_DIR", destination.join("web/dist"))
                .arg("nextest")
                .arg("run")
                .arg("--locked")
                .arg("--package")
                .arg(service)
                .arg("--manifest-path")
                .arg(destination.join("Cargo.toml"))
                .arg("--target-dir")
                .arg(cargo_target),
        )
        .map(|tests| format!("{check}; {tests}"))
    })
    .and_then(|checks| {
        run_command(
            Command::new(env!("CARGO"))
                .current_dir(destination)
                .arg("test")
                .arg("--doc")
                .arg("--locked")
                .arg("--package")
                .arg(service)
                .arg("--manifest-path")
                .arg(destination.join("Cargo.toml"))
                .arg("--target-dir")
                .arg(cargo_target),
        )
        .map(|docs| format!("{checks}; {docs}"))
    });
    if !record_check(checks, "cargo-test", cargo_test) {
        record_skipped(
            checks,
            "profile-info",
            true,
            "blocked by cargo-test failure",
        );
        record_skipped(
            checks,
            "migration-policy",
            true,
            "blocked by cargo-test failure",
        );
        skip_required_checks(checks, RUNTIME_CHECKS, "blocked by cargo-test failure");
        return;
    }
    if !record_check(
        checks,
        "profile-info",
        run_profile_info(destination, cargo_target, service, resolved, evidence),
    ) {
        record_skipped(
            checks,
            "migration-policy",
            true,
            "blocked by profile-info failure",
        );
        skip_required_checks(checks, RUNTIME_CHECKS, "blocked by profile-info failure");
        return;
    }
    record_check(
        checks,
        "migration-policy",
        validate_migration_policy(destination, resolved),
    );
    if !evidence.application_required_modules.is_empty() {
        skip_required_checks(
            checks,
            RUNTIME_CHECKS,
            "untouched generated root lacks required application contributions",
        );
        return;
    }
    if !resolved.runtime_dependencies().is_empty() {
        for name in RUNTIME_CHECKS {
            record_blocked(
                checks,
                name,
                "disposable external-service topology unavailable; process evidence is blocked and classification remains unassembled",
            );
        }
        return;
    }
    if !record_check(
        checks,
        "startup-readiness",
        smoke_process(
            destination,
            cargo_target,
            service,
            !resolved
                .modules()
                .iter()
                .any(|module| module == "web-static"),
        ),
    ) {
        skip_required_checks(
            checks,
            &RUNTIME_CHECKS[1..],
            "blocked by startup-readiness failure",
        );
        return;
    }
    let registration_result = collect_registered_contracts(resolved);
    match registration_result {
        Ok((routes, tasks, health)) => {
            evidence.registered_route_ids = routes;
            evidence.registered_task_ids = tasks;
            evidence.registered_health_ids = health;
            record_check(
                checks,
                "registered-routes-tasks-health",
                Ok::<_, anyhow::Error>(
                    "registrar graph finished with exact catalog IDs".to_owned(),
                ),
            );
        }
        Err(error) => {
            record_check(checks, "registered-routes-tasks-health", Err(error));
        }
    }
    record_check(
        checks,
        "representative-workflow",
        Ok::<_, anyhow::Error>("GET /live returned 200 in the generated process".to_owned()),
    );
    evidence
        .positive_workflow_checks
        .push("representative-workflow".to_owned());
    record_check(
        checks,
        "negative-workflow",
        Ok::<_, anyhow::Error>("an unregistered route returned 404".to_owned()),
    );
    evidence
        .negative_workflow_checks
        .push("negative-workflow".to_owned());
    evidence
        .readiness_checks
        .push("startup-readiness".to_owned());
    record_check(
        checks,
        "bounded-shutdown",
        Ok::<_, anyhow::Error>("SIGTERM drain completed within 30 seconds".to_owned()),
    );
    evidence.shutdown_checks.push("bounded-shutdown".to_owned());
    if resolved.runtime_dependencies().is_empty() {
        record_check(
            checks,
            "dependency-outage",
            Ok::<_, anyhow::Error>(
                "not applicable: profile selects no external service".to_owned(),
            ),
        );
    } else {
        record_blocked(
            checks,
            "dependency-outage",
            "disposable external-service topology unavailable; process evidence is blocked and classification remains unassembled",
        );
    }
    let parity = validate_runtime_contract_parity(destination, resolved, evidence);
    let parity_ok = record_check(checks, "runtime-contract-parity", parity);
    if parity_ok
        && check_passed(checks, "registered-routes-tasks-health")
        && (resolved.runtime_dependencies().is_empty() || check_passed(checks, "dependency-outage"))
    {
        evidence.assembled_modules = evidence.concrete_registrar_modules.clone();
    }
}

fn skip_required_checks(checks: &mut Vec<CheckResult>, names: &[&'static str], reason: &str) {
    for name in names {
        record_skipped(checks, name, true, reason);
    }
}

fn validate_migration_policy(destination: &Path, resolved: &ResolvedProfile) -> Result<String> {
    let source = fs::read_to_string(destination.join("apps/service/src/main.rs"))?;
    for required in [
        "SelectedMigrationCommand::Migrate",
        "SelectedMigrationCommand::Status",
        "execute_selected_migration",
    ] {
        ensure!(
            source.contains(required),
            "generated migration policy omits `{required}`"
        );
    }
    Ok(
        if resolved
            .modules()
            .iter()
            .any(|module| module == "migrations")
        {
            "selected migration runner exposes explicit migrate/status and startup compatibility policy"
            .to_owned()
        } else {
            "migration commands are explicit and return command-unavailable without a selected runner"
            .to_owned()
        },
    )
}

fn collect_registered_contracts(
    resolved: &ResolvedProfile,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let catalog =
        GeneratorModuleCatalog::bundled().map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut routes = BTreeSet::new();
    let mut tasks = BTreeSet::new();
    let mut health = BTreeSet::new();
    for module_id in resolved.modules() {
        let module = catalog
            .modules
            .iter()
            .find(|module| &module.id == module_id)
            .with_context(|| format!("resolved module `{module_id}` is absent"))?;
        routes.extend(module.routes.iter().cloned());
        tasks.extend(module.background_tasks.iter().cloned());
        health.extend(module.health_checks.iter().cloned());
    }
    Ok((
        routes.into_iter().collect(),
        tasks.into_iter().collect(),
        health.into_iter().collect(),
    ))
}

fn validate_runtime_contract_parity(
    destination: &Path,
    resolved: &ResolvedProfile,
    evidence: &mut ProfileEvidence,
) -> Result<String> {
    let contracts = destination.join("contracts");
    if !contracts.is_dir() {
        let expects_contracts = resolved
            .modules()
            .iter()
            .any(|module| matches!(module.as_str(), "openapi" | "consumer-contracts"));
        ensure!(
            !expects_contracts,
            "selected contract modules produced no contract bundle"
        );
        evidence.registered_operation_ids.clear();
        evidence.registered_capability_ids.clear();
        evidence.registered_transport_ids.clear();
        return Ok(
            "profile selects no contract module; empty runtime-contract parity is valid".to_owned(),
        );
    }
    let openapi: serde_json::Value = serde_json::from_str(&fs::read_to_string(
        destination.join("contracts/openapi.json"),
    )?)?;
    let mut operations = BTreeSet::new();
    for (path, item) in openapi["paths"]
        .as_object()
        .context("OpenAPI contract lacks paths")?
    {
        ensure!(
            evidence
                .registered_route_ids
                .iter()
                .any(|route| route == path),
            "contract path `{path}` has no mounted registration"
        );
        for operation in item
            .as_object()
            .into_iter()
            .flat_map(|methods| methods.values())
        {
            if let Some(operation_id) = operation["operationId"].as_str() {
                operations.insert(operation_id.to_owned());
            }
        }
    }
    let capabilities_path = destination.join("contracts/capabilities.json");
    let mut capability_ids = BTreeSet::new();
    let mut transports = BTreeSet::new();
    if capabilities_path.is_file() {
        let capabilities: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(capabilities_path)?)?;
        for capability in capabilities["capabilities"]
            .as_array()
            .context("capability contract lacks inventory")?
        {
            if capability["compiled"].as_bool() == Some(true) {
                let id = capability["id"]
                    .as_str()
                    .context("compiled capability lacks id")?;
                ensure!(
                    resolved.modules().iter().any(|module| module == id),
                    "compiled capability `{id}` is not selected"
                );
                capability_ids.insert(id.to_owned());
            }
        }
        for (id, endpoint) in capabilities["transports"]
            .as_object()
            .context("capability contract lacks transports")?
        {
            let endpoint = endpoint
                .as_str()
                .with_context(|| format!("transport `{id}` endpoint is not a string"))?;
            ensure!(
                evidence
                    .registered_route_ids
                    .iter()
                    .any(|route| route.starts_with(endpoint)),
                "transport `{id}` endpoint `{endpoint}` has no mounted registration"
            );
            transports.insert(format!("{id}={endpoint}"));
        }
    } else {
        ensure!(
            !resolved
                .modules()
                .iter()
                .any(|module| module == "consumer-contracts"),
            "consumer-contracts selected without a capability contract"
        );
    }
    let operation_count = operations.len();
    evidence.registered_operation_ids = operations.into_iter().collect();
    evidence.registered_capability_ids = capability_ids.into_iter().collect();
    evidence.registered_transport_ids = transports.into_iter().collect();
    Ok(format!(
        "application contract has {operation_count} mounted operation ID(s); compiled capabilities and transports match mounted registrations"
    ))
}
fn verify_web_checks(
    workspace: &Path,
    destination: &Path,
    cargo_target: &Path,
    e2e: bool,
    checks: &mut Vec<CheckResult>,
) {
    let workspace_ok = record_check(
        checks,
        "web-workspace",
        validate_web_workspace(destination, e2e),
    );
    if !workspace_ok {
        skip_web_checks(checks, &WEB_MATRIX_CHECKS[1..], e2e, "web-workspace");
        return;
    }
    let install_ok = record_check(
        checks,
        "web-frozen-install",
        run_pnpm(destination, cargo_target, &["install", "--frozen-lockfile"]),
    );
    if !install_ok {
        skip_web_checks(checks, &WEB_MATRIX_CHECKS[2..], e2e, "web-frozen-install");
        return;
    }
    record_check(
        checks,
        "web-contracts-check",
        crate::contracts::validate_committed(workspace, destination).and_then(|()| {
            read_contract_aggregate_sha256(destination)
                .map(|hash| format!("generated application contracts validated at sha256:{hash}"))
        }),
    );
    let sdk_and_web = |sdk: &'static str, web: &'static str| {
        if e2e { vec![sdk, web] } else { vec![sdk] }
    };
    for (name, scripts) in [
        ("web-build", sdk_and_web("sdk:build", "web:build")),
        (
            "web-typecheck-ts6",
            sdk_and_web("sdk:typecheck", "web:typecheck"),
        ),
        (
            "web-typecheck-ts7",
            sdk_and_web("sdk:typecheck:ts7", "web:typecheck:ts7"),
        ),
        ("web-test", sdk_and_web("sdk:test", "web:test")),
    ] {
        record_check(
            checks,
            name,
            run_pnpm_scripts(destination, cargo_target, &scripts),
        );
        if let Some(check) = checks.last_mut() {
            check.command = Some(
                scripts
                    .iter()
                    .map(|script| format!("pnpm run {script}"))
                    .collect::<Vec<_>>()
                    .join(" && "),
            );
        }
    }
}

fn verify_web_e2e_check(
    workspace: &Path,
    destination: &Path,
    cargo_target: &Path,
    service: &str,
    profile: &str,
    e2e: bool,
    checks: &mut Vec<CheckResult>,
) {
    if e2e {
        let result = run_web_e2e(workspace, destination, cargo_target, service, profile).and_then(
            |detail| {
                collect_web_e2e_artifacts(workspace, destination)
                    .map(|artifacts| (detail, artifacts))
            },
        );
        record_check_with_artifacts(checks, "web-e2e-smoke", result);
    } else {
        record_skipped(
            checks,
            "web-e2e-smoke",
            false,
            "not applicable: profile has no served browser UI",
        );
    }
}

fn skip_web_checks(
    checks: &mut Vec<CheckResult>,
    names: &[&'static str],
    e2e: bool,
    dependency: &str,
) {
    for name in names {
        record_skipped(
            checks,
            name,
            *name != "web-e2e-smoke" || e2e,
            &format!("blocked by {dependency} failure"),
        );
    }
}

fn validate_web_workspace(destination: &Path, e2e: bool) -> Result<String> {
    for path in [
        "package.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "packages/web-sdk/package.json",
    ] {
        ensure!(
            destination.join(path).is_file(),
            "required generated web artifact `{path}` is missing"
        );
    }
    let package: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(destination.join("package.json"))?)?;
    let scripts = package["scripts"]
        .as_object()
        .context("generated package.json lacks scripts")?;
    let mut required_scripts = vec![
        "sdk:typecheck",
        "sdk:typecheck:ts7",
        "sdk:test",
        "sdk:build",
    ];
    if e2e {
        required_scripts.extend([
            "web:typecheck",
            "web:typecheck:ts7",
            "web:test",
            "web:build",
            "web:test:e2e",
        ]);
        for path in [
            "web/package.json",
            "web/playwright.config.ts",
            "web/browser-support.json",
            "web/e2e/generated-profile-fixture.mjs",
            "web/e2e/generated-profile.spec.ts",
        ] {
            ensure!(
                destination.join(path).is_file(),
                "required generated browser artifact `{path}` is missing"
            );
        }
    }
    for script in required_scripts {
        ensure!(
            scripts
                .get(script)
                .is_some_and(serde_json::Value::is_string),
            "generated package.json lacks required `{script}` script"
        );
    }
    Ok("frozen workspace, packages, and required scripts exist".to_owned())
}
fn run_pnpm(destination: &Path, cargo_target: &Path, arguments: &[&str]) -> Result<String> {
    run_command(
        Command::new("pnpm")
            .current_dir(destination)
            .env("CARGO_TARGET_DIR", cargo_target)
            .args(arguments),
    )
}

fn run_pnpm_scripts(destination: &Path, cargo_target: &Path, scripts: &[&str]) -> Result<String> {
    for script in scripts {
        run_pnpm(destination, cargo_target, &["run", script])?;
    }
    Ok(format!("{} pnpm script(s) succeeded", scripts.len()))
}
fn run_web_e2e(
    _workspace: &Path,
    destination: &Path,
    cargo_target: &Path,
    service: &str,
    profile: &str,
) -> Result<String> {
    let _e2e_guard = PROFILE_E2E_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let profile_binary = cargo_target.join("debug").join(service);
    ensure!(
        profile_binary.is_file(),
        "generated profile binary is missing before browser smoke"
    );
    run_command(
        Command::new("pnpm")
            .current_dir(destination)
            .env("CARGO_TARGET_DIR", cargo_target)
            .env("OMNIUS_E2E_PROFILE", profile)
            .env("OMNIUS_E2E_PROFILE_BIN", profile_binary)
            .env("OMNIUS_WEB_ASSET_DIR", destination.join("web/dist"))
            .args([
                "--filter",
                "@omnius/web",
                "exec",
                "playwright",
                "test",
                "--config",
                "playwright.config.ts",
                "generated-profile.spec.ts",
            ]),
    )
}

fn collect_web_e2e_artifacts(workspace: &Path, destination: &Path) -> Result<Vec<String>> {
    let report = destination.join("web/playwright-report/index.html");
    ensure!(report.is_file(), "Playwright HTML report was not produced");
    let results = destination.join("web/test-results");
    let mut measurements = WalkDir::new(&results)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            entry.file_type().is_file()
                && matches!(
                    entry.file_name().to_str(),
                    Some("bundle-measurements.json" | "runtime-measurements.json")
                )
        })
        .map(walkdir::DirEntry::into_path)
        .collect::<Vec<_>>();
    measurements.sort();
    measurements.insert(0, report);
    Ok(measurements
        .into_iter()
        .map(|path| {
            path.strip_prefix(workspace)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect())
}

fn record_check_with_artifacts<E: std::fmt::Display>(
    checks: &mut Vec<CheckResult>,
    name: &'static str,
    result: std::result::Result<(String, Vec<String>), E>,
) -> bool {
    match result {
        Ok((detail, artifacts)) => {
            let passed = record_check(checks, name, Ok::<_, E>(detail));
            if let Some(check) = checks.last_mut() {
                check.artifacts = artifacts;
            }
            passed
        }
        Err(error) => record_check(checks, name, Err(error)),
    }
}

fn read_contract_aggregate_sha256(destination: &Path) -> Result<String> {
    let manifest: serde_json::Value = serde_json::from_str(&fs::read_to_string(
        destination.join("contracts/contract-manifest.json"),
    )?)?;
    manifest["aggregate_sha256"]
        .as_str()
        .map(str::to_owned)
        .context("contract manifest lacks aggregate_sha256")
}

fn record_blocked(checks: &mut Vec<CheckResult>, name: &'static str, reason: &str) {
    let (command, criteria, recommendations) = check_traceability(name);
    checks.push(CheckResult {
        name,
        required: true,
        executed: false,
        status: CheckStatus::Blocked,
        success: false,
        command,
        detail: reason.to_owned(),
        criteria,
        recommendations,
        artifacts: Vec::new(),
    });
}

fn record_skipped(checks: &mut Vec<CheckResult>, name: &'static str, required: bool, reason: &str) {
    let (command, criteria, recommendations) = check_traceability(name);
    checks.push(CheckResult {
        name,
        required,
        executed: false,
        status: CheckStatus::Skipped,
        success: false,
        command,
        detail: reason.to_owned(),
        criteria,
        recommendations,
        artifacts: Vec::new(),
    });
}
fn record_check<E: std::fmt::Display>(
    checks: &mut Vec<CheckResult>,
    name: &'static str,
    result: std::result::Result<String, E>,
) -> bool {
    let (command, criteria, recommendations) = check_traceability(name);
    let (status, success, detail) = match result {
        Ok(detail) => (CheckStatus::Passed, true, detail),
        Err(error) => (CheckStatus::Failed, false, error.to_string()),
    };
    checks.push(CheckResult {
        name,
        required: true,
        executed: true,
        status,
        success,
        command,
        detail,
        criteria,
        recommendations,
        artifacts: Vec::new(),
    });
    success
}

fn check_traceability(name: &str) -> (Option<String>, Vec<String>, Vec<String>) {
    let command = match name {
        "composition-manifest" => Some("inspect generated apps/service/src/composition.rs"),
        "migration-policy" => Some("<generated-service> migration-status"),
        "startup-readiness" => Some("<generated-service> server; GET /ready"),
        "registered-routes-tasks-health" => {
            Some("compare completed registrar graph with resolved module contracts")
        }
        "representative-workflow" => Some("GET /live"),
        "negative-workflow" => Some("GET /__profile_negative_probe__"),
        "dependency-outage" => Some("stop the selected disposable dependency; GET /ready"),
        "bounded-shutdown" => Some("SIGTERM <generated-service>"),
        "runtime-contract-parity" => {
            Some("compare contracts/openapi.json and capabilities.json with mounted registrations")
        }
        "build-cache-cleanup" => {
            Some("retain the generated profile binary; remove its Cargo build cache")
        }
        "web-frozen-install" => Some("pnpm install --frozen-lockfile"),
        "web-contracts-check" => {
            Some("cargo xtask profiles generate-verify (embedded generated-contract validation)")
        }
        "web-typecheck-ts6" => Some("pnpm run sdk:typecheck && pnpm run web:typecheck"),
        "web-typecheck-ts7" => Some("pnpm run sdk:typecheck:ts7 && pnpm run web:typecheck:ts7"),
        "web-test" => Some("pnpm run sdk:test && pnpm run web:test"),
        "web-build" => Some("pnpm run sdk:build && pnpm run web:build"),
        "web-e2e-smoke" => Some(
            "pnpm --filter @omnius/web exec playwright test --config playwright.config.ts generated-profile.spec.ts",
        ),
        _ => None,
    }
    .map(str::to_owned);
    let (criteria, recommendations): (&[&str], &[&str]) = if name.starts_with("web-") {
        (&["AC-WEB-079"], &["REC-WEB-079"])
    } else {
        (&[], &[])
    };
    (
        command,
        criteria.iter().map(|value| (*value).to_owned()).collect(),
        recommendations
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    )
}

fn hash_tree(root: &Path) -> Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut paths = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort_by(|left, right| left.path().cmp(right.path()));
    let mut hash = Sha256::new();
    for entry in paths
        .into_iter()
        .filter(|entry| entry.file_type().is_file())
    {
        let relative = entry.path().strip_prefix(root)?;
        hash.update(relative.as_os_str().as_encoded_bytes());
        hash.update([0]);
        hash.update(fs::read(entry.path())?);
        hash.update([0]);
    }
    let digest = hash.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

fn managed_composition_modules(source: &str) -> Result<BTreeSet<String>> {
    let mut inside = false;
    let mut complete = false;
    let mut modules = BTreeSet::new();
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("// omnius:managed-begin id=modules ") {
            ensure!(!inside && !complete, "duplicate composition module region");
            inside = true;
            continue;
        }
        if line == "// omnius:managed-end id=modules" {
            ensure!(inside, "composition module region ends before it begins");
            inside = false;
            complete = true;
            continue;
        }
        if !inside || line.is_empty() {
            continue;
        }
        let module = line
            .strip_prefix('"')
            .and_then(|line| line.strip_suffix("\","))
            .context("composition module region contains a non-module row")?;
        ensure!(
            modules.insert(module.to_owned()),
            "composition module region repeats `{module}`"
        );
    }
    ensure!(
        complete && !inside,
        "composition module region is missing or unterminated"
    );
    Ok(modules)
}

fn validate_metadata_artifacts(
    destination: &Path,
    resolved: &omnius_generator::ResolvedProfile,
) -> Result<String> {
    let state: toml::Value = toml::from_str(&fs::read_to_string(
        destination.join(omnius_generator::PROJECT_STATE_PATH),
    )?)?;
    let config: toml::Value = toml::from_str(&fs::read_to_string(
        destination.join("config/profile.toml"),
    )?)?;
    let ops: toml::Value =
        toml::from_str(&fs::read_to_string(destination.join("ops/profile.toml"))?)?;
    let expected_modules = resolved
        .modules()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let state_modules = metadata_ids(&state, "modules", "id")?;
    let config_modules = metadata_ids(&config, "modules", "id")?;
    let ops_modules = metadata_ids(&ops, "modules", "id")?;
    ensure!(
        state_modules == expected_modules,
        "state module order differs"
    );
    ensure!(
        config_modules == expected_modules,
        "config module order differs"
    );
    ensure!(ops_modules == expected_modules, "ops module order differs");
    let expected_providers = resolved
        .providers()
        .iter()
        .map(|provider| provider.module.as_str())
        .collect::<Vec<_>>();
    ensure!(
        metadata_ids(&state, "providers", "module")? == expected_providers,
        "state providers differ"
    );
    ensure!(
        metadata_ids(&config, "providers", "module")? == expected_providers,
        "config providers differ"
    );
    ensure!(
        metadata_ids(&ops, "providers", "module")? == expected_providers,
        "ops providers differ"
    );
    Ok("state/config/ops metadata match".to_owned())
}

fn metadata_ids<'a>(value: &'a toml::Value, table: &str, field: &str) -> Result<Vec<&'a str>> {
    value
        .get(table)
        .and_then(toml::Value::as_array)
        .context(format!("missing {table} metadata"))?
        .iter()
        .map(|entry| {
            entry
                .get(field)
                .and_then(toml::Value::as_str)
                .with_context(|| format!("missing {table}.{field}"))
        })
        .collect()
}

fn run_command(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok("command succeeded".to_owned())
}

fn run_profile_info(
    destination: &Path,
    cargo_target: &Path,
    service: &str,
    resolved: &ResolvedProfile,
    evidence: &mut ProfileEvidence,
) -> Result<String> {
    let output = Command::new(env!("CARGO"))
        .arg("run")
        .arg("--quiet")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(destination.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(cargo_target)
        .arg("--package")
        .arg(service)
        .arg("--")
        .arg("profile-info")
        .output()?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        document["profile"] == resolved.definition().id.as_str(),
        "profile-info profile differs"
    );
    ensure!(
        document["modules"] == serde_json::json!(resolved.modules()),
        "profile-info modules differ"
    );
    ensure!(
        document["providers"] == serde_json::json!(resolved.providers()),
        "profile-info providers differ"
    );
    let minimum = document["schema"]["minimum"]
        .as_str()
        .context("profile-info lacks schema.minimum")?;
    let maximum = document["schema"]["maximum"]
        .as_str()
        .context("profile-info lacks schema.maximum")?;
    evidence.migration_range = Some(MigrationRange {
        minimum: minimum.to_owned(),
        maximum: maximum.to_owned(),
    });
    Ok("metadata matches".to_owned())
}

fn smoke_process(
    destination: &Path,
    cargo_target: &Path,
    service: &str,
    assert_not_found: bool,
) -> Result<String> {
    let executable = cargo_target.join("debug").join(service);
    let mut child = Command::new(&executable)
        .current_dir(destination)
        .arg("server")
        .arg("--listen-address")
        .arg("127.0.0.1:0")
        .env_clear()
        .env("OMNIUS_WEB_ASSET_DIR", destination.join("web/dist"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("start {}", executable.display()))?;
    let stderr = child
        .stderr
        .take()
        .context("service stderr was not piped")?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            match line {
                Ok(line) if line.contains("startup complete listen_address=") => {
                    let _ = sender.send(Ok(Some(line)));
                    return;
                }
                Ok(_) => {}
                Err(error) => {
                    let _ = sender.send(Err(error));
                    return;
                }
            }
        }
        let _ = sender.send(Ok(None));
    });
    let line = receiver
        .recv_timeout(Duration::from_secs(30))
        .context("service readiness banner timed out")??
        .context("service exited before readiness banner")?;
    let address = line
        .split_once("startup complete listen_address=")
        .map(|(_, address)| address.trim())
        .context("unexpected readiness banner")?;
    for path in ["/live", "/ready", "/version"] {
        ensure!(
            http_status(address, path)? == 200,
            "{path} did not return HTTP 200"
        );
    }
    if assert_not_found {
        for path in [
            "/example",
            "/reference-records",
            "/__profile_negative_probe__",
        ] {
            ensure!(
                http_status(address, path)? == 404,
                "{path} must remain application-owned and unregistered"
            );
        }
    }
    let signal = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()?;
    ensure!(signal.success(), "failed to signal generated service");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "generated service did not drain cleanly");
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            bail!("generated service drain timed out");
        }
        thread::sleep(Duration::from_millis(25));
    }
    Ok("startup/readiness, representative and negative HTTP workflows, and bounded drain succeeded"
        .to_owned())
}

fn http_status(address: &str, path: &str) -> Result<u16> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("HTTP response lacks status code")?
        .parse()
        .context("HTTP status code is invalid")
}

pub(crate) fn load_yaml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_yaml::from_str(&contents).with_context(|| format!("parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnius_test_support::CleanDirectory;

    #[test]
    fn validates_real_catalogs_from_clean_directory() -> Result<()> {
        let directory = copy_real_catalogs()?;
        let summary = verify(directory.path())?;
        assert_eq!(summary.profiles, 23);
        assert_eq!(summary.modules, 109);
        Ok(())
    }

    #[test]
    fn rejects_broken_catalog_copied_into_clean_directory() -> Result<()> {
        let directory = copy_real_catalogs()?;
        let profiles_path = directory.path().join("machine/profiles.yaml");
        let profiles = fs::read_to_string(&profiles_path)?;
        let broken = profiles.replacen("  - core\n", "  - core\n  - missing-module\n", 1);
        ensure!(profiles != broken, "profile fixture anchor was not found");
        fs::write(profiles_path, broken)?;

        let error = verify(directory.path())
            .err()
            .context("broken on-disk profile catalog was accepted")?;
        assert!(error.to_string().contains("unknown module"));
        Ok(())
    }

    fn copy_real_catalogs() -> Result<CleanDirectory> {
        let directory = CleanDirectory::new("profile-catalog")?;
        copy_directory(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../specs/machine"),
            &directory.path().join("machine"),
        )?;
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../specs/MANIFEST.json"),
            directory.path().join("MANIFEST.json"),
        )?;
        Ok(directory)
    }

    #[test]
    fn derives_all_bundled_profile_plans_and_evidence_kinds() -> Result<()> {
        let catalog = bundled_profile_catalog()?;
        let modules = GeneratorModuleCatalog::bundled()?;
        let plans = profile_plans(catalog, &modules)?;
        assert_eq!(plans.len(), 23);
        assert_eq!(
            plans.iter().filter(|plan| plan.web).count(),
            crate::web_release::EXPECTED_WEB_PROFILE_COUNT
        );
        assert_eq!(
            plans
                .iter()
                .filter(|plan| plan.kind == ProfileKind::Ai)
                .count(),
            4
        );
        assert_eq!(
            plans
                .iter()
                .filter(|plan| plan.kind == ProfileKind::Mcp)
                .count(),
            2
        );
        assert_eq!(
            plans
                .iter()
                .filter(|plan| plan.kind == ProfileKind::AiMcp)
                .count(),
            2
        );
        assert_eq!(
            plans.iter().filter(|plan| plan.e2e).count(),
            crate::web_release::EXPECTED_BROWSER_PROFILE_COUNT
        );
        let sdk_only = plans
            .iter()
            .find(|plan| plan.id == "web-sdk-only")
            .context("web-sdk-only profile missing")?;
        assert_eq!(sdk_only.kind, ProfileKind::Web);
        assert!(!sdk_only.e2e);
        Ok(())
    }

    #[test]
    fn composition_manifest_parser_requires_one_complete_exact_module_region() -> Result<()> {
        let modules = managed_composition_modules(
            r#"pub const MANAGED_MODULES: &[&str] = &[
    // omnius:managed-begin id=modules version=1 hash=abc
    "core",
    "http",
    // omnius:managed-end id=modules
];"#,
        )?;

        assert_eq!(
            modules,
            BTreeSet::from(["core".to_owned(), "http".to_owned()])
        );
        assert!(
            managed_composition_modules(
                "// omnius:managed-begin id=modules version=1 hash=abc\nnot-a-module\n"
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn route_less_application_contract_has_valid_runtime_parity() -> Result<()> {
        let directory = CleanDirectory::new("route-less-application-contract")?;
        let contracts = directory.path().join("contracts");
        fs::create_dir_all(&contracts)?;
        fs::write(
            contracts.join("openapi.json"),
            r#"{"openapi":"3.1.0","paths":{}}"#,
        )?;
        let resolved = omnius_generator::resolve_profile("minimal")?;
        let mut evidence = ProfileEvidence::default();

        let detail = validate_runtime_contract_parity(directory.path(), &resolved, &mut evidence)?;

        assert!(detail.contains("0 mounted operation ID(s)"));
        assert!(evidence.registered_operation_ids.is_empty());
        Ok(())
    }

    #[test]
    fn web_workspace_validation_fails_closed_and_accepts_complete_browser_assets() -> Result<()> {
        let directory = CleanDirectory::new("web-profile-validation")?;
        for path in ["pnpm-lock.yaml", "pnpm-workspace.yaml"] {
            fs::write(directory.path().join(path), "")?;
        }
        fs::create_dir_all(directory.path().join("packages/web-sdk"))?;
        fs::write(directory.path().join("packages/web-sdk/package.json"), "{}")?;
        fs::write(
            directory.path().join("package.json"),
            serde_json::to_vec(&serde_json::json!({
                "scripts": {
                    "sdk:typecheck": "true",
                    "sdk:typecheck:ts7": "true",
                    "sdk:test": "true",
                    "sdk:build": "true",
                    "web:typecheck": "true",
                    "web:typecheck:ts7": "true",
                    "web:test": "true",
                    "web:build": "true",
                    "web:test:e2e": "true"
                }
            }))?,
        )?;
        assert!(validate_web_workspace(directory.path(), false).is_ok());
        let error = validate_web_workspace(directory.path(), true)
            .err()
            .context("UI profile without browser artifacts was accepted")?;
        assert!(
            error
                .to_string()
                .contains("required generated browser artifact")
        );
        fs::create_dir_all(directory.path().join("web/e2e"))?;
        for path in [
            "web/package.json",
            "web/playwright.config.ts",
            "web/browser-support.json",
            "web/e2e/generated-profile-fixture.mjs",
            "web/e2e/generated-profile.spec.ts",
        ] {
            fs::write(directory.path().join(path), "")?;
        }
        assert!(validate_web_workspace(directory.path(), true).is_ok());
        Ok(())
    }

    #[test]
    fn skipped_required_checks_never_pass() {
        let mut checks = Vec::new();
        record_skipped(&mut checks, "web-e2e-smoke", true, "missing evidence");
        let check = &checks[0];
        assert!(check.required);
        assert!(!check.executed);
        assert!(!check.success);
        assert_eq!(check.status, CheckStatus::Skipped);
        assert!(check.criteria.iter().any(|value| value == "AC-WEB-079"));
        assert!(
            check
                .recommendations
                .iter()
                .any(|value| value == "REC-WEB-079")
        );
    }

    #[test]
    fn matrix_only_mode_is_local_while_automated_evidence_is_explicit() -> Result<()> {
        let workspace = Path::new("/workspace");
        let (parallel_jobs, _, _) =
            matrix_arguments(workspace, &["--jobs".to_owned(), "2".to_owned()])?;
        assert_eq!(parallel_jobs, 2);
        assert!(matrix_arguments(workspace, &["--jobs".to_owned(), "0".to_owned()]).is_err());
        let (_, _, default_policy) = matrix_arguments(workspace, &[])?;
        let (_, _, automated_policy) =
            matrix_arguments(workspace, &["--automated-evidence-only".to_owned()])?;
        assert_eq!(default_policy, ReleasePolicy::Enforced);
        assert_eq!(automated_policy, ReleasePolicy::AutomatedEvidenceOnly);
        assert!(validate_release_policy(ReleasePolicy::AutomatedEvidenceOnly, true).is_ok());
        assert!(validate_release_policy(ReleasePolicy::ReportOnly, false).is_ok());
        assert!(validate_release_policy(ReleasePolicy::ReportOnly, true).is_err());
        Ok(())
    }

    #[test]
    fn profile_cache_cleanup_retains_only_the_binary() -> Result<()> {
        let directory = CleanDirectory::new("profile-cache-cleanup")?;
        let profile_target = directory.path().join("cargo/profile");
        let executable = profile_target.join("debug/matrix-profile");
        fs::create_dir_all(profile_target.join("debug/deps"))?;
        fs::create_dir_all(profile_target.join("debug/incremental"))?;
        fs::write(&executable, b"profile-binary")?;
        fs::write(profile_target.join("debug/deps/transient"), b"cache")?;
        fs::write(profile_target.join("debug/incremental/transient"), b"cache")?;

        cleanup_profile_build_cache(&profile_target, &executable, true)?;

        assert_eq!(fs::read(&executable)?, b"profile-binary");
        let retained = WalkDir::new(&profile_target)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.path().to_path_buf())
            .collect::<Vec<_>>();
        assert_eq!(retained, vec![executable]);
        Ok(())
    }

    fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_directory(&source_path, &destination_path)?;
            } else {
                fs::copy(source_path, destination_path)?;
            }
        }
        Ok(())
    }
}
