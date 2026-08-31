use std::{
    collections::HashMap,
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
    ModuleCatalog as GeneratorModuleCatalog, ProfileCatalog as GeneratorProfileCatalog,
    ProjectManager, RenderOutcome, RenderRequest, bundled_profile_catalog, render_project,
    resolve_profile as resolve_generator_profile,
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
    "profile-info",
    "process-lifecycle",
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
const WEB_E2E_MODULE: &str = "web-testing";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileKind {
    Base,
    Web,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReleasePolicy {
    Enforced,
    AutomatedEvidenceOnly,
    ReportOnly,
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
    pub(crate) contract_aggregate_sha256: Option<String>,
    pub(crate) checks: Vec<CheckResult>,
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
    e2e: bool,
}

fn profile_plans(catalog: &GeneratorProfileCatalog) -> Result<Vec<ProfilePlan>> {
    catalog
        .profiles()
        .iter()
        .map(|profile| {
            let resolved = resolve_generator_profile(&profile.id)?;
            let web = resolved
                .modules()
                .iter()
                .any(|module| module == WEB_PROFILE_MODULE);
            let e2e = resolved
                .modules()
                .iter()
                .any(|module| module == WEB_E2E_MODULE);
            ensure!(
                !e2e || web,
                "profile `{}` enables web E2E without web",
                profile.id
            );
            Ok(ProfilePlan {
                id: profile.id.clone(),
                kind: if web {
                    ProfileKind::Web
                } else {
                    ProfileKind::Base
                },
                e2e,
            })
        })
        .collect()
}

pub(crate) fn generate_verify(workspace: &Path, arguments: &[String]) -> Result<MatrixReport> {
    let (jobs, report_path, release_policy) = matrix_arguments(workspace, arguments)?;
    let catalog = bundled_profile_catalog()?;
    let plans = profile_plans(catalog)?;
    ensure!(!plans.is_empty(), "bundled profile catalog is empty");
    let work_root = workspace.join("target/profile-matrix/work");
    if work_root.exists() {
        fs::remove_dir_all(&work_root).with_context(|| format!("reset {}", work_root.display()))?;
    }
    fs::create_dir_all(&work_root)?;
    let cargo_target = workspace.join("target/profile-matrix/cargo");
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
        schema_version: 3,
        expected_profiles: plans.len(),
        web_profiles: plans
            .iter()
            .filter(|plan| plan.kind == ProfileKind::Web)
            .count(),
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
    let mut jobs = thread::available_parallelism()
        .map_or(2, usize::from)
        .min(4);
    let mut report = workspace.join("target/profile-matrix/report.json");
    let mut release_policy = ReleasePolicy::Enforced;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--jobs" => {
                index += 1;
                let value = arguments.get(index).context("--jobs requires a value")?;
                jobs = value.parse().context("--jobs must be a positive integer")?;
                ensure!(jobs > 0 && jobs <= 16, "--jobs must be between 1 and 16");
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

fn verify_generated_profile(
    workspace: &Path,
    work_root: &Path,
    cargo_target: &Path,
    plan: &ProfilePlan,
) -> ProfileResult {
    let profile = plan.id.as_str();
    let service = format!("matrix-{profile}");
    let destination = work_root.join(profile);
    let expected_checks = BASE_MATRIX_CHECKS.len()
        + if plan.kind == ProfileKind::Web {
            WEB_MATRIX_CHECKS.len()
        } else {
            0
        };
    let mut checks = Vec::with_capacity(expected_checks);
    verify_render_checks(&destination, &service, profile, &mut checks);
    verify_catalog_checks(workspace, &destination, profile, &mut checks);
    let profile_target = cargo_target.join(profile);
    if plan.kind == ProfileKind::Web {
        verify_web_checks(
            workspace,
            &destination,
            &profile_target,
            profile,
            plan.e2e,
            &mut checks,
        );
    }
    verify_build_checks(
        &destination,
        &profile_target,
        &service,
        profile,
        &mut checks,
    );
    if plan.kind == ProfileKind::Web {
        verify_web_e2e_check(
            workspace,
            &destination,
            &profile_target,
            &service,
            plan.e2e,
            &mut checks,
        );
    }
    for missing in BASE_MATRIX_CHECKS.iter().chain(
        (plan.kind == ProfileKind::Web)
            .then_some(WEB_MATRIX_CHECKS)
            .into_iter()
            .flatten(),
    ) {
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
    ProfileResult {
        profile: profile.to_owned(),
        service,
        kind: plan.kind,
        success,
        contract_aggregate_sha256,
        checks,
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
        render_project(RenderRequest {
            service_name: service,
            profile,
            destination,
        })
        .and_then(|outcome| match outcome {
            RenderOutcome::Created { files } => Ok(format!("{files} files")),
            RenderOutcome::Unchanged { .. } => {
                Err(omnius_generator::RenderError::DestinationNotEmpty)
            }
        }),
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
        render_project(RenderRequest {
            service_name: service,
            profile,
            destination,
        })
        .and_then(|outcome| match outcome {
            RenderOutcome::Unchanged { files } => Ok(format!("{files} files")),
            RenderOutcome::Created { .. } => {
                Err(omnius_generator::RenderError::DestinationNotEmpty)
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
    workspace: &Path,
    destination: &Path,
    profile: &str,
    checks: &mut Vec<CheckResult>,
) {
    let metadata = resolve_generator_profile(profile)
        .as_ref()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .and_then(|resolved| validate_metadata_artifacts(destination, resolved));
    record_check(checks, "metadata-artifacts", metadata);

    let manager_checks = GeneratorModuleCatalog::bundled()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .map(|catalog| {
            let manager = ProjectManager::new(destination, workspace, &catalog);
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
            Ok::<_, anyhow::Error>(())
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

fn verify_build_checks(
    destination: &Path,
    cargo_target: &Path,
    service: &str,
    profile: &str,
    checks: &mut Vec<CheckResult>,
) {
    let cargo_test = run_command(
        Command::new(env!("CARGO"))
            .current_dir(destination)
            .arg("check")
            .arg("--workspace")
            .arg("--all-targets")
            .arg("--exclude")
            .arg("omnius-generator")
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
                .arg("--package")
                .arg(service)
                .arg("--manifest-path")
                .arg(destination.join("Cargo.toml"))
                .arg("--target-dir")
                .arg(cargo_target),
        )
        .map(|docs| format!("{checks}; {docs}"))
    });
    let cargo_ok = record_check(checks, "cargo-test", cargo_test);
    if !cargo_ok {
        record_skipped(
            checks,
            "profile-info",
            true,
            "blocked by cargo-test failure",
        );
        record_skipped(
            checks,
            "process-lifecycle",
            true,
            "blocked by cargo-test failure",
        );
        return;
    }
    let info_ok = record_check(
        checks,
        "profile-info",
        run_profile_info(destination, cargo_target, service, profile),
    );
    if info_ok {
        record_check(
            checks,
            "process-lifecycle",
            smoke_process(destination, cargo_target, service),
        );
    } else {
        record_skipped(
            checks,
            "process-lifecycle",
            true,
            "blocked by profile-info failure",
        );
    }
}
fn verify_web_checks(
    workspace: &Path,
    destination: &Path,
    cargo_target: &Path,
    profile: &str,
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
        resolve_generator_profile(profile)
            .map_err(anyhow::Error::from)
            .and_then(|resolved| {
                crate::contracts::validate_committed(
                    workspace,
                    destination,
                    profile,
                    resolved.modules(),
                )
            })
            .and_then(|()| {
                read_contract_aggregate_sha256(destination)
                    .map(|hash| format!("generated contracts validated at sha256:{hash}"))
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
    e2e: bool,
    checks: &mut Vec<CheckResult>,
) {
    if e2e {
        let result =
            run_web_e2e(workspace, destination, cargo_target, service).and_then(|detail| {
                collect_web_e2e_artifacts(workspace, destination)
                    .map(|artifacts| (detail, artifacts))
            });
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
            "web/e2e/axum-fixture.mjs",
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
        (&["AC-WEB-079"], &[])
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
    profile: &str,
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
    let expected = resolve_generator_profile(profile)?;
    ensure!(
        document["profile"] == profile,
        "profile-info profile differs"
    );
    ensure!(
        document["modules"] == serde_json::json!(expected.modules()),
        "profile-info modules differ"
    );
    ensure!(
        document["providers"] == serde_json::json!(expected.providers()),
        "profile-info providers differ"
    );
    Ok("metadata matches".to_owned())
}

fn smoke_process(destination: &Path, cargo_target: &Path, service: &str) -> Result<String> {
    let executable = cargo_target.join("debug").join(service);
    let mut child = Command::new(&executable)
        .current_dir(destination)
        .arg("server")
        .env_clear()
        .env("OMNIUS_BIND", "127.0.0.1:0")
        .env("OMNIUS_WEB_ASSET_DIR", destination.join("web/dist"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("start {}", executable.display()))?;
    let stdout = child
        .stdout
        .take()
        .context("service stdout was not piped")?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let line = BufReader::new(stdout).lines().next().transpose();
        let _ = sender.send(line);
    });
    let line = receiver
        .recv_timeout(Duration::from_secs(30))
        .context("service readiness banner timed out")??
        .context("service exited before readiness banner")?;
    let address = line
        .strip_prefix("listening on http://")
        .context("unexpected readiness banner")?;
    for path in ["/ready", "/version", "/example"] {
        http_get(address, path)?;
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
    Ok("ready/version/example and drain succeeded".to_owned())
}

fn http_get(address: &str, path: &str) -> Result<()> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    ensure!(
        response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200"),
        "{path} did not return HTTP 200"
    );
    Ok(())
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
        assert_eq!(summary.profiles, 24);
        assert_eq!(summary.modules, 111);
        Ok(())
    }

    #[test]
    fn rejects_broken_catalog_copied_into_clean_directory() -> Result<()> {
        let directory = copy_real_catalogs()?;
        let profiles_path = directory.path().join("machine/profiles.yaml");
        let profiles = fs::read_to_string(&profiles_path)?;
        let broken = profiles.replacen("  - generator\n", "  - generator\n  - missing-module\n", 1);
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
    fn derives_all_bundled_profile_plans_and_web_kinds() -> Result<()> {
        let catalog = bundled_profile_catalog()?;
        let plans = profile_plans(catalog)?;
        assert_eq!(plans.len(), 24);
        assert_eq!(
            plans
                .iter()
                .filter(|plan| plan.kind == ProfileKind::Web)
                .count(),
            crate::web_release::EXPECTED_WEB_PROFILE_COUNT
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
    fn web_workspace_validation_fails_closed() -> Result<()> {
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
                    "sdk:build": "true"
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
