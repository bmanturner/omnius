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

static PROFILE_BUILD_GATE: Mutex<()> = Mutex::new(());

const MATRIX_CHECKS: &[&str] = &[
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

#[derive(Serialize)]
pub(crate) struct MatrixReport {
    schema_version: u32,
    expected_profiles: usize,
    passed_profiles: usize,
    success: bool,
    profiles: Vec<ProfileResult>,
}

#[derive(Serialize)]
struct ProfileResult {
    profile: String,
    service: String,
    success: bool,
    checks: Vec<CheckResult>,
}

#[derive(Serialize)]
struct CheckResult {
    name: &'static str,
    success: bool,
    detail: String,
}

pub(crate) fn generate_verify(workspace: &Path, arguments: &[String]) -> Result<MatrixReport> {
    let (jobs, report_path) = matrix_arguments(workspace, arguments)?;
    let catalog = bundled_profile_catalog()?;
    ensure!(
        catalog.profiles().len() == 9,
        "base profile catalog must contain exactly 9 profiles"
    );
    let profile_ids = catalog
        .profiles()
        .iter()
        .map(|profile| profile.id.clone())
        .collect::<Vec<_>>();
    let work_root = workspace.join("target/profile-matrix/work");
    if work_root.exists() {
        fs::remove_dir_all(&work_root).with_context(|| format!("reset {}", work_root.display()))?;
    }
    fs::create_dir_all(&work_root)?;
    let cargo_target = workspace.join("target/profile-matrix/cargo");
    fs::create_dir_all(&cargo_target)?;

    let worker_count = jobs.min(profile_ids.len()).max(1);
    let mut partitions = vec![Vec::new(); worker_count];
    for (index, profile) in profile_ids.iter().enumerate() {
        partitions[index % worker_count].push(profile.as_str());
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
                        .map(|profile| {
                            verify_generated_profile(workspace, work_root, cargo_target, profile)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let mut results = Vec::with_capacity(profile_ids.len());
        for handle in handles {
            results.extend(
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("profile matrix worker panicked"))?,
            );
        }
        Ok(results)
    })?;
    let order = profile_ids
        .iter()
        .enumerate()
        .map(|(index, profile)| (profile.as_str(), index))
        .collect::<HashMap<_, _>>();
    results.sort_by_key(|result| {
        order
            .get(result.profile.as_str())
            .copied()
            .unwrap_or(usize::MAX)
    });
    let passed_profiles = results.iter().filter(|result| result.success).count();
    let report = MatrixReport {
        schema_version: 1,
        expected_profiles: profile_ids.len(),
        passed_profiles,
        success: results.len() == 9 && passed_profiles == 9,
        profiles: results,
    };
    let parent = report_path
        .parent()
        .context("matrix report path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut encoded = serde_json::to_string_pretty(&report)?;
    encoded.push('\n');
    fs::write(&report_path, encoded).with_context(|| format!("write {}", report_path.display()))?;
    ensure!(
        report.success,
        "profile matrix failed; see {}",
        report_path.display()
    );
    Ok(report)
}

fn matrix_arguments(workspace: &Path, arguments: &[String]) -> Result<(usize, PathBuf)> {
    let mut jobs = thread::available_parallelism()
        .map_or(2, usize::from)
        .min(4);
    let mut report = workspace.join("target/profile-matrix/report.json");
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
            argument => bail!("unknown profiles generate-verify argument `{argument}`"),
        }
        index += 1;
    }
    Ok((jobs, report))
}

fn verify_generated_profile(
    workspace: &Path,
    work_root: &Path,
    cargo_target: &Path,
    profile: &str,
) -> ProfileResult {
    let service = format!("matrix-{profile}");
    let destination = work_root.join(profile);
    let mut checks = Vec::with_capacity(MATRIX_CHECKS.len());
    verify_render_checks(&destination, &service, profile, &mut checks);
    verify_catalog_checks(workspace, &destination, profile, &mut checks);
    let _build_guard = PROFILE_BUILD_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let profile_target = cargo_target.join(profile);
    verify_build_checks(
        &destination,
        &profile_target,
        &service,
        profile,
        &mut checks,
    );
    for missing in MATRIX_CHECKS {
        if !checks.iter().any(|check| check.name == *missing) {
            checks.push(CheckResult {
                name: missing,
                success: false,
                detail: "check was not executed".to_owned(),
            });
        }
    }
    ProfileResult {
        profile: profile.to_owned(),
        service,
        success: checks.len() == MATRIX_CHECKS.len() && checks.iter().all(|check| check.success),
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
    let first_hash = if rendered {
        hash_tree(destination)
    } else {
        Err(anyhow::anyhow!("blocked by render failure"))
    };
    let repeated = if rendered {
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
        })
    } else {
        Err(omnius_generator::RenderError::DestinationNotEmpty)
    };
    let repeated_ok = record_check(checks, "render-repeat", repeated);
    let byte_result = match (first_hash, repeated_ok) {
        (Ok(before), true) => hash_tree(destination).and_then(|after| {
            ensure!(before == after, "rendered bytes changed on repeat");
            Ok("tree hashes match".to_owned())
        }),
        (Err(error), _) => Err(error),
        _ => Err(anyhow::anyhow!("blocked by repeat render failure")),
    };
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
            record_check(
                checks,
                "diff-clean",
                if clean {
                    Ok("empty".to_owned())
                } else {
                    Err(anyhow::anyhow!("blocked by doctor failure"))
                },
            );
        }
        Err(error) => {
            record_check(checks, "doctor-clean", Err(error));
            record_check(
                checks,
                "diff-clean",
                Err(anyhow::anyhow!("blocked by catalog failure")),
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
            .arg("nextest")
            .arg("run")
            .arg("--workspace")
            .arg("--exclude")
            .arg("omnius-generator")
            .arg("--manifest-path")
            .arg(destination.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(cargo_target),
    )
    .and_then(|tests| {
        run_command(
            Command::new(env!("CARGO"))
                .current_dir(destination)
                .arg("test")
                .arg("--doc")
                .arg("--workspace")
                .arg("--exclude")
                .arg("omnius-generator")
                .arg("--manifest-path")
                .arg(destination.join("Cargo.toml"))
                .arg("--target-dir")
                .arg(cargo_target),
        )
        .map(|docs| format!("{tests}; {docs}"))
    });
    let cargo_ok = record_check(checks, "cargo-test", cargo_test);
    let profile_info = if cargo_ok {
        run_profile_info(destination, cargo_target, service, profile)
    } else {
        Err(anyhow::anyhow!("blocked by cargo-test failure"))
    };
    let info_ok = record_check(checks, "profile-info", profile_info);
    let lifecycle = if info_ok {
        smoke_process(cargo_target, service)
    } else {
        Err(anyhow::anyhow!("blocked by profile-info failure"))
    };
    record_check(checks, "process-lifecycle", lifecycle);
}
fn record_check<E: std::fmt::Display>(
    checks: &mut Vec<CheckResult>,
    name: &'static str,
    result: std::result::Result<String, E>,
) -> bool {
    match result {
        Ok(detail) => {
            checks.push(CheckResult {
                name,
                success: true,
                detail,
            });
            true
        }
        Err(error) => {
            checks.push(CheckResult {
                name,
                success: false,
                detail: error.to_string(),
            });
            false
        }
    }
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

fn smoke_process(cargo_target: &Path, service: &str) -> Result<String> {
    let executable = cargo_target.join("debug").join(service);
    let mut child = Command::new(&executable)
        .arg("server")
        .env_clear()
        .env("OMNIUS_BIND", "127.0.0.1:0")
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
        assert_eq!(summary.profiles, 9);
        assert_eq!(summary.modules, 58);
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
        let machine = directory.path().join("machine");
        fs::create_dir(&machine)?;
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../specs/machine");
        fs::copy(
            source.join("module-catalog.yaml"),
            machine.join("module-catalog.yaml"),
        )?;
        fs::copy(source.join("profiles.yaml"), machine.join("profiles.yaml"))?;
        Ok(directory)
    }
}
