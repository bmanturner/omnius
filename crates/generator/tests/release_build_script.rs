//! End-to-end release build-script binding contracts.

use std::{
    error::Error,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use omnius_test_support::CleanDirectory;

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn git_checkout_binding_covers_detached_and_every_dirty_class() -> TestResult {
    let fixture = CleanDirectory::new("generator-release-build-git")?;
    let build_script = compile_build_script(fixture.path())?;
    let repository = fixture.path().join("repository");
    let manifest = repository.join("crates/generator");
    fs::create_dir_all(&manifest)?;
    fs::write(manifest.join("tracked.rs"), "const CLEAN: bool = true;\n")?;
    git(&repository, ["init"])?;
    git(&repository, ["config", "user.name", "Omnius Test"])?;
    git(
        &repository,
        ["config", "user.email", "omnius-test@example.invalid"],
    )?;
    git(&repository, ["add", "."])?;
    git(&repository, ["commit", "-m", "initial"])?;
    let revision = git_stdout(&repository, ["rev-parse", "HEAD"])?;

    let clean = run_build_script(&build_script, &manifest, None)?;
    assert_binding(&clean, &revision, false);
    assert!(String::from_utf8_lossy(&clean.stdout).contains("omnius-release-status-always-rerun"));

    git(&repository, ["checkout", "--detach"])?;
    assert_binding(
        &run_build_script(&build_script, &manifest, None)?,
        &revision,
        false,
    );

    fs::write(manifest.join("tracked.rs"), "const CLEAN: bool = false;\n")?;
    assert_binding(
        &run_build_script(&build_script, &manifest, None)?,
        &revision,
        true,
    );
    git(
        &repository,
        ["checkout", "--", "crates/generator/tracked.rs"],
    )?;

    fs::write(manifest.join("tracked.rs"), "const STAGED: bool = true;\n")?;
    git(&repository, ["add", "crates/generator/tracked.rs"])?;
    assert_binding(
        &run_build_script(&build_script, &manifest, None)?,
        &revision,
        true,
    );
    git(&repository, ["reset", "--hard", "HEAD"])?;

    let untracked = repository.join("nested/untracked.txt");
    fs::create_dir_all(repository.join("nested"))?;
    fs::write(&untracked, "untracked\n")?;
    assert_binding(
        &run_build_script(&build_script, &manifest, None)?,
        &revision,
        true,
    );
    fs::remove_dir_all(repository.join("nested"))?;

    fs::create_dir_all(repository.join(".cargo"))?;
    fs::write(repository.join(".cargo/config"), "[net]\noffline = true\n")?;
    assert_binding(
        &run_build_script(&build_script, &manifest, None)?,
        &revision,
        true,
    );
    Ok(())
}

#[test]
fn packaged_binding_requires_a_valid_explicit_revision() -> TestResult {
    let fixture = CleanDirectory::new("generator-release-build-packaged")?;
    let build_script = compile_build_script(fixture.path())?;
    let manifest = fixture.path().join("package/crates/generator");
    fs::create_dir_all(&manifest)?;

    assert_binding(
        &run_build_script(&build_script, &manifest, Some(REVISION))?,
        REVISION,
        false,
    );

    let invalid = run_build_script_output(&build_script, &manifest, Some("ABC123"))?;
    assert!(!invalid.status.success());
    assert!(
        String::from_utf8_lossy(&invalid.stderr)
            .contains("must be exactly 40 lowercase hexadecimal characters")
    );
    Ok(())
}

#[test]
fn explicit_revision_must_match_checkout_head() -> TestResult {
    let fixture = CleanDirectory::new("generator-release-build-mismatch")?;
    let build_script = compile_build_script(fixture.path())?;
    let repository = fixture.path().join("repository");
    let manifest = repository.join("crates/generator");
    fs::create_dir_all(&manifest)?;
    fs::write(manifest.join("tracked.rs"), "const TRACKED: bool = true;\n")?;
    git(&repository, ["init"])?;
    git(&repository, ["config", "user.name", "Omnius Test"])?;
    git(
        &repository,
        ["config", "user.email", "omnius-test@example.invalid"],
    )?;
    git(&repository, ["add", "."])?;
    git(&repository, ["commit", "-m", "initial"])?;

    let mismatch = run_build_script_output(&build_script, &manifest, Some(REVISION))?;
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("does not match Git HEAD"));
    Ok(())
}

fn compile_build_script(root: &Path) -> TestResult<PathBuf> {
    let generator = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = root.join(format!(
        "release-build-script{}",
        std::env::consts::EXE_SUFFIX
    ));
    let compilation = Command::new("rustc")
        .current_dir(generator)
        .args(["--edition=2024", "build.rs", "-o"])
        .arg(&output)
        .output()?;
    if !compilation.status.success() {
        return Err(format!(
            "build-script compilation failed: {}",
            String::from_utf8_lossy(&compilation.stderr)
        )
        .into());
    }
    Ok(output)
}

fn run_build_script(
    build_script: &Path,
    manifest: &Path,
    revision: Option<&str>,
) -> TestResult<Output> {
    let output = run_build_script_output(build_script, manifest, revision)?;
    if !output.status.success() {
        return Err(format!(
            "build script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
}

fn run_build_script_output(
    build_script: &Path,
    manifest: &Path,
    revision: Option<&str>,
) -> TestResult<Output> {
    let mut command = Command::new(build_script);
    command
        .env("CARGO_MANIFEST_DIR", manifest)
        .env_remove("OMNIUS_RELEASE_REVISION");
    if let Some(revision) = revision {
        command.env("OMNIUS_RELEASE_REVISION", revision);
    }
    Ok(command.output()?)
}

fn assert_binding(output: &Output, revision: &str, dirty: bool) {
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!(
        "cargo::rustc-env=OMNIUS_BUILD_GIT_REVISION={revision}"
    )));
    assert!(stdout.contains(&format!("cargo::rustc-env=OMNIUS_BUILD_GIT_DIRTY={dirty}")));
}

fn git<I, S>(root: &Path, arguments: I) -> TestResult
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err(format!("Git failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(())
}

fn git_stdout<I, S>(root: &Path, arguments: I) -> TestResult<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err(format!("Git failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
