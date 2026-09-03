//! Binds generator builds to an immutable source revision and dirtiness state.

mod build_support;

use std::{
    env,
    error::Error,
    ffi::OsStr,
    fmt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use build_support::{BuildBinding, GitSnapshot, porcelain_status_is_dirty, resolve_build_binding};

const RELEASE_REVISION_ENV: &str = "OMNIUS_RELEASE_REVISION";
const BUILD_REVISION_ENV: &str = "OMNIUS_BUILD_GIT_REVISION";
const BUILD_DIRTY_ENV: &str = "OMNIUS_BUILD_GIT_DIRTY";

fn main() {
    if let Err(error) = run() {
        eprintln!("generator release binding failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-env-changed={RELEASE_REVISION_ENV}");

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
            BuildScriptError("Cargo did not provide CARGO_MANIFEST_DIR".to_owned())
        })?);
    let explicit_revision = env::var_os(RELEASE_REVISION_ENV)
        .map(|revision| {
            revision.into_string().map_err(|_| {
                BuildScriptError(format!(
                    "{RELEASE_REVISION_ENV} must contain lowercase ASCII hexadecimal characters"
                ))
            })
        })
        .transpose()?;
    // Validate a packager binding before consulting optional checkout metadata.
    resolve_build_binding(explicit_revision.as_deref(), None)?;
    let git_root = find_git_root(&manifest_dir);
    let git = git_root.as_deref().map(read_git_snapshot).transpose()?;

    if let Some(root) = git_root.as_deref() {
        emit_git_rerun_inputs(root)?;
    }

    match resolve_build_binding(explicit_revision.as_deref(), git.as_ref())? {
        BuildBinding::Unbound => {
            println!("cargo::rustc-env={BUILD_DIRTY_ENV}=false");
        }
        BuildBinding::Bound { revision, dirty } => {
            println!("cargo::rustc-env={BUILD_REVISION_ENV}={revision}");
            println!("cargo::rustc-env={BUILD_DIRTY_ENV}={dirty}");
        }
    }

    Ok(())
}

fn find_git_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|ancestor| ancestor.join(".git").exists())
        .map(Path::to_path_buf)
}

fn read_git_snapshot(root: &Path) -> Result<GitSnapshot, BuildScriptError> {
    let revision = git_stdout(root, ["rev-parse", "--verify", "HEAD^{commit}"])?;
    let status = git_output(root, ["status", "--porcelain=v1", "--untracked-files=all"])?;

    Ok(GitSnapshot {
        revision,
        dirty: porcelain_status_is_dirty(&status.stdout),
    })
}

fn emit_git_rerun_inputs(root: &Path) -> Result<(), BuildScriptError> {
    let git_dir = absolute_git_path(root, git_stdout(root, ["rev-parse", "--absolute-git-dir"])?)?;
    let common_dir = absolute_git_path(root, git_stdout(root, ["rev-parse", "--git-common-dir"])?)?;

    emit_rerun_path(&git_dir.join("HEAD"));
    emit_rerun_path(&git_dir.join("index"));
    emit_rerun_path(&common_dir.join("packed-refs"));
    // Cargo has no explicit rerun-always directive. Watching a deliberately
    // absent Git-internal sentinel forces `git status` to be reevaluated on
    // every Cargo invocation, including after unstaged edits or newly
    // untracked paths that do not update HEAD or the index.
    emit_rerun_path(&git_dir.join("omnius-release-status-always-rerun"));

    if let Some(reference) = git_symbolic_head(root)? {
        emit_rerun_path(&common_dir.join(reference));
    }

    // Cargo configuration is provenance-sensitive even while still untracked.
    emit_rerun_path(&root.join(".cargo/config"));
    emit_rerun_path(&root.join(".cargo/config.toml"));

    Ok(())
}

fn absolute_git_path(root: &Path, path: String) -> Result<PathBuf, BuildScriptError> {
    let path = PathBuf::from(path);
    let absolute = if path.is_absolute() {
        path
    } else {
        root.join(path)
    };
    absolute.canonicalize().map_err(|error| {
        BuildScriptError(format!(
            "could not resolve Git metadata path `{}`: {error}",
            absolute.display()
        ))
    })
}

fn git_symbolic_head(root: &Path) -> Result<Option<String>, BuildScriptError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["symbolic-ref", "-q", "HEAD"])
        .output()
        .map_err(|error| BuildScriptError(format!("could not execute Git: {error}")))?;

    if output.status.success() {
        return decode_stdout(output).map(Some);
    }
    if output.status.code() == Some(1) {
        return Ok(None);
    }

    Err(command_failure("git symbolic-ref -q HEAD", &output))
}

fn git_stdout<I, S>(root: &Path, arguments: I) -> Result<String, BuildScriptError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    decode_stdout(git_output(root, arguments)?)
}

fn git_output<I, S>(root: &Path, arguments: I) -> Result<Output, BuildScriptError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .map_err(|error| BuildScriptError(format!("could not execute Git: {error}")))?;

    if output.status.success() {
        Ok(output)
    } else {
        Err(command_failure("Git command", &output))
    }
}

fn decode_stdout(output: Output) -> Result<String, BuildScriptError> {
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| BuildScriptError(format!("Git returned non-UTF-8 output: {error}")))?;
    Ok(stdout.trim().to_owned())
}

fn command_failure(command: &str, output: &Output) -> BuildScriptError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    BuildScriptError(format!(
        "{command} failed with {}: {}",
        output.status,
        stderr.trim()
    ))
}

fn emit_rerun_path(path: &Path) {
    println!("cargo::rerun-if-changed={}", path.display());
}

#[derive(Debug)]
struct BuildScriptError(String);

impl fmt::Display for BuildScriptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for BuildScriptError {}
