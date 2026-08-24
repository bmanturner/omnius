use std::{
    collections::BTreeMap,
    error::Error,
    ffi::{OsStr, OsString},
    fs, io,
    path::{Path, PathBuf},
    process::{Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use thiserror::Error;

/// Environment variable supplied to commands created by [`ProfileGenerationHarness`].
pub const TEST_PROFILE_ENV: &str = "RSK_TEST_PROFILE";

const DEFAULT_PROCESS_TIMEOUT: Duration = Duration::from_secs(60);

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

/// An empty temporary directory removed recursively on drop.
#[derive(Debug)]
pub struct CleanDirectory {
    path: PathBuf,
}

impl CleanDirectory {
    /// Creates a uniquely named empty directory under the system temporary root.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileHarnessError`] for an invalid label or filesystem error.
    pub fn new(label: &str) -> Result<Self, ProfileHarnessError> {
        if !valid_label(label) {
            return Err(ProfileHarnessError::InvalidLabel);
        }
        loop {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("rsk-{label}-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(ProfileHarnessError::Filesystem(error)),
            }
        }
    }

    /// Returns the owned temporary directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CleanDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "failed to remove test directory {}: {error}",
                self.path.display()
            );
        }
    }
}

/// A clean-directory harness for profile generator and generated-project tests.
#[derive(Debug)]
pub struct ProfileGenerationHarness {
    profile: String,
    directory: CleanDirectory,
}

impl ProfileGenerationHarness {
    /// Creates a clean workspace for one normalized profile identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileHarnessError`] if the profile name is invalid or the
    /// temporary directory cannot be created.
    pub fn new(profile: &str) -> Result<Self, ProfileHarnessError> {
        if !valid_profile(profile) {
            return Err(ProfileHarnessError::InvalidProfile);
        }
        Ok(Self {
            profile: profile.to_owned(),
            directory: CleanDirectory::new(&format!("profile-{profile}"))?,
        })
    }

    /// Returns the profile identifier under test.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Returns the clean generated-project root.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.directory.path()
    }

    /// Creates an environment-cleared child command rooted in the generated project.
    ///
    /// Only [`TEST_PROFILE_ENV`] and variables explicitly added through
    /// [`ProfileCommand::env`] are visible to the child.
    pub fn command(&self, program: impl AsRef<OsStr>) -> ProfileCommand<'_> {
        ProfileCommand {
            harness: self,
            program: program.as_ref().to_owned(),
            args: Vec::new(),
            environment: BTreeMap::new(),
            timeout: DEFAULT_PROCESS_TIMEOUT,
        }
    }

    /// Runs a generator twice and proves that the generated tree is nonempty
    /// and byte-for-byte idempotent, excluding volatile filesystem metadata.
    ///
    /// The callback receives the same initially empty root for both passes.
    /// Future generator tests can invoke either a library API or a real CLI
    /// inside the callback without coupling this harness to that interface.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileHarnessError`] if the root was not empty, generation
    /// failed, produced no files, filesystem inspection failed, or the second
    /// pass changed the generated tree.
    pub fn generate_idempotently<F, E>(&self, mut generator: F) -> Result<(), ProfileHarnessError>
    where
        F: FnMut(&Path) -> Result<(), E>,
        E: Error + Send + Sync + 'static,
    {
        if directory_has_entries(self.root())? {
            return Err(ProfileHarnessError::NotEmpty);
        }
        generator(self.root()).map_err(|source| ProfileHarnessError::Generation {
            pass: 1,
            source: Box::new(source),
        })?;
        let first = snapshot(self.root())?;
        if !first
            .values()
            .any(|entry| matches!(entry, SnapshotEntry::File { .. }))
        {
            return Err(ProfileHarnessError::EmptyOutput);
        }

        generator(self.root()).map_err(|source| ProfileHarnessError::Generation {
            pass: 2,
            source: Box::new(source),
        })?;
        let second = snapshot(self.root())?;
        if first != second {
            let path = first
                .iter()
                .find_map(|(path, entry)| (second.get(path) != Some(entry)).then(|| path.clone()))
                .or_else(|| {
                    second
                        .keys()
                        .find(|path| !first.contains_key(*path))
                        .cloned()
                })
                .unwrap_or_default();
            return Err(ProfileHarnessError::NonIdempotent { path });
        }
        Ok(())
    }
}

/// An environment-cleared child process tied to a profile harness lifetime.
#[derive(Debug)]
pub struct ProfileCommand<'a> {
    harness: &'a ProfileGenerationHarness,
    program: OsString,
    args: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
    timeout: Duration,
}

impl ProfileCommand<'_> {
    /// Appends one command argument.
    #[must_use]
    pub fn arg(mut self, argument: impl AsRef<OsStr>) -> Self {
        self.args.push(argument.as_ref().to_owned());
        self
    }

    /// Adds one explicit child environment variable.
    #[must_use]
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.environment
            .insert(key.as_ref().to_owned(), value.as_ref().to_owned());
        self
    }

    /// Replaces the bounded child-process deadline.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Executes the child under a deadline and captures its exit status,
    /// stdout, and stderr.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileHarnessError`] if the process could not be spawned,
    /// waited for, or exceeded its deadline. Nonzero exit status remains
    /// observable in [`Output::status`].
    pub async fn output(self) -> Result<Output, ProfileHarnessError> {
        let mut command = tokio::process::Command::new(self.program);
        command
            .args(self.args)
            .current_dir(self.harness.root())
            .env_clear()
            .envs(self.environment)
            .env(TEST_PROFILE_ENV, self.harness.profile())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(ProfileHarnessError::Process)?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ProfileHarnessError::Process(io::Error::other("missing child stdout"))
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            ProfileHarnessError::Process(io::Error::other("missing child stderr"))
        })?;
        let stdout_task = tokio::spawn(read_pipe(stdout));
        let stderr_task = tokio::spawn(read_pipe(stderr));

        let waited = tokio::time::timeout(self.timeout, child.wait()).await;
        let Ok(status) = waited else {
            let termination = child.kill().await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            termination.map_err(ProfileHarnessError::Process)?;
            return Err(ProfileHarnessError::ProcessTimeout {
                timeout: self.timeout,
            });
        };
        let status = status.map_err(ProfileHarnessError::Process)?;
        let stdout = captured_pipe(stdout_task).await?;
        let stderr = captured_pipe(stderr_task).await?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

async fn read_pipe<R>(mut pipe: R) -> io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

async fn captured_pipe(
    task: tokio::task::JoinHandle<io::Result<Vec<u8>>>,
) -> Result<Vec<u8>, ProfileHarnessError> {
    task.await
        .map_err(|error| ProfileHarnessError::Process(io::Error::other(error)))?
        .map_err(ProfileHarnessError::Process)
}

/// Failure while preparing or exercising a generated profile workspace.
#[derive(Debug, Error)]
pub enum ProfileHarnessError {
    /// A temporary directory label was empty or contained path syntax.
    #[error("clean directory label must contain only ASCII letters, digits, '-' or '_'")]
    InvalidLabel,
    /// A profile identifier did not use the catalog's lowercase name syntax.
    #[error("profile name must use lowercase ASCII letters, digits and internal hyphens")]
    InvalidProfile,
    /// A filesystem operation failed.
    #[error("profile harness filesystem operation failed")]
    Filesystem(#[source] io::Error),
    /// The generated-project root was modified before generation began.
    #[error("profile generation root was not empty")]
    NotEmpty,
    /// A generator pass returned an error.
    #[error("profile generator pass {pass} failed")]
    Generation {
        /// One-based generator pass number.
        pass: u8,
        /// Generator error.
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    /// Generation returned successfully without producing an entry.
    #[error("profile generator produced an empty project")]
    EmptyOutput,
    /// The second generator pass changed the generated project.
    #[error("profile generator was not idempotent at {path}", path = path.display())]
    NonIdempotent {
        /// First changed, added, or removed relative path.
        path: PathBuf,
    },
    /// A child process could not be executed.
    #[error("profile harness child process failed")]
    Process(#[source] io::Error),
    /// A child process exceeded its deadline and was terminated.
    #[error("profile harness child process exceeded {timeout:?}")]
    ProcessTimeout {
        /// Applied process deadline.
        timeout: Duration,
    },
}

#[derive(Debug, Eq, PartialEq)]
enum SnapshotEntry {
    Directory,
    File {
        contents: Vec<u8>,
        permission_mode: u32,
    },
}

fn snapshot(root: &Path) -> Result<BTreeMap<PathBuf, SnapshotEntry>, ProfileHarnessError> {
    let mut entries = BTreeMap::new();
    snapshot_directory(root, root, &mut entries).map_err(ProfileHarnessError::Filesystem)?;
    Ok(entries)
}

fn snapshot_directory(
    root: &Path,
    directory: &Path,
    entries: &mut BTreeMap<PathBuf, SnapshotEntry>,
) -> io::Result<()> {
    for item in fs::read_dir(directory)? {
        let path = item?.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .to_owned();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            entries.insert(relative, SnapshotEntry::Directory);
            snapshot_directory(root, &path, entries)?;
        } else if metadata.is_file() {
            entries.insert(
                relative,
                SnapshotEntry::File {
                    contents: fs::read(&path)?,
                    permission_mode: permission_mode(&metadata),
                },
            );
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported generated entry {}", path.display()),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn permission_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;

    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn permission_mode(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

fn directory_has_entries(path: &Path) -> Result<bool, ProfileHarnessError> {
    fs::read_dir(path)
        .map_err(ProfileHarnessError::Filesystem)?
        .next()
        .transpose()
        .map(|entry| entry.is_some())
        .map_err(ProfileHarnessError::Filesystem)
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_profile(profile: &str) -> bool {
    let bytes = profile.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn profile_generation_is_clean_nonempty_and_idempotent() -> TestResult {
        let harness = ProfileGenerationHarness::new("minimal")?;
        let mut passes = 0;
        harness.generate_idempotently(|root| {
            passes += 1;
            fs::create_dir_all(root.join("src"))?;
            fs::write(
                root.join("Cargo.toml"),
                "[package]\nname = \"generated\"\nversion = \"0.1.0\"\n",
            )?;
            fs::write(root.join("src/main.rs"), "fn main() {}\n")?;
            Ok::<_, io::Error>(())
        })?;
        assert_eq!(passes, 2);
        assert!(harness.root().join("Cargo.toml").is_file());
        Ok(())
    }

    #[test]
    fn profile_generation_rejects_non_idempotent_output() -> TestResult {
        let harness = ProfileGenerationHarness::new("minimal")?;
        let mut pass = 0_u8;
        let error = harness
            .generate_idempotently(|root| {
                pass += 1;
                fs::write(root.join("generated.txt"), pass.to_string())
            })
            .err()
            .ok_or("non-idempotent generation was accepted")?;
        assert!(matches!(error, ProfileHarnessError::NonIdempotent { .. }));
        Ok(())
    }

    #[test]
    fn profile_generation_rejects_directory_only_output() -> TestResult {
        let harness = ProfileGenerationHarness::new("minimal")?;
        let error = harness
            .generate_idempotently(|root| fs::create_dir(root.join("src")))
            .err()
            .ok_or("directory-only generation was accepted")?;
        assert!(matches!(error, ProfileHarnessError::EmptyOutput));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn profile_generation_compares_exact_executable_bits() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;

        let harness = ProfileGenerationHarness::new("minimal")?;
        let mut pass = 0_u8;
        let error = harness
            .generate_idempotently(|root| {
                pass += 1;
                let path = root.join("run.sh");
                fs::write(&path, "#!/bin/sh\n")?;
                let mode = if pass == 1 { 0o755 } else { 0o711 };
                fs::set_permissions(path, fs::Permissions::from_mode(mode))
            })
            .err()
            .ok_or("executable mode change was accepted")?;
        assert!(matches!(error, ProfileHarnessError::NonIdempotent { .. }));
        Ok(())
    }

    #[tokio::test]
    async fn profile_generation_process_uses_clean_cwd_and_explicit_environment() -> TestResult {
        const CHILD_MARKER: &str = "RSK_PROFILE_HARNESS_CHILD";
        if std::env::var_os(CHILD_MARKER).is_some() {
            assert_eq!(std::env::var(TEST_PROFILE_ENV)?, "minimal");
            assert!(std::env::var_os("HOME").is_none());
            assert!(!directory_has_entries(&std::env::current_dir()?)?);
            println!("profile child ready");
            return Ok(());
        }

        let harness = ProfileGenerationHarness::new("minimal")?;
        let output = harness
            .command(std::env::current_exe()?)
            .arg("--exact")
            .arg("profile::tests::profile_generation_process_uses_clean_cwd_and_explicit_environment")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .env(TEST_PROFILE_ENV, "must-not-override-profile")
            .output()
            .await?;
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)?.contains("profile child ready"));
        Ok(())
    }

    #[tokio::test]
    async fn profile_generation_process_is_terminated_at_deadline() -> TestResult {
        const CHILD_MARKER: &str = "RSK_PROFILE_HARNESS_TIMEOUT_CHILD";
        if std::env::var_os(CHILD_MARKER).is_some() {
            std::future::pending::<()>().await;
            return Ok(());
        }

        let harness = ProfileGenerationHarness::new("minimal")?;
        let error = harness
            .command(std::env::current_exe()?)
            .arg("--exact")
            .arg("profile::tests::profile_generation_process_is_terminated_at_deadline")
            .env(CHILD_MARKER, "1")
            .timeout(Duration::from_millis(50))
            .output()
            .await
            .err()
            .ok_or("hung profile process exceeded its deadline")?;
        assert!(matches!(error, ProfileHarnessError::ProcessTimeout { .. }));
        Ok(())
    }

    #[test]
    fn clean_directory_is_removed_on_drop() -> TestResult {
        let path = {
            let directory = CleanDirectory::new("cleanup")?;
            let path = directory.path().to_owned();
            fs::write(path.join("nested.txt"), "test")?;
            path
        };
        assert!(!path.exists());
        Ok(())
    }
}
