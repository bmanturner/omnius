//! Crash-recoverable application of sealed lifecycle file operations.

use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsStr,
    fmt,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use rustix::{
    fd::OwnedFd,
    fs::{
        AtFlags, FileType, FlockOperation, Mode, OFlags, fchmod, flock, fstat, fsync, mkdirat,
        open, openat, renameat, statat, unlinkat,
    },
    io::Errno,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Stable project-relative path of the process-wide lifecycle advisory lock.
pub(crate) const LIFECYCLE_LOCK_PATH: &str = ".omnius/lifecycle.lock";
/// Stable project-relative path of the durable transaction journal.
pub(crate) const TRANSACTION_JOURNAL_PATH: &str = ".omnius/transaction.json";

const JOURNAL_SCHEMA_VERSION: u32 = 1;
const CONTROL_DIRECTORY: &str = ".omnius";
const LOCK_FILE_NAME: &str = "lifecycle.lock";
const JOURNAL_FILE_NAME: &str = "transaction.json";
const JOURNAL_TEMP_FILE_NAME: &str = ".transaction.json.tmp";
const JOURNAL_TEMP_PATH: &str = ".omnius/.transaction.json.tmp";
const JOURNAL_READY_FILE_NAME: &str = ".transaction.json.tmp.ready";
const JOURNAL_READY_PATH: &str = ".omnius/.transaction.json.tmp.ready";
const STATE_FILE_PATH: &str = ".omnius/service.toml";
const DEFAULT_DIRECTORY_MODE: Mode = Mode::RUSR
    .union(Mode::WUSR)
    .union(Mode::XUSR)
    .union(Mode::RGRP)
    .union(Mode::WGRP)
    .union(Mode::XGRP)
    .union(Mode::ROTH)
    .union(Mode::WOTH)
    .union(Mode::XOTH);
const DEFAULT_FILE_MODE: Mode = Mode::RUSR
    .union(Mode::WUSR)
    .union(Mode::RGRP)
    .union(Mode::WGRP)
    .union(Mode::ROTH)
    .union(Mode::WOTH);
const PRIVATE_FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const DIRECTORY_OPEN_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const FILE_READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// One file change whose expected hashes and replacement bytes are sealed before application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalOperation {
    path: String,
    expected_before_sha256: Option<String>,
    expected_after_sha256: Option<String>,
    replacement: Option<Vec<u8>>,
}

impl JournalOperation {
    /// Seals a file creation or replacement against caller-provided before/after hashes.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidOperation`] for an unsafe path, malformed hash, or
    /// replacement bytes that do not match `expected_after_sha256`.
    pub(crate) fn write(
        path: impl Into<String>,
        expected_before_sha256: Option<String>,
        replacement: Vec<u8>,
        expected_after_sha256: String,
    ) -> Result<Self, JournalError> {
        let path = path.into();
        validate_operation_path(&path)?;
        validate_optional_hash(expected_before_sha256.as_deref(), &path, "before")?;
        validate_hash(&expected_after_sha256, &path, "after")?;
        let actual_after = sha256_hex(&replacement);
        if actual_after != expected_after_sha256 {
            return Err(JournalError::InvalidOperation {
                path,
                reason: format!(
                    "replacement SHA-256 `{actual_after}` does not match sealed after hash `{expected_after_sha256}`"
                ),
            });
        }
        Ok(Self {
            path,
            expected_before_sha256,
            expected_after_sha256: Some(expected_after_sha256),
            replacement: Some(replacement),
        })
    }

    /// Seals deletion of a regular file with the expected current hash.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidOperation`] for an unsafe path or malformed hash.
    pub(crate) fn remove(
        path: impl Into<String>,
        expected_before_sha256: String,
    ) -> Result<Self, JournalError> {
        let path = path.into();
        validate_operation_path(&path)?;
        validate_hash(&expected_before_sha256, &path, "before")?;
        Ok(Self {
            path,
            expected_before_sha256: Some(expected_before_sha256),
            expected_after_sha256: None,
            replacement: None,
        })
    }
}

/// A durable point at which fault tests may interrupt transaction application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyBoundary {
    /// Immediately before a transaction-owned parent directory is created.
    BeforeDirectory { directory: usize },
    /// After the journal records directory-creation intent and before `mkdir`.
    AfterDirectoryIntentSync { directory: usize },
    /// After directory creation and before its parent directory is synced.
    AfterDirectoryCreated { directory: usize },
    /// After the new directory's parent has been synced.
    AfterDirectorySync { directory: usize },
    /// Immediately before one sealed file entry is inspected or changed.
    BeforeOperation { entry: usize },
    /// After the journal records temporary-file intent and before exclusive creation.
    AfterTemporaryIntentSync { entry: usize },
    /// After exclusive temporary-file creation and before its identity is journaled.
    AfterTemporaryFileCreated { entry: usize },
    /// After a replacement temporary file has been synced and before rename.
    AfterTemporaryFileSync { entry: usize },
    /// After rename or deletion and before the containing directory is synced.
    AfterTargetChange { entry: usize },
    /// After the changed target's containing directory has been synced.
    AfterTargetDirectorySync { entry: usize },
    /// After the entry's applied status has been durably journaled.
    AfterAppliedStatusSync { entry: usize },
    /// Before the journal transitions from prepared to committed.
    BeforeCommit,
    /// After the committed journal has been durably persisted.
    AfterCommitSync,
    /// After the committed journal has been removed but before directory sync.
    AfterJournalRemoval,
    /// After journal removal has been durably synced.
    AfterJournalDirectorySync,
}

impl fmt::Display for ApplyBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeDirectory { directory } => {
                write!(formatter, "before-directory-{directory}")
            }
            Self::AfterDirectoryIntentSync { directory } => {
                write!(formatter, "after-directory-intent-sync-{directory}")
            }
            Self::AfterDirectoryCreated { directory } => {
                write!(formatter, "after-directory-created-{directory}")
            }
            Self::AfterDirectorySync { directory } => {
                write!(formatter, "after-directory-sync-{directory}")
            }
            Self::BeforeOperation { entry } => write!(formatter, "before-operation-{entry}"),
            Self::AfterTemporaryIntentSync { entry } => {
                write!(formatter, "after-temporary-intent-sync-{entry}")
            }
            Self::AfterTemporaryFileCreated { entry } => {
                write!(formatter, "after-temporary-file-created-{entry}")
            }
            Self::AfterTemporaryFileSync { entry } => {
                write!(formatter, "after-temporary-file-sync-{entry}")
            }
            Self::AfterTargetChange { entry } => {
                write!(formatter, "after-target-change-{entry}")
            }
            Self::AfterTargetDirectorySync { entry } => {
                write!(formatter, "after-target-directory-sync-{entry}")
            }
            Self::AfterAppliedStatusSync { entry } => {
                write!(formatter, "after-applied-status-sync-{entry}")
            }
            Self::BeforeCommit => formatter.write_str("before-commit"),
            Self::AfterCommitSync => formatter.write_str("after-commit-sync"),
            Self::AfterJournalRemoval => formatter.write_str("after-journal-removal"),
            Self::AfterJournalDirectorySync => formatter.write_str("after-journal-directory-sync"),
        }
    }
}

/// Injectable application checkpoint used by exhaustive crash-boundary tests.
pub(crate) trait ApplyFaultInjector {
    /// Observes a boundary, returning a deterministic message to simulate interruption.
    fn checkpoint(&mut self, boundary: ApplyBoundary) -> Result<(), String>;
}

#[derive(Debug, Default)]
struct NoFault;

impl ApplyFaultInjector for NoFault {
    fn checkpoint(&mut self, _boundary: ApplyBoundary) -> Result<(), String> {
        Ok(())
    }
}

/// Result of recovering a journal found while holding the lifecycle lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryOutcome {
    /// No transaction journal existed.
    None,
    /// A prepared transaction was restored to its sealed original bytes.
    RolledBack { plan_id: String },
    /// A committed transaction was verified at replacement bytes and finalized.
    Finalized { plan_id: String },
}

/// Exclusive advisory lock for one managed project's lifecycle mutations.
#[derive(Debug)]
pub(crate) struct LifecycleLock {
    project_root: PathBuf,
    root_fd: OwnedFd,
    control_fd: OwnedFd,
    _lock_file: File,
}

impl LifecycleLock {
    /// Opens the project without following symlinks, ensures `.omnius`, and takes an exclusive
    /// non-blocking OS advisory lock on [`.omnius/lifecycle.lock`](LIFECYCLE_LOCK_PATH).
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::LockBusy`] when another process holds the lock, or a deterministic
    /// filesystem/unsafe-path error when the control directory or lock file is unsuitable.
    pub(crate) fn acquire(project_root: &Path) -> Result<Self, JournalError> {
        let root_fd = open_project_directory(project_root)?;
        let (control_fd, created_control) = ensure_control_directory(&root_fd, project_root)?;
        let lock_path = project_root.join(LIFECYCLE_LOCK_PATH);
        let lock_existed = match stat_optional(&control_fd, OsStr::new(LOCK_FILE_NAME), &lock_path)?
        {
            Some(stat) => {
                ensure_regular_type(&lock_path, stat.st_mode)?;
                true
            }
            None => false,
        };
        let lock_fd = openat(
            &control_fd,
            LOCK_FILE_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            PRIVATE_FILE_MODE,
        )
        .map_err(|error| filesystem_errno("open lifecycle lock", &lock_path, error))?;
        let lock_stat = fstat(&lock_fd)
            .map_err(|error| filesystem_errno("inspect lifecycle lock", &lock_path, error))?;
        ensure_regular_type(&lock_path, lock_stat.st_mode)?;
        let lock_file = File::from(lock_fd);
        if created_control || !lock_existed {
            fsync(&control_fd).map_err(|error| {
                filesystem_errno(
                    "sync lifecycle control directory",
                    project_root.join(CONTROL_DIRECTORY),
                    error,
                )
            })?;
        }
        match flock(&lock_file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(error) if error == Errno::WOULDBLOCK || error == Errno::AGAIN => {
                return Err(JournalError::LockBusy { path: lock_path });
            }
            Err(error) => {
                return Err(filesystem_errno(
                    "acquire lifecycle lock",
                    &lock_path,
                    error,
                ));
            }
        }
        Ok(Self {
            project_root: project_root.to_path_buf(),
            root_fd,
            control_fd,
            _lock_file: lock_file,
        })
    }

    /// Recovers and removes any durable transaction journal while the exclusive lock is held.
    ///
    /// Prepared journals restore original bytes in reverse order. Committed journals only verify
    /// replacement bytes and finalize; they are never silently rolled back.
    ///
    /// # Errors
    ///
    /// Returns an error without removing the journal when any managed path contains neither its
    /// sealed original nor replacement bytes, or when a path is a symlink/non-regular file.
    pub(crate) fn recover(&self) -> Result<RecoveryOutcome, JournalError> {
        self.cleanup_journal_temporary_file()?;
        let Some(journal_bytes) = read_named_file(
            &self.control_fd,
            OsStr::new(JOURNAL_FILE_NAME),
            &self.project_root.join(TRANSACTION_JOURNAL_PATH),
        )?
        else {
            return Ok(RecoveryOutcome::None);
        };
        let mut journal = Journal::decode(&journal_bytes.bytes)?;
        journal.validate()?;
        self.preflight_created_directories(&journal)?;
        self.preflight_recovery(&journal)?;
        self.cleanup_operation_temporary_files(&mut journal)?;

        match journal.state {
            JournalState::Prepared => {
                for index in (0..journal.entries.len()).rev() {
                    let entry = journal.entries[index].clone();
                    let original = entry.original.decode_optional(&entry.path, "original")?;
                    let replacement = entry
                        .replacement
                        .decode_optional(&entry.path, "replacement")?;
                    let current = self.read_operation_file(&entry.path)?;
                    match classify_contents(
                        current.as_ref().map(|file| file.bytes.as_slice()),
                        original.as_deref(),
                        replacement.as_deref(),
                    ) {
                        ContentDecision::Replacement => self.restore_entry(
                            &mut journal,
                            index,
                            &entry,
                            replacement.as_deref(),
                            original.as_deref(),
                        )?,
                        ContentDecision::Original => {}
                        ContentDecision::Other => {
                            return Err(unexpected_contents(
                                &entry.path,
                                "sealed original or replacement bytes",
                                current.as_ref().map(|file| file.bytes.as_slice()),
                            ));
                        }
                    }
                    if journal.entries[index].applied {
                        let mut updated = journal.clone();
                        updated.entries[index].applied = false;
                        self.replace_journal(&journal, &updated)?;
                        journal = updated;
                    }
                }
                self.remove_created_directories(&journal)?;
                let plan_id = journal.plan_id.clone();
                self.remove_journal(&journal, None)?;
                Ok(RecoveryOutcome::RolledBack { plan_id })
            }
            JournalState::Committed => {
                let plan_id = journal.plan_id.clone();
                self.remove_journal(&journal, None)?;
                Ok(RecoveryOutcome::Finalized { plan_id })
            }
        }
    }

    /// Validates all expected inputs, captures exact originals, and durably writes a prepared
    /// journal before returning an applicator. No file operation can be added afterward.
    ///
    /// # Errors
    ///
    /// Returns a stale-input, unsafe-path, existing-journal, or persistence error. No operation
    /// target is changed when preparation fails.
    pub(crate) fn prepare_transaction(
        &mut self,
        plan_id: impl Into<String>,
        operations: Vec<JournalOperation>,
    ) -> Result<PreparedTransaction<'_>, JournalError> {
        self.cleanup_journal_temporary_file()?;
        if read_named_file(
            &self.control_fd,
            OsStr::new(JOURNAL_FILE_NAME),
            &self.project_root.join(TRANSACTION_JOURNAL_PATH),
        )?
        .is_some()
        {
            return Err(JournalError::TransactionExists {
                path: self.project_root.join(TRANSACTION_JOURNAL_PATH),
            });
        }
        let plan_id = plan_id.into();
        validate_plan_id(&plan_id)?;
        if operations.is_empty() {
            return Err(JournalError::InvalidPlan(
                "a transaction must contain at least one file operation".to_owned(),
            ));
        }

        let mut seen_paths = BTreeSet::new();
        let mut created_directories = Vec::new();
        let mut planned_directories = BTreeSet::new();
        let mut entries = Vec::with_capacity(operations.len());
        for operation in operations {
            if !seen_paths.insert(operation.path.clone()) {
                return Err(JournalError::InvalidOperation {
                    path: operation.path,
                    reason: "duplicate transaction path".to_owned(),
                });
            }
            let current = self.inspect_for_preparation(
                &operation.path,
                &mut created_directories,
                &mut planned_directories,
            )?;
            verify_expected_hash(
                &operation.path,
                operation.expected_before_sha256.as_deref(),
                current.as_ref().map(|file| file.bytes.as_slice()),
            )?;
            let original = current.as_ref().map(|file| file.bytes.as_slice());
            let replacement = operation.replacement.as_deref();
            if original == replacement {
                return Err(JournalError::InvalidOperation {
                    path: operation.path,
                    reason: "sealed original and replacement bytes are identical".to_owned(),
                });
            }
            entries.push(JournalEntry {
                path: operation.path,
                expected_before_sha256: operation.expected_before_sha256,
                expected_after_sha256: operation.expected_after_sha256,
                original: EncodedBytes::from_optional(original),
                replacement: EncodedBytes::from_optional(replacement),
                original_mode: current.map(|file| file.mode),
                temporary_state: TemporaryState::Absent,
                temporary_identity: None,
                applied: false,
            });
        }

        let journal = Journal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            plan_id,
            state: JournalState::Prepared,
            created_directories: created_directories
                .into_iter()
                .map(|path| JournalDirectory {
                    path,
                    state: DirectoryState::Planned,
                    device: None,
                    inode: None,
                })
                .collect(),
            entries,
        };
        journal.validate()?;
        for (index, entry) in journal.entries.iter().enumerate() {
            self.ensure_operation_temporary_absent(index, entry)?;
        }
        self.ensure_created_directories_absent(&journal)?;
        self.create_journal(&journal)?;
        Ok(PreparedTransaction {
            lock: self,
            journal,
        })
    }

    fn preflight_recovery(&self, journal: &Journal) -> Result<(), JournalError> {
        for entry in &journal.entries {
            let original = entry.original.decode_optional(&entry.path, "original")?;
            let replacement = entry
                .replacement
                .decode_optional(&entry.path, "replacement")?;
            let current = self.read_operation_file(&entry.path)?;
            let decision = classify_contents(
                current.as_ref().map(|file| file.bytes.as_slice()),
                original.as_deref(),
                replacement.as_deref(),
            );
            let accepted = match journal.state {
                JournalState::Prepared => decision != ContentDecision::Other,
                JournalState::Committed => decision == ContentDecision::Replacement,
            };
            if !accepted {
                let expected = match journal.state {
                    JournalState::Prepared => "sealed original or replacement bytes",
                    JournalState::Committed => {
                        "sealed replacement bytes of a committed transaction"
                    }
                };
                return Err(unexpected_contents(
                    &entry.path,
                    expected,
                    current.as_ref().map(|file| file.bytes.as_slice()),
                ));
            }
        }
        Ok(())
    }

    fn inspect_for_preparation(
        &self,
        path: &str,
        created_directories: &mut Vec<String>,
        planned_directories: &mut BTreeSet<String>,
    ) -> Result<Option<CurrentFile>, JournalError> {
        let (parent_path, file_name) = split_parent_name(path);
        let mut directory = duplicate_directory(&self.root_fd, &self.project_root)?;
        let mut prefix = String::new();
        let mut below_missing_directory = false;
        for segment in parent_path.split('/').filter(|segment| !segment.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            if below_missing_directory || planned_directories.contains(&prefix) {
                if planned_directories.insert(prefix.clone()) {
                    created_directories.push(prefix.clone());
                }
                below_missing_directory = true;
                continue;
            }
            let display = self.project_root.join(&prefix);
            if let Some(stat) = stat_optional(&directory, OsStr::new(segment), &display)? {
                ensure_directory_type(&display, stat.st_mode)?;
                directory = openat(&directory, segment, DIRECTORY_OPEN_FLAGS, Mode::empty())
                    .map_err(|error| filesystem_errno("open parent directory", &display, error))?;
            } else {
                planned_directories.insert(prefix.clone());
                created_directories.push(prefix.clone());
                below_missing_directory = true;
            }
        }
        if below_missing_directory {
            return Ok(None);
        }
        let file_name = OsStr::new(file_name);
        read_named_file(&directory, file_name, &self.project_root.join(path))
    }

    fn read_operation_file(&self, path: &str) -> Result<Option<CurrentFile>, JournalError> {
        let Some((directory, name)) = self.open_parent_if_present(path)? else {
            return Ok(None);
        };
        read_named_file(&directory, name, &self.project_root.join(path))
    }

    fn open_parent_if_present<'path>(
        &self,
        path: &'path str,
    ) -> Result<Option<(OwnedFd, &'path OsStr)>, JournalError> {
        let (parent_path, file_name) = split_parent_name(path);
        let mut directory = duplicate_directory(&self.root_fd, &self.project_root)?;
        let mut prefix = String::new();
        for segment in parent_path.split('/').filter(|segment| !segment.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            let display = self.project_root.join(&prefix);
            let Some(stat) = stat_optional(&directory, OsStr::new(segment), &display)? else {
                return Ok(None);
            };
            ensure_directory_type(&display, stat.st_mode)?;
            directory = openat(&directory, segment, DIRECTORY_OPEN_FLAGS, Mode::empty())
                .map_err(|error| filesystem_errno("open parent directory", &display, error))?;
        }
        Ok(Some((directory, OsStr::new(file_name))))
    }

    fn open_parent_required<'path>(
        &self,
        path: &'path str,
    ) -> Result<(OwnedFd, &'path OsStr), JournalError> {
        self.open_parent_if_present(path)?
            .ok_or_else(|| JournalError::UnsafePath {
                path: self.project_root.join(path),
                reason: "required parent directory is missing",
            })
    }
    fn open_parent_for_restore<'path>(
        &self,
        path: &'path str,
    ) -> Result<(OwnedFd, &'path OsStr), JournalError> {
        let (parent_path, file_name) = split_parent_name(path);
        let mut directory = duplicate_directory(&self.root_fd, &self.project_root)?;
        let mut prefix = String::new();
        for segment in parent_path.split('/').filter(|segment| !segment.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            let display = self.project_root.join(&prefix);
            if let Some(stat) = stat_optional(&directory, OsStr::new(segment), &display)? {
                ensure_directory_type(&display, stat.st_mode)?;
            } else {
                mkdirat(&directory, segment, DEFAULT_DIRECTORY_MODE).map_err(|error| {
                    filesystem_errno("restore operation parent directory", &display, error)
                })?;
                fsync(&directory).map_err(|error| {
                    filesystem_errno("sync restored parent directory", &display, error)
                })?;
            }
            directory = openat(&directory, segment, DIRECTORY_OPEN_FLAGS, Mode::empty()).map_err(
                |error| filesystem_errno("open restored parent directory", &display, error),
            )?;
        }
        Ok((directory, OsStr::new(file_name)))
    }

    fn prune_empty_operation_parents(
        &self,
        path: &str,
        later_entries: &[JournalEntry],
    ) -> Result<(), JournalError> {
        let (parent_path, _) = split_parent_name(path);
        let mut directories = Vec::new();
        let mut prefix = String::new();
        for segment in parent_path.split('/').filter(|segment| !segment.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            directories.push(prefix.clone());
        }
        for directory_path in directories.into_iter().rev() {
            let nested_prefix = format!("{directory_path}/");
            if later_entries.iter().any(|entry| {
                entry.expected_after_sha256.is_some()
                    && entry.path.starts_with(nested_prefix.as_str())
            }) {
                break;
            }
            let Some((parent, name)) = self.open_parent_if_present(&directory_path)? else {
                continue;
            };
            let display = self.project_root.join(&directory_path);
            let Some(stat) = stat_optional(&parent, name, &display)? else {
                continue;
            };
            ensure_directory_type(&display, stat.st_mode)?;
            match unlinkat(&parent, name, AtFlags::REMOVEDIR) {
                Ok(()) => {
                    fsync(&parent).map_err(|error| {
                        filesystem_errno("sync pruned operation directory", &display, error)
                    })?;
                }
                Err(error) if error == Errno::EXIST || error == Errno::NOTEMPTY => break,
                Err(error) => {
                    return Err(filesystem_errno(
                        "prune empty operation directory",
                        &display,
                        error,
                    ));
                }
            }
        }
        Ok(())
    }

    fn create_journal(&self, journal: &Journal) -> Result<(), JournalError> {
        let replacement = journal.encode()?;
        self.write_journal_bytes(None, &replacement)
    }

    fn replace_journal(
        &self,
        current: &Journal,
        replacement: &Journal,
    ) -> Result<(), JournalError> {
        let expected = current.encode()?;
        let replacement = replacement.encode()?;
        self.write_journal_bytes(Some(&expected), &replacement)
    }

    fn write_journal_bytes(
        &self,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<(), JournalError> {
        self.cleanup_journal_temporary_file()?;
        let target_path = self.project_root.join(TRANSACTION_JOURNAL_PATH);
        let temporary_path = self
            .project_root
            .join(CONTROL_DIRECTORY)
            .join(JOURNAL_TEMP_FILE_NAME);
        let mut journal_checkpoint = |boundary: AtomicWriteBoundary| match boundary {
            AtomicWriteBoundary::TemporaryFileSynced => self.mark_journal_temporary_ready(),
            AtomicWriteBoundary::TargetChanged => self.remove_journal_ready_marker(),
            AtomicWriteBoundary::ParentSynced => Ok(()),
        };
        write_named_atomically(
            &self.control_fd,
            OsStr::new(JOURNAL_FILE_NAME),
            OsStr::new(JOURNAL_TEMP_FILE_NAME),
            &target_path,
            &temporary_path,
            expected,
            replacement,
            Some(PRIVATE_FILE_MODE),
            &mut journal_checkpoint,
        )
    }

    fn cleanup_journal_temporary_file(&self) -> Result<(), JournalError> {
        let journal_path = self.project_root.join(TRANSACTION_JOURNAL_PATH);
        let temporary_path = self.project_root.join(JOURNAL_TEMP_PATH);
        let marker_path = self.project_root.join(JOURNAL_READY_PATH);
        let temporary = read_named_file(
            &self.control_fd,
            OsStr::new(JOURNAL_TEMP_FILE_NAME),
            &temporary_path,
        )?;
        let marker = read_named_file(
            &self.control_fd,
            OsStr::new(JOURNAL_READY_FILE_NAME),
            &marker_path,
        )?;
        if marker.as_ref().is_some_and(|file| !file.bytes.is_empty()) {
            return Err(unexpected_contents(
                JOURNAL_READY_PATH,
                "an empty durable journal-ready marker",
                marker.as_ref().map(|file| file.bytes.as_slice()),
            ));
        }

        match (temporary, marker) {
            (None, None) => Ok(()),
            (Some(_), None) => self.remove_interrupted_journal_temporary(&temporary_path),
            (None, Some(_)) => {
                let current = read_named_file(
                    &self.control_fd,
                    OsStr::new(JOURNAL_FILE_NAME),
                    &journal_path,
                )?
                .ok_or_else(|| {
                    unexpected_contents(
                        TRANSACTION_JOURNAL_PATH,
                        "a valid durable journal after temporary rename",
                        None,
                    )
                })?;
                Journal::decode(&current.bytes)?.validate()?;
                self.remove_journal_ready_marker()
            }
            (Some(temporary), Some(_)) => {
                let candidate = Journal::decode(&temporary.bytes)?;
                candidate.validate()?;
                if let Some(current_bytes) = read_named_file(
                    &self.control_fd,
                    OsStr::new(JOURNAL_FILE_NAME),
                    &journal_path,
                )? {
                    let current = Journal::decode(&current_bytes.bytes)?;
                    current.validate()?;
                    if !current.same_sealed_plan(&candidate)
                        || (current.state == JournalState::Committed
                            && candidate.state != JournalState::Committed)
                    {
                        return Err(unexpected_contents(
                            JOURNAL_TEMP_PATH,
                            "a valid next state of the durable transaction journal",
                            Some(&temporary.bytes),
                        ));
                    }
                }
                renameat(
                    &self.control_fd,
                    JOURNAL_TEMP_FILE_NAME,
                    &self.control_fd,
                    JOURNAL_FILE_NAME,
                )
                .map_err(|error| {
                    filesystem_errno(
                        "finish interrupted journal replacement",
                        &journal_path,
                        error,
                    )
                })?;
                unlinkat(&self.control_fd, JOURNAL_READY_FILE_NAME, AtFlags::empty()).map_err(
                    |error| {
                        filesystem_errno("remove durable journal-ready marker", &marker_path, error)
                    },
                )?;
                fsync(&self.control_fd).map_err(|error| {
                    filesystem_errno(
                        "sync completed journal replacement",
                        self.project_root.join(CONTROL_DIRECTORY),
                        error,
                    )
                })
            }
        }
    }

    fn mark_journal_temporary_ready(&self) -> Result<(), JournalError> {
        let marker_path = self.project_root.join(JOURNAL_READY_PATH);
        fsync(&self.control_fd).map_err(|error| {
            filesystem_errno(
                "sync durable journal temporary name",
                self.project_root.join(CONTROL_DIRECTORY),
                error,
            )
        })?;
        let marker = openat(
            &self.control_fd,
            JOURNAL_READY_FILE_NAME,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            PRIVATE_FILE_MODE,
        )
        .map_err(|error| {
            filesystem_errno("create durable journal-ready marker", &marker_path, error)
        })?;
        let stat = fstat(&marker).map_err(|error| {
            filesystem_errno("inspect durable journal-ready marker", &marker_path, error)
        })?;
        ensure_regular_type(&marker_path, stat.st_mode)?;
        File::from(marker)
            .sync_all()
            .map_err(|source| JournalError::Filesystem {
                action: "sync durable journal-ready marker",
                path: marker_path,
                source,
            })?;
        fsync(&self.control_fd).map_err(|error| {
            filesystem_errno(
                "sync durable journal-ready marker name",
                self.project_root.join(CONTROL_DIRECTORY),
                error,
            )
        })
    }

    fn remove_interrupted_journal_temporary(
        &self,
        temporary_path: &Path,
    ) -> Result<(), JournalError> {
        unlinkat(&self.control_fd, JOURNAL_TEMP_FILE_NAME, AtFlags::empty()).map_err(|error| {
            filesystem_errno(
                "remove interrupted journal temporary file",
                temporary_path,
                error,
            )
        })?;
        fsync(&self.control_fd).map_err(|error| {
            filesystem_errno(
                "sync interrupted journal temporary cleanup",
                self.project_root.join(CONTROL_DIRECTORY),
                error,
            )
        })
    }

    fn remove_journal_ready_marker(&self) -> Result<(), JournalError> {
        let marker_path = self.project_root.join(JOURNAL_READY_PATH);
        unlinkat(&self.control_fd, JOURNAL_READY_FILE_NAME, AtFlags::empty()).map_err(|error| {
            filesystem_errno("remove durable journal-ready marker", &marker_path, error)
        })?;
        fsync(&self.control_fd).map_err(|error| {
            filesystem_errno(
                "sync durable journal-ready marker removal",
                self.project_root.join(CONTROL_DIRECTORY),
                error,
            )
        })
    }

    fn ensure_operation_temporary_absent(
        &self,
        index: usize,
        entry: &JournalEntry,
    ) -> Result<(), JournalError> {
        let Some((directory, _name)) = self.open_parent_if_present(&entry.path)? else {
            return Ok(());
        };
        if entry.temporary_state != TemporaryState::Absent || entry.temporary_identity.is_some() {
            return Err(JournalError::InvalidOperation {
                path: entry.path.clone(),
                reason: "operation temporary state is not absent before apply".to_owned(),
            });
        }
        let temporary_name = operation_temporary_name(index);
        let temporary_path =
            temporary_display_path(&self.project_root, &entry.path, &temporary_name);
        let temporary = read_named_file(&directory, OsStr::new(&temporary_name), &temporary_path)?;
        if let Some(temporary) = temporary {
            return Err(unexpected_contents(
                temporary_path.to_string_lossy().as_ref(),
                "no pre-existing transaction temporary file",
                Some(&temporary.bytes),
            ));
        }
        Ok(())
    }
    fn cleanup_operation_temporary_files(&self, journal: &mut Journal) -> Result<(), JournalError> {
        for index in 0..journal.entries.len() {
            let entry = journal.entries[index].clone();
            self.cleanup_operation_temporary_file(index, &entry)?;
            if journal.entries[index].temporary_state != TemporaryState::Absent {
                let mut updated = journal.clone();
                updated.entries[index].temporary_state = TemporaryState::Absent;
                updated.entries[index].temporary_identity = None;
                self.replace_journal(journal, &updated)?;
                *journal = updated;
            }
        }
        Ok(())
    }

    fn restore_entry(
        &self,
        journal: &mut Journal,
        index: usize,
        entry: &JournalEntry,
        expected_replacement: Option<&[u8]>,
        original: Option<&[u8]>,
    ) -> Result<(), JournalError> {
        let target_path = self.project_root.join(&entry.path);
        if let Some(original) = original {
            let (directory, name) = self.open_parent_for_restore(&entry.path)?;
            let temporary_name = operation_temporary_name(index);
            let temporary_path =
                temporary_display_path(&self.project_root, &entry.path, &temporary_name);
            let mut creating = journal.clone();
            creating.entries[index].temporary_state = TemporaryState::Creating;
            self.replace_journal(journal, &creating)?;
            *journal = creating;
            let exact_mode = entry.original_mode.map(mode_from_u32);
            let (temporary, identity) = create_atomic_temporary(
                &directory,
                OsStr::new(&temporary_name),
                &temporary_path,
                exact_mode,
            )?;
            let mut updated = journal.clone();
            updated.entries[index].temporary_state = TemporaryState::Created;
            updated.entries[index].temporary_identity = Some(identity);
            self.replace_journal(journal, &updated)?;
            *journal = updated;
            let mut no_checkpoint = |_boundary: AtomicWriteBoundary| Ok(());
            write_precreated_atomically(
                &directory,
                name,
                OsStr::new(&temporary_name),
                &target_path,
                &temporary_path,
                expected_replacement,
                original,
                exact_mode,
                temporary,
                &mut no_checkpoint,
            )?;
            let mut updated = journal.clone();
            updated.entries[index].temporary_state = TemporaryState::Absent;
            updated.entries[index].temporary_identity = None;
            self.replace_journal(journal, &updated)?;
            *journal = updated;
            Ok(())
        } else {
            let Some((directory, name)) = self.open_parent_if_present(&entry.path)? else {
                return Ok(());
            };
            remove_named_file_durably(
                &directory,
                name,
                &target_path,
                expected_replacement,
                &mut |_boundary| Ok(()),
            )
        }
    }

    fn ensure_created_directories_absent(&self, journal: &Journal) -> Result<(), JournalError> {
        for directory_record in &journal.created_directories {
            let Some((parent, name)) = self.open_parent_if_present(&directory_record.path)? else {
                continue;
            };
            let display = self.project_root.join(&directory_record.path);
            if let Some(stat) = stat_optional(&parent, name, &display)? {
                ensure_directory_type(&display, stat.st_mode)?;
                return Err(JournalError::UnsafePath {
                    path: display,
                    reason: "transaction parent directory appeared during preparation",
                });
            }
        }
        Ok(())
    }

    fn preflight_created_directories(&self, journal: &Journal) -> Result<(), JournalError> {
        for directory_record in &journal.created_directories {
            let Some((parent, name)) = self.open_parent_if_present(&directory_record.path)? else {
                if journal.state == JournalState::Committed {
                    return Err(JournalError::UnsafePath {
                        path: self.project_root.join(&directory_record.path),
                        reason: "committed transaction parent directory is missing",
                    });
                }
                continue;
            };
            let display = self.project_root.join(&directory_record.path);
            match stat_optional(&parent, name, &display)? {
                Some(stat) => {
                    ensure_directory_type(&display, stat.st_mode)?;
                    match directory_record.state {
                        DirectoryState::Planned => {
                            return Err(JournalError::UnsafePath {
                                path: display,
                                reason: "unowned directory appeared after transaction sealing",
                            });
                        }
                        DirectoryState::Creating => {}
                        DirectoryState::Created => {
                            verify_directory_identity(directory_record, &stat, &display)?;
                        }
                    }
                }
                None if journal.state == JournalState::Committed => {
                    return Err(JournalError::UnsafePath {
                        path: display,
                        reason: "committed transaction parent directory is missing",
                    });
                }
                None => {}
            }
        }
        Ok(())
    }

    fn remove_created_directories(&self, journal: &Journal) -> Result<(), JournalError> {
        for directory_record in journal.created_directories.iter().rev() {
            if directory_record.state == DirectoryState::Planned {
                continue;
            }
            let Some((parent, name)) = self.open_parent_if_present(&directory_record.path)? else {
                continue;
            };
            let display = self.project_root.join(&directory_record.path);
            let Some(stat) = stat_optional(&parent, name, &display)? else {
                continue;
            };
            ensure_directory_type(&display, stat.st_mode)?;
            if directory_record.state == DirectoryState::Created {
                verify_directory_identity(directory_record, &stat, &display)?;
            }
            unlinkat(&parent, name, AtFlags::REMOVEDIR).map_err(|error| {
                filesystem_errno("remove transaction-created directory", &display, error)
            })?;
            fsync(&parent).map_err(|error| {
                filesystem_errno("sync removed directory parent", &display, error)
            })?;
        }
        Ok(())
    }

    fn remove_journal(
        &self,
        journal: &Journal,
        mut injector: Option<&mut dyn ApplyFaultInjector>,
    ) -> Result<(), JournalError> {
        let expected = journal.encode()?;
        let journal_path = self.project_root.join(TRANSACTION_JOURNAL_PATH);
        let current = read_named_file(
            &self.control_fd,
            OsStr::new(JOURNAL_FILE_NAME),
            &journal_path,
        )?;
        if current.as_ref().map(|file| file.bytes.as_slice()) != Some(expected.as_slice()) {
            return Err(unexpected_contents(
                TRANSACTION_JOURNAL_PATH,
                "the current durable journal bytes",
                current.as_ref().map(|file| file.bytes.as_slice()),
            ));
        }
        unlinkat(&self.control_fd, JOURNAL_FILE_NAME, AtFlags::empty())
            .map_err(|error| filesystem_errno("remove committed journal", &journal_path, error))?;
        if let Some(injector) = injector.as_deref_mut() {
            checkpoint(injector, ApplyBoundary::AfterJournalRemoval)?;
        }
        fsync(&self.control_fd).map_err(|error| {
            filesystem_errno(
                "sync lifecycle control directory",
                self.project_root.join(CONTROL_DIRECTORY),
                error,
            )
        })?;
        if let Some(injector) = injector {
            checkpoint(injector, ApplyBoundary::AfterJournalDirectorySync)?;
        }
        Ok(())
    }
}

/// Applicator for a prepared, exact-byte journal. Entries cannot be changed after construction.
#[derive(Debug)]
pub(crate) struct PreparedTransaction<'lock> {
    lock: &'lock mut LifecycleLock,
    journal: Journal,
}

impl PreparedTransaction<'_> {
    /// Applies every sealed entry and rolls back any ordinary application error before returning.
    ///
    /// # Errors
    ///
    /// Returns the application error after successful reverse recovery, or
    /// [`JournalError::RollbackFailed`] when both application and recovery fail.
    pub(crate) fn apply(mut self) -> Result<(), JournalError> {
        match self.apply_inner(&mut NoFault) {
            Ok(()) => Ok(()),
            Err(apply_error) => match self.lock.recover() {
                Ok(RecoveryOutcome::Finalized { .. }) => Ok(()),
                Ok(RecoveryOutcome::None | RecoveryOutcome::RolledBack { .. }) => Err(apply_error),
                Err(rollback_error) => Err(JournalError::RollbackFailed {
                    apply: apply_error.to_string(),
                    rollback: rollback_error.to_string(),
                }),
            },
        }
    }

    /// Applies the transaction while exposing every durable mutation boundary to `injector`.
    ///
    /// Injected faults deliberately retain crash state for a later explicit recovery.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InjectedFault`] at an injected boundary, or the same errors as
    /// [`Self::apply`].
    #[cfg(test)]
    pub(crate) fn apply_with_fault(
        mut self,
        injector: &mut dyn ApplyFaultInjector,
    ) -> Result<(), JournalError> {
        self.apply_inner(injector)
    }

    fn apply_inner(&mut self, injector: &mut dyn ApplyFaultInjector) -> Result<(), JournalError> {
        self.apply_created_directories(injector)?;
        self.apply_entries(injector)?;
        self.commit(injector)
    }

    fn apply_created_directories(
        &mut self,
        injector: &mut dyn ApplyFaultInjector,
    ) -> Result<(), JournalError> {
        for directory_index in 0..self.journal.created_directories.len() {
            self.apply_created_directory(directory_index, injector)?;
        }
        Ok(())
    }

    fn apply_created_directory(
        &mut self,
        directory_index: usize,
        injector: &mut dyn ApplyFaultInjector,
    ) -> Result<(), JournalError> {
        let directory_path = self.journal.created_directories[directory_index]
            .path
            .clone();
        let (parent, name) = self.lock.open_parent_required(&directory_path)?;
        let display = self.lock.project_root.join(&directory_path);
        if let Some(stat) = stat_optional(&parent, name, &display)? {
            ensure_directory_type(&display, stat.st_mode)?;
            return Err(JournalError::UnsafePath {
                path: display,
                reason: "transaction parent directory appeared after sealing",
            });
        }
        checkpoint(
            injector,
            ApplyBoundary::BeforeDirectory {
                directory: directory_index,
            },
        )?;
        let mut creating = self.journal.clone();
        creating.created_directories[directory_index].state = DirectoryState::Creating;
        self.lock.replace_journal(&self.journal, &creating)?;
        self.journal = creating;
        checkpoint(
            injector,
            ApplyBoundary::AfterDirectoryIntentSync {
                directory: directory_index,
            },
        )?;
        mkdirat(&parent, name, DEFAULT_DIRECTORY_MODE).map_err(|error| {
            filesystem_errno("create transaction parent directory", &display, error)
        })?;
        checkpoint(
            injector,
            ApplyBoundary::AfterDirectoryCreated {
                directory: directory_index,
            },
        )?;
        let stat = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
            filesystem_errno("inspect transaction-created directory", &display, error)
        })?;
        ensure_directory_type(&display, stat.st_mode)?;
        let identity = file_identity(&stat, &display)?;
        let mut updated = self.journal.clone();
        updated.created_directories[directory_index].state = DirectoryState::Created;
        updated.created_directories[directory_index].device = Some(identity.device);
        updated.created_directories[directory_index].inode = Some(identity.inode);
        self.lock.replace_journal(&self.journal, &updated)?;
        self.journal = updated;
        fsync(&parent).map_err(|error| {
            filesystem_errno("sync transaction parent directory", &display, error)
        })?;
        checkpoint(
            injector,
            ApplyBoundary::AfterDirectorySync {
                directory: directory_index,
            },
        )
    }

    fn apply_entries(&mut self, injector: &mut dyn ApplyFaultInjector) -> Result<(), JournalError> {
        for index in 0..self.journal.entries.len() {
            self.apply_operation(index, injector)?;
        }
        Ok(())
    }

    fn apply_operation(
        &mut self,
        index: usize,
        injector: &mut dyn ApplyFaultInjector,
    ) -> Result<(), JournalError> {
        checkpoint(injector, ApplyBoundary::BeforeOperation { entry: index })?;
        let entry = self.journal.entries[index].clone();
        let original = entry.original.decode_optional(&entry.path, "original")?;
        let replacement = entry
            .replacement
            .decode_optional(&entry.path, "replacement")?;
        self.lock.ensure_operation_temporary_absent(index, &entry)?;
        let current = self.lock.read_operation_file(&entry.path)?;
        match classify_contents(
            current.as_ref().map(|file| file.bytes.as_slice()),
            original.as_deref(),
            replacement.as_deref(),
        ) {
            ContentDecision::Original => self.apply_entry(
                index,
                &entry,
                original.as_deref(),
                replacement.as_deref(),
                injector,
            )?,
            ContentDecision::Replacement => {}
            ContentDecision::Other => {
                return Err(unexpected_contents(
                    &entry.path,
                    "sealed original or replacement bytes",
                    current.as_ref().map(|file| file.bytes.as_slice()),
                ));
            }
        }
        if !self.journal.entries[index].applied {
            let mut updated = self.journal.clone();
            updated.entries[index].applied = true;
            updated.entries[index].temporary_state = TemporaryState::Absent;
            updated.entries[index].temporary_identity = None;
            self.lock.replace_journal(&self.journal, &updated)?;
            self.journal = updated;
        }
        checkpoint(
            injector,
            ApplyBoundary::AfterAppliedStatusSync { entry: index },
        )
    }

    fn commit(&mut self, injector: &mut dyn ApplyFaultInjector) -> Result<(), JournalError> {
        checkpoint(injector, ApplyBoundary::BeforeCommit)?;
        for entry in &self.journal.entries {
            let replacement = entry
                .replacement
                .decode_optional(&entry.path, "replacement")?;
            let current = self.lock.read_operation_file(&entry.path)?;
            if current.as_ref().map(|file| file.bytes.as_slice()) != replacement.as_deref() {
                return Err(unexpected_contents(
                    &entry.path,
                    "sealed replacement bytes before commit",
                    current.as_ref().map(|file| file.bytes.as_slice()),
                ));
            }
        }
        let mut committed = self.journal.clone();
        committed.state = JournalState::Committed;
        self.lock.replace_journal(&self.journal, &committed)?;
        self.journal = committed;
        checkpoint(injector, ApplyBoundary::AfterCommitSync)?;
        self.lock.remove_journal(&self.journal, Some(injector))
    }

    fn apply_entry(
        &mut self,
        index: usize,
        entry: &JournalEntry,
        expected_original: Option<&[u8]>,
        replacement: Option<&[u8]>,
        injector: &mut dyn ApplyFaultInjector,
    ) -> Result<(), JournalError> {
        let (directory, name) = self.lock.open_parent_required(&entry.path)?;
        let target_path = self.lock.project_root.join(&entry.path);
        if let Some(replacement) = replacement {
            let temporary_name = operation_temporary_name(index);
            let temporary_path =
                temporary_display_path(&self.lock.project_root, &entry.path, &temporary_name);
            let mut creating = self.journal.clone();
            creating.entries[index].temporary_state = TemporaryState::Creating;
            self.lock.replace_journal(&self.journal, &creating)?;
            self.journal = creating;
            checkpoint(
                injector,
                ApplyBoundary::AfterTemporaryIntentSync { entry: index },
            )?;
            let exact_mode = entry.original_mode.map(mode_from_u32);
            let (temporary, identity) = create_atomic_temporary(
                &directory,
                OsStr::new(&temporary_name),
                &temporary_path,
                exact_mode,
            )?;
            checkpoint(
                injector,
                ApplyBoundary::AfterTemporaryFileCreated { entry: index },
            )?;
            let mut updated = self.journal.clone();
            updated.entries[index].temporary_state = TemporaryState::Created;
            updated.entries[index].temporary_identity = Some(identity);
            self.lock.replace_journal(&self.journal, &updated)?;
            self.journal = updated;
            let mut notify = |boundary| match boundary {
                AtomicWriteBoundary::TemporaryFileSynced => checkpoint(
                    injector,
                    ApplyBoundary::AfterTemporaryFileSync { entry: index },
                ),
                AtomicWriteBoundary::TargetChanged => {
                    checkpoint(injector, ApplyBoundary::AfterTargetChange { entry: index })
                }
                AtomicWriteBoundary::ParentSynced => checkpoint(
                    injector,
                    ApplyBoundary::AfterTargetDirectorySync { entry: index },
                ),
            };
            write_precreated_atomically(
                &directory,
                name,
                OsStr::new(&temporary_name),
                &target_path,
                &temporary_path,
                expected_original,
                replacement,
                exact_mode,
                temporary,
                &mut notify,
            )
        } else {
            let mut notify = |boundary| match boundary {
                RemoveBoundary::TargetChanged => {
                    checkpoint(injector, ApplyBoundary::AfterTargetChange { entry: index })
                }
                RemoveBoundary::ParentSynced => checkpoint(
                    injector,
                    ApplyBoundary::AfterTargetDirectorySync { entry: index },
                ),
            };
            remove_named_file_durably(
                &directory,
                name,
                &target_path,
                expected_original,
                &mut notify,
            )?;
            self.lock
                .prune_empty_operation_parents(&entry.path, &self.journal.entries[index + 1..])
        }
    }
}

impl LifecycleLock {
    fn cleanup_operation_temporary_file(
        &self,
        index: usize,
        entry: &JournalEntry,
    ) -> Result<(), JournalError> {
        let Some((directory, _name)) = self.open_parent_if_present(&entry.path)? else {
            return Ok(());
        };
        let temporary_name = operation_temporary_name(index);
        let temporary_path =
            temporary_display_path(&self.project_root, &entry.path, &temporary_name);
        let temporary = read_named_file(&directory, OsStr::new(&temporary_name), &temporary_path)?;
        let Some(temporary) = temporary else {
            return Ok(());
        };
        match entry.temporary_state {
            TemporaryState::Absent => {
                return Err(unexpected_contents(
                    temporary_path.to_string_lossy().as_ref(),
                    "no unowned transaction temporary file",
                    Some(&temporary.bytes),
                ));
            }
            TemporaryState::Creating if !temporary.bytes.is_empty() => {
                return Err(unexpected_contents(
                    temporary_path.to_string_lossy().as_ref(),
                    "the empty temporary file claimed before a crash",
                    Some(&temporary.bytes),
                ));
            }
            TemporaryState::Creating => {}
            TemporaryState::Created => {
                let identity =
                    entry
                        .temporary_identity
                        .ok_or_else(|| JournalError::InvalidOperation {
                            path: entry.path.clone(),
                            reason: "created temporary file has no ownership identity".to_owned(),
                        })?;
                let stat = statat(
                    &directory,
                    OsStr::new(&temporary_name),
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(|error| {
                    filesystem_errno("inspect operation temporary file", &temporary_path, error)
                })?;
                verify_file_identity(identity, &stat, &temporary_path)?;
            }
        }
        unlinkat(&directory, temporary_name.as_str(), AtFlags::empty()).map_err(|error| {
            filesystem_errno("remove operation temporary file", &temporary_path, error)
        })?;
        fsync(&directory).map_err(|error| {
            filesystem_errno("sync operation parent directory", &temporary_path, error)
        })
    }
}

/// Deterministic lifecycle journal failure.
#[derive(Debug)]
pub(crate) enum JournalError {
    /// The exclusive lifecycle lock is already held.
    LockBusy { path: PathBuf },
    /// A file or directory would traverse a symlink or use an unexpected file type.
    UnsafePath { path: PathBuf, reason: &'static str },
    /// A transaction journal already exists and must be recovered first.
    TransactionExists { path: PathBuf },
    /// A plan identifier or journal-level invariant is invalid.
    InvalidPlan(String),
    /// One operation is malformed or internally inconsistent.
    InvalidOperation { path: String, reason: String },
    /// Expected presealed bytes no longer match the filesystem.
    StaleInput {
        path: String,
        expected_sha256: Option<String>,
        actual_sha256: Option<String>,
    },
    /// Recovery or application found bytes outside both sealed states.
    UnexpectedContents {
        path: String,
        expected: &'static str,
        actual_sha256: Option<String>,
    },
    /// Journal JSON could not be decoded.
    Decode(serde_json::Error),
    /// Journal JSON could not be encoded.
    Encode(serde_json::Error),
    /// A filesystem operation failed.
    Filesystem {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// A test seam deliberately interrupted application.
    InjectedFault {
        boundary: ApplyBoundary,
        message: String,
    },
    /// An ordinary apply failure could not be reversed to the sealed original bytes.
    RollbackFailed {
        /// Original application failure.
        apply: String,
        /// Recovery failure.
        rollback: String,
    },
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockBusy { path } => {
                write!(
                    formatter,
                    "lifecycle lock is already held at {}",
                    path.display()
                )
            }
            Self::UnsafePath { path, reason } => {
                write!(
                    formatter,
                    "unsafe lifecycle path {}: {reason}",
                    path.display()
                )
            }
            Self::TransactionExists { path } => write!(
                formatter,
                "transaction journal already exists at {}; recover it before preparing another transaction",
                path.display()
            ),
            Self::InvalidPlan(message) => write!(formatter, "invalid lifecycle plan: {message}"),
            Self::InvalidOperation { path, reason } => {
                write!(formatter, "invalid lifecycle operation `{path}`: {reason}")
            }
            Self::StaleInput {
                path,
                expected_sha256,
                actual_sha256,
            } => write!(
                formatter,
                "stale lifecycle input `{path}`: expected {}, found {}",
                hash_or_missing(expected_sha256.as_deref()),
                hash_or_missing(actual_sha256.as_deref())
            ),
            Self::UnexpectedContents {
                path,
                expected,
                actual_sha256,
            } => write!(
                formatter,
                "unexpected bytes at `{path}`: expected {expected}, found {}",
                hash_or_missing(actual_sha256.as_deref())
            ),
            Self::Decode(error) => write!(
                formatter,
                "invalid durable journal at {TRANSACTION_JOURNAL_PATH}: {error}"
            ),
            Self::Encode(error) => write!(formatter, "cannot encode durable journal: {error}"),
            Self::Filesystem {
                action,
                path,
                source,
            } => write!(formatter, "cannot {action} at {}: {source}", path.display()),
            Self::InjectedFault { boundary, message } => {
                write!(
                    formatter,
                    "injected lifecycle fault at {boundary}: {message}"
                )
            }
            Self::RollbackFailed { apply, rollback } => {
                write!(
                    formatter,
                    "lifecycle apply failed: {apply}; rollback also failed: {rollback}"
                )
            }
        }
    }
}

impl Error for JournalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(error) | Self::Encode(error) => Some(error),
            Self::Filesystem { source, .. } => Some(source),
            Self::LockBusy { .. }
            | Self::UnsafePath { .. }
            | Self::TransactionExists { .. }
            | Self::InvalidPlan(_)
            | Self::InvalidOperation { .. }
            | Self::StaleInput { .. }
            | Self::UnexpectedContents { .. }
            | Self::InjectedFault { .. }
            | Self::RollbackFailed { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    plan_id: String,
    state: JournalState,
    created_directories: Vec<JournalDirectory>,
    entries: Vec<JournalEntry>,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalDirectory {
    path: String,
    state: DirectoryState,
    device: Option<u64>,
    inode: Option<u64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DirectoryState {
    Planned,
    Creating,
    Created,
}

impl Journal {
    fn encode(&self) -> Result<Vec<u8>, JournalError> {
        let mut encoded = serde_json::to_vec_pretty(self).map_err(JournalError::Encode)?;
        encoded.push(b'\n');
        Ok(encoded)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        serde_json::from_slice(bytes).map_err(JournalError::Decode)
    }

    fn same_sealed_plan(&self, other: &Self) -> bool {
        let mut left = self.clone();
        let mut right = other.clone();
        for journal in [&mut left, &mut right] {
            journal.state = JournalState::Prepared;
            for directory in &mut journal.created_directories {
                directory.state = DirectoryState::Planned;
                directory.device = None;
                directory.inode = None;
            }
            for entry in &mut journal.entries {
                entry.temporary_state = TemporaryState::Absent;
                entry.temporary_identity = None;
                entry.applied = false;
            }
        }
        left == right
    }
    fn validate(&self) -> Result<(), JournalError> {
        self.validate_header()?;
        self.validate_created_directories()?;
        self.validate_entries()?;
        self.validate_committed_state()
    }

    fn validate_header(&self) -> Result<(), JournalError> {
        if self.schema_version != JOURNAL_SCHEMA_VERSION {
            return Err(JournalError::InvalidPlan(format!(
                "unsupported journal schema version {}; expected {JOURNAL_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        validate_plan_id(&self.plan_id)?;
        if self.entries.is_empty() {
            return Err(JournalError::InvalidPlan(
                "a transaction journal must contain at least one entry".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_created_directories(&self) -> Result<(), JournalError> {
        let mut directories = BTreeSet::new();
        for directory in &self.created_directories {
            validate_relative_path(&directory.path).map_err(|reason| {
                JournalError::InvalidPlan(format!(
                    "invalid created directory `{}`: {reason}",
                    directory.path
                ))
            })?;
            if directory.path == CONTROL_DIRECTORY || directory.path.starts_with(".omnius/") {
                return Err(JournalError::InvalidPlan(format!(
                    "transaction cannot create reserved directory `{}`",
                    directory.path
                )));
            }
            if !directories.insert(directory.path.as_str()) {
                return Err(JournalError::InvalidPlan(format!(
                    "duplicate created directory `{}`",
                    directory.path
                )));
            }
            match (directory.state, directory.device, directory.inode) {
                (DirectoryState::Created, Some(_), Some(_))
                | (DirectoryState::Planned | DirectoryState::Creating, None, None) => {}
                _ => {
                    return Err(JournalError::InvalidPlan(format!(
                        "created directory `{}` has inconsistent ownership identity",
                        directory.path
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_entries(&self) -> Result<(), JournalError> {
        let mut operation_phase = 0;
        let mut paths = BTreeSet::new();
        for entry in &self.entries {
            let entry_phase = match entry.path.as_str() {
                "Cargo.lock" => 1,
                STATE_FILE_PATH => 2,
                _ => 0,
            };
            if entry_phase < operation_phase {
                return Err(JournalError::InvalidPlan(
                    "ordinary files must precede Cargo.lock and lifecycle state".to_owned(),
                ));
            }
            operation_phase = entry_phase;
            validate_operation_path(&entry.path)?;
            if !paths.insert(entry.path.as_str()) {
                return Err(JournalError::InvalidOperation {
                    path: entry.path.clone(),
                    reason: "duplicate transaction path".to_owned(),
                });
            }
            validate_optional_hash(
                entry.expected_before_sha256.as_deref(),
                &entry.path,
                "before",
            )?;
            validate_optional_hash(entry.expected_after_sha256.as_deref(), &entry.path, "after")?;
            let original = entry.original.decode_optional(&entry.path, "original")?;
            let replacement = entry
                .replacement
                .decode_optional(&entry.path, "replacement")?;
            if original == replacement {
                return Err(JournalError::InvalidOperation {
                    path: entry.path.clone(),
                    reason: "sealed original and replacement bytes are identical".to_owned(),
                });
            }
            if entry.expected_before_sha256.as_deref()
                != original.as_deref().map(sha256_hex).as_deref()
            {
                return Err(JournalError::InvalidOperation {
                    path: entry.path.clone(),
                    reason: "sealed original bytes do not match the recorded before hash"
                        .to_owned(),
                });
            }
            if entry.expected_after_sha256.as_deref()
                != replacement.as_deref().map(sha256_hex).as_deref()
            {
                return Err(JournalError::InvalidOperation {
                    path: entry.path.clone(),
                    reason: "sealed replacement bytes do not match the recorded after hash"
                        .to_owned(),
                });
            }
            match (entry.temporary_state, entry.temporary_identity) {
                (TemporaryState::Absent | TemporaryState::Creating, None)
                | (TemporaryState::Created, Some(_)) => {}
                _ => {
                    return Err(JournalError::InvalidOperation {
                        path: entry.path.clone(),
                        reason: "temporary file state has inconsistent ownership identity"
                            .to_owned(),
                    });
                }
            }
            match (original.as_ref(), entry.original_mode) {
                (Some(_), Some(mode)) if mode & !0o7777 == 0 => {}
                (None, None) => {}
                (Some(_), Some(_)) => {
                    return Err(JournalError::InvalidOperation {
                        path: entry.path.clone(),
                        reason: "sealed original mode contains unsupported bits".to_owned(),
                    });
                }
                _ => {
                    return Err(JournalError::InvalidOperation {
                        path: entry.path.clone(),
                        reason: "sealed original mode does not match original presence".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_committed_state(&self) -> Result<(), JournalError> {
        if self.state == JournalState::Committed
            && (self.entries.iter().any(|entry| {
                entry.temporary_state != TemporaryState::Absent
                    || entry.temporary_identity.is_some()
                    || !entry.applied
            }) || self
                .created_directories
                .iter()
                .any(|directory| directory.state != DirectoryState::Created))
        {
            return Err(JournalError::InvalidPlan(
                "a committed journal must mark every entry and directory applied".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TemporaryState {
    Absent,
    Creating,
    Created,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum JournalState {
    Prepared,
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    path: String,
    expected_before_sha256: Option<String>,
    expected_after_sha256: Option<String>,
    original: Option<EncodedBytes>,
    replacement: Option<EncodedBytes>,
    original_mode: Option<u32>,
    temporary_state: TemporaryState,
    temporary_identity: Option<FileIdentity>,
    applied: bool,
}

trait OptionalEncodedBytes {
    fn decode_optional(
        &self,
        path: &str,
        field: &'static str,
    ) -> Result<Option<Vec<u8>>, JournalError>;
}

impl OptionalEncodedBytes for Option<EncodedBytes> {
    fn decode_optional(
        &self,
        path: &str,
        field: &'static str,
    ) -> Result<Option<Vec<u8>>, JournalError> {
        self.as_ref()
            .map(|encoded| encoded.decode(path, field))
            .transpose()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EncodedBytes {
    encoding: ByteEncoding,
    data: String,
}

impl EncodedBytes {
    fn from_optional(bytes: Option<&[u8]>) -> Option<Self> {
        bytes.map(|bytes| Self {
            encoding: ByteEncoding::Hex,
            data: encode_hex(bytes),
        })
    }

    fn decode(&self, path: &str, field: &'static str) -> Result<Vec<u8>, JournalError> {
        match self.encoding {
            ByteEncoding::Hex => {
                decode_hex(&self.data).map_err(|reason| JournalError::InvalidOperation {
                    path: path.to_owned(),
                    reason: format!("invalid {field} byte encoding: {reason}"),
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum ByteEncoding {
    Hex,
}

#[derive(Debug)]
struct CurrentFile {
    bytes: Vec<u8>,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentDecision {
    Original,
    Replacement,
    Other,
}

#[derive(Clone, Copy, Debug)]
enum AtomicWriteBoundary {
    TemporaryFileSynced,
    TargetChanged,
    ParentSynced,
}

#[derive(Clone, Copy, Debug)]
enum RemoveBoundary {
    TargetChanged,
    ParentSynced,
}

fn open_project_directory(project_root: &Path) -> Result<OwnedFd, JournalError> {
    if project_root.as_os_str().is_empty() {
        return Err(JournalError::UnsafePath {
            path: project_root.to_path_buf(),
            reason: "project root path is empty",
        });
    }
    let directory = open(project_root, DIRECTORY_OPEN_FLAGS, Mode::empty())
        .map_err(|error| filesystem_errno("open project root", project_root, error))?;
    let stat = fstat(&directory)
        .map_err(|error| filesystem_errno("inspect project root", project_root, error))?;
    ensure_directory_type(project_root, stat.st_mode)?;
    Ok(directory)
}
fn ensure_control_directory(
    root_fd: &OwnedFd,
    project_root: &Path,
) -> Result<(OwnedFd, bool), JournalError> {
    let control_path = project_root.join(CONTROL_DIRECTORY);
    let created = match stat_optional(root_fd, OsStr::new(CONTROL_DIRECTORY), &control_path)? {
        Some(stat) => {
            ensure_directory_type(&control_path, stat.st_mode)?;
            false
        }
        None => match mkdirat(root_fd, CONTROL_DIRECTORY, DEFAULT_DIRECTORY_MODE) {
            Ok(()) => {
                fsync(root_fd)
                    .map_err(|error| filesystem_errno("sync project root", project_root, error))?;
                true
            }
            Err(Errno::EXIST) => {
                let stat = stat_optional(root_fd, OsStr::new(CONTROL_DIRECTORY), &control_path)?
                    .ok_or_else(|| JournalError::UnsafePath {
                        path: control_path.clone(),
                        reason: "lifecycle control directory disappeared during creation",
                    })?;
                ensure_directory_type(&control_path, stat.st_mode)?;
                false
            }
            Err(error) => {
                return Err(filesystem_errno(
                    "create lifecycle control directory",
                    &control_path,
                    error,
                ));
            }
        },
    };
    let control_fd = openat(
        root_fd,
        CONTROL_DIRECTORY,
        DIRECTORY_OPEN_FLAGS,
        Mode::empty(),
    )
    .map_err(|error| filesystem_errno("open lifecycle control directory", &control_path, error))?;
    Ok((control_fd, created))
}

fn duplicate_directory(directory: &OwnedFd, display: &Path) -> Result<OwnedFd, JournalError> {
    openat(directory, ".", DIRECTORY_OPEN_FLAGS, Mode::empty())
        .map_err(|error| filesystem_errno("duplicate directory handle", display, error))
}

fn stat_optional(
    directory: &OwnedFd,
    name: &OsStr,
    display: &Path,
) -> Result<Option<rustix::fs::Stat>, JournalError> {
    match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat)),
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(filesystem_errno("inspect filesystem entry", display, error)),
    }
}

fn read_named_file(
    directory: &OwnedFd,
    name: &OsStr,
    display: &Path,
) -> Result<Option<CurrentFile>, JournalError> {
    let Some(stat) = stat_optional(directory, name, display)? else {
        return Ok(None);
    };
    ensure_regular_type(display, stat.st_mode)?;
    let fd = match openat(directory, name, FILE_READ_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(filesystem_errno(
                "open regular file without following symlinks",
                display,
                error,
            ));
        }
    };
    let opened_stat =
        fstat(&fd).map_err(|error| filesystem_errno("inspect opened file", display, error))?;
    ensure_regular_type(display, opened_stat.st_mode)?;
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| JournalError::Filesystem {
            action: "read regular file",
            path: display.to_path_buf(),
            source,
        })?;
    Ok(Some(CurrentFile {
        bytes,
        mode: permission_mode(opened_stat.st_mode),
    }))
}

#[expect(
    clippy::too_many_arguments,
    reason = "atomic replacement needs both descriptor names and diagnostic paths"
)]
fn write_named_atomically(
    directory: &OwnedFd,
    target_name: &OsStr,
    temporary_name: &OsStr,
    target_display: &Path,
    temporary_display: &Path,
    expected_current: Option<&[u8]>,
    replacement: &[u8],
    exact_mode: Option<Mode>,
    notify: &mut dyn FnMut(AtomicWriteBoundary) -> Result<(), JournalError>,
) -> Result<(), JournalError> {
    let (temporary, _) =
        create_atomic_temporary(directory, temporary_name, temporary_display, exact_mode)?;
    write_precreated_atomically(
        directory,
        target_name,
        temporary_name,
        target_display,
        temporary_display,
        expected_current,
        replacement,
        exact_mode,
        temporary,
        notify,
    )
}

fn create_atomic_temporary(
    directory: &OwnedFd,
    temporary_name: &OsStr,
    temporary_display: &Path,
    exact_mode: Option<Mode>,
) -> Result<(File, FileIdentity), JournalError> {
    let fd = openat(
        directory,
        temporary_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        exact_mode.unwrap_or(DEFAULT_FILE_MODE),
    )
    .map_err(|error| filesystem_errno("create atomic temporary file", temporary_display, error))?;
    let stat = fstat(&fd).map_err(|error| {
        filesystem_errno("inspect atomic temporary file", temporary_display, error)
    })?;
    ensure_regular_type(temporary_display, stat.st_mode)?;
    let identity = file_identity(&stat, temporary_display)?;
    Ok((File::from(fd), identity))
}

#[expect(
    clippy::too_many_arguments,
    reason = "atomic replacement needs both descriptor names and diagnostic paths"
)]
fn write_precreated_atomically(
    directory: &OwnedFd,
    target_name: &OsStr,
    temporary_name: &OsStr,
    target_display: &Path,
    temporary_display: &Path,
    expected_current: Option<&[u8]>,
    replacement: &[u8],
    exact_mode: Option<Mode>,
    mut temporary: File,
    notify: &mut dyn FnMut(AtomicWriteBoundary) -> Result<(), JournalError>,
) -> Result<(), JournalError> {
    temporary
        .write_all(replacement)
        .map_err(|source| JournalError::Filesystem {
            action: "write atomic temporary file",
            path: temporary_display.to_path_buf(),
            source,
        })?;
    if let Some(mode) = exact_mode {
        fchmod(&temporary, mode).map_err(|error| {
            filesystem_errno("set atomic temporary file mode", temporary_display, error)
        })?;
    }
    temporary
        .sync_all()
        .map_err(|source| JournalError::Filesystem {
            action: "sync atomic temporary file",
            path: temporary_display.to_path_buf(),
            source,
        })?;
    notify(AtomicWriteBoundary::TemporaryFileSynced)?;
    let current = read_named_file(directory, target_name, target_display)?;
    if current.as_ref().map(|file| file.bytes.as_slice()) != expected_current {
        return Err(unexpected_contents(
            &target_display.to_string_lossy(),
            "the exact presealed bytes immediately before rename",
            current.as_ref().map(|file| file.bytes.as_slice()),
        ));
    }
    let opened_stat = fstat(&temporary).map_err(|error| {
        filesystem_errno(
            "inspect opened atomic temporary file",
            temporary_display,
            error,
        )
    })?;
    let named_stat =
        statat(directory, temporary_name, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
            filesystem_errno(
                "inspect named atomic temporary file",
                temporary_display,
                error,
            )
        })?;
    verify_file_identity(
        file_identity(&opened_stat, temporary_display)?,
        &named_stat,
        temporary_display,
    )?;
    renameat(directory, temporary_name, directory, target_name).map_err(|error| {
        filesystem_errno("atomically replace target file", target_display, error)
    })?;
    notify(AtomicWriteBoundary::TargetChanged)?;
    fsync(directory)
        .map_err(|error| filesystem_errno("sync target parent directory", target_display, error))?;
    notify(AtomicWriteBoundary::ParentSynced)
}

fn remove_named_file_durably(
    directory: &OwnedFd,
    name: &OsStr,
    display: &Path,
    expected_current: Option<&[u8]>,
    notify: &mut dyn FnMut(RemoveBoundary) -> Result<(), JournalError>,
) -> Result<(), JournalError> {
    let current = read_named_file(directory, name, display)?;
    if current.as_ref().map(|file| file.bytes.as_slice()) != expected_current {
        return Err(unexpected_contents(
            display.to_string_lossy().as_ref(),
            "the exact presealed bytes immediately before deletion",
            current.as_ref().map(|file| file.bytes.as_slice()),
        ));
    }
    unlinkat(directory, name, AtFlags::empty())
        .map_err(|error| filesystem_errno("remove sealed file", display, error))?;
    notify(RemoveBoundary::TargetChanged)?;
    fsync(directory)
        .map_err(|error| filesystem_errno("sync removed file parent", display, error))?;
    notify(RemoveBoundary::ParentSynced)
}

fn classify_contents(
    current: Option<&[u8]>,
    original: Option<&[u8]>,
    replacement: Option<&[u8]>,
) -> ContentDecision {
    if current == original {
        ContentDecision::Original
    } else if current == replacement {
        ContentDecision::Replacement
    } else {
        ContentDecision::Other
    }
}

fn verify_file_identity(
    identity: FileIdentity,
    stat: &rustix::fs::Stat,
    display: &Path,
) -> Result<(), JournalError> {
    ensure_regular_type(display, stat.st_mode)?;
    if identity == file_identity(stat, display)? {
        Ok(())
    } else {
        Err(JournalError::UnsafePath {
            path: display.to_path_buf(),
            reason: "transaction temporary file identity changed",
        })
    }
}
fn verify_expected_hash(
    path: &str,
    expected_sha256: Option<&str>,
    current: Option<&[u8]>,
) -> Result<(), JournalError> {
    let actual_sha256 = current.map(sha256_hex);
    if actual_sha256.as_deref() == expected_sha256 {
        Ok(())
    } else {
        Err(JournalError::StaleInput {
            path: path.to_owned(),
            expected_sha256: expected_sha256.map(str::to_owned),
            actual_sha256,
        })
    }
}

fn checkpoint(
    injector: &mut dyn ApplyFaultInjector,
    boundary: ApplyBoundary,
) -> Result<(), JournalError> {
    injector
        .checkpoint(boundary)
        .map_err(|message| JournalError::InjectedFault { boundary, message })
}

fn ensure_regular_type(path: &Path, raw_mode: rustix::fs::RawMode) -> Result<(), JournalError> {
    if FileType::from_raw_mode(raw_mode) == FileType::RegularFile {
        Ok(())
    } else {
        Err(JournalError::UnsafePath {
            path: path.to_path_buf(),
            reason: "existing path is a symlink or non-regular file",
        })
    }
}

fn ensure_directory_type(path: &Path, raw_mode: rustix::fs::RawMode) -> Result<(), JournalError> {
    if FileType::from_raw_mode(raw_mode) == FileType::Directory {
        Ok(())
    } else {
        Err(JournalError::UnsafePath {
            path: path.to_path_buf(),
            reason: "parent path is a symlink or non-directory",
        })
    }
}
fn verify_directory_identity(
    directory: &JournalDirectory,
    stat: &rustix::fs::Stat,
    display: &Path,
) -> Result<(), JournalError> {
    let identity = file_identity(stat, display)?;
    if directory.device == Some(identity.device) && directory.inode == Some(identity.inode) {
        Ok(())
    } else {
        Err(JournalError::UnsafePath {
            path: display.to_path_buf(),
            reason: "transaction-created directory identity changed",
        })
    }
}

fn file_identity(stat: &rustix::fs::Stat, display: &Path) -> Result<FileIdentity, JournalError> {
    Ok(FileIdentity {
        device: checked_device_id(stat.st_dev, display)?,
        inode: stat.st_ino,
    })
}

fn checked_device_id<T>(device: T, display: &Path) -> Result<u64, JournalError>
where
    u64: TryFrom<T>,
{
    u64::try_from(device).map_err(|_| JournalError::UnsafePath {
        path: display.to_path_buf(),
        reason: "filesystem reported a negative device identifier",
    })
}

fn permission_mode<T>(mode: T) -> u32
where
    u32: From<T>,
{
    u32::from(mode) & 0o7777
}

fn mode_from_u32(mode: u32) -> Mode {
    Mode::from_raw_mode(mode as rustix::fs::RawMode)
}

fn validate_plan_id(plan_id: &str) -> Result<(), JournalError> {
    if plan_id.is_empty()
        || plan_id.len() > 128
        || !plan_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(JournalError::InvalidPlan(
            "plan id must be 1..=128 ASCII letters, digits, hyphens, or underscores".to_owned(),
        ));
    }
    Ok(())
}

fn validate_operation_path(path: &str) -> Result<(), JournalError> {
    validate_relative_path(path).map_err(|reason| JournalError::InvalidOperation {
        path: path.to_owned(),
        reason: reason.to_owned(),
    })?;
    if matches!(
        path,
        LIFECYCLE_LOCK_PATH | TRANSACTION_JOURNAL_PATH | JOURNAL_TEMP_PATH | JOURNAL_READY_PATH
    ) {
        return Err(JournalError::InvalidOperation {
            path: path.to_owned(),
            reason: "transaction cannot target lifecycle control files".to_owned(),
        });
    }
    let file_name = split_parent_name(path).1;
    if file_name.starts_with(".omnius-transaction-") {
        return Err(JournalError::InvalidOperation {
            path: path.to_owned(),
            reason: "path uses the lifecycle transaction internal-file namespace".to_owned(),
        });
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("path is empty");
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err("path must use portable project-relative separators");
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err("path contains an empty, current, or parent component");
    }
    Ok(())
}

fn validate_optional_hash(
    hash: Option<&str>,
    path: &str,
    field: &'static str,
) -> Result<(), JournalError> {
    match hash {
        Some(hash) => validate_hash(hash, path, field),
        None => Ok(()),
    }
}

fn validate_hash(hash: &str, path: &str, field: &'static str) -> Result<(), JournalError> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(JournalError::InvalidOperation {
            path: path.to_owned(),
            reason: format!("{field} SHA-256 must be exactly 64 lowercase hexadecimal characters"),
        });
    }
    Ok(())
}

fn split_parent_name(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn operation_temporary_name(index: usize) -> String {
    format!(".omnius-transaction-{index:08x}.tmp")
}

fn temporary_display_path(project_root: &Path, target: &str, temporary_name: &str) -> PathBuf {
    let target = Path::new(target);
    match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            project_root.join(parent).join(temporary_name)
        }
        _ => project_root.join(temporary_name),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    encode_hex(&digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, &'static str> {
    if !encoded.len().is_multiple_of(2) {
        return Err("hex data has an odd length");
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().as_chunks::<2>().0 {
        let high =
            decode_hex_digit(pair[0]).ok_or("hex data contains a non-lowercase-hex character")?;
        let low =
            decode_hex_digit(pair[1]).ok_or("hex data contains a non-lowercase-hex character")?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn unexpected_contents(path: &str, expected: &'static str, actual: Option<&[u8]>) -> JournalError {
    JournalError::UnexpectedContents {
        path: path.to_owned(),
        expected,
        actual_sha256: actual.map(sha256_hex),
    }
}

fn hash_or_missing(hash: Option<&str>) -> &str {
    hash.unwrap_or("<missing>")
}

fn filesystem_errno(action: &'static str, path: impl AsRef<Path>, error: Errno) -> JournalError {
    JournalError::Filesystem {
        action,
        path: path.as_ref().to_path_buf(),
        source: io::Error::from_raw_os_error(error.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use omnius_test_support::CleanDirectory;

    use super::*;

    #[derive(Debug)]
    struct FailAt(ApplyBoundary);

    impl ApplyFaultInjector for FailAt {
        fn checkpoint(&mut self, boundary: ApplyBoundary) -> Result<(), String> {
            if boundary == self.0 {
                Err("simulated interruption".to_owned())
            } else {
                Ok(())
            }
        }
    }

    fn require_error<T, E>(
        result: Result<T, E>,
        message: &'static str,
    ) -> Result<E, Box<dyn Error>> {
        let Err(error) = result else {
            return Err(message.into());
        };
        Ok(error)
    }

    #[test]
    fn journal_round_trip_preserves_arbitrary_exact_bytes() -> Result<(), Box<dyn Error>> {
        let original = [0, 1, 2, 0xff, b'\n'];
        let replacement = [0xfe, 0, b'\r', b'\n'];
        let journal = Journal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            plan_id: "round-trip".to_owned(),
            state: JournalState::Prepared,
            created_directories: Vec::new(),
            entries: vec![JournalEntry {
                path: "data.bin".to_owned(),
                expected_before_sha256: Some(sha256_hex(&original)),
                expected_after_sha256: Some(sha256_hex(&replacement)),
                original: EncodedBytes::from_optional(Some(&original)),
                replacement: EncodedBytes::from_optional(Some(&replacement)),
                original_mode: Some(0o600),
                temporary_state: TemporaryState::Absent,
                temporary_identity: None,
                applied: false,
            }],
        };

        let decoded = Journal::decode(&journal.encode()?)?;
        decoded.validate()?;
        let decoded_original = decoded.entries[0]
            .original
            .decode_optional("data.bin", "original")?;
        let decoded_replacement = decoded.entries[0]
            .replacement
            .decode_optional("data.bin", "replacement")?;

        assert_eq!(
            (decoded, decoded_original, decoded_replacement),
            (journal, Some(original.to_vec()), Some(replacement.to_vec()),)
        );
        Ok(())
    }

    #[test]
    fn prepared_recovery_restores_replacement_after_target_change_fault()
    -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("journal-prepared-recovery")?;
        let target = directory.path().join("target.bin");
        fs::write(&target, b"original")?;
        let mut lock = LifecycleLock::acquire(directory.path())?;
        let operation = JournalOperation::write(
            "target.bin",
            Some(sha256_hex(b"original")),
            b"replacement".to_vec(),
            sha256_hex(b"replacement"),
        )?;
        let transaction = lock.prepare_transaction("prepared-recovery", vec![operation])?;
        let error = require_error(
            transaction
                .apply_with_fault(&mut FailAt(ApplyBoundary::AfterTargetChange { entry: 0 })),
            "fault must interrupt application",
        )?;
        assert!(matches!(error, JournalError::InjectedFault { .. }));
        drop(lock);

        let recovered_lock = LifecycleLock::acquire(directory.path())?;
        let outcome = recovered_lock.recover()?;

        assert_eq!(
            (outcome, fs::read(&target)?, recovered_lock.recover()?),
            (
                RecoveryOutcome::RolledBack {
                    plan_id: "prepared-recovery".to_owned(),
                },
                b"original".to_vec(),
                RecoveryOutcome::None,
            )
        );
        Ok(())
    }

    #[test]
    fn prepared_recovery_removes_synced_temporary_file_and_created_parent()
    -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("journal-temporary-recovery")?;
        let mut lock = LifecycleLock::acquire(directory.path())?;
        let operation = JournalOperation::write(
            "nested/target.bin",
            None,
            b"replacement".to_vec(),
            sha256_hex(b"replacement"),
        )?;
        let transaction = lock.prepare_transaction("temporary-recovery", vec![operation])?;
        require_error(
            transaction.apply_with_fault(&mut FailAt(ApplyBoundary::AfterTemporaryFileSync {
                entry: 0,
            })),
            "fault must interrupt after temporary-file sync",
        )?;
        drop(lock);

        let recovered_lock = LifecycleLock::acquire(directory.path())?;
        let outcome = recovered_lock.recover()?;

        assert_eq!(
            (
                outcome,
                directory.path().join("nested/target.bin").exists(),
                directory.path().join("nested").exists(),
            ),
            (
                RecoveryOutcome::RolledBack {
                    plan_id: "temporary-recovery".to_owned(),
                },
                false,
                false,
            )
        );
        Ok(())
    }

    #[test]
    fn prepared_recovery_fails_closed_on_third_party_bytes() -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("journal-third-bytes")?;
        let target = directory.path().join("target.bin");
        fs::write(&target, b"original")?;
        let mut lock = LifecycleLock::acquire(directory.path())?;
        let operation = JournalOperation::write(
            "target.bin",
            Some(sha256_hex(b"original")),
            b"replacement".to_vec(),
            sha256_hex(b"replacement"),
        )?;
        let transaction = lock.prepare_transaction("third-bytes", vec![operation])?;
        require_error(
            transaction
                .apply_with_fault(&mut FailAt(ApplyBoundary::AfterTargetChange { entry: 0 })),
            "fault must interrupt application",
        )?;
        fs::write(&target, b"third-party")?;
        drop(lock);

        let recovered_lock = LifecycleLock::acquire(directory.path())?;
        let error = require_error(
            recovered_lock.recover(),
            "third-party bytes must block recovery",
        )?;

        assert!(matches!(error, JournalError::UnexpectedContents { .. }));
        Ok(())
    }

    #[test]
    fn committed_recovery_finalizes_without_rolling_back() -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("journal-committed-recovery")?;
        let target = directory.path().join("target.bin");
        fs::write(&target, b"original")?;
        let mut lock = LifecycleLock::acquire(directory.path())?;
        let operation = JournalOperation::write(
            "target.bin",
            Some(sha256_hex(b"original")),
            b"replacement".to_vec(),
            sha256_hex(b"replacement"),
        )?;
        let transaction = lock.prepare_transaction("committed-recovery", vec![operation])?;
        require_error(
            transaction.apply_with_fault(&mut FailAt(ApplyBoundary::AfterCommitSync)),
            "fault must interrupt after commit",
        )?;
        drop(lock);

        let recovered_lock = LifecycleLock::acquire(directory.path())?;
        let outcome = recovered_lock.recover()?;

        assert_eq!(
            (outcome, fs::read(&target)?),
            (
                RecoveryOutcome::Finalized {
                    plan_id: "committed-recovery".to_owned(),
                },
                b"replacement".to_vec(),
            )
        );
        Ok(())
    }

    #[test]
    fn prepared_recovery_handles_crash_before_directory_identity_is_journaled()
    -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("journal-directory-intent-recovery")?;
        let mut lock = LifecycleLock::acquire(directory.path())?;
        let operation = JournalOperation::write(
            "nested/target.bin",
            None,
            b"replacement".to_vec(),
            sha256_hex(b"replacement"),
        )?;
        let transaction = lock.prepare_transaction("directory-intent-recovery", vec![operation])?;
        require_error(
            transaction.apply_with_fault(&mut FailAt(ApplyBoundary::AfterDirectoryCreated {
                directory: 0,
            })),
            "fault must interrupt before directory identity is journaled",
        )?;
        drop(lock);

        let recovered_lock = LifecycleLock::acquire(directory.path())?;
        let outcome = recovered_lock.recover()?;

        assert_eq!(
            outcome,
            RecoveryOutcome::RolledBack {
                plan_id: "directory-intent-recovery".to_owned(),
            }
        );
        assert!(!directory.path().join("nested").exists());
        Ok(())
    }

    #[test]
    fn prepared_recovery_handles_crash_before_temporary_identity_is_journaled()
    -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("journal-temporary-intent-recovery")?;
        let target = directory.path().join("target.bin");
        fs::write(&target, b"original")?;
        let mut lock = LifecycleLock::acquire(directory.path())?;
        let operation = JournalOperation::write(
            "target.bin",
            Some(sha256_hex(b"original")),
            b"replacement".to_vec(),
            sha256_hex(b"replacement"),
        )?;
        let transaction = lock.prepare_transaction("temporary-intent-recovery", vec![operation])?;
        require_error(
            transaction.apply_with_fault(&mut FailAt(ApplyBoundary::AfterTemporaryFileCreated {
                entry: 0,
            })),
            "fault must interrupt before temporary identity is journaled",
        )?;
        drop(lock);

        let recovered_lock = LifecycleLock::acquire(directory.path())?;
        let outcome = recovered_lock.recover()?;

        assert_eq!(
            (outcome, fs::read(target)?, recovered_lock.recover()?,),
            (
                RecoveryOutcome::RolledBack {
                    plan_id: "temporary-intent-recovery".to_owned(),
                },
                b"original".to_vec(),
                RecoveryOutcome::None,
            )
        );
        Ok(())
    }
    #[test]
    fn one_transaction_applies_creation_replacement_and_deletion() -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("journal-operation-kinds")?;
        fs::write(directory.path().join("replace.bin"), b"old")?;
        fs::write(directory.path().join("delete.bin"), b"delete")?;
        let mut lock = LifecycleLock::acquire(directory.path())?;
        let operations = vec![
            JournalOperation::write(
                "nested/create.bin",
                None,
                b"created".to_vec(),
                sha256_hex(b"created"),
            )?,
            JournalOperation::write(
                "replace.bin",
                Some(sha256_hex(b"old")),
                b"new".to_vec(),
                sha256_hex(b"new"),
            )?,
            JournalOperation::remove("delete.bin", sha256_hex(b"delete"))?,
        ];

        lock.prepare_transaction("all-operation-kinds", operations)?
            .apply()?;

        assert_eq!(
            (
                fs::read(directory.path().join("nested/create.bin"))?,
                fs::read(directory.path().join("replace.bin"))?,
                directory.path().join("delete.bin").exists(),
                lock.recover()?,
            ),
            (
                b"created".to_vec(),
                b"new".to_vec(),
                false,
                RecoveryOutcome::None,
            )
        );
        Ok(())
    }

    #[test]
    fn prepared_recovery_recreates_pruned_parents_for_deleted_files() -> Result<(), Box<dyn Error>>
    {
        let directory = CleanDirectory::new("journal-pruned-parent-recovery")?;
        let deleted = directory.path().join("legacy/nested/deleted.bin");
        fs::create_dir_all(deleted.parent().ok_or("deleted file has no parent")?)?;
        fs::write(&deleted, b"original")?;
        let mut lock = LifecycleLock::acquire(directory.path())?;
        let operations = vec![
            JournalOperation::remove("legacy/nested/deleted.bin", sha256_hex(b"original"))?,
            JournalOperation::write(
                "marker.bin",
                None,
                b"marker".to_vec(),
                sha256_hex(b"marker"),
            )?,
        ];
        let transaction = lock.prepare_transaction("pruned-parent-recovery", operations)?;
        require_error(
            transaction.apply_with_fault(&mut FailAt(ApplyBoundary::BeforeOperation { entry: 1 })),
            "fault must interrupt after the deleted file's parents are pruned",
        )?;
        assert!(!directory.path().join("legacy").exists());
        drop(lock);

        let recovered_lock = LifecycleLock::acquire(directory.path())?;
        assert_eq!(
            recovered_lock.recover()?,
            RecoveryOutcome::RolledBack {
                plan_id: "pruned-parent-recovery".to_owned(),
            }
        );
        assert_eq!(fs::read(deleted)?, b"original");
        assert!(!directory.path().join("marker.bin").exists());
        Ok(())
    }

    #[test]
    fn recovery_removes_partial_journal_without_ready_marker() -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("journal-partial-initialization")?;
        let lock = LifecycleLock::acquire(directory.path())?;
        fs::write(
            directory
                .path()
                .join(CONTROL_DIRECTORY)
                .join(JOURNAL_TEMP_FILE_NAME),
            b"{\"schema_version\":",
        )?;

        assert_eq!(lock.recover()?, RecoveryOutcome::None);
        assert!(
            !directory
                .path()
                .join(CONTROL_DIRECTORY)
                .join(JOURNAL_TEMP_FILE_NAME)
                .exists()
        );
        Ok(())
    }

    #[test]
    fn recovery_rejects_malformed_journal_with_ready_marker() -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("journal-malformed-ready")?;
        let lock = LifecycleLock::acquire(directory.path())?;
        let control = directory.path().join(CONTROL_DIRECTORY);
        fs::write(
            control.join(JOURNAL_TEMP_FILE_NAME),
            b"{\"schema_version\":",
        )?;
        fs::write(control.join(JOURNAL_READY_FILE_NAME), [])?;

        assert!(matches!(lock.recover(), Err(JournalError::Decode(_))));
        assert!(control.join(JOURNAL_TEMP_FILE_NAME).exists());
        assert!(control.join(JOURNAL_READY_FILE_NAME).exists());
        Ok(())
    }

    #[test]
    fn every_file_and_commit_boundary_recovers_to_one_complete_identity()
    -> Result<(), Box<dyn Error>> {
        let mut boundaries = Vec::new();
        for entry in 0..3 {
            boundaries.extend([
                ApplyBoundary::BeforeOperation { entry },
                ApplyBoundary::AfterTemporaryIntentSync { entry },
                ApplyBoundary::AfterTemporaryFileCreated { entry },
                ApplyBoundary::AfterTemporaryFileSync { entry },
                ApplyBoundary::AfterTargetChange { entry },
                ApplyBoundary::AfterTargetDirectorySync { entry },
                ApplyBoundary::AfterAppliedStatusSync { entry },
            ]);
        }
        boundaries.extend([
            ApplyBoundary::BeforeCommit,
            ApplyBoundary::AfterCommitSync,
            ApplyBoundary::AfterJournalRemoval,
            ApplyBoundary::AfterJournalDirectorySync,
        ]);

        for (case, boundary) in boundaries.into_iter().enumerate() {
            let label = format!("journal-exhaustive-boundary-{case}");
            let directory = CleanDirectory::new(&label)?;
            fs::create_dir_all(directory.path().join(".omnius"))?;
            fs::write(directory.path().join("ordinary.bin"), b"ordinary-old")?;
            fs::write(directory.path().join("Cargo.lock"), b"lock-old")?;
            fs::write(directory.path().join(".omnius/service.toml"), b"state-old")?;
            let operations = vec![
                JournalOperation::write(
                    "ordinary.bin",
                    Some(sha256_hex(b"ordinary-old")),
                    b"ordinary-new".to_vec(),
                    sha256_hex(b"ordinary-new"),
                )?,
                JournalOperation::write(
                    "Cargo.lock",
                    Some(sha256_hex(b"lock-old")),
                    b"lock-new".to_vec(),
                    sha256_hex(b"lock-new"),
                )?,
                JournalOperation::write(
                    ".omnius/service.toml",
                    Some(sha256_hex(b"state-old")),
                    b"state-new".to_vec(),
                    sha256_hex(b"state-new"),
                )?,
            ];
            let mut lock = LifecycleLock::acquire(directory.path())?;
            require_error(
                lock.prepare_transaction(format!("boundary-{case}"), operations)?
                    .apply_with_fault(&mut FailAt(boundary)),
                "every enumerated boundary must interrupt application",
            )?;
            drop(lock);

            let recovered = LifecycleLock::acquire(directory.path())?;
            let _outcome = recovered.recover()?;
            let actual = (
                fs::read(directory.path().join("ordinary.bin"))?,
                fs::read(directory.path().join("Cargo.lock"))?,
                fs::read(directory.path().join(".omnius/service.toml"))?,
            );
            let old = (
                b"ordinary-old".to_vec(),
                b"lock-old".to_vec(),
                b"state-old".to_vec(),
            );
            let new = (
                b"ordinary-new".to_vec(),
                b"lock-new".to_vec(),
                b"state-new".to_vec(),
            );
            assert!(
                actual == old || actual == new,
                "boundary {boundary} recovered a mixed identity"
            );
            assert!(!directory.path().join(TRANSACTION_JOURNAL_PATH).exists());
            assert_eq!(recovered.recover()?, RecoveryOutcome::None);
        }
        Ok(())
    }

    #[test]
    fn lifecycle_lock_is_exclusive_until_guard_drop() -> Result<(), Box<dyn Error>> {
        let directory = CleanDirectory::new("journal-exclusive-lock")?;
        let first = LifecycleLock::acquire(directory.path())?;
        let error = require_error(
            LifecycleLock::acquire(directory.path()),
            "second lock acquisition must not succeed",
        )?;
        drop(first);
        let second = LifecycleLock::acquire(directory.path())?;

        assert!(matches!(error, JournalError::LockBusy { .. }));
        drop(second);
        Ok(())
    }
}
