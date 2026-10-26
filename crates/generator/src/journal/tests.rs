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

fn require_error<T, E>(result: Result<T, E>, message: &'static str) -> Result<E, Box<dyn Error>> {
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
fn prepared_recovery_restores_replacement_after_target_change_fault() -> Result<(), Box<dyn Error>>
{
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
        transaction.apply_with_fault(&mut FailAt(ApplyBoundary::AfterTargetChange { entry: 0 })),
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
fn prepared_recovery_removes_synced_temporary_file_and_created_parent() -> Result<(), Box<dyn Error>>
{
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
        transaction.apply_with_fault(&mut FailAt(ApplyBoundary::AfterTargetChange { entry: 0 })),
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
fn prepared_recovery_recreates_pruned_parents_for_deleted_files() -> Result<(), Box<dyn Error>> {
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
fn every_file_and_commit_boundary_recovers_to_one_complete_identity() -> Result<(), Box<dyn Error>>
{
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
