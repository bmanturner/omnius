//! Build-time release-binding contracts.

#[path = "../build_support.rs"]
mod build_support;

use build_support::{
    BuildBinding, BuildBindingError, GitSnapshot, porcelain_status_is_dirty, resolve_build_binding,
};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_REVISION: &str = "89abcdef0123456789abcdef0123456789abcdef";
fn test_binding(result: Result<BuildBinding, BuildBindingError>) -> BuildBinding {
    let Ok(binding) = result else {
        panic!("expected a valid build binding");
    };
    binding
}

fn test_error(result: Result<BuildBinding, BuildBindingError>) -> BuildBindingError {
    let Err(error) = result else {
        panic!("expected build binding validation to fail");
    };
    error
}

#[test]
fn clean_attached_or_detached_git_should_bind_head() {
    let snapshot = GitSnapshot {
        revision: REVISION.to_owned(),
        dirty: false,
    };

    let binding = test_binding(resolve_build_binding(None, Some(&snapshot)));

    assert_eq!(
        binding,
        BuildBinding::Bound {
            revision: REVISION.to_owned(),
            dirty: false,
        }
    );
}

#[test]
fn packaged_explicit_revision_should_bind_without_git() {
    let binding = test_binding(resolve_build_binding(Some(REVISION), None));

    assert_eq!(
        binding,
        BuildBinding::Bound {
            revision: REVISION.to_owned(),
            dirty: false,
        }
    );
}

#[test]
fn absent_explicit_revision_and_git_should_remain_unbound() {
    let binding = test_binding(resolve_build_binding(None, None));

    assert_eq!(binding, BuildBinding::Unbound);
}

#[test]
fn explicit_revision_should_have_precedence_but_must_match_git() {
    let snapshot = GitSnapshot {
        revision: OTHER_REVISION.to_owned(),
        dirty: false,
    };

    let error = test_error(resolve_build_binding(Some(REVISION), Some(&snapshot)));

    assert_eq!(
        error,
        BuildBindingError::RevisionMismatch {
            explicit: REVISION.to_owned(),
            git: OTHER_REVISION.to_owned(),
        }
    );
}

#[test]
fn malformed_explicit_revision_should_fail_even_without_git() {
    let error = test_error(resolve_build_binding(Some("ABC123"), None));

    assert_eq!(
        error,
        BuildBindingError::InvalidExplicitRevision("ABC123".to_owned())
    );
}

#[test]
fn malformed_git_revision_should_never_bind() {
    let snapshot = GitSnapshot {
        revision: "ABC123".to_owned(),
        dirty: false,
    };

    let error = test_error(resolve_build_binding(None, Some(&snapshot)));

    assert_eq!(
        error,
        BuildBindingError::InvalidGitRevision("ABC123".to_owned())
    );
}

#[test]
fn git_dirty_state_should_survive_a_matching_explicit_revision() {
    let snapshot = GitSnapshot {
        revision: REVISION.to_owned(),
        dirty: true,
    };

    let binding = test_binding(resolve_build_binding(Some(REVISION), Some(&snapshot)));

    assert_eq!(
        binding,
        BuildBinding::Bound {
            revision: REVISION.to_owned(),
            dirty: true,
        }
    );
}

#[test]
fn porcelain_status_should_cover_staged_unstaged_and_untracked_paths() {
    for status in [
        b"M  crates/generator/src/lib.rs\n".as_slice(),
        b" M crates/generator/src/lib.rs\n".as_slice(),
        b"?? .cargo/config\n".as_slice(),
        b"?? nested/untracked.txt\n".as_slice(),
    ] {
        assert!(porcelain_status_is_dirty(status));
    }
}

#[test]
fn empty_porcelain_status_should_be_clean() {
    assert!(!porcelain_status_is_dirty(b""));
}
